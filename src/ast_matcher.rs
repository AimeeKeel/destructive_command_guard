//! Default policy for executable heredoc and inline-script source.
//!
//! Source recovery and the configurable AST corpus live in
//! `ast_source_analysis.rs`. This entry point also revalidates Python's
//! temporary-directory producer grants before the evaluator can use them.
//! An unknown or replaced factory keeps the existing recursive-deletion rule.

#[path = "ast_source_analysis.rs"]
mod source_analysis;
#[path = "ast_matcher/tempfile_provenance.rs"]
mod tempfile_provenance;

pub use source_analysis::*;

use crate::heredoc::ScriptLanguage;
use std::ops::Deref;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// The default matcher used by the CLI and hooks, including producer provenance.
/// Explicit `AstMatcher` corpora remain independently configurable as before.
#[derive(Debug, Default)]
pub struct DefaultPolicyMatcher;

/// The entry point used by the evaluator after executable-source extraction.
pub static DEFAULT_MATCHER: LazyLock<DefaultPolicyMatcher> =
    LazyLock::new(DefaultPolicyMatcher::default);

impl Deref for DefaultPolicyMatcher {
    type Target = source_analysis::DefaultPolicyMatcher;

    fn deref(&self) -> &Self::Target {
        &source_analysis::DEFAULT_MATCHER
    }
}

impl DefaultPolicyMatcher {
    /// Match executable source and revalidate its temporary producer exemptions.
    ///
    /// # Errors
    ///
    /// Returns the source matcher's parsing, availability, or timeout error.
    /// An incomplete producer proof instead withholds the optional exemption.
    pub fn find_matches(
        &self,
        code: &str,
        language: ScriptLanguage,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let matches = source_analysis::DEFAULT_MATCHER.find_matches(code, language)?;
        Ok(tempfile_provenance::validate(
            code,
            language,
            matches,
            source_analysis::protected_scan_budget(),
        ))
    }

    /// Match source with an explicit budget. The producer proof uses only the
    /// time remaining after source matching, never an additional time envelope.
    ///
    /// # Errors
    ///
    /// Returns the source matcher's parsing, availability, or timeout error.
    pub fn find_matches_with_timeout(
        &self,
        code: &str,
        language: ScriptLanguage,
        timeout: Duration,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let started = Instant::now();
        let matches = source_analysis::DEFAULT_MATCHER
            .find_matches_with_timeout(code, language, timeout)?;
        Ok(tempfile_provenance::validate(
            code,
            language,
            matches,
            timeout.saturating_sub(started.elapsed()),
        ))
    }

    /// Return the first blocking match from the complete default policy.
    #[must_use]
    pub fn has_blocking_match(&self, code: &str, language: ScriptLanguage) -> Option<PatternMatch> {
        self.find_matches(code, language)
            .ok()?
            .into_iter()
            .find(|hit| hit.severity.blocks_by_default())
    }
}

/// Recover literal shell values only from source with execution evidence.
///
/// #560 was caused by promoting every unowned string containing backticks or
/// dollar-parens to a complete shell program. A tuple, regex replacement, or
/// opaque text-editing helper does not establish that execution context. This
/// gate is NOT a source exemption: the evaluator still checks named sinks,
/// interpreter operations, protected writes, and the original outer command.
///
/// Be conservative when a program refers to execution APIs, aliases them, or
/// uses reflective/computed dispatch: retain the complete original recovery,
/// including every indirect literal and exec/eval dependency. This is a
/// program-level evidence screen, not a proof of non-execution or a taint analysis.
/// Unknown helper calls alone do not establish a shell-command role.
///
/// The screen runs INSIDE the existing worker's permit and deadline, including
/// parsing. No extra worker or fresh time envelope is created. A failed or
/// incomplete screen keeps the original fail-closed analysis, not an allowance.
pub(crate) fn interpreter_literal_shell_commands(
    code: &str,
    language: ScriptLanguage,
    allow_documentation_literals: impl FnOnce() -> Option<bool> + Send + 'static,
    budget: Duration,
) -> Result<Vec<ReconstructedCommand>, MatchError> {
    // Let the existing implementation own its cheap gate and byte-limit error.
    // Avoid allocating a second unbounded source before its worker starts.
    if !source_analysis::has_interpreter_literal_candidates(code, language)
        || code.len() > LITERAL_EVIDENCE_MAX_BYTES
    {
        return source_analysis::interpreter_literal_shell_commands(
            code,
            language,
            allow_documentation_literals,
            budget,
        );
    }
    let started = Instant::now();
    let source = code.to_owned();
    source_analysis::interpreter_literal_shell_commands(
        code,
        language,
        move || {
            // Preserve the caller's unsupported-inline and outer-consumer
            // contracts. The callback is invoked exactly once, as before.
            let allow_documentation = allow_documentation_literals()?;
            literal_source_has_execution_evidence(&source, language)
                .then_some(allow_documentation)
        },
        budget.saturating_sub(started.elapsed()),
    )
}

// Independent bounds on this optional screen. Crossing either withholds the
// screen, leaving the existing source analyzer's hard bounds and errors intact.
const LITERAL_EVIDENCE_MAX_BYTES: usize = 256 * 1024;
const LITERAL_EVIDENCE_MAX_NODES: usize = 4096;

fn literal_source_has_execution_evidence(code: &str, language: ScriptLanguage) -> bool {
    use ast_grep_core::AstGrep;
    use ast_grep_language::SupportLang;

    if code.len() > LITERAL_EVIDENCE_MAX_BYTES {
        return true;
    }
    let grammar = match language {
        ScriptLanguage::Python => SupportLang::Python,
        ScriptLanguage::JavaScript => SupportLang::JavaScript,
        _ => return true,
    };
    let _phase = crate::perf::phase(crate::perf::ProfilePhase::AstMatch);
    let ast = {
        let _parse = crate::perf::phase(crate::perf::ProfilePhase::AstParse);
        AstGrep::try_new(code, grammar)
    };
    let Ok(ast) = ast else {
        return true;
    };
    let root = ast.root();
    for (index, node) in root.dfs().enumerate() {
        if index >= LITERAL_EVIDENCE_MAX_NODES || node.is_error() || node.is_missing() {
            return true;
        }
        let kind = node.kind();
        if matches!(kind.as_ref(), "call" | "call_expression") {
            let Some(function) = node.field("function") else {
                return true;
            };
            if !matches!(
                function.kind().as_ref(),
                "identifier" | "attribute" | "member_expression"
            ) || language == ScriptLanguage::JavaScript
                && node
                    .field("arguments")
                    .is_none_or(|arguments| arguments.kind().as_ref() != "arguments")
            {
                // Computed calls, returned callables, tagged templates, and
                // parenthesized dispatch keep the original conservative scan.
                return true;
            }
        }
        if language == ScriptLanguage::JavaScript
            && matches!(
                kind.as_ref(),
                "import_statement" | "new_expression" | "subscript_expression"
            )
        {
            // ESM imports and computed members may expose/alias execution
            // capabilities without a literal terminal method name.
            return true;
        }
        if language == ScriptLanguage::Python
            && kind.as_ref() == "import_from_statement"
            && node.text().contains('*')
        {
            return true;
        }
        if matches!(kind.as_ref(), "identifier" | "property_identifier") {
            let name = node.text();
            // Python normalizes Unicode names; JavaScript accepts identifier
            // escapes. Unmodeled spellings cannot exclude an execution API.
            if !name.is_ascii()
                || name.contains('\\')
                || name.starts_with("__")
                || literal_execution_name(name.as_ref())
            {
                return true;
            }
        }
    }
    false
}

fn literal_execution_name(name: &str) -> bool {
    // References count, not just direct calls: f = os.system; f(value), imports
    // with aliases, and methods in nested callbacks retain the original scan.
    // Names are deliberately a superset: an unrelated run()/call() may still
    // need review, but a familiar execution API never gains a new exemption.
    name.starts_with("exec")
        || name.starts_with("spawn")
        || name.starts_with("popen")
        || matches!(
            name,
            "system"
                | "popen"
                | "Popen"
                | "run"
                | "call"
                | "check_call"
                | "check_output"
                | "getoutput"
                | "getstatusoutput"
                | "create_subprocess_shell"
                | "create_subprocess_exec"
                | "shell"
                | "sh"
                | "bash"
                | "zsh"
                | "dash"
                | "ksh"
                | "fish"
                | "posix_spawn"
                | "posix_spawnp"
                | "fork"
                | "forkpty"
                | "startfile"
                | "pexpect"
                | "pty"
                | "eval"
                | "compile"
                | "getattr"
                | "setattr"
                | "delattr"
                | "globals"
                | "locals"
                | "vars"
                | "import_module"
                | "importlib"
                | "runpy"
                | "ctypes"
                | "Function"
                | "AsyncFunction"
                | "GeneratorFunction"
                | "constructor"
                | "Reflect"
                | "global"
                | "globalThis"
                | "window"
                | "process"
                | "module"
                | "require"
        )
}

#[cfg(test)]
mod literal_execution_evidence_tests {
    use super::*;

    #[test]
    fn python_data_literals_do_not_establish_shell_execution_560() {
        for source in [
            "import re\ns = re.sub(r'x$', \"it's `tool --help`\", 'x')",
            "y = ('x', \"it's `tool --help`\")",
            "y = f('x', \"it's `tool --help`\")",
            "rep('''use core::fav;\nfn with_store<R>(\n/// The items `zone` belongs to (`list_items`).''')",
            "import sys\nnew = ('echo $(date)\\n' '(cd t && task >\"$W/out-$SHA.log\")\\n' + old)",
            "text = \"os.system('echo $(date)')\"\nwrite_example(text)",
            "# os.system and eval are documentation, not references\ny = ('$(date)', 'text')",
        ] {
            assert!(
                !literal_source_has_execution_evidence(source, ScriptLanguage::Python),
                "interpreter data was promoted to a shell program: {source}"
            );
        }
    }

    #[test]
    fn javascript_data_literals_do_not_establish_shell_execution_560() {
        for source in [
            "const text = \"it's `tool --help`\"; edit(text);",
            "const pair = ['x', \"it's `tool --help`\"];",
            "const text = 'fn with_store<R>( `zone`'; rep(text);",
            "const text = '(task >\"$W/out.log\") $(date)'; edit(text);",
            "const text = \"execSync('echo $(date)')\"; writeExample(text);",
        ] {
            assert!(
                !literal_source_has_execution_evidence(source, ScriptLanguage::JavaScript),
                "interpreter data was promoted to a shell program: {source}"
            );
        }
    }

    #[test]
    fn direct_indirect_and_reflective_execution_keep_full_recovery_560() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import os\ns = 'echo $(date); task >\"$W/out\"'\nos.system(s)",
            ),
            (
                ScriptLanguage::Python,
                "from os import system as dispatch\ns = 'echo $(date)'\ndispatch(s)",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess as p\nf = p.run\nf('echo $(date)', shell=True)",
            ),
            (
                ScriptLanguage::Python,
                "import os\nos.posix_spawn('/bin/sh', ['sh', '-c', 'echo $(date)'], {})",
            ),
            (
                ScriptLanguage::Python,
                "import os\nf = getattr(os, 'sys' + 'tem')\nf('echo $(date)')",
            ),
            (
                ScriptLanguage::Python,
                "import os\ns = 'git reset --hard'\nexec('os.system(s)')",
            ),
            (
                ScriptLanguage::Python,
                "from helpers import *\nf('echo $(date)')",
            ),
            (
                ScriptLanguage::Python,
                "def helper(s):\n    os.system(s)\nhelper('echo $(date)')",
            ),
            (ScriptLanguage::Python, "ｅxec('echo $(date)')"),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); const s = 'echo $(date)'; cp.execSync(s);",
            ),
            (
                ScriptLanguage::JavaScript,
                "import {execSync as dispatch} from 'node:child_process'; dispatch('echo $(date)');",
            ),
            (
                ScriptLanguage::JavaScript,
                "const f = cp['exe' + 'cSync']; f('echo $(date)');",
            ),
            (
                ScriptLanguage::JavaScript,
                "Function('return process')();",
            ),
            (ScriptLanguage::JavaScript, "tag`echo $(date)`;"),
            (ScriptLanguage::JavaScript, r"e\u0076al('echo $(date)');"),
            (
                ScriptLanguage::JavaScript,
                "const handler = value => cp.execSync(value); handler('echo $(date)');",
            ),
        ] {
            assert!(
                literal_source_has_execution_evidence(source, language),
                "execution evidence must retain every original recovery rule: {source}"
            );
        }
    }

    #[test]
    fn incomplete_evidence_is_not_an_absence_proof_560() {
        for (language, source) in [
            (ScriptLanguage::Python, "f('$(date)'"),
            (ScriptLanguage::JavaScript, "edit('$(date)'"),
            (ScriptLanguage::Ruby, "puts '$(date)'"),
        ] {
            assert!(literal_source_has_execution_evidence(source, language));
        }
        let large = format!("#{}", "x".repeat(LITERAL_EVIDENCE_MAX_BYTES));
        assert!(literal_source_has_execution_evidence(
            &large,
            ScriptLanguage::Python
        ));
        let many_nodes = "pass\n".repeat(LITERAL_EVIDENCE_MAX_NODES);
        assert!(literal_source_has_execution_evidence(
            &many_nodes,
            ScriptLanguage::Python
        ));
    }

    #[test]
    fn data_volume_does_not_invent_an_execution_use_560() {
        let source = "text = 'example $(date) with `tool --help`'\n".repeat(160);
        assert!(!literal_source_has_execution_evidence(
            &source,
            ScriptLanguage::Python
        ));
        let with_sink = format!("{source}os.system(text)\n");
        assert!(literal_source_has_execution_evidence(
            &with_sink,
            ScriptLanguage::Python
        ));
    }
}
