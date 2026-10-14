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
        complete_python_deletion_matches(
            code,
            language,
            matches,
            source_analysis::protected_scan_budget(),
        )
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
        complete_python_deletion_matches(
            code,
            language,
            matches,
            timeout.saturating_sub(started.elapsed()),
        )
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

// These are invocations of a statically named deletion member, not mere
// lookups. Keep both quote spellings explicit: matching must not depend on a
// grammar's treatment of quote tokens. Like the existing $M.rmtree pattern,
// the receiver is deliberately not restricted to one module variable name.
const PYTHON_REFLECTIVE_DELETE_CALLEES: [&str; 7] = [
    "getattr($M, 'rmtree')",
    "getattr($M, \"rmtree\")",
    "$B.getattr($M, 'rmtree')",
    "$B.getattr($M, \"rmtree\")",
    "$M.__dict__['rmtree']",
    "$M.__dict__[\"rmtree\"]",
    "$M.rmtree.__call__",
];

static PYTHON_REFLECTIVE_DELETE_MATCHER: LazyLock<AstMatcher> = LazyLock::new(|| {
    // Reuse the registered rule, including its target refinement, rather than
    // harvesting a receiver's first literal ('rmtree') as the deletion path.
    // Explicit user-created AstMatcher corpora remain unchanged.
    let meta = source_analysis::default_patterns()
        .remove(&ScriptLanguage::Python)
        .and_then(|patterns| {
            patterns
                .into_iter()
                .find(|meta| meta.rule_id == "heredoc.python.shutil_rmtree")
        })
        .expect("the default Python corpus registers its recursive-deletion rule");
    let mut patterns = Vec::new();
    for callee in PYTHON_REFLECTIVE_DELETE_CALLEES {
        for pattern in [format!("{callee}($$$)"), format!("({callee})($$$)")] {
            let mut pattern_meta = meta.clone();
            pattern_meta.pattern_str = pattern;
            patterns.push(pattern_meta);
        }
    }
    AstMatcher::with_patterns(std::collections::HashMap::from([(
        ScriptLanguage::Python,
        patterns,
    )]))
});

fn complete_python_deletion_matches(
    code: &str,
    language: ScriptLanguage,
    mut matches: Vec<PatternMatch>,
    budget: Duration,
) -> Result<Vec<PatternMatch>, MatchError> {
    let started = Instant::now();
    if language == ScriptLanguage::Python
        && code.contains("rmtree")
        && ["getattr", "__dict__", "__call__"]
            .iter()
            .any(|name| code.contains(name))
    {
        // The ordinary AST worker supplies byte bounds, cancellation and the
        // error contract. An incomplete extra scan is not an empty success.
        let extra = PYTHON_REFLECTIVE_DELETE_MATCHER.find_matches_with_timeout(
            code,
            language,
            budget.saturating_sub(started.elapsed()),
        )?;
        let mut seen: std::collections::HashSet<_> = matches
            .iter()
            .map(|hit| (hit.start, hit.end, hit.rule_id.clone()))
            .collect();
        for hit in extra {
            if seen.insert((hit.start, hit.end, hit.rule_id.clone())) {
                matches.push(hit);
            }
        }
        // Keep the original finding's precedence on a tie. The supplemental
        // corpus also resolves imported aliases; do not duplicate those hits.
        matches.sort_by_key(|hit| hit.start);
    }
    // A reflected call gets exactly the existing descendant and factory
    // policies. New .temp matches must not bypass factory/dependency proofs.
    // Share the remaining budget; do not grant the proof a fresh deadline.
    Ok(tempfile_provenance::validate(
        code,
        language,
        matches,
        budget.saturating_sub(started.elapsed()),
    ))
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
/// Unknown helper calls alone do not establish a shell-command role in an
/// isolated interpreter program. An unproved outer consumer still requires
/// the original recovery: even a print-only program can feed a later shell.
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
            literal_recovery_scope(&source, language, allow_documentation)
        },
        budget.saturating_sub(started.elapsed()),
    )
}

fn literal_recovery_scope(
    code: &str,
    language: ScriptLanguage,
    isolated_source: bool,
) -> Option<bool> {
    // No source-local absence of execution APIs proves where stdout or a
    // generated file goes. Keep the caller's stricter interpretation before
    // attempting this screen, including pipelines, wrappers and later readers.
    if !isolated_source {
        return Some(false);
    }
    literal_source_has_execution_evidence(code, language).then_some(true)
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
    fn python_reflective_rmtree_uses_the_existing_path_policy() {
        #[derive(serde::Deserialize)]
        struct Case {
            id: String,
            decision: String,
            source: String,
        }
        let cases: Vec<Case> = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/python_reflective_rmtree.json"
        )))
        .expect("valid reflective-deletion verdict fixtures");
        assert!(!cases.is_empty());
        for case in cases {
            let matches = DEFAULT_MATCHER
                .find_matches_with_timeout(
                    &case.source,
                    ScriptLanguage::Python,
                    Duration::from_secs(5),
                )
                .unwrap_or_else(|error| panic!("{}: {error:?}", case.id));
            assert_eq!(
                matches.iter().any(|hit| hit.severity.blocks_by_default()),
                case.decision == "deny",
                "{}: {}",
                case.id,
                case.source,
            );
        }
    }

    #[test]
    fn reflective_deletion_budget_exhaustion_is_not_a_clean_result() {
        assert!(
            complete_python_deletion_matches(
                "import shutil\ngetattr(shutil, 'rmtree')('/tmp')",
                ScriptLanguage::Python,
                Vec::new(),
                Duration::ZERO,
            )
            .is_err()
        );
        assert!(
            complete_python_deletion_matches(
                "print('ready')",
                ScriptLanguage::Python,
                Vec::new(),
                Duration::ZERO,
            )
            .expect("unrelated source does not start a supplemental scan")
            .is_empty()
        );
    }

    #[test]
    fn reflective_deletion_merge_preserves_primary_rule_identity() {
        let source = "import shutil\nfrom shutil import rmtree as wipe\nwipe('/tmp')\ngetattr(shutil, 'copy')";
        let original = source_analysis::DEFAULT_MATCHER
            .find_matches_with_timeout(source, ScriptLanguage::Python, Duration::from_secs(5))
            .expect("complete primary deletion analysis");
        let primary = original
            .iter()
            .find(|hit| hit.rule_id == "heredoc.python.shutil_rmtree")
            .expect("the imported deletion has the established rule")
            .clone();
        let matches = complete_python_deletion_matches(
            source,
            ScriptLanguage::Python,
            original,
            Duration::from_secs(5),
        )
        .expect("complete supplemental scan");
        assert_eq!(
            matches.iter().filter(|hit| **hit == primary).count(),
            1,
            "do not duplicate or replace the primary finding",
        );
    }

    #[test]
    fn unproved_outer_consumers_keep_the_original_recovery_560() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "text = 'echo $(git reset --hard)'\nprint(text)",
            ),
            (
                ScriptLanguage::JavaScript,
                "const text = 'echo $(git reset --hard)'; console.log(text);",
            ),
        ] {
            assert_eq!(literal_recovery_scope(source, language, false), Some(false));
            assert_eq!(literal_recovery_scope(source, language, true), None);
        }
    }

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
