//! Recheck name-based Python cleanup grants at the default policy boundary.
//!
//! A callable named `mkdtemp` is not necessarily the standard-library factory.
//! This positive proof only keeps an existing producer exemption when an
//! immutable, dominating import establishes that identity. It never grants a
//! new exemption, changes literal-path policy, or resolves the host filesystem.

use super::{PatternMatch, ScriptLanguage, Severity};
use ast_grep_core::{AstGrep, Doc, Node};
use ast_grep_language::SupportLang;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const TEMP_RULE: &str = "heredoc.python.shutil_rmtree.temp";
const DELETE_RULE: &str = "heredoc.python.shutil_rmtree";
const MAX_SOURCE_BYTES: usize = 256 * 1024;
const MAX_NODES: usize = 40_000;
const MAX_IMPORTS: usize = 256;
const MAX_DEPTH: usize = 128;

type Span = (usize, usize);

fn needs_proof(code: &str, hit: &PatternMatch) -> bool {
    hit.rule_id == TEMP_RULE
        && code.get(hit.start..hit.end).is_some_and(|text| {
            text.contains("mkdtemp") || text.contains("TemporaryDirectory")
        })
}

/// Tighten only existing producer grants. All unrelated matches, including
/// every established blocking result, retain their identity and precedence.
pub(super) fn validate(
    code: &str,
    language: ScriptLanguage,
    mut matches: Vec<PatternMatch>,
    budget: Duration,
) -> Vec<PatternMatch> {
    if language != ScriptLanguage::Python || !matches.iter().any(|hit| needs_proof(code, hit)) {
        return matches;
    }
    let candidates: HashSet<_> = matches
        .iter()
        .filter(|hit| needs_proof(code, hit))
        .map(|hit| (hit.start, hit.end))
        .collect();
    let proved = prove_bounded(code, candidates, budget).unwrap_or_default();
    for hit in &mut matches {
        if needs_proof(code, hit) && !proved.contains(&(hit.start, hit.end)) {
            // Restore the registered recursive-deletion rule, not a novel rule
            // that could bypass an existing per-rule policy or allowlist.
            hit.rule_id = DELETE_RULE.to_string();
            hit.reason = "shutil.rmtree() target is not a proven temporary directory".to_string();
            hit.severity = Severity::Critical;
            hit.suggestion = Some(
                "Use a literal temporary descendant or an unmodified tempfile factory".to_string(),
            );
        }
    }
    matches
}

fn prove_bounded(code: &str, candidates: HashSet<Span>, budget: Duration) -> Option<HashSet<Span>> {
    if budget.is_zero() || code.len() > MAX_SOURCE_BYTES {
        return None;
    }
    let started = Instant::now();
    let source = code.to_string();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);
    let (sender, receiver) = mpsc::sync_channel(1);
    let profile = crate::perf::capture_profile();
    let _worker = thread::Builder::new()
        .name("dcg-tempfile-proof".to_string())
        .spawn(move || {
            let _profile = profile.enter();
            let _phase = crate::perf::phase(crate::perf::ProfilePhase::AstMatch);
            let result = prove(&source, &candidates, started, budget, &worker_cancel);
            let _ = sender.send(result);
        })
        .ok()?;
    let result = budget
        .checked_sub(started.elapsed())
        .and_then(|remaining| receiver.recv_timeout(remaining).ok())
        .flatten();
    // A late success is not proof within the caller's time envelope.
    cancel.store(true, Ordering::Relaxed);
    if started.elapsed() > budget {
        None
    } else {
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImportKind {
    Module,
    Mkdtemp,
    TemporaryDirectory,
    // tempfile shares os/path module objects with other imports. Replacing
    // os.path.abspath can make the real mkdtemp return an existing root.
    // These handles may veto a factory grant, but never establish one.
    DependencyModule,
    DependencyCarrier,
}

struct Import {
    name: String,
    kind: ImportKind,
    statement: Range<usize>,
    container: Range<usize>,
}

#[derive(Default)]
struct Proof {
    imports: Vec<Import>,
}

#[allow(clippy::too_many_lines)] // Keep the two bounded import-proof passes together.
fn prove(
    code: &str,
    candidates: &HashSet<Span>,
    started: Instant,
    budget: Duration,
    cancel: &AtomicBool,
) -> Option<HashSet<Span>> {
    if code.len() > MAX_SOURCE_BYTES || budget.is_zero() {
        return None;
    }
    let check = |index: usize| {
        index < MAX_NODES && !cancel.load(Ordering::Relaxed) && started.elapsed() <= budget
    };
    let ast = {
        let _phase = crate::perf::phase(crate::perf::ProfilePhase::AstParse);
        AstGrep::try_new(code, SupportLang::Python).ok()?
    };
    let root = ast.root();
    let mut proof = Proof::default();
    let mut declarations: HashMap<String, Option<ImportKind>> = HashMap::new();
    let mut handles = HashSet::new();
    let mut import_ranges = Vec::new();
    let mut calls = Vec::new();
    let mut immutable = true;

    for (index, node) in root.dfs().enumerate() {
        if !check(index) || node.is_error() || node.is_missing() {
            return None;
        }
        // CPython normalizes names with NFKC. Do not mistake a differently
        // spelled identifier for proof that a trusted binding is untouched.
        if node.kind() == "identifier" && !node.text().is_ascii() {
            immutable = false;
        }
        let range = node.range();
        if node.kind() == "call" && candidates.contains(&(range.start, range.end)) {
            calls.push(node.clone());
        }
        if !matches!(
            node.kind().as_ref(),
            "import_statement" | "import_from_statement"
        ) {
            continue;
        }
        if node
            .children()
            .any(|child| child.kind() == "wildcard_import")
        {
            immutable = false;
        }
        let module = node
            .field("module_name")
            .map(|name| name.text().into_owned());
        import_ranges.push(range.clone());
        for imported in node.field_children("name") {
            if declarations.len() >= MAX_IMPORTS || proof.imports.len() >= MAX_IMPORTS {
                immutable = false;
                break;
            }
            let source = imported
                .field("name")
                .unwrap_or_else(|| imported.clone())
                .text()
                .into_owned();
            if module.as_deref() == Some("builtins") && reflective_name(&source)
                || module.as_deref() == Some("sys") && source == "modules"
            {
                immutable = false;
            }
            let name = imported.field("alias").map_or_else(
                || {
                    if module.is_none() {
                        source.split('.').next().unwrap_or(&source).to_string()
                    } else {
                        source.clone()
                    }
                },
                |alias| alias.text().into_owned(),
            );
            let kind = match (module.as_deref(), source.as_str()) {
                (None, "tempfile") => Some(ImportKind::Module),
                (Some("tempfile"), "mkdtemp") => Some(ImportKind::Mkdtemp),
                (Some("tempfile"), "TemporaryDirectory") => {
                    Some(ImportKind::TemporaryDirectory)
                }
                (
                    None,
                    "os" | "os.path" | "posixpath" | "ntpath" | "genericpath",
                )
                | (Some("os"), "path")
                | (
                    Some("os.path" | "posixpath" | "ntpath" | "genericpath" | "shutil"
                        | "pathlib" | "pathlib._local"),
                    "os" | "genericpath",
                )
                | (Some("tempfile"), "_os") => {
                    Some(ImportKind::DependencyModule)
                }
                (None, "shutil" | "pathlib" | "pathlib._local")
                | (Some("tempfile"), "_shutil") => Some(ImportKind::DependencyCarrier),
                _ => None,
            };
            declarations
                .entry(name.clone())
                .and_modify(|existing| {
                    if *existing != kind {
                        *existing = None;
                    }
                })
                .or_insert(kind);
            if let Some(kind) = kind {
                handles.insert(name.clone());
                if let Some(container) = node.parent() {
                    proof.imports.push(Import {
                        name,
                        kind,
                        statement: range.clone(),
                        container: container.range(),
                    });
                }
            }
        }
    }
    proof
        .imports
        .retain(|import| declarations.get(&import.name) == Some(&Some(import.kind)));
    import_ranges.sort_unstable_by_key(|range| range.start);
    if immutable && !proof.imports.is_empty() {
        for (index, node) in root.dfs().enumerate() {
            if !check(index) {
                return None;
            }
            let range = node.range();
            let before = import_ranges.partition_point(|import| import.start <= range.start);
            if before > 0 && range.end <= import_ranges[before - 1].end {
                continue;
            }
            if reflects_bindings(&node) {
                immutable = false;
                break;
            }
            if node.kind() == "identifier" && handles.contains(node.text().as_ref()) {
                let kind = declarations.get(node.text().as_ref()).copied().flatten();
                if !kind.is_some_and(|kind| read_only_use(&node, kind)) {
                    immutable = false;
                    break;
                }
            }
        }
    }
    let mut proved = HashSet::new();
    for call in calls {
        if !check(0) {
            return None;
        }
        let Some(target) = deletion_target(&call) else {
            continue;
        };
        // This is an existing .temp match. A complete static literal has
        // already passed the engine's descendant/traversal check. Factory
        // names inside a literal filename do not change that established grant.
        if literal_target(&target, 0) || immutable && proof.directory(&target) {
            let range = call.range();
            proved.insert((range.start, range.end));
        }
    }
    Some(proved)
}

fn reflective_name(name: &str) -> bool {
    matches!(
        name,
        "exec"
            | "eval"
            | "getattr"
            | "setattr"
            | "delattr"
            | "vars"
            | "globals"
            | "locals"
            | "__builtins__"
            | "__import__"
            | "__setattr__"
            | "__delattr__"
            | "__getattribute__"
            | "import_module"
    )
}

fn reflects_bindings<D: Doc>(node: &Node<'_, D>) -> bool {
    // A reference can be captured and invoked under a different name later.
    // Merely checking direct exec/eval calls would miss that mutation route.
    if node.kind() == "identifier" && reflective_name(node.text().as_ref()) {
        return true;
    }
    node.kind() == "attribute"
        && node.field("attribute").is_some_and(|name| {
            reflective_name(name.text().as_ref())
                || matches!(
                    name.text().as_ref(),
                    "__dict__"
                        | "__code__"
                        | "__globals__"
                        | "__defaults__"
                        | "__kwdefaults__"
                        | "modules"
                )
        })
}

// These path bytes already passed the engine's descendant check. Preserve the
// existing grant only for a whole constant expression, never for a literal
// inside a call, attribute, or interpolation. No new path allowance is derived.
fn literal_target<D: Doc>(node: &Node<'_, D>, depth: usize) -> bool {
    if depth >= MAX_DEPTH {
        return false;
    }
    match node.kind().as_ref() {
        "string" => !node.dfs().any(|child| child.kind() == "interpolation"),
        "concatenated_string" => node
            .children()
            .filter(|child| child.is_named() && child.kind() != "comment")
            .all(|child| literal_target(&child, depth + 1)),
        "binary_operator" => {
            node.field("operator")
                .is_some_and(|operator| operator.text() == "+")
                && node
                    .field("left")
                    .is_some_and(|left| literal_target(&left, depth + 1))
                && node
                    .field("right")
                    .is_some_and(|right| literal_target(&right, depth + 1))
        }
        _ => false,
    }
}

fn read_only_use<D: Doc>(name: &Node<'_, D>, kind: ImportKind) -> bool {
    if kind == ImportKind::DependencyModule {
        return dependency_read_only_use(name);
    }
    let Some(parent) = name.parent() else {
        return false;
    };
    if kind == ImportKind::DependencyCarrier {
        // shutil/pathlib can expose the same os module. Their other members
        // are not tempfile dependencies: capturing shutil.rmtree as a local
        // deletion alias must retain its established cleanup policy.
        return parent.kind() == "attribute"
            && parent
                .field("object")
                .is_some_and(|object| object.range() == name.range())
            && parent.field("attribute").is_some_and(|attribute| {
                let member = attribute.text();
                !member.starts_with("__")
                    && (!matches!(
                        member.as_ref(),
                        "os" | "_os" | "posixpath" | "ntpath" | "genericpath" | "_local"
                    ) || dependency_read_only_use(name))
            });
    }
    if kind != ImportKind::Module {
        return parent.kind() == "call"
            && parent
                .field("function")
                .is_some_and(|function| function.range() == name.range());
    }
    if parent.kind() != "attribute"
        || !parent
            .field("object")
            .is_some_and(|object| object.range() == name.range())
        || !parent.field("attribute").is_some_and(|attribute| {
            matches!(
                attribute.text().as_ref(),
                "mkdtemp"
                    | "TemporaryDirectory"
                    | "mkstemp"
                    | "TemporaryFile"
                    | "NamedTemporaryFile"
                    | "SpooledTemporaryFile"
                    | "gettempdir"
                    | "gettempdirb"
                    | "gettempprefix"
                    | "gettempprefixb"
            )
        })
    {
        return false;
    }
    parent.parent().is_some_and(|call| {
        call.kind() == "call"
            && call
                .field("function")
                .is_some_and(|function| function.range() == parent.range())
    })
}

/// A shared dependency may be called, not replaced or handed to unknown code.
/// Follow the whole attribute chain: checking only `os.path` would mistake
/// `os.path.abspath = ...` and `shutil.os.path.abspath = ...` for reads.
/// The whole-body pass also catches a write after the call in a loop, or a
/// write through a second import of the same module. No host imports run here.
fn dependency_read_only_use<D: Doc>(name: &Node<'_, D>) -> bool {
    let mut value = name.clone();
    for _ in 0..MAX_DEPTH {
        let Some(parent) = value.parent() else {
            return false;
        };
        if parent.kind() == "attribute"
            && parent
                .field("object")
                .is_some_and(|object| object.range() == value.range())
        {
            let Some(attribute) = parent.field("attribute") else {
                return false;
            };
            if attribute.text().starts_with("__") {
                return false;
            }
            value = parent;
            continue;
        }
        if parent.kind() == "parenthesized_expression" {
            value = parent;
            continue;
        }
        if parent.kind() == "call" {
            return parent
                .field("function")
                .is_some_and(|function| function.range() == value.range());
        }
        // Known immutable module constants can be read without exposing a
        // module or callable. Preserve ordinary os.name checks and path
        // separators, but not writes, deletes, or ambiguous binding positions.
        let scalar = value.kind() == "attribute"
            && value.field("attribute").is_some_and(|attribute| {
                matches!(
                    attribute.text().as_ref(),
                    "name" | "sep" | "altsep" | "curdir" | "pardir" | "pathsep"
                        | "defpath" | "extsep" | "devnull"
                )
            });
        return scalar
            && (matches!(
                parent.kind().as_ref(),
                "argument_list" | "keyword_argument" | "comparison_operator"
                    | "binary_operator" | "return_statement" | "expression_statement"
            ) || parent.kind() == "assignment"
                && parent
                    .field("right")
                    .is_some_and(|right| right.range() == value.range()));
    }
    false
}

fn deletion_target<'a, D: Doc>(call: &Node<'a, D>) -> Option<Node<'a, D>> {
    let arguments = call.field("arguments")?;
    let mut target = None;
    let mut positional = false;
    for argument in arguments
        .children()
        .filter(|node| node.is_named() && node.kind() != "comment")
    {
        match argument.kind().as_ref() {
            "list_splat" | "dictionary_splat" => return None,
            "keyword_argument" => {
                if argument
                    .field("name")
                    .is_some_and(|name| name.text() == "path")
                {
                    if target.is_some() {
                        return None;
                    }
                    target = argument.field("value");
                }
            }
            _ if !positional => {
                if target.is_some() {
                    return None;
                }
                positional = true;
                target = Some(argument);
            }
            _ => {}
        }
    }
    let mut target = target?;
    for _ in 0..MAX_DEPTH {
        if target.kind() != "parenthesized_expression" {
            return Some(target);
        }
        target = {
            let mut children = target
                .children()
                .filter(|node| node.is_named() && node.kind() != "comment");
            let inner = children.next()?;
            if children.next().is_some() {
                return None;
            }
            inner
        };
    }
    None
}

impl Proof {
    fn directory<D: Doc>(&self, target: &Node<'_, D>) -> bool {
        let (call, takes_name) = if target.kind() == "attribute"
            && target
                .field("attribute")
                .is_some_and(|name| name.text() == "name")
        {
            let Some(object) = target.field("object") else {
                return false;
            };
            (object, true)
        } else {
            (target.clone(), false)
        };
        if call.kind() != "call" {
            return false;
        }
        let Some(function) = call.field("function") else {
            return false;
        };
        match self.factory(&function) {
            Some(ImportKind::TemporaryDirectory) => true,
            Some(ImportKind::Mkdtemp) => !takes_name,
            _ => false,
        }
    }

    fn factory<D: Doc>(&self, function: &Node<'_, D>) -> Option<ImportKind> {
        let (name, member) = match function.kind().as_ref() {
            "identifier" => (function.clone(), None),
            "attribute" => {
                let object = function.field("object")?;
                if object.kind() != "identifier" {
                    return None;
                }
                (
                    object,
                    Some(function.field("attribute")?.text().into_owned()),
                )
            }
            _ => return None,
        };
        for imported in &self.imports {
            if imported.name.as_str() != name.text().as_ref()
                || imported.statement.end > function.range().start
            {
                continue;
            }
            let kind = match (imported.kind, member.as_deref()) {
                (ImportKind::Module, Some("mkdtemp")) | (ImportKind::Mkdtemp, None) => {
                    ImportKind::Mkdtemp
                }
                (ImportKind::Module, Some("TemporaryDirectory"))
                | (ImportKind::TemporaryDirectory, None) => ImportKind::TemporaryDirectory,
                _ => continue,
            };
            let mut ancestor = function.parent();
            for _ in 0..MAX_DEPTH {
                let Some(node) = ancestor else {
                    break;
                };
                if node.kind() == "class_definition" {
                    break;
                }
                if node.range() == imported.container {
                    if node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "class_definition")
                    {
                        break;
                    }
                    return Some(kind);
                }
                ancestor = node.parent();
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Case {
        id: String,
        decision: String,
        source: String,
    }

    #[test]
    fn default_policy_tempfile_provenance_verdicts() {
        let cases: Vec<Case> = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/python_tempfile_provenance.json"
        )))
        .expect("valid shared verdict fixtures");
        assert!(!cases.is_empty());
        for case in cases {
            let matches = super::super::DEFAULT_MATCHER
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
    fn exhausted_proof_withholds_only_candidate_exemptions() {
        for (source, denied) in [
            (
                "import shutil, tempfile\nshutil.rmtree(tempfile.mkdtemp())",
                true,
            ),
            ("import shutil\nshutil.rmtree('/tmp/build')", false),
            ("import shutil\nshutil.rmtree('/tmp')", true),
        ] {
            let original = super::super::source_analysis::DEFAULT_MATCHER
                .find_matches_with_timeout(
                    source,
                    ScriptLanguage::Python,
                    Duration::from_secs(5),
                )
                .expect("complete source classification before withholding the optional proof");
            let matches = validate(source, ScriptLanguage::Python, original, Duration::ZERO);
            assert_eq!(
                matches.iter().any(|hit| hit.severity.blocks_by_default()),
                denied,
                "{source}",
            );
        }
    }

    #[test]
    fn deterministic_proof_limits_never_establish_safety() {
        let source = "x=0\n".repeat(MAX_NODES / 2 + 1);
        assert!(source.len() < MAX_SOURCE_BYTES);
        assert!(
            prove(
                &source,
                &HashSet::new(),
                Instant::now(),
                Duration::from_secs(60),
                &AtomicBool::new(false),
            )
            .is_none()
        );
        assert!(
            prove_bounded(
                &" ".repeat(MAX_SOURCE_BYTES + 1),
                HashSet::new(),
                Duration::from_secs(5),
            )
            .is_none()
        );
        assert!(
            prove(
                "import tempfile",
                &HashSet::new(),
                Instant::now(),
                Duration::from_secs(5),
                &AtomicBool::new(true),
            )
            .is_none()
        );
    }
}
