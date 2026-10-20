//! Keep literal shell cleanup consistent with core's recursive-rm policy.
//!
//! This optional refinement handles one complete literal command only. It
//! never approves a script, discards another finding, resolves filesystem
//! paths, or changes the independently configurable AST pattern corpus.

use super::{PatternMatch, Severity};
use crate::heredoc::ScriptLanguage;
use crate::packs::core::filesystem::{RmParseDecision, parse_rm_command_segment};
use std::time::{Duration, Instant};

const MAX_LITERAL_COMMAND_BYTES: usize = 16 * 1024;

fn is_recursive_rm_rule(rule: &str) -> bool {
    matches!(rule, "heredoc.bash.rm_rf" | "heredoc.bash.rm_r")
}

/// The lexical screen proves a single literal argv and bounds the destination
/// shape. Core's existing parser must independently approve the complete command.
/// Never borrow a custom core-rule grant for a root or traversing destination.
///
/// The evaluator applies the same proof to the outer core rm rules when they
/// match the text of a verified literal inline shell payload (#576), so both
/// views of one payload share a single definition of literal temp cleanup.
pub(crate) fn literal_temp_rm(command: &str) -> bool {
    if command.len() > MAX_LITERAL_COMMAND_BYTES {
        return false;
    }
    let command = command.trim_matches([' ', '\t', '\n']);
    // No expansion, glob, operator, redirect, comment, line continuation, or
    // second command can be hidden by quote removal. Unmodeled spellings keep
    // their original findings; this is not another general-purpose shell parser.
    if command.is_empty()
        || !command.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'/' | b'.' | b'_' | b'-' | b' ' | b'\t' | b'\'' | b'"'
                )
        })
    {
        return false;
    }
    let Ok(words) = shell_words::split(command) else {
        return false;
    };
    let Some((program, arguments)) = words.split_first() else {
        return false;
    };
    if program != "rm" {
        return false;
    }
    let mut options = true;
    let mut recursive = false;
    let mut targets = 0;
    let mut saw_end_of_options = false;
    for argument in arguments {
        if options && argument == "--" {
            // A second `--` is a literal operand, not another option marker.
            // Reject it rather than accidentally treating it as a temp path.
            options = false;
            saw_end_of_options = true;
            continue;
        }
        if options && argument.starts_with('-') {
            match argument.as_str() {
                "--recursive" => recursive = true,
                "--force" => {}
                short => {
                    let Some(flags) = short.strip_prefix('-') else {
                        return false;
                    };
                    if flags.is_empty() || !flags.bytes().all(|b| matches!(b, b'r' | b'R' | b'f')) {
                        return false;
                    }
                    recursive |= flags.contains(['r', 'R']);
                }
            }
            continue;
        }
        // Deliberately do not borrow core's interactive-mode, no-op, or custom
        // non-temp allowances. Options after an operand are outside this proof.
        options = false;
        if saw_end_of_options && argument.starts_with('-') {
            return false;
        }
        if !literal_temp_descendant(argument) {
            return false;
        }
        targets += 1;
    }
    recursive
        && targets > 0
        && matches!(
            parse_rm_command_segment(command, false),
            RmParseDecision::Allow
        )
}

fn literal_temp_descendant(path: &str) -> bool {
    let Some(relative) = path
        .strip_prefix("/tmp/")
        .or_else(|| path.strip_prefix("/var/tmp/"))
    else {
        return false;
    };
    let mut descendant = false;
    for component in relative.split('/') {
        match component {
            ".." => return false,
            "" | "." => {}
            _ => descendant = true,
        }
    }
    descendant
}

pub(super) fn refine(
    code: &str,
    language: ScriptLanguage,
    mut findings: Vec<PatternMatch>,
    budget: Duration,
) -> Vec<PatternMatch> {
    if language != ScriptLanguage::Bash
        || budget.is_zero()
        || !findings
            .iter()
            .any(|hit| is_recursive_rm_rule(&hit.rule_id))
    {
        return findings;
    }
    let started = Instant::now();
    if !literal_temp_rm(code) || started.elapsed() >= budget {
        return findings;
    }
    let command = code.trim_matches([' ', '\t', '\n']);
    let start = code.len() - code.trim_start_matches([' ', '\t', '\n']).len();
    let end = start + command.len();
    for hit in &mut findings {
        // Only a finding owning the complete proven command may use the
        // refinement. Keep unrelated rules, spans, ordering and duplicates.
        if is_recursive_rm_rule(&hit.rule_id) && hit.start == start && hit.end == end {
            hit.rule_id.push_str(".temp");
            hit.reason
                .push_str(" (all targets are literal temp subdirectories)");
            hit.severity = Severity::Medium;
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUDGET: Duration = Duration::from_secs(5);

    fn finding(rule: &str, code: &str) -> PatternMatch {
        PatternMatch {
            rule_id: rule.to_string(),
            reason: "recursive deletion".to_string(),
            matched_text_preview: code.to_string(),
            start: 0,
            end: code.len(),
            line_number: 1,
            severity: Severity::Critical,
            suggestion: None,
        }
    }

    #[test]
    fn literal_cleanup_uses_the_existing_core_decision() {
        for code in [
            "rm -rf /tmp/probe",
            "rm -r /var/tmp/probe",
            "rm -R /tmp/probe",
            "rm -fr /tmp/probe",
            "rm -r -f -- /tmp/probe /var/tmp/other",
            "rm --recursive --force /tmp/probe",
            "rm -rf \"/var/tmp/quoted\"",
            "rm -rf /tmp/foo..bar",
            "rm -rf /tmp/probe/child",
        ] {
            assert!(
                matches!(
                    parse_rm_command_segment(code, false),
                    RmParseDecision::Allow
                ),
                "core must independently approve every fixture: {code}"
            );
            assert!(
                literal_temp_rm(code),
                "literal cleanup was not refined: {code}"
            );
        }
    }

    #[test]
    fn roots_dynamic_paths_and_other_execution_keep_their_findings() {
        for code in [
            "rm -rf /tmp",
            "rm -rf /tmp/",
            "rm -rf /tmp/.",
            "rm -rf /var/tmp/",
            "rm -rf /tmp/a/..",
            "rm -rf /tmp/../etc",
            "rm -rf /tmp/safe /etc",
            "rm -rf /etc /tmp/safe",
            "rm -rf ./build",
            "rm -rf /tmp/$target",
            "rm -rf '/tmp/$target'",
            "rm -rf '/tmp/quoted'",
            "rm -rf /tmp/*",
            "rm -rf /tmp/{safe,../etc}",
            "rm -rf /tmp/$(printf safe)",
            "rm -rf /tmp/`printf safe`",
            "rm -rf /tmp/safe; git reset --hard",
            "rm -rf /tmp/safe\ngit reset --hard",
            "rm -rf /tmp/safe && rm -rf /etc",
            "rm -rf /tmp/safe > /etc/shadow",
            "rm -rf /tmp/safe # another statement is not proved here",
            "rm -rf /tmp/safe -rf /tmp/other",
            "rm -ri /etc",
            "rm --help /tmp/safe",
            "rm -f /tmp/safe",
            "rm -rf '/tmp/unclosed",
            "sudo rm -rf /tmp/safe",
            "printf 'rm -rf /tmp/safe'",
        ] {
            assert!(
                !literal_temp_rm(code),
                "unproved command gained an exemption: {code}"
            );
            let original = finding("heredoc.bash.rm_rf", code);
            assert_eq!(
                refine(code, ScriptLanguage::Bash, vec![original.clone()], BUDGET),
                vec![original],
                "a failed proof must preserve all finding metadata: {code}"
            );
        }
    }

    #[test]
    fn refinement_is_scoped_to_exact_rules_and_complete_source_spans() {
        let code = "rm -rf /tmp/probe";
        let rm = finding("heredoc.bash.rm_rf", code);
        let independent = finding("core.filesystem.credential-file-write", code);
        let mut partial = rm.clone();
        partial.end -= 1;
        let mut expected = rm.clone();
        expected.rule_id.push_str(".temp");
        expected
            .reason
            .push_str(" (all targets are literal temp subdirectories)");
        expected.severity = Severity::Medium;
        assert_eq!(
            refine(
                code,
                ScriptLanguage::Bash,
                vec![rm.clone(), independent.clone(), partial.clone(), rm.clone()],
                BUDGET,
            ),
            vec![expected.clone(), independent, partial, expected],
        );
        for (language, budget) in [
            (ScriptLanguage::Python, BUDGET),
            (ScriptLanguage::Bash, Duration::ZERO),
        ] {
            assert_eq!(
                refine(code, language, vec![rm.clone()], budget),
                vec![rm.clone()]
            );
        }
        let oversized = format!("rm -rf /tmp/{}", "x".repeat(MAX_LITERAL_COMMAND_BYTES));
        assert!(!literal_temp_rm(&oversized));
    }

    #[test]
    fn root_and_traversal_refusal_is_independent_of_core_allowlist_grants() {
        for path in [
            "/tmp/",
            "/tmp//./",
            "/var/tmp/././",
            "/tmp/safe/..",
            "/tmp/../etc",
            "/var/tmp/safe/../../home",
        ] {
            assert!(!literal_temp_descendant(path), "{path}");
        }
        for path in [
            "/tmp/probe",
            "/var/tmp/probe",
            "/tmp/foo..bar",
            "/tmp/./probe/",
        ] {
            assert!(literal_temp_descendant(path), "{path}");
        }
    }

    #[test]
    fn default_matcher_refines_cleanup_but_custom_corpora_are_unchanged() {
        for (code, rule) in [
            ("rm -rf /tmp/probe", "heredoc.bash.rm_rf"),
            ("rm -r /var/tmp/probe", "heredoc.bash.rm_r"),
        ] {
            let custom = super::super::AstMatcher::new()
                .find_matches_with_timeout(code, ScriptLanguage::Bash, BUDGET)
                .expect("the independent AST corpus completes");
            assert!(
                custom
                    .iter()
                    .any(|hit| hit.rule_id == rule && hit.severity.blocks_by_default())
            );
            let default = super::super::DEFAULT_MATCHER
                .find_matches_with_timeout(code, ScriptLanguage::Bash, BUDGET)
                .expect("the default policy completes");
            assert!(
                default
                    .iter()
                    .any(|hit| hit.rule_id == format!("{rule}.temp"))
            );
            assert!(!default.iter().any(|hit| hit.severity.blocks_by_default()));
        }
        for code in ["rm -rf /tmp", "rm -rf /tmp/probe /etc", "rm -rf /etc"] {
            let hits = super::super::DEFAULT_MATCHER
                .find_matches_with_timeout(code, ScriptLanguage::Bash, BUDGET)
                .expect("destructive control completes");
            assert!(
                hits.iter().any(|hit| hit.severity.blocks_by_default()),
                "{code}"
            );
        }
    }
}
