use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{
    LayeredAllowlist, config::Config, evaluator::evaluate_command, load_default_allowlists,
};

#[test]
fn test_shell_comment_false_positive() {
    let config = Config::default();
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    let keywords = &["rm", "git"];

    // Command with destructive operation inside a comment
    let cmd = "ls -la # rm -rf /";

    // Should be allowed because the destructive part is a comment
    let result = evaluate_command(cmd, &config, keywords, &compiled_overrides, &allowlists);

    assert!(
        result.is_allowed(),
        "Command with destructive comment should be allowed, but was: {:?}",
        result.decision
    );
}

/// The default pack set, read under `dialect`.
fn evaluate_in(
    command: &str,
    dialect: ShellDialect,
) -> destructive_command_guard::EvaluationResult {
    let config = Config::default();
    let enabled_packs = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY
        .build_enabled_keyword_index(&ordered_packs)
        .expect("keyword index should build for enabled pack set");
    evaluate_command_with_pack_order_at_path_in_dialect(
        command,
        &enabled_keywords,
        &ordered_packs,
        Some(&keyword_index),
        &config.overrides.compile(),
        &LayeredAllowlist::default(),
        &config.heredoc_settings(),
        None,
        dialect,
    )
}

/// A `#` starts a comment only where a word starts. Inside a `${…}`
/// expansion a blank does not end the word, and a carriage return or form
/// feed is no blank to the shell at all, so a `#` after one is an ordinary
/// character and the rest of the line still runs. Taking it for a comment
/// hid that rest of the line from every pack.
#[test]
fn hash_inside_a_word_hides_nothing() {
    for command in [
        "echo ${x:- #}; rm -rf ~",
        "echo ${x:-a #b}; rm -rf ~",
        ": ${x:= #}; rm -rf ~",
        "echo ${x:-${y} #}; rm -rf ~",
        "echo ${x:- #}; git reset --hard",
        "echo ${x:- #} && git reset --hard",
        "echo a\r#b; rm -rf ~",
        "echo a\x0c#b; rm -rf ~",
    ] {
        for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
            let result = evaluate_in(command, dialect);
            assert!(
                result.is_denied(),
                "{command:?} must be denied under {dialect:?}, got {result:?}"
            );
        }
    }
    // A comment that does start a word still hides what follows it, and a
    // plain `{` does not nest: the first `}` closes the expansion.
    for command in [
        "echo ${x:- #}; echo done",
        "echo ${x} # rm -rf ~",
        "echo ${x:-{} # rm -rf ~",
        "ls -la\r\n# rm -rf ~",
        "echo '${x:- #}'; ls",
    ] {
        let result = evaluate_in(command, ShellDialect::Posix);
        assert!(
            result.is_allowed(),
            "{command:?} must stay allowed, got {result:?}"
        );
    }
}
