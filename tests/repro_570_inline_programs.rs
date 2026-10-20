//! Issue #570: classify the argv program, not its first quoted segment.
//! Fixtures are input to DCG only; no destructive fixture is executed.

use destructive_command_guard::heredoc::{
    ExtractedContent, ExtractionLimits, ExtractionResult, ScriptLanguage, SkipReason,
    extract_content,
};
use std::io::Write;
use std::process::{Command, Stdio};

fn quote(code: &str, style: usize) -> String {
    match style {
        0 => format!("'{}'", code.replace('\'', "'\\''")),
        1 => format!("'{}'", code.replace('\'', "'\"'\"'")),
        2 => {
            let mut word = String::from("\"");
            for ch in code.chars() {
                if matches!(ch, '\\' | '"' | '$' | '`') {
                    word.push('\\');
                }
                word.push(ch);
            }
            word.push('"');
            word
        }
        _ => panic!("unknown quoting style"),
    }
}

fn extraction(source: &str, max_heredocs: usize) -> ExtractionResult {
    extract_content(
        source,
        &ExtractionLimits {
            timeout_ms: 5_000,
            max_heredocs,
            ..ExtractionLimits::default()
        },
    )
}

fn complete(source: &str) -> Vec<ExtractedContent> {
    match extraction(source, 10) {
        ExtractionResult::Extracted(items) => items,
        result => panic!("static program must be completely extracted: {source:?}: {result:?}"),
    }
}

#[test]
fn every_quoted_segment_reaches_the_existing_language_analyzer() {
    for (launcher, language, code) in [
        (
            "bash -c",
            ScriptLanguage::Bash,
            "echo 'x'; git reset --hard",
        ),
        (
            "sh -c",
            ScriptLanguage::Bash,
            "printf '%s' x; git reset --hard",
        ),
        (
            "dash -c",
            ScriptLanguage::Bash,
            "echo 'x'; git reset --hard",
        ),
        ("zsh -c", ScriptLanguage::Bash, "echo 'x'; git reset --hard"),
        ("ksh -c", ScriptLanguage::Bash, "echo 'x'; git reset --hard"),
        (
            "mksh -c",
            ScriptLanguage::Bash,
            "echo 'x'; git reset --hard",
        ),
        (
            "python3 -c",
            ScriptLanguage::Python,
            "import os; os.system('git reset --hard')",
        ),
        (
            "python3.11 -I -c",
            ScriptLanguage::Python,
            "import os; os.system('git reset --hard')",
        ),
        (
            "node -e",
            ScriptLanguage::JavaScript,
            "require('child_process').execSync('git reset --hard')",
        ),
        (
            "nodejs -p",
            ScriptLanguage::JavaScript,
            "require('child_process').execSync('git reset --hard')",
        ),
        (
            "ruby -e",
            ScriptLanguage::Ruby,
            "system('git reset --hard')",
        ),
        (
            "perl -e",
            ScriptLanguage::Perl,
            "system('git reset --hard')",
        ),
        (
            "perl -E",
            ScriptLanguage::Perl,
            "system('git reset --hard')",
        ),
    ] {
        for style in 0..3 {
            let source = format!("{launcher} {}", quote(code, style));
            let items = complete(&source);
            let programs: Vec<_> = items
                .iter()
                .filter(|item| item.language == language)
                .collect();
            assert_eq!(
                programs.len(),
                1,
                "duplicate or missing program: {source}: {items:?}"
            );
            assert_eq!(
                programs[0].content, code,
                "truncated/incorrect argv: {source}"
            );
            assert_eq!(
                programs[0].byte_range.end,
                source.len(),
                "incomplete source range: {source}"
            );
            for item in &items {
                if let Some(range) = &item.content_range {
                    assert_eq!(source.get(range.clone()), Some(item.content.as_str()));
                }
            }
        }
    }
}

#[test]
fn decoding_preserves_literals_empty_segments_unicode_and_boundaries() {
    for (word, code) in [
        (
            r"'echo '\''x'\''; git reset --hard'",
            "echo 'x'; git reset --hard",
        ),
        (
            r#""echo \"x\"; git reset --hard""#,
            "echo \"x\"; git reset --hard",
        ),
        (
            r#"'echo '"'"'élève'"'"'; git reset --hard'"#,
            "echo 'élève'; git reset --hard",
        ),
        (
            r#"''"echo x; "'git reset --hard'"#,
            "echo x; git reset --hard",
        ),
        (r"echo\ 'x; git reset --hard'", "echo x; git reset --hard"),
        (r"git\ reset\ --hard", "git reset --hard"),
        (
            r"$'echo \'x\'; git reset --hard'",
            "echo 'x'; git reset --hard",
        ),
        (
            r"$'echo safe\0ignored'\;'git reset --hard'",
            "echo safe;git reset --hard",
        ),
        (
            "'echo x; '\\\n'git reset --hard'",
            "echo x; git reset --hard",
        ),
        (
            r#""printf '%s' '\q \$VALUE \`date\`'""#,
            "printf '%s' '\\q $VALUE `date`'",
        ),
        (
            r#"'printf %s "$VALUE * ? [x]"'"#,
            "printf %s \"$VALUE * ? [x]\"",
        ),
    ] {
        let source = format!("bash -c {word}>out ignored_argument");
        let items = complete(&source);
        assert!(
            items.iter().any(|item| item.content == code),
            "{source}: {items:?}"
        );
        for item in &items {
            assert!(item.byte_range.end <= source.find(">out").unwrap());
            if let Some(range) = &item.content_range {
                assert_eq!(source.get(range.clone()), Some(item.content.as_str()));
            }
        }
    }
}

#[test]
fn overlapping_locators_and_redirect_views_do_not_exhaust_the_payload_budget() {
    let source = r"bash 2>/dev/null -c 'echo '\''x'\''; git reset --hard'";
    match extraction(source, 1) {
        ExtractionResult::Extracted(items) => {
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].content, "echo 'x'; git reset --hard");
            assert!(items[0].content_range.is_none());
        }
        other => panic!("one program must use one budget slot: {other:?}"),
    }
}

#[test]
fn unresolved_or_malformed_words_are_not_reported_as_complete() {
    for source in [
        r#"bash -c 'echo '"$VALUE"'; echo tail'"#,
        r#"python3 -c 'print('"$VALUE"')'"#,
        r"node -e 'console.log('$(printf value)')'",
        r"bash -c 'echo '`printf value`'; echo tail'",
        r#"bash -c $"echo translated""#,
        "bash -c 'echo unterminated",
        r"bash -c 'echo '\",
        r"bash -c 'echo '*",
        r#"ssh host 'echo '"$VALUE"'; echo tail'"#,
        r#"mise exec -c 'echo '"$VALUE"'; echo tail'"#,
    ] {
        let skipped = match extraction(source, 10) {
            ExtractionResult::Partial { skipped, .. } | ExtractionResult::Skipped(skipped) => {
                skipped
            }
            other => panic!("incomplete argument silently accepted: {source}: {other:?}"),
        };
        assert!(
            skipped
                .iter()
                .any(|reason| matches!(reason, SkipReason::MalformedInput { .. }))
        );
    }
}

fn decision(source: &str, expected: &str, strict: bool) {
    for hook in [false, true] {
        let temp = tempfile::tempdir().expect("isolated working directory");
        let home = temp.path().join("home");
        std::fs::create_dir(&home).expect("isolated home");
        let config = temp.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[heredoc]\ntimeout_ms = 5000\nfallback_on_parse_error = {}\n",
                !strict
            ),
        )
        .expect("explicit test configuration");
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
        let input = if hook {
            command.args(["hook", "--batch"]);
            serde_json::json!({
                "hook_event_name": "PreToolUse", "tool_name": "Bash",
                "tool_input": {"command": source},
            })
            .to_string()
        } else {
            command.args(["test", "--stdin", "--dialect", "posix", "--format", "json"]);
            source.to_string()
        };
        let mut child = command
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("DCG_CONFIG", &config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_NO_SELF_HEAL", "1")
            .env("DCG_HISTORY_ENABLED", "false")
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .env("DCG_AST_TIMEOUT_MS", "5000")
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn DCG, never the fixture");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let verdict: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("{error}: stdout={stdout}; stderr={stderr}"));
        assert_eq!(
            verdict["decision"].as_str(),
            Some(expected),
            "hook={hook}, strict={strict}, source={source:?}, status={}, verdict={verdict}, stderr={stderr}",
            output.status
        );
    }
}

#[test]
fn confirmed_interpreter_repros_deny_in_cli_and_hook_mode() {
    for (launcher, code) in [
        ("bash -c", "echo 'x'; git reset --hard"),
        ("python3 -I -c", "import os; os.system('git reset --hard')"),
        (
            "node -e",
            "require('child_process').execSync('git reset --hard')",
        ),
        ("ruby -e", "system('git reset --hard')"),
        ("perl -e", "system('git reset --hard')"),
    ] {
        for style in 0..3 {
            decision(&format!("{launcher} {}", quote(code, style)), "deny", false);
        }
    }
}

#[test]
fn wrappers_and_option_variants_keep_the_complete_program() {
    let code = "echo 'x'; git reset --hard";
    for launcher in [
        "bash -lc",
        "bash -o pipefail -c",
        "bash -c --",
        "bash -c -o errexit",
        "sudo -u root bash -c",
        "env FOO=1 sh -c",
        "timeout 5 bash -c",
        "printf x | xargs sh -c",
        "ssh -p 22 host",
        "mise exec -c",
        "mise x --command",
        "bun exec",
        "watch -n 1",
        "/usr/bin/bash -c",
    ] {
        decision(&format!("{launcher} {}", quote(code, 0)), "deny", false);
    }
    for (prefix, suffix) in [
        ("find . -name x -exec sh -c ", " \\;"),
        ("python3 -c", ""),
        ("mise exec --command=", ""),
        ("mise exec -c", ""),
    ] {
        let body = if prefix.starts_with("python") {
            "import os; os.system('git reset --hard')"
        } else {
            code
        };
        decision(
            &format!("{prefix}{}{suffix}", quote(body, 0)),
            "deny",
            false,
        );
    }
    let nested = format!("bash -c {}", quote(code, 0));
    decision(&format!("bash -c {}", quote(&nested, 1)), "deny", false);
}

#[test]
fn awk_and_osascript_decode_the_outer_program_before_extracting_sinks() {
    for (launcher, code) in [
        ("awk", "BEGIN { system(\"echo 'x'; git reset --hard\") }"),
        (
            "osascript -e",
            "do shell script \"echo 'x'; git reset --hard\"",
        ),
    ] {
        for style in 0..3 {
            decision(&format!("{launcher} {}", quote(code, style)), "deny", false);
        }
    }
}

#[test]
fn harmless_command_like_strings_remain_data_in_both_modes() {
    for (launcher, code) in [
        ("bash -c", "printf '%s' 'git reset --hard'"),
        ("python3 -c", "print('git reset --hard is dangerous')"),
        ("node -e", "console.log('git reset --hard is dangerous')"),
        ("ruby -e", "puts('git reset --hard is dangerous')"),
        ("perl -e", "print('git reset --hard is dangerous')"),
        ("ssh host", "printf '%s' 'git reset --hard'"),
        ("mise exec -c", "printf '%s' 'git reset --hard'"),
        ("bun exec", "printf '%s' 'git reset --hard'"),
        ("awk", "BEGIN { print \"git reset --hard\" }"),
        ("osascript -e", "return \"git reset --hard\""),
    ] {
        for style in 0..3 {
            decision(
                &format!("{launcher} {}", quote(code, style)),
                "allow",
                false,
            );
        }
    }
    decision(
        r#"ssh host printf '%s' "'git reset --hard'""#,
        "allow",
        false,
    );
}

#[test]
fn uncertainty_obeys_the_existing_configured_policy() {
    let source = r#"python3 -c 'print('"$VALUE"')'"#;
    decision(source, "allow", false);
    decision(source, "deny", true);
    decision(
        r#"bash -c 'echo '"$VALUE"'; git reset --hard'"#,
        "deny",
        false,
    );
    decision("bash -c 'echo unterminated", "deny", true);
}
