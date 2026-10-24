//! #576: a verified literal inline shell script keeps the literal-temp
//! exemption its text gets at top level.
//!
//! Every command is classifier input only, sent to the real binary through
//! both reproduction paths of the report (`dcg hook --batch` and
//! `dcg test --stdin --dialect posix`) with the default configuration and an
//! empty HOME. Nothing is executed.

use std::io::Write;
use std::process::{Command, Stdio};

/// `(decision, rule id)` for `command` through `hook --batch` (`hook = true`)
/// or `test --stdin --dialect posix`.
fn verdict(command: &str, hook: bool) -> (String, String) {
    let scratch = tempfile::tempdir().expect("isolated test state");
    let home = scratch.path().join("home");
    std::fs::create_dir(&home).expect("isolated home");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"));
    let input = if hook {
        child.args(["hook", "--batch"]);
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        })
        .to_string()
            + "\n"
    } else {
        child.args(["test", "--stdin", "--dialect", "posix", "--format", "json"]);
        command.to_string()
    };
    let mut child = child
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("APPDATA", home.join(".config"))
        .env("LOCALAPPDATA", home.join(".local"))
        .env("TMPDIR", scratch.path())
        .env("TEMP", scratch.path())
        .env("TMP", scratch.path())
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HISTORY_ENABLED", "false")
        .env("DCG_HISTORY_DISABLED", "1")
        // Completed semantic verdicts, not assertions about host scheduling.
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .current_dir(scratch.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the DCG classifier");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes())
        .expect("write classifier input");
    let output = child.wait_with_output().expect("classifier exit");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{command:?} hook={hook}: {error}; status={}; stdout={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    });
    let decision = json["decision"].as_str().unwrap_or_default().to_string();
    let rule = if hook {
        json["rule_id"].as_str().unwrap_or_default().to_string()
    } else {
        format!(
            "{}:{}",
            json["pack_id"].as_str().unwrap_or_default(),
            json["pattern_name"].as_str().unwrap_or_default()
        )
    };
    (decision, rule)
}

fn assert_decision(command: &str, expected: &str) {
    for hook in [true, false] {
        let (decision, rule) = verdict(command, hook);
        assert_eq!(decision, expected, "{command:?} hook={hook}: {rule}");
    }
}

#[test]
fn literal_temp_cleanup_scripts_are_allowed_like_their_top_level_text() {
    for command in [
        // Controls from the report, unchanged.
        "rm -rf /tmp/probe",
        "eval 'rm -rf /tmp/probe'",
        "sudo rm -rf /tmp/probe",
        "ssh host 'rm -rf /tmp/probe'",
        // The denied rows of the report.
        "sh -c 'rm -rf /tmp/probe'",
        "bash -c 'rm -rf /tmp/probe'",
        "sh -c 'rm -r /tmp/probe'",
        "sh -c 'rm -rf /var/tmp/probe'",
        // Other literal spellings the core rm parser exempts at top level.
        "dash -c 'rm -fr /tmp/probe/child'",
        "sh -c 'rm -r -f -- /tmp/probe /var/tmp/other'",
        "bash -c 'rm --recursive --force /tmp/probe'",
    ] {
        assert_decision(command, "allow");
    }
}

#[test]
fn roots_traversal_extra_operands_and_dynamic_scripts_stay_denied() {
    for command in [
        "sh -c 'rm -rf /tmp'",
        "sh -c 'rm -rf /home/user/Documents'",
        "sh -c 'rm -rf /tmp/../home/user'",
        "sh -c 'rm -rf -- -x /tmp/a'",
        "sh -c 'rm -rf /tmp/a /home/user'",
        "sh -c \"rm -rf /tmp/$X\"",
        "sh -c 'rm -rf /tmp/$X'",
        "sh -c 'rm -rf /tmp/*'",
        "sh -c 'cd /; rm -rf tmp/probe'",
        "sh -c 'rm -rf /tmp/probe; rm -rf /'",
        "sh -c 'rm -rf /tmp/probe' && rm -rf ~",
        "bash -c 'rm -rf /tmp/probe $(rm -rf /)'",
        "ssh host 'rm -rf /'",
    ] {
        assert_decision(command, "deny");
    }
    // The root and home spellings keep their critical attribution.
    for command in [
        "sh -c 'rm -rf /tmp'",
        "sh -c 'rm -rf /home/user/Documents'",
        "sh -c 'rm -rf /tmp/../home/user'",
    ] {
        let (_, rule) = verdict(command, true);
        assert_eq!(rule, "core.filesystem:rm-rf-root-home", "{command:?}");
    }
}
