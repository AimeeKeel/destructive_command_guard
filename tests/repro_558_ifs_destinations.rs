//! #558: rebound IFS must not conceal writer destinations from native rules.
//! Shell source is passed to dcg as data, never executed by these tests.

use std::io::Write;
use std::process::{Command, Stdio};

fn isolated_dcg(temp: &tempfile::TempDir) -> Command {
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("isolated home");
    let config = temp.path().join("config.toml");
    std::fs::write(&config, "[history]\nenabled = false\n").expect("isolated config");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
    command
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("APPDATA", home.join("appdata"))
        .env("LOCALAPPDATA", home.join("localappdata"))
        .env("TEMP", temp.path())
        .env("TMP", temp.path())
        .env("TMPDIR", temp.path())
        .env("DCG_CONFIG", &config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            temp.path().join("pending.jsonl"),
        )
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .current_dir(temp.path());
    command
}

fn assert_decision(source: &str, allowed: bool, rule: Option<&str>) {
    let temp = tempfile::tempdir().expect("tempdir");
    let cli = isolated_dcg(&temp)
        .args(["test", source])
        .stdin(Stdio::null())
        .output()
        .expect("dcg test");
    let stdout = String::from_utf8_lossy(&cli.stdout);
    let stderr = String::from_utf8_lossy(&cli.stderr);
    let field = |prefix: &str| {
        stdout
            .lines()
            .chain(stderr.lines())
            .find_map(|line| line.trim().strip_prefix(prefix))
            .map(str::trim)
    };
    let result = field("Result:").unwrap_or_default();
    if allowed {
        assert_eq!(result, "ALLOWED", "{source}: {stdout}\n{stderr}");
    } else {
        assert!(
            result.starts_with("BLOCKED") || result.starts_with("REVIEW REQUIRED"),
            "{source}: {stdout}\n{stderr}"
        );
    }
    if let Some(rule) = rule {
        let (pack, pattern) = rule.split_once(':').expect("pack:pattern");
        assert_eq!(field("Pack:"), Some(pack), "{source}: {stdout}\n{stderr}");
        assert_eq!(field("Pattern:"), Some(pattern), "{source}: {stdout}\n{stderr}");
    }

    let mut hook = isolated_dcg(&temp)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("dcg hook");
    hook.stdin
        .take()
        .expect("hook stdin")
        .write_all(
            &serde_json::to_vec(&serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": { "command": source }
            }))
            .expect("hook request"),
        )
        .expect("write hook request");
    let output = hook.wait_with_output().expect("hook response");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{source}: {stdout}\n{stderr}");
    if allowed {
        assert!(stdout.trim().is_empty(), "{source}: {stdout}\n{stderr}");
    } else {
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{source}: {error}: {stdout}\n{stderr}"));
        assert!(
            matches!(
                response["hookSpecificOutput"]["permissionDecision"].as_str(),
                Some("deny" | "ask")
            ),
            "{source}: {stdout}\n{stderr}"
        );
        if let Some(rule) = rule {
            assert_eq!(response["hookSpecificOutput"]["ruleId"], rule, "{source}");
        }
    }
}

#[test]
fn split_destinations_reach_native_credential_policy_without_custom_packs() {
    for source in [
        "S=/tmp/scratch/a@/etc/profile; IFS=@; echo x | tee $S",
        "IFS=@; S=/tmp/scratch/a@/etc/profile; echo x | tee $S",
        "S=/tmp/scratch/a@/etc/profile IFS=@; echo x | tee $S",
        "IFS=@ S=/tmp/scratch/a@/etc/profile; echo x | tee ${S}",
        "S=/tmp/scratch/a@/etc/profile; IFS+=@; echo x | tee $S",
        "S=/tmp/scratch/a@/etc/profile; export IFS=@; echo x | tee $S",
        "export S=/tmp/scratch/a@/etc/profile IFS=@; echo x | tee $S",
        "S=/etc/profile@/tmp/scratch/a; IFS=@; tee $S",
        "S=/tmp/scratch/a@/tmp/scratch/b@/etc/profile; IFS=@; tee $S",
        "S=/tmp/scratch/a@/etc/profile; IFS=@; command tee -- $S",
        "S=/tmp/scratch/a@/etc/profile; IFS=@; /usr/bin/tee $S",
        "S=/tmp/scratch/a@/etc/profile; IFS=@; tee -a $S",
        "S=/tmp/source@/etc/profile; IFS=@; cp $S",
        "S=/tmp/source@/etc/profile; IFS=@; mv $S",
        "S=if=/tmp/source@of=/etc/profile; IFS=@; dd $S",
    ] {
        assert_decision(source, false, Some("core.filesystem:credential-file-write"));
    }
}

#[test]
fn split_git_destinations_keep_their_separate_native_rule() {
    for source in [
        "S=/tmp/scratch/a@.git/config; IFS=@; tee $S",
        "S=/tmp/scratch/a@/tmp/scratch/b@.git/config; IFS=@; tee $S",
        "S=.git/config@/tmp/scratch/a; IFS=@; tee -- $S",
    ] {
        assert_decision(source, false, Some("core.filesystem:git-internals-write"));
    }
}

#[test]
fn unverified_splitting_and_mutations_cannot_pass_native_protection() {
    for source in [
        "S=/tmp/scratch/a@/etc/profile IFS=@ tee $S",
        "S=/tmp/scratch/a@/etc/profile; IFS=$CUSTOM; tee $S",
        "IFS=@; tee $UNKNOWN",
        "S=/tmp/scratch/a@/etc/profile; IFS=@; tee prefix${S}",
        "S=/tmp/scratch/a@/etc/profile; IFS=@; tee $S \"/tmp/\"*",
        "S=/tmp/safe; IFS=@; S=/tmp/scratch/a@/etc/profile :; tee $S",
        "S=/tmp/safe; IFS=@; printf -v S /tmp/scratch/a@/etc/profile; tee $S",
        "f() { S=/tmp/scratch/a@/etc/profile; }; S=/tmp/safe; IFS=@; f; tee $S",
        "declare -n S=T; T=/tmp/scratch/a@/etc/profile; IFS=@; tee $S",
        "IFS=@; A=(/tmp/scratch/a /etc/profile); tee \"${A[@]}\"",
        "S=/tmp/scratch/a@/etc/profile; export I'F'S=@; tee $S",
    ] {
        assert_decision(source, false, None);
    }
}

#[test]
fn quoting_safe_destinations_and_read_idioms_remain_allowed() {
    for source in [
        "S=/tmp/scratch/a@/tmp/scratch/b; IFS=@; echo x | tee $S",
        "S=/tmp/scratch/a@/etc/profile; IFS=@; tee \"$S\"",
        "S=/tmp/scratch/a@/etc/profile; IFS=@; tee \"${S}\"",
        "S=/tmp/scratch/a@/etc/profile; IFS=; tee $S",
        "S=/tmp/scratch/a@/etc/profile; IFS=@; tee '$S'",
        "S=/tmp/scratch/a@/etc/profile; IFS=@; tee \\$S",
        "S=/tmp/scratch/a@/etc/profile; IFS=@; printf '%s' \"$S\"",
        "S=/tmp/scratch/a@/etc/profile; IFS=@; echo 'tee $S'",
        "S=/tmp/scratch/a@/etc/profile; IFS=@",
        "OIFS=$IFS",
        "while IFS= read -r l; do :; done < /etc/hostname",
        "IFS=, read a b <<< 'x,y'",
        "S=/tmp/safe; IFS=@; S=/tmp/scratch/a@/etc/profile IFS=: tee $S",
        "IFS=@; S=/tmp/scratch/a@/tmp/scratch/b; tee $S; tee /tmp/other",
    ] {
        assert_decision(source, true, None);
    }
}
