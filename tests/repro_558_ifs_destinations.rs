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
    assert_decision_with_grant(source, allowed, rule, None);
}

fn assert_decision_with_grant(source: &str, allowed: bool, rule: Option<&str>, grant: Option<&str>) {
    let temp = tempfile::tempdir().expect("tempdir");
    if let Some(grant) = grant {
        let allowlist = format!(
            "[[allow]]\nrule = \"{grant}\"\nreason = \"isolated single-family regression grant\"\n"
        );
        for path in ["home/config/dcg", "home/.config/dcg", "home/appdata/dcg"] {
            let dir = temp.path().join(path);
            std::fs::create_dir_all(&dir).expect("isolated allowlist directory");
            std::fs::write(dir.join("allowlist.toml"), &allowlist).expect("isolated rule grant");
        }
    }
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

#[test]
fn quoted_positional_and_indirect_lists_require_native_review() {
    for source in [
        r#"set -- /tmp/a /etc/profile; IFS=@; tee "${@:1}""#,
        r#"set -- /tmp/a /etc/profile; IFS=@; tee "${@#/missing/}""#,
        r#"set -- /tmp/a /etc/profile; IFS=@; tee "${@%/missing}""#,
        r#"set -- /tmp/a /etc/profile; IFS=@; S=@; tee "${!S}""#,
        r#"IFS=@; A=(/tmp/a /etc/profile); S='A[@]'; tee "${!S}""#,
        r#"IFS=@; A=(/tmp/a /etc/profile); tee "${A[@]:0:2}""#,
        r#"set -- /tmp/a /etc/profile; IFS=@; tee "${S:-"$@"}""#,
    ] {
        assert_decision(source, false, Some("core.filesystem:credential-file-write"));
    }
}

#[test]
fn late_tee_options_cannot_hide_or_downgrade_native_destination_checks() {
    for source in [
        "S=/tmp/a@/etc/profile@--help; IFS=@; POSIXLY_CORRECT=1 tee $S",
        "S=/tmp/a@/etc/profile@--version; IFS=@; env POSIXLY_CORRECT=1 tee $S",
        "S=/tmp/a@/etc/profile@--help; IFS=@; tee $S",
        "S=/home/example/.ssh/known_hosts@-a; IFS=@; POSIXLY_CORRECT=1 tee $S",
        "S=/home/example/.ssh/known_hosts@--append; IFS=@; tee $S",
    ] {
        assert_decision(source, false, Some("core.filesystem:credential-file-write"));
    }
    assert_decision(
        "S=/tmp/a@.git/config@--help; IFS=@; POSIXLY_CORRECT=1 tee $S",
        false,
        Some("core.filesystem:git-internals-write"),
    );
}

#[test]
fn quoted_scalar_results_and_literal_list_text_remain_data() {
    for source in [
        r#"IFS=@; S=ok; tee "$S"'[@]'"#,
        r#"IFS=@; S=ok; tee "$S"'${@:1}'"#,
        r#"IFS=@; tee "\${@:1}""#,
        r#"IFS=@; tee '${@:1}'"#,
        r#"IFS=@; tee "${#@}""#,
        r#"IFS=@; tee "${#A[@]}""#,
        r#"IFS=@; A=(/tmp/a /tmp/b); tee "${A[*]}""#,
        r#"set -- /tmp/a /tmp/b; IFS=@; tee "$*""#,
        r#"IFS=@; tee "$(printf '%s' "$@")""#,
    ] {
        assert_decision(source, true, None);
    }
}

#[test]
fn quoted_and_expanded_assignment_builtins_cannot_hide_later_writes() {
    for source in [
        "S=/tmp/safe; IFS=@; ex''port S=/tmp/a@/etc/profile; tee $S",
        r#"S=/tmp/safe; IFS=@; "export" S=/tmp/a@/etc/profile; tee $S"#,
        r"S=/tmp/safe; IFS=@; \export S=/tmp/a@/etc/profile; tee $S",
        r#"S=/tmp/safe; IFS=@; e'x'p"o"rt S=/tmp/a@/etc/profile; tee $S"#,
        "S=/tmp/safe; IFS=@; printf '-v' S '%s' /tmp/a@/etc/profile; tee $S",
        r#"S=/tmp/safe; IFS=@; printf "-v" S %s /tmp/a@/etc/profile; tee $S"#,
        "S=/tmp/safe; IFS=@; printf -''v S %s /tmp/a@/etc/profile; tee $S",
        r"S=/tmp/safe; IFS=@; printf \-v S %s /tmp/a@/etc/profile; tee $S",
        "S=/tmp/safe; IFS=@; printf '-vS' %s /tmp/a@/etc/profile; tee $S",
        "S=/tmp/safe; IFS=@; F=-v; printf $F S %s /tmp/a@/etc/profile; tee $S",
        r#"S=/tmp/safe; IFS=@; F=-v; printf "$F" S %s /tmp/a@/etc/profile; tee $S"#,
        "S=/tmp/safe; IFS=@; F=-v@S; printf $F %s /tmp/a@/etc/profile; tee $S",
        "S=/tmp/safe; IFS=@; E=; printf $E '-v' S %s /tmp/a@/etc/profile; tee $S",
        "S=/tmp/safe; IFS=@; printf $UNKNOWN S %s /tmp/a@/etc/profile; tee $S",
        "S=/tmp/safe; IFS=@; ex''port IFS=:; S=/tmp/a:/etc/profile; tee $S",
        "S=/tmp/safe; IFS=@; printf '-v' IFS %s :; S=/tmp/a:/etc/profile; tee $S",
    ] {
        assert_decision(source, false, Some("core.filesystem:credential-file-write"));
    }
}

#[test]
fn printf_option_text_after_the_format_preserves_harmless_bindings() {
    for source in [
        "S=/tmp/safe; IFS=@; printf '%s' '-v' S /tmp/a@/etc/profile; tee $S",
        "S=/tmp/safe; IFS=@; printf -- '-v' S /tmp/a@/etc/profile; tee $S",
        "S=/tmp/safe; IFS=@; printf '' '-v' S /tmp/a@/etc/profile; tee $S",
        r#"S=/tmp/safe; IFS=@; F=%s; printf "$F" '-v' S /tmp/a@/etc/profile; tee $S"#,
        r#"S=/tmp/safe; IFS=@; E=; printf "$E" -v S /tmp/a@/etc/profile; tee $S"#,
        "S=/tmp/safe; IFS=@; printf '%s' '$@' '-v' S /tmp/a@/etc/profile; tee $S",
        "IFS=@; export S=/tmp/a@/tmp/b; tee $S",
        "export IFS=@ S=/tmp/a@/tmp/b; tee $S",
    ] {
        assert_decision(source, true, None);
    }
}

#[test]
fn stale_binding_refusal_keeps_native_allowlist_families_independent() {
    for (grant, control, remaining) in [
        (
            "core.filesystem:credential-file-write",
            "tee /etc/profile",
            "core.filesystem:git-internals-write",
        ),
        (
            "core.filesystem:git-internals-write",
            "tee .git/config",
            "core.filesystem:credential-file-write",
        ),
    ] {
        // Prove the grant was loaded, rather than mistaking an ignored
        // allowlist for evidence that the other family stayed protected.
        assert_decision_with_grant(control, true, None, Some(grant));
        for source in [
            "S=/tmp/safe; IFS=@; ex''port S=/tmp/a@.git/config; tee $S",
            "S=/tmp/safe; IFS=@; printf '-v' S %s /tmp/a@/etc/profile; tee $S",
            "SEP=@; IFS=@; S=/tmp/a5/etc/profile; printf 'abcde%n' SEP; IFS=$SEP; tee $S",
        ] {
            assert_decision_with_grant(source, false, Some(remaining), Some(grant));
        }
    }
}

#[test]
fn printf_count_assignments_cannot_hide_native_writer_destinations() {
    for printing in [
        "printf 'abcde%n' SEP",
        "printf -- 'abcde%n' SEP",
        "printf 'abcde%05n' SEP",
        "printf 'abcde%*.*n' 0 0 SEP",
        "printf 'abcde%ln' SEP",
        "printf '%s%n' abcde SEP",
        r#"F=abcde%n; printf "$F" SEP"#,
        "F=--@abcde%n@SEP; printf $F",
        "E=; printf $E 'abcde%n' SEP",
        "p''rintf 'abcde%n' SEP",
    ] {
        let source = format!(
            "SEP=@; IFS=@; S=/tmp/a5/etc/profile; {printing}; IFS=$SEP; tee $S"
        );
        assert_decision(&source, false, Some("core.filesystem:credential-file-write"));
    }
    // %n can also replace IFS itself. Reassignment forces shells that cache
    // their splitting table to observe the new value before the writer runs.
    assert_decision(
        "S=/tmp/a5/etc/profile; IFS=@; printf 'abcde%n' IFS; IFS=$IFS; tee $S",
        false,
        Some("core.filesystem:credential-file-write"),
    );
    for writer in ["tee $S", "cp $S", "mv $S", "install $S", "ln -s $S"] {
        let source = format!(
            "SEP=@; IFS=@; S=/tmp/a5/etc/profile; printf 'abcde%n' SEP; IFS=$SEP; {writer}"
        );
        assert_decision(&source, false, Some("core.filesystem:credential-file-write"));
    }
}

#[test]
fn printf_count_shaped_data_and_time_formats_remain_allowed() {
    for printing in [
        "printf '%s' 'abcde%n' SEP",
        "printf '%b' 'abcde%n' SEP",
        "printf '%q' 'abcde%n' SEP",
        "printf '%%n' SEP",
        "printf '%dn' 5",
        r"printf '\045n' SEP",
        "printf '%(%n)T' 0",
        "printf '%(a(b)%n)T' 0",
        "printf -- -- 'abcde%n' SEP",
        r#"F=%%n; printf "$F" SEP"#,
        r#"E=; printf "$E" 'abcde%n' SEP"#,
    ] {
        let source = format!(
            "SEP=@; IFS=@; S=/tmp/a5/etc/profile; {printing}; IFS=$SEP; tee $S"
        );
        assert_decision(&source, true, None);
    }
}
