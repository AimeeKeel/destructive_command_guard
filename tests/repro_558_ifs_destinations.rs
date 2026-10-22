//! #558: rebound IFS must not conceal writer destinations from native rules.
//! Shell source is passed to dcg as data, never executed by these tests.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn generated_frontend_options_cannot_allow_split_native_destinations() {
    for (setup, invocation) in [
        ("OPT=-n", "nice $OPT 0 tee $S"),
        ("E=", "nice $E -n 0 tee $S"),
        ("E=", "nice ${E}${E} --adjustment=0 tee $S"),
        ("E=", "nice $E -- tee $S"),
        ("OPT=--adjustment=0", r#"/usr/bin/nice "$OPT" tee $S"#),
        ("OPT=-oL", "stdbuf $OPT tee $S"),
        ("E=", "stdbuf -oL $E -eL tee $S"),
        ("E=", "/usr/bin/time $E -p tee $S"),
        ("E=", "nohup $E -- tee $S"),
        ("OPT=-w", "setsid $OPT tee $S"),
        ("E=", "ionice $E -c 2 tee $S"),
    ] {
        for value in ["/tmp/a@/etc/shadow", "/tmp/a@.git/config"] {
            let source = format!("S={value}; IFS=@; {setup}; {invocation}");
            // Another native launcher rule may own the first finding.
            // Neither CLI nor hook may allow a hidden protected write.
            assert_decision(&source, false, None);
        }
    }
}

#[test]
fn literal_frontend_options_keep_concrete_native_checks_and_harmless_reads() {
    for prefix in [
        "nice -n 0 ",
        "stdbuf -oL ",
        "nohup -- ",
        "/usr/bin/time -p ",
        "setsid -w ",
        "ionice -c 2 ",
    ] {
        for (value, rule) in [
            (
                "/tmp/a@/etc/shadow",
                "core.filesystem:credential-file-write",
            ),
            ("/tmp/a@.git/config", "core.filesystem:git-internals-write"),
        ] {
            let source = format!("S={value}; IFS=@; {prefix}tee $S");
            assert_decision(&source, false, Some(rule));
        }
        let source = format!("S=/tmp/a@/tmp/b; IFS=@; {prefix}tee $S");
        assert_decision(&source, true, None);
        let source = format!("S=/tmp/a@/etc/shadow; IFS=@; {prefix}printf '%s' '-n' $S");
        assert_decision(&source, true, None);
    }
}

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

/// `allowed` means a plain `Result: ALLOWED`: no rule fired. A command the
/// isolated grant lets through is checked by [`assert_allowed_by_grant`]
/// instead, because only that report proves the grant was loaded.
fn assert_decision_with_grant(
    source: &str,
    allowed: bool,
    rule: Option<&str>,
    grant: Option<&str>,
) {
    assert_verdict(
        source,
        if allowed {
            Verdict::Allowed
        } else {
            Verdict::Blocked
        },
        rule,
        grant,
    );
}

/// A grant control must be denied by the granted rule without the grant and
/// reported as allowlisted with it. A control allowed for any other reason
/// (an unprotected path, an unloaded allowlist that nothing needed) cannot
/// show that the grant was in effect for the commands checked after it.
fn assert_allowed_by_grant(control: &str, grant: &str) {
    assert_verdict(control, Verdict::Blocked, Some(grant), None);
    assert_verdict(control, Verdict::AllowedByGrant, None, Some(grant));
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// `Result: ALLOWED`, with no allowlist involved.
    Allowed,
    /// `Result: ALLOWED (allowlisted by user)` with the isolated grant's
    /// reason: a rule fired and the user-layer grant waived it.
    AllowedByGrant,
    Blocked,
}

fn assert_verdict(source: &str, verdict: Verdict, rule: Option<&str>, grant: Option<&str>) {
    assert!(
        verdict != Verdict::AllowedByGrant || grant.is_some(),
        "an allowlisted verdict needs a grant: {source}"
    );
    let allowed = verdict != Verdict::Blocked;
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
    if verdict == Verdict::AllowedByGrant {
        assert_eq!(
            result, "ALLOWED (allowlisted by user)",
            "{source}: {stdout}\n{stderr}"
        );
        assert_eq!(
            field("Allowlist reason:"),
            Some("isolated single-family regression grant"),
            "{source}: {stdout}\n{stderr}"
        );
    } else if allowed {
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
        assert_eq!(
            field("Pattern:"),
            Some(pattern),
            "{source}: {stdout}\n{stderr}"
        );
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

/// Every protected destination below is in the shared native table. The
/// #558 vectors first named /etc/profile, which that table has never listed
/// (00ffdb6 leaves unlisted /etc files to the ordinary truncation rules):
/// `tee /etc/profile` is allowed, so those vectors proved nothing either way.
#[test]
fn split_destinations_reach_native_credential_policy_without_custom_packs() {
    for source in [
        "S=/tmp/scratch/a@/etc/shadow; IFS=@; echo x | tee $S",
        "IFS=@; S=/tmp/scratch/a@/etc/shadow; echo x | tee $S",
        "S=/tmp/scratch/a@/etc/shadow IFS=@; echo x | tee $S",
        "IFS=@ S=/tmp/scratch/a@/etc/shadow; echo x | tee ${S}",
        "S=/tmp/scratch/a@/etc/shadow; IFS+=@; echo x | tee $S",
        "S=/tmp/scratch/a@/etc/shadow; export IFS=@; echo x | tee $S",
        "export S=/tmp/scratch/a@/etc/shadow IFS=@; echo x | tee $S",
        "S=/etc/shadow@/tmp/scratch/a; IFS=@; tee $S",
        "S=/tmp/scratch/a@/tmp/scratch/b@/etc/shadow; IFS=@; tee $S",
        "S=/tmp/scratch/a@/etc/shadow; IFS=@; command tee -- $S",
        "S=/tmp/scratch/a@/etc/shadow; IFS=@; /usr/bin/tee $S",
        "S=/tmp/scratch/a@/etc/shadow; IFS=@; tee -a $S",
        "S=/tmp/scratch/a@/etc/passwd; IFS=@; echo x | tee $S",
        "S=/tmp/scratch/a@/home/example/.bashrc; IFS=@; echo x | tee $S",
        "S=/tmp/source@/etc/shadow; IFS=@; cp $S",
        "S=/tmp/source@/etc/shadow; IFS=@; mv $S",
        "S=if=/tmp/source@of=/etc/shadow; IFS=@; dd $S",
    ] {
        assert_decision(source, false, Some("core.filesystem:credential-file-write"));
    }
}

#[test]
fn export_brace_assignments_require_native_review_without_custom_packs() {
    for source in [
        "IFS=@; export S=/tmp/a{,@/etc/shadow}; tee $S",
        "S=/tmp/safe; IFS=@; export S=/tmp/a{,@/etc/shadow}; tee $S",
        "IFS=@; export S={/tmp/safe,/tmp/a@/etc/shadow}; tee $S",
        r#"IFS=@; export S="/tmp/a"{,@/etc/shadow}; tee $S"#,
        r#"IFS=@; export S=/tmp/a{,"@/etc/shadow"}; tee $S"#,
        "IFS=@; export S=/tmp/a{1..2}@/etc/shadow; tee $S",
        "IFS=@; S=/tmp/a; export S+={,@/etc/shadow}; tee $S",
        "IFS=@; export T=ok S=/tmp/a{,@/etc/shadow}; tee $S",
        "S=/tmp/a:/etc/shadow; IFS=@; export IFS={/,:}; tee $S",
        "IFS=@; export S=/tmp/a@{/tmp/safe,.git/config}; tee $S",
    ] {
        assert_decision(source, false, Some("core.filesystem:credential-file-write"));
    }
}

#[test]
fn exhausted_wrappers_cannot_allow_split_protected_destinations() {
    for wrapper in ["command ", "command -p ", "env "] {
        for depth in [33, 64, 96] {
            for value in ["/tmp/a@/etc/shadow", "/tmp/a@.git/config"] {
                let source = format!("S={value}; IFS=@; {}tee $S", wrapper.repeat(depth));
                // Earlier native launcher checks may own the denial. What
                // matters at the CLI/hook boundary is that it cannot allow.
                assert_decision(&source, false, None);
            }
        }
    }
}

#[test]
fn bounded_wrappers_preserve_native_attribution_and_benign_destinations() {
    for wrapper in ["command ", "command -p ", "env "] {
        for depth in [1, 8] {
            let prefix = wrapper.repeat(depth);
            for (value, rule) in [
                (
                    "/tmp/a@/etc/shadow",
                    "core.filesystem:credential-file-write",
                ),
                ("/tmp/a@.git/config", "core.filesystem:git-internals-write"),
            ] {
                let source = format!("S={value}; IFS=@; {prefix}tee $S");
                assert_decision(&source, false, Some(rule));
            }
            let source = format!("S=/tmp/a@/tmp/b; IFS=@; {prefix}tee $S");
            assert_decision(&source, true, None);
        }
    }
}

#[test]
fn quoted_braces_assignment_only_words_and_unrelated_exports_remain_allowed() {
    for source in [
        "IFS=@; S=/tmp/a{,@/etc/shadow}; tee $S",
        "IFS=@; S=/tmp/a; S+={,@/etc/shadow}; tee $S",
        "IFS=@; export S='/tmp/a{,@/etc/shadow}'; tee $S",
        r#"IFS=@; export S="/tmp/a{,@/etc/shadow}"; tee $S"#,
        r"IFS=@; export S=/tmp/a\{,@/etc/shadow\}; tee $S",
        r#"IFS=@; export S=/tmp/a"{,@/etc/shadow}"; tee $S"#,
        "IFS=@; S=/tmp/safe; export T={a,b}; tee $S",
        "IFS=@; S=/tmp/safe; export T={a,b} U=ok; tee $S",
        "IFS=@; export S=/tmp/a{,@/etc/shadow}; S=/tmp/safe; tee $S",
        "IFS=@; export S=/tmp/a{,@/etc/shadow} S=/tmp/safe; tee $S",
        "S=/tmp/a@/etc/shadow; IFS=; export T={a,b}; tee $S",
        "S=/tmp/safe; export IFS={/,:}; IFS=@; tee $S",
        "IFS=@; export T=/tmp/* S=/tmp/safe; tee $S",
        "IFS=@; export T=/tmp/[ab]? S=/tmp/safe; tee $S",
    ] {
        assert_decision(source, true, None);
    }
}

#[test]
fn unrelated_export_braces_do_not_erase_concrete_native_rule_attribution() {
    for (source, rule) in [
        (
            "IFS=@; S=/tmp/a@/etc/shadow; export T={a,b}; tee $S",
            "core.filesystem:credential-file-write",
        ),
        (
            "IFS=@; S=/tmp/a@.git/config; export T={a,b}; tee $S",
            "core.filesystem:git-internals-write",
        ),
        (
            "IFS=@; export T={a,b} S=/tmp/a@/etc/shadow; tee $S",
            "core.filesystem:credential-file-write",
        ),
    ] {
        assert_decision(source, false, Some(rule));
    }
}

#[test]
fn export_brace_uncertainty_keeps_native_allowlist_families_independent() {
    for (grant, control, remaining) in [
        (
            "core.filesystem:credential-file-write",
            "tee /etc/shadow",
            "core.filesystem:git-internals-write",
        ),
        (
            "core.filesystem:git-internals-write",
            "tee .git/config",
            "core.filesystem:credential-file-write",
        ),
    ] {
        assert_allowed_by_grant(control, grant);
        for source in [
            "IFS=@; export S=/tmp/a{,@/etc/shadow}; tee $S",
            "S=/tmp/a:/etc/shadow; IFS=@; export IFS={/,:}; tee $S",
            "IFS=@; export S=/tmp/a@{/tmp/safe,.git/config}; tee $S",
        ] {
            assert_decision_with_grant(source, false, Some(remaining), Some(grant));
        }
    }
}

#[test]
fn vanished_words_before_wrapper_controls_cannot_allow_protected_writes() {
    for invocation in [
        "command $E -p tee $S",
        "command $E $E -p -- tee $S",
        "command ${E}${E} -p tee $S",
        "command $E $OPT tee $S",
        "env $E DCG_X=1 tee $S",
        "env $E $SETTING tee $S",
        "env $E -i tee $S",
        "env $E -- tee $S",
        "command env $E DCG_X=1 tee $S",
    ] {
        for value in ["/tmp/a@/etc/shadow", "/tmp/a@.git/config"] {
            let source = format!("E=; OPT=-p; SETTING=DCG_X=1; S={value}; IFS=@; {invocation}");
            // Other native launcher checks may own the first finding. No
            // custom pack or allowlist is needed to prevent an allowance.
            assert_decision(&source, false, None);
        }
    }
}

#[test]
fn vanished_words_keep_known_writers_and_harmless_lookups_distinct() {
    for invocation in ["command $E tee $S", "env $E tee $S"] {
        for (value, rule) in [
            (
                "/tmp/a@/etc/shadow",
                "core.filesystem:credential-file-write",
            ),
            ("/tmp/a@.git/config", "core.filesystem:git-internals-write"),
        ] {
            let source = format!("E=; S={value}; IFS=@; {invocation}");
            assert_decision(&source, false, Some(rule));
        }
        let source = format!("E=; S=/tmp/a@/tmp/b; IFS=@; {invocation}");
        assert_decision(&source, true, None);
    }
    for invocation in [
        "command $E printf '%s' $S",
        "env $E printf '%s' $S",
        "command -v $E tee",
        "command -V $E tee",
    ] {
        let source = format!("E=; S=/tmp/a@/etc/shadow; IFS=@; {invocation}");
        assert_decision(&source, true, None);
    }
}

#[test]
fn continued_names_cannot_hide_split_destinations_from_native_cli_and_hook() {
    for (target, rule) in [
        ("/etc/shadow", "core.filesystem:credential-file-write"),
        (".git/config", "core.filesystem:git-internals-write"),
    ] {
        for (ifs, binding, read) in [
            ("I\\\nFS=@", "TARGET", "$TARGET"),
            ("IF\\\nS=@", "TARGET", "$TARGET"),
            ("I\\\nF\\\nS=@", "TARGET", "$TARGET"),
            ("IFS=@", "TA\\\nRGET", "$TARGET"),
            ("IFS=@", "TARGET", "$TA\\\nRGET"),
            ("IFS=@", "TARGET", "${TA\\\nRGET}"),
        ] {
            let source = format!("TA=/tmp/safe; {binding}=/tmp/a@{target}; {ifs}; tee {read}");
            assert_decision(&source, false, Some(rule));
        }
    }
    assert_decision(
        "NA=DCG_UNUSED; NAME=DCG_UNUSED@tee; S=/tmp/a@/etc/shadow; IFS=@; env -u $NA\\\nME echo $S",
        false,
        None,
    );
}

#[test]
fn continued_source_keeps_quoted_data_and_benign_shell_constructs_allowed() {
    for source in [
        "TARGET=/tmp/a@/tmp/b; I\\\nFS=@; tee $TARGET",
        "TARGET=/tmp/a@/etc/shadow; I\\\nFS=; tee $TARGET",
        "TARGET=/tmp/a@/etc/shadow; I\\\nFS=@; tee \"$TARGET\"",
        "TA=/tmp/safe; TARGET=/etc/shadow; IFS=@; tee \"$TA\"\\\nRGET",
        "IFS=@; printf '%s' '$TA\\\nRGET'",
        "I\\\nFS= read -r line",
        "TA\\\nRGET=/tmp/safe",
        "IFS=@; S='a\\\nb'; tee \"$S\"",
        "NA=DCG_UNUSED; NAME=DCG_UNUSED@tee; S=/tmp/a@/etc/shadow; IFS=@; env -u \"$NA\\\nME\" echo $S",
    ] {
        assert_decision(source, true, None);
    }
}

#[test]
fn continued_names_keep_each_split_destination_rule_independently_protected() {
    for (grant, control, remaining) in [
        (
            "core.filesystem:credential-file-write",
            "tee /etc/shadow",
            "core.filesystem:git-internals-write",
        ),
        (
            "core.filesystem:git-internals-write",
            "tee .git/config",
            "core.filesystem:credential-file-write",
        ),
    ] {
        assert_allowed_by_grant(control, grant);
        for source in [
            "TA=/tmp/safe; TARGET=/tmp/a@/etc/shadow@.git/config; IFS=@; tee $TA\\\nRGET",
            "TARGET=/tmp/a@/etc/shadow@.git/config; I\\\nFS=@; tee $TARGET",
        ] {
            assert_decision_with_grant(source, false, Some(remaining), Some(grant));
        }
    }
}

#[test]
fn split_wrapper_options_cannot_turn_apparent_readers_into_hidden_writers() {
    for (setup, invocation) in [
        ("N=DCG_UNUSED@tee", "env -u $N echo $S"),
        ("N=DCG_UNUSED@tee", "env --unset=$N echo $S"),
        ("D=1@tee", "timeout $D echo $S"),
        ("P=0@tee", "nice -n $P echo $S"),
        ("B=L@tee", "stdbuf -o $B echo $S"),
        ("U=root@tee", "sudo -u $U echo $S"),
        ("W=env", "$W tee $S"),
        ("OPT=-p", "command $OPT tee $S"),
        ("SETTING=DCG_X=1", "env $SETTING tee $S"),
        ("E=; N=DCG_UNUSED", r#"$E env -u "$N" tee $S"#),
        ("N=DCG_UNUSED", r#""env" -u "$N" tee $S"#),
    ] {
        for value in ["/tmp/a@/etc/shadow", "/tmp/a@.git/config"] {
            let source = format!("S={value}; IFS=@; {setup}; {invocation}");
            // Existing launcher checks may own the denial. The native hook
            // and CLI must not allow the command regardless of attribution.
            assert_decision(&source, false, None);
        }
    }
}

#[test]
fn single_field_wrapper_options_preserve_concrete_destination_checks() {
    for invocation in [
        "env -u $N tee $S",
        r#"env -u "$N" tee $S"#,
        r#"env --unset="$N" tee $S"#,
        r#"timeout "$D" tee $S"#,
        r#"nice -n "$P" tee $S"#,
        r#"stdbuf -o "$B" tee $S"#,
        r"\tee $S",
    ] {
        for (value, rule) in [
            (
                "/tmp/a@/etc/shadow",
                "core.filesystem:credential-file-write",
            ),
            ("/tmp/a@.git/config", "core.filesystem:git-internals-write"),
        ] {
            let source = format!("N=DCG_UNUSED; D=1; P=0; B=L; S={value}; IFS=@; {invocation}");
            assert_decision(&source, false, Some(rule));
        }
        let source = format!("N=DCG_UNUSED; D=1; P=0; B=L; S=/tmp/a@/tmp/b; IFS=@; {invocation}");
        assert_decision(&source, true, None);
    }
}

#[test]
fn literal_command_queries_and_quoted_wrapper_operands_remain_harmless() {
    for invocation in [
        "command -v tee $S",
        "command -p -V tee $S",
        "command -pv tee $S",
        "env -u DCG_UNUSED printf '%s' $S",
        r#"env -u "$N" echo $S"#,
        r#"env -u "$UNKNOWN" printf '%s' $S"#,
        "timeout 1 printf '%s' $S",
        "printf '%s' 'env' $S",
    ] {
        let source = format!("N=DCG_UNUSED@tee; S=/tmp/a@/etc/shadow; IFS=@; {invocation}");
        assert_decision(&source, true, None);
    }
}

#[test]
fn background_assignment_groups_cannot_hide_inherited_native_destinations() {
    for mutation in [
        "S=/tmp/safe T=x &",
        "T=x S=/tmp/safe U=y &",
        "IFS=: T=x &",
        "T=x IFS=: U=y &",
        "export S=/tmp/safe T=x &",
        "export IFS=: T=x &",
        "S=/tmp/safe \\\n&",
        "S=/tmp/safe T=x \\\n&",
        "IFS=: T=x \\\n&",
    ] {
        let source = format!("S=/tmp/a@/etc/shadow; IFS=@; {mutation} tee $S");
        assert_decision(
            &source,
            false,
            Some("core.filesystem:credential-file-write"),
        );
    }
}

#[test]
fn foreground_groups_and_unrelated_background_assignments_keep_cli_hook_precision() {
    for source in [
        "S=/tmp/a@/etc/shadow; IFS=@; S=/tmp/safe T=x; tee $S",
        "S=/tmp/a@/etc/shadow; IFS=@; IFS=: T=x; tee $S",
        "S=/tmp/safe; IFS=@; T=x U=y & tee $S",
        "S=/tmp/safe; IFS=@; T=x U=y \\\n& tee $S",
        "S=/tmp/a@/etc/shadow; IFS=@; S=/tmp/other T=x & S=/tmp/safe; tee $S",
        "S=/tmp/a@/etc/shadow; IFS=@; IFS=: T=x & IFS=; tee $S",
        "S='safe&'; IFS=@; T=x U=y; tee $S",
        "IFS=@; S=/tmp/safe T=x &",
    ] {
        assert_decision(source, true, None);
    }
}

#[test]
fn background_assignment_uncertainty_preserves_independent_rule_grants() {
    for (grant, control, remaining) in [
        (
            "core.filesystem:credential-file-write",
            "tee /etc/shadow",
            "core.filesystem:git-internals-write",
        ),
        (
            "core.filesystem:git-internals-write",
            "tee .git/config",
            "core.filesystem:credential-file-write",
        ),
    ] {
        assert_allowed_by_grant(control, grant);
        for source in [
            "S=/tmp/a@/etc/shadow; IFS=@; S=/tmp/safe T=x & tee $S",
            "S=/tmp/a@.git/config; IFS=@; IFS=: T=x & tee $S",
        ] {
            assert_decision_with_grant(source, false, Some(remaining), Some(grant));
        }
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
        // A protected split field, so each allowed control is not vacuous.
        "S=/tmp/scratch/a@/etc/shadow; IFS=@; tee \"$S\"",
        "S=/tmp/scratch/a@/etc/shadow; IFS=@; tee \"${S}\"",
        "S=/tmp/scratch/a@/etc/shadow; IFS=; tee $S",
        "S=/tmp/scratch/a@/etc/shadow; IFS=@; tee '$S'",
        "S=/tmp/scratch/a@/etc/shadow; IFS=@; tee \\$S",
        "S=/tmp/scratch/a@/etc/shadow; IFS=@; printf '%s' \"$S\"",
        "S=/tmp/scratch/a@/etc/shadow; IFS=@; echo 'tee $S'",
        "S=/tmp/scratch/a@/etc/shadow; IFS=@",
        "OIFS=$IFS",
        "while IFS= read -r l; do :; done < /etc/hostname",
        "IFS=, read a b <<< 'x,y'",
        "S=/tmp/safe; IFS=@; S=/tmp/scratch/a@/etc/shadow IFS=: tee $S",
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
        // #565: tree-sitter reads this `$@` as plain operator text, and
        // single quotes inside a double-quoted operator word are literal.
        r#"set -- /tmp/a /etc/passwd; S=x; IFS=@; echo x | tee "${S:+$@}""#,
        r#"set -- /tmp/a /etc/passwd; IFS=@; echo x | tee "${S:-$@}""#,
        r#"set -- /tmp/a /etc/passwd x; S=x; IFS=@; tee "${S:+'$@'}""#,
    ] {
        assert_decision(source, false, Some("core.filesystem:credential-file-write"));
    }
}

#[test]
fn late_tee_options_cannot_hide_or_downgrade_native_destination_checks() {
    for source in [
        "S=/tmp/a@/etc/shadow@--help; IFS=@; POSIXLY_CORRECT=1 tee $S",
        "S=/tmp/a@/etc/shadow@--version; IFS=@; env POSIXLY_CORRECT=1 tee $S",
        "S=/tmp/a@/etc/shadow@--help; IFS=@; tee $S",
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
        r"IFS=@; tee '${@:1}'",
        r#"IFS=@; tee "${#@}""#,
        r#"IFS=@; tee "${#A[@]}""#,
        r#"IFS=@; A=(/tmp/a /tmp/b); tee "${A[*]}""#,
        r#"set -- /tmp/a /tmp/b; IFS=@; tee "$*""#,
        r#"IFS=@; tee "$(printf '%s' "$@")""#,
        r#"IFS=@; S=x; tee "${S:+\$@}""#,
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
        "S=/tmp/safe; IFS=@; printf '%s' '-v' S /tmp/a@/etc/shadow; tee $S",
        "S=/tmp/safe; IFS=@; printf -- '-v' S /tmp/a@/etc/shadow; tee $S",
        "S=/tmp/safe; IFS=@; printf '' '-v' S /tmp/a@/etc/shadow; tee $S",
        r#"S=/tmp/safe; IFS=@; F=%s; printf "$F" '-v' S /tmp/a@/etc/shadow; tee $S"#,
        r#"S=/tmp/safe; IFS=@; E=; printf "$E" -v S /tmp/a@/etc/shadow; tee $S"#,
        "S=/tmp/safe; IFS=@; printf '%s' '$@' '-v' S /tmp/a@/etc/shadow; tee $S",
        "IFS=@; export S=/tmp/a@/tmp/b; tee $S",
        "export IFS=@ S=/tmp/a@/tmp/b; tee $S",
    ] {
        assert_decision(source, true, None);
    }
}

#[test]
fn in_place_multi_destination_writes_keep_native_rule_grants_independent() {
    for (grant, control, remaining, destinations) in [
        (
            "core.filesystem:credential-file-write",
            "tee /etc/shadow",
            "core.filesystem:git-internals-write",
            "/etc/shadow@.git/config",
        ),
        (
            "core.filesystem:git-internals-write",
            "tee .git/config",
            "core.filesystem:credential-file-write",
            ".git/config@/etc/shadow",
        ),
    ] {
        assert_allowed_by_grant(control, grant);
        for writer in ["sed -i s/x/y/", "perl -i -pe 1"] {
            let source = format!("S={destinations}; IFS=@; {writer} $S");
            assert_decision_with_grant(&source, false, Some(remaining), Some(grant));
        }
    }
}

#[test]
fn stale_binding_refusal_keeps_native_allowlist_families_independent() {
    for (grant, control, remaining) in [
        (
            "core.filesystem:credential-file-write",
            "tee /etc/shadow",
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
        // The control is denied by the granted rule alone and is reported
        // as allowlisted once granted (`tee /etc/profile` was allowed with
        // no grant at all: that path is not in the native table).
        assert_allowed_by_grant(control, grant);
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
fn failed_redirections_cannot_make_stale_dangerous_bindings_look_safe() {
    for mutation in [
        "S=/tmp/safe >/definitely/missing/parent/file",
        "export S=/tmp/safe >/definitely/missing/parent/file",
        "IFS=: >/definitely/missing/parent/file",
        "export IFS=: >/definitely/missing/parent/file",
    ] {
        let source = format!("S=/tmp/a@/etc/profile; IFS=@; {mutation}; tee $S");
        assert_decision(
            &source,
            false,
            Some("core.filesystem:credential-file-write"),
        );
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
        let source = format!("SEP=@; IFS=@; S=/tmp/a5/etc/profile; {printing}; IFS=$SEP; tee $S");
        assert_decision(
            &source,
            false,
            Some("core.filesystem:credential-file-write"),
        );
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
        assert_decision(
            &source,
            false,
            Some("core.filesystem:credential-file-write"),
        );
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
        // A wrong SEP=5 would split out /etc/shadow: not a vacuous allow.
        let source = format!("SEP=@; IFS=@; S=/tmp/a5/etc/shadow; {printing}; IFS=$SEP; tee $S");
        assert_decision(&source, true, None);
    }
}

#[test]
fn scalar_log_paths_and_later_read_prefixes_remain_data_566() {
    for source in [
        "S=/tmp/work; IFS= ; sed -n 3,8p $S/e2e.log",
        "S=/tmp/work; sed -n 3,8p $S/e2e.log | while IFS= read -r l; do echo \"$l\"; done",
        "S=/tmp/work; sed -n p $S/e2e.log | while IFS= read -r l; do echo; done",
        "S=/tmp/work; IFS=@; sed -n p ${S}/a@b",
        "S='/tmp/élève work'; IFS=; sed -n p \"$S\"/e2e.log",
    ] {
        assert_decision(source, true, None);
    }
}

#[test]
fn scalar_path_reconstruction_does_not_exempt_native_writers_566() {
    for source in [
        "S=/etc; IFS=; tee $S/shadow",
        "S=/etc; IFS=; cp source ${S}/shadow",
        "S=/etc; IFS=; dd of=${S}/shadow",
        "S=/etc; IFS=; sed -i s/x/y/ $S/shadow",
    ] {
        assert_decision(source, false, Some("core.filesystem:credential-file-write"));
    }
    assert_decision(
        "S=.git; IFS=; tee ${S}/config",
        false,
        Some("core.filesystem:git-internals-write"),
    );
}

#[test]
fn scalar_path_unknowns_and_caller_side_splitting_still_require_review_566() {
    for source in [
        "S=/tmp/a@/etc; IFS=@; IFS= tee ${S}/shadow",
        "S=/tmp/work; IFS=$CUSTOM; tee ${S}/shadow",
        "S=/tmp/safe; IFS=; printf -v S /etc; tee $S/shadow",
        "S=-i@/etc; IFS=@; sed -n p ${S}/shadow",
    ] {
        assert_decision(source, false, None);
    }
}

#[test]
fn scalar_path_uncertainty_preserves_independent_rule_grants_566() {
    for (grant, control, remaining) in [
        (
            "core.filesystem:credential-file-write",
            "tee /etc/shadow",
            "core.filesystem:git-internals-write",
        ),
        (
            "core.filesystem:git-internals-write",
            "tee .git/config",
            "core.filesystem:credential-file-write",
        ),
    ] {
        // Both sides of the control prove that this grant is effective.
        // An unknown destination may still name the other protected family.
        assert_allowed_by_grant(control, grant);
        assert_decision_with_grant(
            "IFS=; tee ${UNRESOLVED}/file",
            false,
            Some(remaining),
            Some(grant),
        );
    }
}
