//! Regression pins for issue #313: false positives on read-only PowerShell
//! commands driven through a POSIX shell.
//!
//! Items 3 and 4 of the report were fixed in v0.11.0 (`67dcb1a`, `200e3f1`,
//! `032a23e`); items 1 and 2 could not be reproduced from the report's
//! descriptions and await the literal command strings. This file pins the
//! fixed behavior and the maintainer's reconstructions of 1 and 2 against
//! `dcg test` — the entry point the report used — with the opt-in
//! Windows/guardrails packs enabled as on a native Windows install, and with
//! the default all-dialect analysis (the strictest view). Each allow is paired
//! with the nearest shape that must still deny.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

const PACKS: &str =
    "core.git,core.filesystem,windows.filesystem,careful_company_running_windows.guardrails";

/// `dcg test <command>` under a hermetic config; returns the `Result:` line
/// plus the full output for diagnostics.
fn dcg_test(command: &str) -> (String, String) {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(temp.path().join("home")).unwrap();
    std::fs::create_dir_all(temp.path().join("xdg")).unwrap();
    let output = Command::new(dcg_binary())
        .args(["test", "--with-packs", PACKS, command])
        .env_clear()
        .env("HOME", temp.path().join("home"))
        .env("USERPROFILE", temp.path().join("home"))
        .env("XDG_CONFIG_HOME", temp.path().join("xdg"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_PACKS", "core.git,core.filesystem")
        .current_dir(temp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run dcg test");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let result = stdout
        .lines()
        .chain(stderr.lines())
        .find(|line| line.trim_start().starts_with("Result:"))
        .map(|line| line.trim().to_string())
        .unwrap_or_default();
    (result, format!("{stdout}\n{stderr}"))
}

fn assert_allowed(command: &str) {
    let (result, full) = dcg_test(command);
    assert_eq!(result, "Result: ALLOWED", "command: {command}\n{full}");
}

fn assert_blocked(command: &str, rule: &str) {
    let (result, full) = dcg_test(command);
    assert!(
        result.starts_with("Result: BLOCKED") || result.starts_with("Result: REVIEW REQUIRED"),
        "command: {command}\n{full}"
    );
    let separate_fields = rule.split_once(':').is_some_and(|(pack, pattern)| {
        full.lines().any(|line| line == format!("Pack: {pack}"))
            && full
                .lines()
                .any(|line| line == format!("Pattern: {pattern}"))
    });
    assert!(
        full.contains(rule) || separate_fields,
        "expected {rule} for {command}\n{full}"
    );
}

#[test]
fn item3_backup_copy_of_hook_config_is_a_read() {
    assert_allowed("Copy-Item ~/.claude/settings.json ~/backups/settings.json.bak");
    assert_allowed("Copy-Item -Path ~/.claude/settings.json -Destination ~/backups/");
    assert_allowed(
        r"Copy-Item 'C:\Users\me\.claude\settings.json' 'C:\backup\settings (old).json'",
    );
}

#[test]
fn item3_planted_negatives_writes_to_hook_config_still_deny() {
    assert_blocked(
        "Copy-Item ~/backups/settings.json.bak ~/.claude/settings.json",
        "agent-hook-config-overwrite",
    );
    assert_blocked(
        "Copy-Item -Path ~/backups/settings.json.bak -Destination ~/.claude/settings.json",
        "agent-hook-config-overwrite",
    );
    assert_blocked(
        "Remove-Item ~/.claude/settings.json",
        "agent-hook-config-tamper",
    );
}

#[test]
fn item4_shell_assignment_before_pwsh_is_not_an_expansion_in_the_payload() {
    assert_allowed(r#"SP="/tmp/x"; pwsh -NoProfile -c "Invoke-Pester tests""#);
    // A bare variable read is inert — when the POSIX shell does not expand
    // it first. Single quotes hand `$PSVersionTable` to pwsh intact.
    assert_allowed("pwsh -NoProfile -c '$PSVersionTable.PSVersion'");
    assert_allowed("pwsh --version");
    // Double-quoted, the OUTER shell expands `$PSVersionTable` before pwsh
    // runs, so the payload is only known at run time: fail closed is right.
    assert_blocked(
        r#"pwsh -NoProfile -c "$PSVersionTable.PSVersion""#,
        "launcher-unverified",
    );
}

#[test]
fn item4_planted_negative_destructive_pwsh_payload_still_denies() {
    // Attribution moved here in `c917a36` (#451), which removed
    // `rm_semantic_scan_required`'s PowerShell prefilter. This command carries
    // none of the ``` ` @ & $ ( ``` characters that prefilter demanded, so
    // core.filesystem was previously not even a candidate and windows.filesystem
    // answered by default. core.* is tier 1 and windows.* is tier 11, so once
    // core.filesystem could match it claimed the command — the documented order
    // working as designed, not a tier regression.
    //
    // Pinned to the pack that actually answers, and paired below with the bare
    // spelling that still routes to windows.filesystem, so this file fails if
    // EITHER route moves again. The verdict assertion is unchanged.
    assert_blocked(
        r#"SP="/tmp/x"; pwsh -NoProfile -c "Remove-Item -Recurse -Force C:\src""#,
        "core.filesystem",
    );
}

/// Bare and `pwsh -c`-wrapped spellings are both answered by core.filesystem.
///
/// This used to pin an asymmetry: wrapped, the inline script reached
/// core.filesystem's `powershell-remove-item-recursive`, while bare it was
/// windows.filesystem's `remove-item-recurse-force`. `3f1a2da` (#491) made the
/// semantic rm path run its Windows front ends under the unknown dialect too,
/// which is the all-dialect analysis `dcg test` uses by default, so the bare
/// spelling now reaches core.filesystem as well — and core.* is tier 1 while
/// windows.* is tier 11, the same documented order `c917a36` applied to the
/// wrapped spelling. Both spellings now share one rule id, so an allowlist
/// entry covers them alike. The verdict is unchanged; this fails if either
/// route moves again.
#[test]
fn item4_bare_and_wrapped_spellings_deny_under_one_rule_id() {
    for target in [r"C:\src", "./build"] {
        assert_blocked(
            &format!("Remove-Item -Recurse -Force {target}"),
            "powershell-remove-item-recursive",
        );
        assert_blocked(
            &format!(r#"pwsh -NoProfile -c "Remove-Item -Recurse -Force {target}""#),
            "powershell-remove-item-recursive",
        );
    }
}

#[test]
fn items1_and_2_maintainer_reconstructions_allow() {
    // Item 1: read-only pipelines ending in Measure-Object — no `rm`.
    assert_allowed("Get-ChildItem -Recurse *.log | Measure-Object -Property Length -Sum");
    assert_allowed("Get-ChildItem -Recurse -Force | Where-Object Length -gt 1MB | Measure-Object");
    assert_allowed("gci -r | measure");
    // Item 2: a pure-read function definition.
    assert_allowed(
        "function Get-Stats { Get-Content data.txt | Group-Object | Sort-Object Count }",
    );
    assert_allowed(
        "function Get-LogSummary { param([string]$Path) Get-Content $Path | ConvertFrom-Json }",
    );
}

#[test]
fn items1_and_2_planted_negatives_recursive_delete_still_denies() {
    // The bare spelling reaches core.filesystem first (tier 1; see item4
    // above). Inside a function body the semantic rm path does not look, so
    // windows.filesystem still answers there.
    assert_blocked("Remove-Item -Recurse -Force ./build", "core.filesystem");
    assert_blocked(
        "function Clean { Remove-Item -Recurse -Force ./build }",
        "windows.filesystem",
    );
}

#[test]
fn global_options_cannot_hide_guardrail_changes() {
    for command in [
        "dcg --robot allow-once abc123 --yes",
        "dcg --agent codex --no-color allow-once abc123 --yes",
        "dcg --agent test allow-once abc123 --yes",
        "dcg --agent classify allowlist add core.git:reset-hard --reason reviewed",
        "dcg --robot allowlist add core.git:reset-hard --reason reviewed",
        "dcg allowlist --robot add core.git:reset-hard --reason reviewed",
        "dcg allowlist --agent=codex add-command 'rm -rf dist' --reason reviewed",
        "dcg --legacy-output -vv allow core.git:reset-hard --reason reviewed",
        "env dcg --robot allow-once abc123 --yes",
    ] {
        assert_blocked(
            command,
            "careful_company_running_windows.guardrails:dcg-policy-self-weakening",
        );
    }
    for command in [
        "dcg --robot uninstall",
        "dcg -q --no-suggestions uninstall",
        "dcg --agent 'codex' --no-color uninstall",
        "dcg --agent= --robot uninstall",
        "dcg --agent explain uninstall",
        "dcg --agent='dcg --robot uninstall' --robot uninstall",
        "dcg --agent='dcg --robot uninstall' doctor; dcg --robot uninstall",
        "bash -c 'dcg --robot uninstall'",
        r"C:\tools\dcg.exe --robot uninstall",
        "git status && dcg --robot uninstall",
    ] {
        assert_blocked(
            command,
            "careful_company_running_windows.guardrails:dcg-bypass-or-uninstall",
        );
    }
}

#[test]
fn global_options_preserve_inspection_and_argument_data() {
    for command in [
        "dcg --robot allowlist list",
        "dcg allowlist --agent add list",
        "dcg --agent uninstall doctor",
        "dcg --agent='allowlist add' doctor",
        "dcg --agent='dcg --robot uninstall' doctor",
        "dcg --agent='dcg --robot allow-once abc --yes' allowlist list",
        "dcg --robot allowlist remove core.git:reset-hard",
        "dcg --robot test 'dcg --robot uninstall'",
        "dcg --no-color explain 'dcg --robot allow-once abc123 --yes'",
        "dcg --agent codex --robot test 'dcg --robot uninstall'",
        "printf '%s\\n' 'dcg --robot uninstall'",
        "echo 'dcg --robot allowlist add core.git:reset-hard --reason reviewed'",
    ] {
        assert_allowed(command);
    }
}

#[test]
fn hook_protocol_keeps_guardrails_active_with_global_options() {
    use std::io::Write;

    // The strings are hook input only; no uninstall or exception grant runs.
    let temp = tempfile::tempdir().expect("isolated hook test");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("isolated home");
    let config = temp.path().join("config.toml");
    std::fs::write(&config, "[history]\nenabled = false\n").expect("hook config");
    for tool_name in ["Bash", "PowerShell", "cmd"] {
        let cases: &[(&str, Option<&str>)] = if tool_name == "cmd" {
            &[
                (
                    "echo 'data & dcg --robot uninstall & data'",
                    Some("dcg-bypass-or-uninstall"),
                ),
                ("echo \"data & dcg --robot uninstall & data\"", None),
            ]
        } else {
            &[
                (
                    "dcg --robot allow-once abc123 --yes",
                    Some("dcg-policy-self-weakening"),
                ),
                (
                    "dcg --agent test allow-once abc123 --yes",
                    Some("dcg-policy-self-weakening"),
                ),
                (
                    "dcg --agent 'test' --robot allow-once abc123 --yes",
                    Some("dcg-policy-self-weakening"),
                ),
                (
                    "dcg --agent explain uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --agent co'dex' --robot uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --a'gent'=codex --robot uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --agent= --robot uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --agent='dcg --robot uninstall' --robot uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "dcg --agent='dcg --robot uninstall' doctor; dcg --robot uninstall",
                    Some("dcg-bypass-or-uninstall"),
                ),
                (
                    "bash -c 'dcg --robot uninstall'",
                    Some("dcg-bypass-or-uninstall"),
                ),
                ("dcg --agent uninstall doctor", None),
                ("dcg --agent='allowlist add' doctor", None),
                ("dcg --agent='dcg --robot uninstall' doctor", None),
                (
                    "dcg --agent='dcg --robot allow-once abc --yes' allowlist list",
                    None,
                ),
                ("dcg --robot test 'dcg --robot uninstall'", None),
                (
                    "dcg --agent codex --no-color explain 'dcg --robot allow-once abc123 --yes'",
                    None,
                ),
            ]
        };
        for &(command, expected_rule) in cases {
            let mut child = Command::new(dcg_binary())
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
                .env("DCG_PACKS", PACKS)
                .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
                .env(
                    "DCG_PENDING_EXCEPTIONS_PATH",
                    temp.path().join("pending.jsonl"),
                )
                .env("DCG_SELF_HEAL_HOOK", "0")
                .env("DCG_HOOK_TIMEOUT_MS", "5000")
                .env("DCG_AST_TIMEOUT_MS", "5000")
                .current_dir(temp.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start dcg hook");
            let payload = serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": tool_name,
                "tool_input": {"command": command},
            });
            child
                .stdin
                .take()
                .expect("hook stdin")
                .write_all(payload.to_string().as_bytes())
                .expect("write hook input");
            let output = child.wait_with_output().expect("hook result");
            assert_eq!(
                output.status.code(),
                Some(0),
                "{tool_name} {command:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            if let Some(rule) = expected_rule {
                let result: serde_json::Value =
                    serde_json::from_slice(&output.stdout).expect("structured hook denial");
                let decision = &result["hookSpecificOutput"];
                assert_eq!(decision["hookEventName"], "PreToolUse");
                assert_eq!(
                    decision["permissionDecision"], "deny",
                    "{tool_name}: {command}"
                );
                // The Bash adapter provides ruleId; the PowerShell adapter
                // currently carries the same rule in its decision reason.
                let reported_rule = decision["ruleId"].as_str().or_else(|| {
                    decision["permissionDecisionReason"]
                        .as_str()?
                        .lines()
                        .find_map(|line| line.strip_prefix("Rule: "))
                });
                let expected_rule = format!("careful_company_running_windows.guardrails:{rule}");
                assert_eq!(
                    reported_rule,
                    Some(expected_rule.as_str()),
                    "{tool_name}: {command}"
                );
            } else {
                assert!(
                    output.stdout.is_empty(),
                    "{tool_name} {command:?}: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
            }
        }
    }
}
