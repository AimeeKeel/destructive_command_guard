//! End-to-end regressions for lost trusted protection policy (#568).
//! Shell commands are input data for DCG; none is executed by these tests.
use assert_cmd::Command;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

const VALID: &str = r#"
[general]
check_updates = false
self_heal_hook = false
hook_timeout_ms = 10000
[history]
enabled = false
[packs]
enabled = ["database.postgresql"]
[[overrides.block]]
pattern = "^printf dcg-protected$"
reason = "required custom protection"
"#;
const PROTECTED: &str = "printf dcg-protected";
const HARMLESS: &str = "git status";
const BAD_TOML: &str = "[general";
const BAD_POLICY: &str = "[policy.rules]\n\"core.git:reset-hard\" = \"invalid-policy-value\"";

struct Fixture {
    root: tempfile::TempDir,
    user: PathBuf,
    repo: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let user = root.path().join("xdg/dcg/config.toml");
        let repo = root.path().join("repo");
        std::fs::create_dir_all(user.parent().unwrap()).unwrap();
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(root.path().join("home")).unwrap();
        std::fs::create_dir_all(root.path().join("tmp")).unwrap();
        Self { root, user, repo }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("dcg"));
        cmd.env_clear();
        for key in ["PATH", "SystemRoot", "WINDIR", "PATHEXT"] {
            if let Some(value) = std::env::var_os(key) {
                cmd.env(key, value);
            }
        }
        let home = self.root.path().join("home");
        cmd.current_dir(&self.repo)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", self.root.path().join("xdg"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("APPDATA", self.root.path().join("appdata"))
            .env("LOCALAPPDATA", self.root.path().join("localappdata"))
            .env("TMPDIR", self.root.path().join("tmp"))
            .env("TMP", self.root.path().join("tmp"))
            .env("TEMP", self.root.path().join("tmp"))
            .env("DCG_HISTORY_DISABLED", "1")
            .env("DCG_NO_COLOR", "1")
            .env("DCG_HOOK_TIMEOUT_MS", "10000")
            .timeout(Duration::from_secs(30));
        cmd
    }

    fn write_user(&self, content: &str) {
        std::fs::write(&self.user, content).unwrap();
    }

    fn hook(&self, command: &str, env: &[(&str, &str)]) -> Output {
        let mut cmd = self.command();
        cmd.envs(env.iter().copied()).write_stdin(
            json!({
                "tool_name": "Bash", "tool_input": {"command": command}
            })
            .to_string(),
        );
        cmd.output().unwrap()
    }

    fn cli(&self, command: &str, env: &[(&str, &str)]) -> Output {
        let mut cmd = self.command();
        cmd.args(["test", "--format", "json", command])
            .envs(env.iter().copied());
        cmd.output().unwrap()
    }
}

fn parsed(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("JSON error {error}; output={output:?}"))
}

fn assert_config_error(output: &Output, hook: bool, path: &Path) {
    assert_eq!(
        output.status.code(),
        Some(if hook { 0 } else { 3 }),
        "{output:?}"
    );
    let value = parsed(output);
    let reason = if hook {
        assert_eq!(
            value["hookSpecificOutput"]["permissionDecision"], "deny",
            "{value}"
        );
        value["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
    } else {
        assert_eq!(value["decision"], "deny", "{value}");
        assert_eq!(value["error"]["kind"], "configuration_error");
        value["reason"].as_str().unwrap()
    };
    assert!(reason.contains("DCG configuration error"), "{reason}");
    assert!(
        reason.contains(path.file_name().unwrap().to_str().unwrap()),
        "{reason}"
    );
    assert!(reason.contains("dcg doctor --strict"), "{reason}");
}

fn assert_batch_config_error(output: &Output, path: &Path) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let value = parsed(output);
    assert_eq!(value["index"], 0, "{value}");
    assert_eq!(value["decision"], "deny", "{value}");
    assert_eq!(value["error_kind"], "configuration_error", "{value}");
    let reason = value["error"].as_str().expect("batch error stays a string");
    assert!(reason.contains("DCG configuration error"), "{reason}");
    assert!(
        reason.contains(path.file_name().unwrap().to_str().unwrap()),
        "{reason}"
    );
    assert!(reason.contains("dcg doctor --strict"), "{reason}");
    assert!(value.get("hookSpecificOutput").is_none(), "{value}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn malformed_trusted_policy_never_authorizes_commands() {
    let fixture = Fixture::new();
    for bad in [BAD_TOML, BAD_POLICY] {
        fixture.write_user(&format!("{VALID}\n{bad}"));
        for env in [
            vec![],
            vec![("DCG_FAIL_CLOSED", "1")],
            vec![("DCG_UNVERIFIED_DECISION", "deny")],
            vec![("DCG_FAIL_CLOSED", "0"), ("DCG_UNVERIFIED_DECISION", "ask")],
            vec![("DCG_ROBOT", "1")],
        ] {
            for command in [
                PROTECTED,
                HARMLESS,
                "git reset --hard",
                "psql -c 'DROP TABLE important'",
            ] {
                assert_config_error(&fixture.hook(command, &env), true, &fixture.user);
                assert_config_error(&fixture.cli(command, &env), false, &fixture.user);
            }
        }
    }
}

#[test]
fn valid_config_keeps_custom_blocks_and_allows_harmless_commands() {
    let fixture = Fixture::new();
    fixture.write_user(VALID);
    for env in [
        vec![],
        vec![
            ("DCG_FAIL_CLOSED", "1"),
            ("DCG_UNVERIFIED_DECISION", "deny"),
        ],
    ] {
        let output = fixture.hook(PROTECTED, &env);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            parsed(&output)["hookSpecificOutput"]["permissionDecision"],
            "deny"
        );
        let output = fixture.cli(PROTECTED, &env);
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(parsed(&output)["decision"], "deny");
        let output = fixture.hook(HARMLESS, &env);
        assert!(output.status.success(), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let output = fixture.cli(HARMLESS, &env);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(parsed(&output)["decision"], "allow");
    }
}

#[test]
fn explicit_selection_replaces_user_config_without_failure_fallback() {
    let fixture = Fixture::new();
    fixture.write_user(BAD_POLICY);
    let explicit = fixture.root.path().join("selected.toml");
    std::fs::write(&explicit, VALID).unwrap();
    let env = [("DCG_CONFIG", explicit.to_str().unwrap())];
    assert!(fixture.hook(HARMLESS, &env).stdout.is_empty());
    assert_eq!(parsed(&fixture.cli(HARMLESS, &env))["decision"], "allow");
    assert_eq!(parsed(&fixture.cli(PROTECTED, &env))["decision"], "deny");
    fixture.write_user(VALID);
    std::fs::write(&explicit, BAD_TOML).unwrap();
    assert_config_error(&fixture.hook(PROTECTED, &env), true, &explicit);
    assert_config_error(&fixture.cli(PROTECTED, &env), false, &explicit);
}

#[test]
fn cli_config_selection_is_authoritative_and_cannot_be_forced_open() {
    let fixture = Fixture::new();
    fixture.write_user(BAD_POLICY);
    let explicit = fixture.root.path().join("cli-selected.toml");
    std::fs::write(&explicit, VALID).unwrap();
    let output = fixture
        .command()
        .args(["test", "--format", "json", "--config"])
        .arg(&explicit)
        .arg(HARMLESS)
        .env("DCG_CONFIG", fixture.root.path().join("absent-env.toml"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(parsed(&output)["decision"], "allow");
    fixture.write_user(VALID);
    std::fs::write(&explicit, BAD_POLICY).unwrap();
    for extra in ["--force", "--explain", "--quiet"] {
        let output = fixture
            .command()
            .args(["test", "--format", "json", extra, "--config"])
            .arg(&explicit)
            .arg(PROTECTED)
            .output()
            .unwrap();
        assert_config_error(&output, false, &explicit);
    }
}

#[test]
fn optional_absence_is_normal_but_missing_explicit_policy_is_fatal() {
    let fixture = Fixture::new();
    assert!(fixture.hook(HARMLESS, &[]).stdout.is_empty());
    assert_eq!(parsed(&fixture.cli(HARMLESS, &[]))["decision"], "allow");
    assert_eq!(
        parsed(&fixture.cli("git reset --hard", &[]))["decision"],
        "deny"
    );
    let missing = fixture.root.path().join("required-missing.toml");
    let env = [("DCG_CONFIG", missing.to_str().unwrap())];
    assert_config_error(&fixture.hook(HARMLESS, &env), true, &missing);
    assert_config_error(&fixture.cli(HARMLESS, &env), false, &missing);
    let output = fixture.cli(HARMLESS, &[("DCG_CONFIG", " ")]);
    assert_eq!(output.status.code(), Some(3));
    assert!(
        parsed(&output)["reason"]
            .as_str()
            .unwrap()
            .contains("empty")
    );
}

#[test]
fn automatic_repository_errors_are_not_trusted_policy_failures() {
    let fixture = Fixture::new();
    fixture.write_user(VALID);
    let project = fixture.repo.join(".dcg.toml");
    for bad in [BAD_TOML, BAD_POLICY] {
        std::fs::write(&project, bad).unwrap();
        let env = [
            ("DCG_FAIL_CLOSED", "1"),
            ("DCG_UNVERIFIED_DECISION", "deny"),
        ];
        assert!(fixture.hook(HARMLESS, &env).stdout.is_empty());
        assert_eq!(parsed(&fixture.cli(HARMLESS, &env))["decision"], "allow");
        assert_eq!(parsed(&fixture.cli(PROTECTED, &env))["decision"], "deny");
        let env = [("DCG_CONFIG", ".dcg.toml")];
        assert_config_error(&fixture.hook(PROTECTED, &env), true, &project);
        assert_config_error(&fixture.cli(PROTECTED, &env), false, &project);
    }
}

#[test]
fn lower_user_candidate_cannot_hide_invalid_preferred_policy() {
    let fixture = Fixture::new();
    fixture.write_user(BAD_POLICY);
    let lower = fixture.root.path().join("home/.config/dcg/config.toml");
    std::fs::create_dir_all(lower.parent().unwrap()).unwrap();
    std::fs::write(&lower, VALID).unwrap();
    assert_config_error(&fixture.hook(PROTECTED, &[]), true, &fixture.user);
    assert_config_error(&fixture.cli(HARMLESS, &[]), false, &fixture.user);
}

#[test]
fn batch_denies_invalid_policy_and_allows_valid_harmless_commands() {
    let fixture = Fixture::new();
    let payload = json!({"tool_name":"Bash","tool_input":{"command":HARMLESS}});
    fixture.write_user(BAD_TOML);
    for input in [
        format!("{payload}\n").into_bytes(),
        b"not JSON\n".to_vec(),
        vec![0xff, b'\n'],
    ] {
        let output = fixture
            .command()
            .args(["hook", "--batch"])
            .env("DCG_FAIL_CLOSED", "0")
            .env("DCG_UNVERIFIED_DECISION", "ask")
            .write_stdin(input)
            .output()
            .unwrap();
        assert_batch_config_error(&output, &fixture.user);
    }
    // Preserve every input position, including a malformed middle line; a
    // failed trusted policy cannot authorize later input or truncate the batch.
    let output = fixture
        .command()
        .args(["hook", "--batch", "--parallel", "--workers", "2"])
        .env("DCG_FAIL_CLOSED", "0")
        .env("DCG_UNVERIFIED_DECISION", "ask")
        .write_stdin(format!("\n{payload}\nnot JSON\n{payload}\n"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let values: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(values.len(), 3, "{values:?}");
    for (index, value) in values.iter().enumerate() {
        assert_eq!(value["index"], index, "{value}");
        assert_eq!(value["decision"], "deny", "{value}");
        assert_eq!(value["error_kind"], "configuration_error", "{value}");
        let reason = value["error"].as_str().unwrap();
        assert!(reason.contains("config.toml"), "{reason}");
        assert!(reason.contains("dcg doctor --strict"), "{reason}");
    }
    fixture.write_user(VALID);
    let output = fixture
        .command()
        .args(["hook", "--batch"])
        .write_stdin(format!("{payload}\n{payload}\n"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let values: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(values.len(), 2, "{values:?}");
    for (index, value) in values.iter().enumerate() {
        assert_eq!(value["index"], index, "{value}");
        assert_eq!(value["decision"], "allow", "{value}");
        assert!(value.get("error").is_none(), "{value}");
        assert!(value.get("error_kind").is_none(), "{value}");
    }
}

#[test]
fn configuration_denials_preserve_each_harness_blocking_contract() {
    let cases = [
        (
            "claude",
            json!({"tool_name":"Bash","tool_input":{"command":HARMLESS}}),
            "/hookSpecificOutput/permissionDecision",
            "deny",
        ),
        (
            "codex",
            json!({"tool_name":"Bash","tool_input":{"command":HARMLESS},"turn_id":"568"}),
            "/hookSpecificOutput/permissionDecision",
            "deny",
        ),
        (
            "gemini",
            json!({"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":HARMLESS}}),
            "/decision",
            "deny",
        ),
        (
            "copilot",
            json!({"sessionId":"568","timestamp":1,"cwd":"/tmp","toolName":"bash","toolArgs":{"command":HARMLESS}}),
            "/permissionDecision",
            "deny",
        ),
        (
            "hermes",
            json!({"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":HARMLESS}}),
            "/decision",
            "block",
        ),
        (
            "grok",
            json!({"hookEventName":"pre_tool_use","toolName":"run_terminal_cmd","toolInput":{"command":HARMLESS}}),
            "/decision",
            "deny",
        ),
        // Antigravity's strict protojson parser accepts only its documented
        // fields; since #573 (16b4225) a denial is exactly
        // {"decision":"deny","reason":...}.
        (
            "antigravity",
            json!({"toolCall":{"name":"run_command","args":{"CommandLine":HARMLESS}},"conversationId":"568","stepIdx":1}),
            "/decision",
            "deny",
        ),
        (
            "crush",
            json!({"event":"PreToolUse","session_id":"568","cwd":"/work","tool_name":"bash","tool_input":{"command":HARMLESS}}),
            "/decision",
            "deny",
        ),
    ];
    let fixture = Fixture::new();
    fixture.write_user(BAD_TOML);
    for batch in [false, true] {
        for (host, payload, field, expected) in &cases {
            let mut command = fixture.command();
            if batch {
                command.args(["hook", "--batch"]);
            }
            let output = command
                .env("DCG_ROBOT", "1")
                .write_stdin(format!("{payload}\n"))
                .output()
                .unwrap();
            if batch {
                assert_batch_config_error(&output, &fixture.user);
                continue;
            }
            assert_eq!(
                output.status.code(),
                Some(0),
                "{host} batch={batch}: {output:?}"
            );
            let value = parsed(&output);
            assert_eq!(
                value.pointer(field).and_then(Value::as_str),
                Some(*expected),
                "{host} batch={batch}: {value}"
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("DCG configuration error"));
            assert!(output.stderr.is_empty(), "{host} batch={batch}: {output:?}");
            if *host == "codex" {
                for unsupported in ["allowOnceCode", "remediation", "ruleId"] {
                    assert!(
                        value["hookSpecificOutput"].get(unsupported).is_none(),
                        "{value}"
                    );
                }
            }
            if *host == "antigravity" {
                let mut fields: Vec<&str> = value
                    .as_object()
                    .expect("Antigravity reply is a JSON object")
                    .keys()
                    .map(String::as_str)
                    .collect();
                fields.sort_unstable();
                assert_eq!(
                    fields,
                    ["decision", "reason"],
                    "any other field fails agy's strict parser (#573): {value}"
                );
            }
        }
        let mut command = fixture.command();
        if batch {
            command.args(["hook", "--batch"]);
        }
        let payload = json!({"event":"PreToolUse","cwd":"/tmp","toolName":"bash","toolArgs":{"command":HARMLESS}});
        let output = command
            .env("DCG_ROBOT", "1")
            .write_stdin(payload.to_string())
            .output()
            .unwrap();
        if batch {
            assert_batch_config_error(&output, &fixture.user);
            continue;
        }
        assert_eq!(
            output.status.code(),
            Some(2),
            "Reasonix batch={batch}: {output:?}"
        );
        assert!(
            output.stdout.is_empty(),
            "Reasonix must not use stdout: {output:?}"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("DCG configuration error"));
    }
}

#[test]
fn valid_config_still_honors_fail_closed_environment_overrides() {
    let fixture = Fixture::new();
    fixture.write_user(VALID);
    for (setting, deny) in [("0", false), ("1", true)] {
        let output = fixture
            .command()
            .env("DCG_FAIL_CLOSED", setting)
            .write_stdin("not JSON")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        if deny {
            assert_eq!(
                parsed(&output)["hookSpecificOutput"]["permissionDecision"],
                "deny"
            );
        } else {
            assert!(output.stdout.is_empty(), "{output:?}");
        }
    }
}

#[test]
fn valid_config_still_honors_unverified_decision_environment_overrides() {
    let fixture = Fixture::new();
    fixture.write_user(&VALID.replace(
        "hook_timeout_ms = 10000",
        "hook_timeout_ms = 10000\nmax_command_bytes = 8",
    ));
    for expected in ["ask", "deny"] {
        let output = fixture.hook("printf harmless", &[("DCG_UNVERIFIED_DECISION", expected)]);
        assert_eq!(
            parsed(&output)["hookSpecificOutput"]["permissionDecision"],
            expected
        );
    }
}

#[test]
fn non_shell_hook_requests_remain_outside_command_enforcement() {
    let fixture = Fixture::new();
    fixture.write_user(BAD_TOML);
    let output = fixture
        .command()
        .write_stdin(
            json!({"tool_name": "Read", "tool_input": {"file_path": "README.md"}}).to_string(),
        )
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
}

#[test]
fn invalid_utf8_and_unreadable_trusted_files_do_not_use_defaults() {
    let fixture = Fixture::new();
    std::fs::write(&fixture.user, [0xff, 0xfe]).unwrap();
    assert_config_error(&fixture.hook(PROTECTED, &[]), true, &fixture.user);
    assert_config_error(&fixture.cli(PROTECTED, &[]), false, &fixture.user);
    let env = [("DCG_CONFIG", fixture.repo.to_str().unwrap())];
    assert_config_error(&fixture.cli(HARMLESS, &env), false, &fixture.repo);
}
