//! Mock-free end-to-end tests for the real `dcg` binary.
//!
//! These tests intentionally spawn the compiled binary instead of calling
//! library functions. Each case uses an isolated HOME/TMPDIR and writes a
//! per-test tracing log under `tests/_logs/`.

#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;
use tracing::Dispatch;
use tracing_subscriber::fmt::MakeWriter;

const DESTRUCTIVE_COMMAND: &str = "git reset --hard HEAD~1";

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Claude,
    Codex,
}

impl Protocol {
    fn label(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }

    fn payload(self, command: &str, cwd: &Path) -> String {
        let payload = match self {
            Self::Claude => json!({
                "session_id": "sess-real-service-claude",
                "transcript_path": cwd.join("claude-transcript.jsonl"),
                "cwd": cwd,
                "permission_mode": "default",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": { "command": command },
                "tool_use_id": "toolu_real_service_001",
            }),
            Self::Codex => json!({
                "session_id": "019dd11d-b795-7261-a9cb-9b85a5dad632",
                "turn_id": "turn-real-service-001",
                "transcript_path": null,
                "cwd": cwd,
                "hook_event_name": "PreToolUse",
                "model": "gpt-5.5",
                "permission_mode": "bypassPermissions",
                "tool_name": "Bash",
                "tool_input": { "command": command },
                "tool_use_id": "call_real_service_001",
            }),
        };

        serde_json::to_string_pretty(&payload).expect("payload JSON should serialize")
    }
}

struct RealServiceEnv {
    home: TempDir,
    cwd: TempDir,
    tmp_dir: PathBuf,
}

impl RealServiceEnv {
    fn new(test_name: &str) -> Self {
        let home = tempfile::Builder::new()
            .prefix(&format!("dcg-{test_name}-home-"))
            .tempdir()
            .expect("failed to create test HOME");
        let cwd = tempfile::Builder::new()
            .prefix(&format!("dcg-{test_name}-cwd-"))
            .tempdir()
            .expect("failed to create test cwd");
        let tmp_dir = home.path().join("tmp");
        fs::create_dir_all(&tmp_dir).expect("failed to create test TMPDIR");

        Self { home, cwd, tmp_dir }
    }

    fn write_config(&self, contents: &str) {
        let config_dir = self.home.path().join(".config/dcg");
        fs::create_dir_all(&config_dir).expect("failed to create config dir");
        fs::write(config_dir.join("config.toml"), contents).expect("failed to write config");
    }

    fn home_path(&self) -> &Path {
        self.home.path()
    }

    fn cwd_path(&self) -> &Path {
        self.cwd.path()
    }

    fn allow_once_path(&self) -> PathBuf {
        self.home.path().join(".config/dcg/allow_once.jsonl")
    }
}

struct DcgRun {
    stdout: String,
    stderr: String,
    exit_code: i32,
    duration: Duration,
}

impl DcgRun {
    fn stdout_json(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "stdout was not valid JSON: {error}\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

struct TestLog {
    name: String,
    path: PathBuf,
}

#[derive(Clone)]
struct SharedLogWriter {
    file: Arc<Mutex<File>>,
}

struct SharedLogGuard {
    file: Arc<Mutex<File>>,
}

impl<'a> MakeWriter<'a> for SharedLogWriter {
    type Writer = SharedLogGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogGuard {
            file: Arc::clone(&self.file),
        }
    }
}

impl Write for SharedLogGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.lock().expect("log mutex poisoned").write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.lock().expect("log mutex poisoned").flush()
    }
}

fn with_test_log<R>(name: &str, test: impl FnOnce(&TestLog) -> R) -> R {
    let log_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/_logs");
    fs::create_dir_all(&log_dir).expect("failed to create e2e log dir");
    let log_path = log_dir.join(format!("{name}.log"));
    let file = File::create(&log_path).expect("failed to create test log");
    let writer = SharedLogWriter {
        file: Arc::new(Mutex::new(file)),
    };
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_target(true)
        .with_level(true)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .finish();
    let dispatch = Dispatch::new(subscriber);
    let log = TestLog {
        name: name.to_string(),
        path: log_path,
    };

    tracing::dispatcher::with_default(&dispatch, || {
        let started = Instant::now();
        tracing::info!(
            target: "e2e_real_service",
            event = "test_start",
            test = %name,
            log_path = %log.path.display()
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(&log)));
        match result {
            Ok(value) => {
                tracing::info!(
                    target: "e2e_real_service",
                    event = "test_end",
                    test = %name,
                    status = "PASS",
                    duration_ms = started.elapsed().as_millis()
                );
                value
            }
            Err(payload) => {
                tracing::error!(
                    target: "e2e_real_service",
                    event = "test_end",
                    test = %name,
                    status = "FAIL",
                    duration_ms = started.elapsed().as_millis()
                );
                std::panic::resume_unwind(payload);
            }
        }
    })
}

fn dcg_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("DCG_E2E_BINARY").map(PathBuf::from) {
        return path;
    }

    let tmp_root = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let pane_target_binary = tmp_root.join("rch_target_dcg_cod4/debug/dcg");
    if pane_target_binary.exists() {
        return pane_target_binary;
    }

    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

fn run_hook(
    log: &TestLog,
    env: &RealServiceEnv,
    protocol: Protocol,
    command: &str,
    extra_env: &[(&str, &str)],
) -> DcgRun {
    run_hook_at(log, env, env.cwd_path(), protocol, command, extra_env)
}

fn run_hook_at(
    log: &TestLog,
    env: &RealServiceEnv,
    cwd: &Path,
    protocol: Protocol,
    command: &str,
    extra_env: &[(&str, &str)],
) -> DcgRun {
    let payload = protocol.payload(command, cwd);
    run_dcg_at(log, env, cwd, &[], Some(&payload), extra_env)
}

fn run_dcg(
    log: &TestLog,
    env: &RealServiceEnv,
    args: &[&str],
    stdin: Option<&str>,
    extra_env: &[(&str, &str)],
) -> DcgRun {
    run_dcg_at(log, env, env.cwd_path(), args, stdin, extra_env)
}

fn run_dcg_at(
    log: &TestLog,
    env: &RealServiceEnv,
    cwd: &Path,
    args: &[&str],
    stdin: Option<&str>,
    extra_env: &[(&str, &str)],
) -> DcgRun {
    let binary = dcg_binary();
    let system_path = std::env::var("PATH").unwrap_or_default();

    tracing::info!(
        target: "e2e_real_service",
        event = "dcg_invoke",
        test = %log.name,
        binary = %binary.display(),
        args = ?args,
        cwd = %cwd.display(),
        home = %env.home_path().display(),
        stdin_bytes = stdin.map_or(0, str::len)
    );

    let started = Instant::now();
    let mut cmd = Command::new(&binary);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", system_path)
        .env("HOME", env.home_path())
        .env("USERPROFILE", env.home_path())
        .env("TMPDIR", &env.tmp_dir)
        .env("TEMP", &env.tmp_dir)
        .env("TMP", &env.tmp_dir)
        .env("XDG_CONFIG_HOME", env.home_path().join(".config"))
        .env("DCG_ALLOW_ONCE_PATH", env.allow_once_path())
        .env(
            "DCG_PENDING_EXCEPTIONS_PATH",
            env.home_path().join(".config/dcg/pending_exceptions.jsonl"),
        )
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().unwrap_or_else(|error| {
        panic!(
            "failed to spawn dcg binary at {}: {error}",
            binary.display()
        )
    });

    if let Some(input) = stdin {
        let written = child
            .stdin
            .as_mut()
            .expect("child stdin should be piped")
            .write_all(input.as_bytes());
        // A bypassed hook exits without reading its input, so the write can
        // lose the race with that exit; the run's output is what is judged.
        if let Err(error) = written {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe,
                "failed to write hook JSON to stdin: {error}"
            );
        }
    }

    let output = child.wait_with_output().expect("failed to wait for dcg");
    let run = DcgRun {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code().unwrap_or(-1),
        duration: started.elapsed(),
    };

    tracing::info!(
        target: "e2e_real_service",
        event = "dcg_complete",
        test = %log.name,
        exit_code = run.exit_code,
        duration_ms = run.duration.as_millis(),
        stdout_bytes = run.stdout.len(),
        stderr_bytes = run.stderr.len(),
        stdout = %run.stdout,
        stderr = %run.stderr
    );

    run
}

fn canonical_stdout_json(stdout: &str) -> Value {
    let mut json: Value =
        serde_json::from_str(stdout.trim()).expect("stdout JSON should parse before canonicalize");

    if let Some(hook_output) = json
        .get_mut("hookSpecificOutput")
        .and_then(Value::as_object_mut)
    {
        if hook_output
            .get("allowOnceCode")
            .is_some_and(|value| !value.is_null())
        {
            hook_output.insert(
                "allowOnceCode".to_string(),
                Value::String("<allow-once-code>".to_string()),
            );
        }
        if hook_output
            .get("allowOnceFullHash")
            .is_some_and(|value| !value.is_null())
        {
            hook_output.insert(
                "allowOnceFullHash".to_string(),
                Value::String("sha256:<allow-once-hash>".to_string()),
            );
        }
        if let Some(remediation) = hook_output
            .get_mut("remediation")
            .and_then(Value::as_object_mut)
        {
            if remediation
                .get("allowOnceCommand")
                .is_some_and(|value| !value.is_null())
            {
                remediation.insert(
                    "allowOnceCommand".to_string(),
                    Value::String("dcg allow-once <allow-once-code>".to_string()),
                );
            }
        }
    }

    json
}

fn hook_shape_snapshot(json: &Value, command: &str, rule: Option<&str>) -> Value {
    let hook_output = json
        .get("hookSpecificOutput")
        .and_then(Value::as_object)
        .expect("hookSpecificOutput object should exist");
    let reason = hook_output
        .get("permissionDecisionReason")
        .and_then(Value::as_str)
        .unwrap_or_default();

    json!({
        "hookSpecificOutput": {
            "allowOnceCode": presence_marker(hook_output.get("allowOnceCode")),
            "allowOnceFullHash": presence_marker(hook_output.get("allowOnceFullHash")),
            "confidence": if hook_output.get("confidence").is_some_and(Value::is_number) { "<number>" } else { "<null>" },
            "hookEventName": hook_output.get("hookEventName").cloned().unwrap_or(Value::Null),
            "packId": hook_output.get("packId").cloned().unwrap_or(Value::Null),
            "permissionDecision": hook_output.get("permissionDecision").cloned().unwrap_or(Value::Null),
            "permissionDecisionReason": {
                "containsCommand": reason.contains(command),
                "containsDcgMarker": reason.contains("BLOCKED by dcg")
                    || reason.contains("APPROVAL REQUIRED by dcg")
                    || reason.contains("DCG warn:"),
                "containsRule": rule.is_none_or(|expected| reason.contains(expected)),
            },
            "remediation": remediation_shape(hook_output.get("remediation")),
            "ruleId": hook_output.get("ruleId").cloned().unwrap_or(Value::Null),
            "severity": hook_output.get("severity").cloned().unwrap_or(Value::Null),
        }
    })
}

fn presence_marker(value: Option<&Value>) -> &'static str {
    match value {
        Some(Value::String(s)) if !s.is_empty() => "<present>",
        Some(value) if !value.is_null() => "<present>",
        _ => "<null>",
    }
}

fn remediation_shape(value: Option<&Value>) -> Value {
    let Some(remediation) = value.and_then(Value::as_object) else {
        return Value::String("<null>".to_string());
    };

    json!({
        "allowOnceCommand": remediation
            .get("allowOnceCommand")
            .and_then(Value::as_str)
            .map(|_| "dcg allow-once <allow-once-code>")
            .unwrap_or("<null>"),
        "explanation": presence_marker(remediation.get("explanation")),
        "safeAlternative": presence_marker(remediation.get("safeAlternative")),
    })
}

fn assert_shape_snapshot(log: &TestLog, name: &str, actual: &Value, expected: Value) {
    let actual_pretty =
        serde_json::to_string_pretty(actual).expect("shape snapshot should serialize");
    let expected_pretty =
        serde_json::to_string_pretty(&expected).expect("expected snapshot should serialize");

    tracing::info!(
        target: "e2e_real_service",
        event = "snapshot_compare",
        test = %log.name,
        snapshot = %name,
        actual = %actual_pretty,
        expected = %expected_pretty
    );

    assert_eq!(
        actual_pretty,
        expected_pretty,
        "snapshot {name} changed; see {}",
        log.path.display()
    );
}

fn assert_contains(log: &TestLog, label: &str, haystack: &str, needle: &str) {
    let passed = haystack.contains(needle);
    tracing::info!(
        target: "e2e_real_service",
        event = "assert_contains",
        test = %log.name,
        label = %label,
        needle = %needle,
        passed
    );
    assert!(
        passed,
        "{label}: expected output to contain {needle:?}; see {}",
        log.path.display()
    );
}

fn assert_empty(log: &TestLog, label: &str, value: &str) {
    let passed = value.trim().is_empty();
    tracing::info!(
        target: "e2e_real_service",
        event = "assert_empty",
        test = %log.name,
        label = %label,
        passed,
        bytes = value.len()
    );
    assert!(
        passed,
        "{label}: expected empty output, got {value:?}; see {}",
        log.path.display()
    );
}

fn expected_deny_shape() -> Value {
    json!({
        "hookSpecificOutput": {
            "allowOnceCode": "<present>",
            "allowOnceFullHash": "<present>",
            "confidence": "<number>",
            "hookEventName": "PreToolUse",
            "packId": "core.git",
            "permissionDecision": "deny",
            "permissionDecisionReason": {
                "containsCommand": true,
                "containsDcgMarker": true,
                "containsRule": true
            },
            "remediation": {
                "allowOnceCommand": "dcg allow-once <allow-once-code>",
                "explanation": "<present>",
                "safeAlternative": "<present>"
            },
            "ruleId": "core.git:reset-hard",
            "severity": "critical"
        }
    })
}

fn expected_ask_shape() -> Value {
    json!({
        "hookSpecificOutput": {
            "allowOnceCode": "<present>",
            "allowOnceFullHash": "<present>",
            "confidence": "<number>",
            "hookEventName": "PreToolUse",
            "packId": "core.git",
            "permissionDecision": "ask",
            "permissionDecisionReason": {
                "containsCommand": true,
                "containsDcgMarker": true,
                "containsRule": true
            },
            "remediation": {
                "allowOnceCommand": "dcg allow-once <allow-once-code>",
                "explanation": "<present>",
                "safeAlternative": "<present>"
            },
            "ruleId": "core.git:reset-hard",
            "severity": "critical"
        }
    })
}

fn assert_reset_denied(run: &DcgRun, case: &str) {
    assert_eq!(run.exit_code, 0, "{case}: hook should exit normally");
    let output = run.stdout_json();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"], "deny",
        "{case}: an invalid or out-of-scope grant must not authorize the command"
    );
    assert_eq!(
        output["hookSpecificOutput"]["ruleId"], "core.git:reset-hard",
        "{case}: the normal destructive-command policy should remain effective"
    );
}

fn grant_allow_once(log: &TestLog, env: &RealServiceEnv, cwd: &Path, reusable: bool) -> Value {
    let denied = run_hook_at(log, env, cwd, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
    assert_reset_denied(&denied, "before approval");
    let output = denied.stdout_json();
    let code = output["hookSpecificOutput"]["allowOnceCode"]
        .as_str()
        .expect("denied command should issue a pending code");
    let mut args = vec!["allow-once", code, "--yes"];
    if reusable {
        args.push("--reusable");
    }
    let approved = run_dcg_at(log, env, cwd, &args, None, &[]);
    assert_eq!(
        approved.exit_code, 0,
        "real pending-code redemption failed: {}\n{}",
        approved.stdout, approved.stderr
    );

    let stored = fs::read_to_string(env.allow_once_path()).expect("read the approved grant");
    serde_json::from_str(stored.lines().last().expect("approved grant line"))
        .expect("parse the approved grant")
}

fn write_allow_once_entry(env: &RealServiceEnv, entry: &Value) {
    let mut line = serde_json::to_string(entry).expect("serialize test grant");
    line.push('\n');
    fs::write(env.allow_once_path(), line).expect("write isolated test grant");
}

fn init_test_repo(path: &Path) {
    fs::create_dir_all(path).expect("create test repository directory");
    let output = Command::new("git")
        .args(["-c", "init.templateDir=", "init", "--quiet"])
        .arg(path)
        .output()
        .expect("initialize test git repository");
    assert!(
        output.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn safe_bash_allows_silently_for_claude_and_codex() {
    with_test_log("safe_bash_allows_silently_for_claude_and_codex", |log| {
        for protocol in [Protocol::Claude, Protocol::Codex] {
            let env = RealServiceEnv::new(&format!("safe-{}", protocol.label()));
            let run = run_hook(log, &env, protocol, "git status", &[]);

            assert_eq!(
                run.exit_code,
                0,
                "{} safe command should exit 0; see {}",
                protocol.label(),
                log.path.display()
            );
            assert_empty(log, "safe stdout", &run.stdout);
            assert_empty(log, "safe stderr", &run.stderr);
        }
    });
}

#[test]
fn destructive_bash_blocks_with_protocol_specific_output() {
    with_test_log(
        "destructive_bash_blocks_with_protocol_specific_output",
        |log| {
            let claude_env = RealServiceEnv::new("deny-claude");
            let claude = run_hook(log, &claude_env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
            assert_eq!(claude.exit_code, 0, "Claude deny should exit 0");
            let canonical = canonical_stdout_json(&claude.stdout);
            tracing::info!(
                target: "e2e_real_service",
                event = "canonical_stdout_json",
                test = %log.name,
                protocol = "claude",
                json = %serde_json::to_string_pretty(&canonical).unwrap()
            );
            let shape =
                hook_shape_snapshot(&canonical, DESTRUCTIVE_COMMAND, Some("core.git:reset-hard"));
            assert_shape_snapshot(
                log,
                "claude_deny_core_git_reset_hard",
                &shape,
                expected_deny_shape(),
            );
            assert_contains(log, "Claude deny stderr marker", &claude.stderr, "BLOCKED");
            assert_contains(
                log,
                "Claude deny stderr rule",
                &claude.stderr,
                "core.git:reset-hard",
            );

            let codex_env = RealServiceEnv::new("deny-codex");
            let codex = run_hook(log, &codex_env, Protocol::Codex, DESTRUCTIVE_COMMAND, &[]);
            assert_eq!(codex.exit_code, 0, "Codex deny should exit normally");
            let codex_json = codex.stdout_json();
            let codex_specific = codex_json["hookSpecificOutput"]
                .as_object()
                .expect("Codex hookSpecificOutput object");
            assert_eq!(codex_specific.len(), 3, "Codex deny must stay minimal");
            assert_eq!(codex_specific["hookEventName"], "PreToolUse");
            assert_eq!(codex_specific["permissionDecision"], "deny");
            assert!(
                codex_specific["permissionDecisionReason"]
                    .as_str()
                    .is_some_and(|reason| {
                        reason.contains(DESTRUCTIVE_COMMAND)
                            && reason.contains("core.git:reset-hard")
                    }),
                "Codex deny reason must contain command and rule"
            );
            assert_contains(log, "Codex deny stderr marker", &codex.stderr, "BLOCKED");
            assert_contains(
                log,
                "Codex deny stderr rule",
                &codex.stderr,
                "core.git:reset-hard",
            );
        },
    );
}

#[test]
fn ask_policy_uses_native_review_or_fails_closed() {
    with_test_log("ask_policy_uses_native_review_or_fails_closed", |log| {
        let config = "[policy]\ndefault_mode = \"ask\"\n";

        let claude_env = RealServiceEnv::new("ask-claude");
        claude_env.write_config(config);
        let claude = run_hook(log, &claude_env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
        assert_eq!(claude.exit_code, 0, "Claude ask should exit 0");
        let canonical = canonical_stdout_json(&claude.stdout);
        tracing::info!(
            target: "e2e_real_service",
            event = "canonical_stdout_json",
            test = %log.name,
            protocol = "claude",
            json = %serde_json::to_string_pretty(&canonical).unwrap()
        );
        let shape =
            hook_shape_snapshot(&canonical, DESTRUCTIVE_COMMAND, Some("core.git:reset-hard"));
        assert_shape_snapshot(
            log,
            "claude_ask_core_git_reset_hard",
            &shape,
            expected_ask_shape(),
        );
        assert_contains(log, "Claude ask stderr", &claude.stderr, "BLOCKED");

        let codex_env = RealServiceEnv::new("ask-codex");
        codex_env.write_config(config);
        let codex = run_hook(log, &codex_env, Protocol::Codex, DESTRUCTIVE_COMMAND, &[]);
        assert_eq!(codex.exit_code, 0, "Codex ask fallback should exit 0");
        let codex_json = codex.stdout_json();
        assert_eq!(
            codex_json["hookSpecificOutput"]["permissionDecision"], "deny",
            "Codex has no ask decision and must fail closed"
        );
        assert_contains(log, "Codex ask stderr", &codex.stderr, "BLOCKED");
        assert_contains(
            log,
            "Codex ask stderr rule",
            &codex.stderr,
            "core.git:reset-hard",
        );
    });
}

#[test]
fn warn_policy_allows_with_visible_stderr_for_claude_and_codex() {
    with_test_log("warn_policy_allows_with_visible_stderr", |log| {
        let config = "[policy.rules]\n\"core.git:reset-hard\" = \"warn\"\n";

        for (protocol, label) in [(Protocol::Claude, "claude"), (Protocol::Codex, "codex")] {
            let env = RealServiceEnv::new(&format!("warn-{label}"));
            env.write_config(config);
            let outcome = run_hook(log, &env, protocol, DESTRUCTIVE_COMMAND, &[]);
            assert_eq!(outcome.exit_code, 0, "{label} warn should exit 0");
            assert_empty(log, &format!("{label} warn stdout"), &outcome.stdout);
            assert_contains(
                log,
                &format!("{label} warn stderr"),
                &outcome.stderr,
                "WARNING",
            );
        }
    });
}

#[test]
fn heredoc_embedded_destructive_blocks_for_claude_and_codex() {
    with_test_log(
        "heredoc_embedded_destructive_blocks_for_claude_and_codex",
        |log| {
            let command =
                // Non-temp target: #455 gave the recursive-delete rule the
                // temp carve-out `rm -rf` has always had, so a /tmp payload
                // no longer blocks and this test is about the heredoc path
                // reaching the service at all.
                "python3 <<'PY'\nimport shutil\nshutil.rmtree('/home/example/project')\nPY";

            let claude_env = RealServiceEnv::new("heredoc-claude");
            let claude = run_hook(log, &claude_env, Protocol::Claude, command, &[]);
            assert_eq!(claude.exit_code, 0, "Claude heredoc deny should exit 0");
            let json = claude.stdout_json();
            let hook_output = &json["hookSpecificOutput"];
            assert_eq!(hook_output["permissionDecision"], "deny");
            let pack = hook_output["packId"].as_str().unwrap_or_default();
            assert!(
                pack.starts_with("heredoc."),
                "expected heredoc pack for Claude, got {pack:?}; see {}",
                log.path.display()
            );
            assert_contains(log, "Claude heredoc stderr", &claude.stderr, "BLOCKED");

            let codex_env = RealServiceEnv::new("heredoc-codex");
            let codex = run_hook(log, &codex_env, Protocol::Codex, command, &[]);
            assert_eq!(
                codex.exit_code, 0,
                "Codex heredoc deny should exit normally"
            );
            let codex_json = codex.stdout_json();
            assert_eq!(
                codex_json["hookSpecificOutput"]["permissionDecision"],
                "deny"
            );
            assert_eq!(
                codex_json["hookSpecificOutput"]
                    .as_object()
                    .map(serde_json::Map::len),
                Some(3)
            );
            assert_contains(log, "Codex heredoc stderr", &codex.stderr, "BLOCKED");
            assert_contains(log, "Codex heredoc pack", &codex.stderr, "heredoc.");
        },
    );
}

#[test]
fn bypass_env_allows_destructive_silently_for_both_protocols() {
    with_test_log(
        "bypass_env_allows_destructive_silently_for_both_protocols",
        |log| {
            for protocol in [Protocol::Claude, Protocol::Codex] {
                let env = RealServiceEnv::new(&format!("bypass-{}", protocol.label()));
                let run = run_hook(
                    log,
                    &env,
                    protocol,
                    DESTRUCTIVE_COMMAND,
                    &[("DCG_BYPASS", "1")],
                );

                assert_eq!(
                    run.exit_code,
                    0,
                    "{} bypass should exit 0; see {}",
                    protocol.label(),
                    log.path.display()
                );
                assert_empty(log, "bypass stdout", &run.stdout);
                assert_empty(log, "bypass stderr", &run.stderr);
            }
        },
    );
}

#[test]
fn allow_once_short_code_round_trip_redeems_real_pending_exception() {
    with_test_log(
        "allow_once_short_code_round_trip_redeems_real_pending_exception",
        |log| {
            let env = RealServiceEnv::new("allow-once");

            let deny = run_hook(log, &env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
            assert_eq!(deny.exit_code, 0, "initial Claude deny should exit 0");
            let json = deny.stdout_json();
            let allow_code = json["hookSpecificOutput"]["allowOnceCode"]
                .as_str()
                .expect("deny JSON should include allowOnceCode")
                .to_string();
            assert!(
                allow_code.len() >= 5,
                "allowOnceCode should be substantial; see {}",
                log.path.display()
            );

            let redeem = run_dcg(log, &env, &["allow-once", &allow_code, "--yes"], None, &[]);
            assert_eq!(
                redeem.exit_code,
                0,
                "allow-once redemption should exit 0; see {}",
                log.path.display()
            );

            let retry = run_hook(log, &env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
            assert_eq!(retry.exit_code, 0, "allow-once retry should exit 0");
            assert_empty(log, "allow-once retry stdout", &retry.stdout);

            let consumed = run_hook(log, &env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
            assert_reset_denied(&consumed, "default grant is consumed on first use");
        },
    );
}

#[test]
fn allow_once_rejects_forged_lifetime_and_scope_records() {
    with_test_log(
        "allow_once_rejects_forged_lifetime_and_scope_records",
        |log| {
            let env = RealServiceEnv::new("forged-grants");
            let approved = grant_allow_once(log, &env, env.cwd_path(), true);
            let now = chrono::Utc::now();
            let future = (now + chrono::Duration::hours(1)).to_rfc3339();
            let later = (now + chrono::Duration::hours(2)).to_rfc3339();
            let expired_created = (now - chrono::Duration::hours(25)).to_rfc3339();
            let expired = (now - chrono::Duration::hours(1)).to_rfc3339();
            let root = env.cwd_path().ancestors().last().expect("filesystem root");

            for (case, changes) in [
                (
                    "expiry in 2099",
                    json!({ "expires_at": "2099-01-01T00:00:00Z" }),
                ),
                (
                    "future creation within a 24-hour window",
                    json!({ "created_at": future, "expires_at": later }),
                ),
                (
                    "expired reusable grant",
                    json!({ "created_at": expired_created, "expires_at": expired }),
                ),
                (
                    "nonpositive lifetime",
                    json!({ "expires_at": approved["created_at"] }),
                ),
                ("malformed creation", json!({ "created_at": "not-a-time" })),
                ("malformed expiry", json!({ "expires_at": "not-a-time" })),
                ("unsupported schema", json!({ "schema_version": 99 })),
                ("empty scope", json!({ "scope_path": "" })),
                ("relative scope", json!({ "scope_path": "." })),
                (
                    "project scope at filesystem root",
                    json!({ "scope_kind": "project", "scope_path": root }),
                ),
                (
                    "project scope outside a repository",
                    json!({ "scope_kind": "project", "scope_path": env.cwd_path() }),
                ),
            ] {
                let mut forged = approved.clone();
                forged
                    .as_object_mut()
                    .expect("grant object")
                    .extend(changes.as_object().expect("changed fields").clone());
                write_allow_once_entry(&env, &forged);
                let result = run_hook(log, &env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
                assert_reset_denied(&result, case);
            }

            // Invalid neighbors must not discard an independently valid approval.
            let mut forged = approved.clone();
            forged["expires_at"] = json!("2099-01-01T00:00:00Z");
            fs::write(
                env.allow_once_path(),
                format!("not json\n{forged}\n{approved}\n"),
            )
            .expect("write malformed, forged and valid grants together");
            for _ in 0..2 {
                let result = run_hook(log, &env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
                assert_eq!(result.exit_code, 0);
                assert_empty(
                    log,
                    "valid reusable grant survives invalid records",
                    &result.stdout,
                );
            }
        },
    );
}

#[test]
fn allow_once_reusable_grants_respect_project_and_exact_command_boundaries() {
    with_test_log(
        "allow_once_reusable_grants_respect_project_and_exact_command_boundaries",
        |log| {
            let env = RealServiceEnv::new("project-grants");
            let project = env.cwd_path().join("project");
            let child = project.join("src");
            let sibling = env.cwd_path().join("project-other");
            let nested = project.join("nested-repo");
            init_test_repo(&project);
            fs::create_dir_all(&child).expect("create project child");
            fs::create_dir_all(&sibling).expect("create sibling with common path prefix");
            init_test_repo(&nested);

            let approved = grant_allow_once(log, &env, &child, true);
            assert_eq!(approved["scope_kind"], "project");
            assert_eq!(approved["single_use"], false);
            for cwd in [&project, &child, &project] {
                let result =
                    run_hook_at(log, &env, cwd, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
                assert_eq!(result.exit_code, 0);
                assert_empty(log, "approved project root/descendant", &result.stdout);
            }

            let changed_command = run_hook_at(
                log,
                &env,
                &project,
                Protocol::Claude,
                "git reset --hard HEAD~2",
                &[],
            );
            assert_reset_denied(&changed_command, "different command text");
            for cwd in [sibling.as_path(), nested.as_path(), env.cwd_path()] {
                let result =
                    run_hook_at(log, &env, cwd, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
                assert_reset_denied(&result, "different project or outside the repository");
            }

            #[cfg(unix)]
            {
                let escape = project.join("outside-link");
                std::os::unix::fs::symlink(&sibling, &escape)
                    .expect("create symlink outside project");
                let result = run_hook_at(
                    log,
                    &env,
                    &escape,
                    Protocol::Claude,
                    DESTRUCTIVE_COMMAND,
                    &[],
                );
                assert_reset_denied(&result, "symlink exits project scope");
            }

            let retry = run_hook_at(
                log,
                &env,
                &child,
                Protocol::Claude,
                DESTRUCTIVE_COMMAND,
                &[],
            );
            assert_eq!(retry.exit_code, 0);
            assert_empty(
                log,
                "out-of-scope attempts do not consume valid reusable grant",
                &retry.stdout,
            );
        },
    );
}

#[test]
fn allow_once_cwd_grants_do_not_cover_descendants() {
    with_test_log("allow_once_cwd_grants_do_not_cover_descendants", |log| {
        let env = RealServiceEnv::new("cwd-grants");
        let child = env.cwd_path().join("child");
        fs::create_dir_all(&child).expect("create non-project child directory");
        let approved = grant_allow_once(log, &env, env.cwd_path(), false);
        assert_eq!(approved["scope_kind"], "cwd");
        assert_eq!(approved["single_use"], true);

        let outside = run_hook_at(
            log,
            &env,
            &child,
            Protocol::Claude,
            DESTRUCTIVE_COMMAND,
            &[],
        );
        assert_reset_denied(&outside, "cwd grants are exact, not recursive");
        let permitted = run_hook(log, &env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
        assert_eq!(permitted.exit_code, 0);
        assert_empty(
            log,
            "nonmatching cwd does not consume single-use approval",
            &permitted.stdout,
        );
        let consumed = run_hook(log, &env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
        assert_reset_denied(&consumed, "valid single-use grant is consumed");
    });
}

#[test]
fn allow_once_uses_request_cwd_instead_of_hook_process_cwd() {
    with_test_log(
        "allow_once_uses_request_cwd_instead_of_hook_process_cwd",
        |log| {
            let env = RealServiceEnv::new("request-cwd-grants");
            let request_cwd = env.cwd_path().join("request");
            fs::create_dir_all(&request_cwd).expect("create requested working directory");
            let process_grant = grant_allow_once(log, &env, env.cwd_path(), true);

            let request = Protocol::Claude.payload(DESTRUCTIVE_COMMAND, &request_cwd);
            let outside = run_dcg(log, &env, &[], Some(&request), &[]);
            assert_reset_denied(&outside, "process cwd grant must not cover request cwd");

            for invalid_cwd in [PathBuf::from("relative"), env.cwd_path().join("missing")] {
                let invalid = Protocol::Claude.payload(DESTRUCTIVE_COMMAND, &invalid_cwd);
                let result = run_dcg(log, &env, &[], Some(&invalid), &[]);
                assert_reset_denied(
                    &result,
                    "invalid request cwd cannot fall back to process cwd",
                );
            }

            // Redeem the code minted by the hook launched from a different cwd.
            // Both the pending record and the eventual grant must retain request scope.
            let output = outside.stdout_json();
            let code = output["hookSpecificOutput"]["allowOnceCode"]
                .as_str()
                .expect("out-of-scope denial should issue a code for request cwd");
            let approval = run_dcg(
                log,
                &env,
                &["allow-once", code, "--yes", "--reusable"],
                None,
                &[],
            );
            assert_eq!(approval.exit_code, 0, "{}", approval.stderr);
            let allowed = run_dcg(log, &env, &[], Some(&request), &[]);
            assert_eq!(allowed.exit_code, 0);
            assert_empty(
                log,
                "request cwd grant is honored from another process cwd",
                &allowed.stdout,
            );

            // Leave only the request grant, then try the reverse mismatch.
            let entries = fs::read_to_string(env.allow_once_path()).expect("read granted entries");
            let request_grant = entries
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).expect("grant JSON"))
                .find(|entry| entry["source_full_hash"] != process_grant["source_full_hash"])
                .expect("request grant was recorded separately");
            write_allow_once_entry(&env, &request_grant);
            let process_request = Protocol::Claude.payload(DESTRUCTIVE_COMMAND, env.cwd_path());
            let denied = run_dcg_at(log, &env, &request_cwd, &[], Some(&process_request), &[]);
            assert_reset_denied(
                &denied,
                "request grant cannot cover caller working directory",
            );
        },
    );
}

#[test]
fn allow_once_can_approve_exact_nested_cd_command_from_request_scope() {
    with_test_log(
        "allow_once_can_approve_exact_nested_cd_command_from_request_scope",
        |log| {
            let env = RealServiceEnv::new("nested-cd-grant");
            let command = r#"sh -c 'cd "$DEST" && git reset --hard HEAD~1'"#;
            let denied = run_hook(log, &env, Protocol::Claude, command, &[]);
            assert_eq!(denied.exit_code, 0);
            let output = denied.stdout_json();
            assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
            let code = output["hookSpecificOutput"]["allowOnceCode"]
                .as_str()
                .expect("blocked exact envelope should remain approvable");
            let approval = run_dcg(
                log,
                &env,
                &["allow-once", code, "--yes", "--reusable"],
                None,
                &[],
            );
            assert_eq!(approval.exit_code, 0, "{}", approval.stderr);
            let allowed = run_hook(log, &env, Protocol::Claude, command, &[]);
            assert_eq!(allowed.exit_code, 0);
            assert_empty(log, "exact approved nested-cd command", &allowed.stdout);

            let unrelated = env.cwd_path().join("other-base");
            fs::create_dir_all(&unrelated).expect("create unrelated command base");
            let outside = run_hook_at(log, &env, &unrelated, Protocol::Claude, command, &[]);
            assert_eq!(outside.exit_code, 0);
            assert_eq!(
                outside.stdout_json()["hookSpecificOutput"]["permissionDecision"],
                "deny",
                "exact command grants remain bound to their approved request directory"
            );
        },
    );
}

#[test]
fn allow_once_redemption_rejects_unresolvable_pending_directories() {
    with_test_log(
        "allow_once_redemption_rejects_unresolvable_pending_directories",
        |log| {
            let env = RealServiceEnv::new("invalid-pending-cwd");
            let denied = run_hook(log, &env, Protocol::Claude, DESTRUCTIVE_COMMAND, &[]);
            assert_reset_denied(&denied, "initial pending-code issuance");
            let output = denied.stdout_json();
            let code = output["hookSpecificOutput"]["allowOnceCode"]
                .as_str()
                .expect("real denial must issue a pending code");
            let pending_path = env.home_path().join(".config/dcg/pending_exceptions.jsonl");
            let original: Value = serde_json::from_str(
                fs::read_to_string(&pending_path)
                    .expect("read issued pending record")
                    .trim(),
            )
            .expect("pending record JSON");

            for cwd in [
                json!("<unknown>"),
                json!(""),
                json!("relative-directory"),
                json!(env.cwd_path().join("missing-directory")),
            ] {
                let mut malformed = original.clone();
                malformed["cwd"] = cwd.clone();
                fs::write(&pending_path, format!("{malformed}\n"))
                    .expect("write isolated malformed pending scope");
                let redemption = run_dcg(log, &env, &["allow-once", code, "--yes"], None, &[]);
                assert_ne!(
                    redemption.exit_code, 0,
                    "invalid pending cwd {cwd} must not be rebound to approval cwd"
                );
                assert_contains(
                    log,
                    "invalid pending scope error",
                    &redemption.stderr,
                    "scope",
                );
                if env.allow_once_path().exists() {
                    let grants = fs::read_to_string(env.allow_once_path()).expect("read grants");
                    assert_empty(log, "invalid pending scope cannot mint a grant", &grants);
                }
            }

            fs::write(&pending_path, format!("{original}\n"))
                .expect("restore the valid issued pending record");
            let valid = run_dcg(log, &env, &["allow-once", code, "--yes"], None, &[]);
            assert_eq!(
                valid.exit_code, 0,
                "valid original pending record: {}",
                valid.stderr
            );
        },
    );
}

#[test]
fn guardrails_block_authorization_store_writes_without_blocking_reads() {
    with_test_log(
        "guardrails_block_authorization_store_writes_without_blocking_reads",
        |log| {
            let env = RealServiceEnv::new("authorization-store-writes");
            env.write_config(
                "[packs]\nenabled = [\"careful_company_running_windows.guardrails\"]\n",
            );

            // These strings are submitted only to the hook; no shell executes them.
            for command in [
                "printf '%s\\n' '{}' >> ~/.config/dcg/allow_once.jsonl",
                "printf '%s\\n' '{}' | tee -a ~/.config/dcg/pending_exceptions.jsonl",
                "cp /tmp/forged.jsonl ~/.config/dcg/allow_once.jsonl",
                "sed -i 's/true/false/' ~/.config/dcg/allow_once.jsonl",
            ] {
                let result = run_hook(log, &env, Protocol::Claude, command, &[]);
                assert_eq!(result.exit_code, 0);
                let output = result.stdout_json();
                assert_eq!(
                    output["hookSpecificOutput"]["permissionDecision"], "deny",
                    "authorization-store mutation must be denied: {command}"
                );
                assert_eq!(
                    output["hookSpecificOutput"]["packId"],
                    "careful_company_running_windows.guardrails",
                    "write must reach the guardrails pack: {command}"
                );
                assert_eq!(
                    output["hookSpecificOutput"]["ruleId"],
                    "careful_company_running_windows.guardrails:dcg-policy-self-weakening"
                );
            }

            for command in [
                "cat ~/.config/dcg/allow_once.jsonl",
                "cp ~/.config/dcg/allow_once.jsonl /tmp/grant-backup.jsonl",
                "printf '%s\\n' '{}' >> /tmp/application.jsonl",
                "printf '%s\\n' '~/.config/dcg/allow_once.jsonl' > /tmp/notes.txt",
                "echo 'x > ~/.config/dcg/allow_once.jsonl'",
                "printf '%s\\n' '{}' > ~/.config/dcg/allow_once.jsonl.bak",
            ] {
                let result = run_hook(log, &env, Protocol::Claude, command, &[]);
                assert_eq!(result.exit_code, 0);
                assert_empty(log, command, &result.stdout);
            }
        },
    );
}

#[test]
fn guardrails_resolve_relative_store_writes_from_request_cwd() {
    with_test_log(
        "guardrails_resolve_relative_store_writes_from_request_cwd",
        |log| {
            let env = RealServiceEnv::new("store-write-request-cwd");
            env.write_config(
                "[packs]\nenabled = [\"careful_company_running_windows.guardrails\"]\n",
            );
            let store_dir = env.home_path().join(".config/dcg");
            let command = "printf forged > allow_once.jsonl";
            let request = Protocol::Claude.payload(command, &store_dir);
            let blocked = run_dcg(log, &env, &[], Some(&request), &[]);
            assert_eq!(blocked.exit_code, 0);
            let output = blocked.stdout_json();
            assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
            assert_eq!(
                output["hookSpecificOutput"]["ruleId"],
                "careful_company_running_windows.guardrails:dcg-policy-self-weakening",
                "a relative destination in request cwd must resolve to the selected store"
            );

            let unrelated_request = Protocol::Claude.payload(command, env.cwd_path());
            let unrelated = run_dcg_at(log, &env, &store_dir, &[], Some(&unrelated_request), &[]);
            assert_eq!(unrelated.exit_code, 0);
            assert_empty(
                log,
                "same basename in an unrelated request directory",
                &unrelated.stdout,
            );
        },
    );
}

#[test]
fn cli_version_and_help_emit_human_output() {
    with_test_log("cli_version_and_help_emit_human_output", |log| {
        let env = RealServiceEnv::new("cli-help-version");

        let version = run_dcg(log, &env, &["--version"], None, &[]);
        assert_eq!(version.exit_code, 0, "--version should exit 0");
        assert_contains(
            log,
            "--version stdout",
            &version.stdout,
            env!("CARGO_PKG_VERSION"),
        );
        assert_contains(log, "--version stderr", &version.stderr, "dcg");
        assert_contains(
            log,
            "--version stderr version",
            &version.stderr,
            env!("CARGO_PKG_VERSION"),
        );

        let help = run_dcg(log, &env, &["--help"], None, &[]);
        assert_eq!(help.exit_code, 0, "--help should exit 0");
        assert_empty(log, "--help stdout", &help.stdout);
        assert_contains(log, "--help stderr", &help.stderr, "USAGE");
        assert_contains(
            log,
            "--help stderr multi-agent",
            &help.stderr,
            "Claude Code, Codex CLI",
        );
        assert_contains(
            log,
            "--help stderr codex contract",
            &help.stderr,
            "including Codex, receive protocol-specific stdout JSON",
        );
        assert_contains(log, "--help stderr command", &help.stderr, "COMMANDS");
    });
}
