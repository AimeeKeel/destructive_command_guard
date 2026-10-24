//! Repro for issue #588: a pack loaded through `packs.custom_paths` stayed
//! enabled even when `packs.disabled` named it.
//!
//! Every evaluation path computed the configured pack set (which applies
//! `packs.disabled`) and then auto-enabled every loaded external pack on top
//! of it, appending each one to the evaluation order unconditionally. The
//! hook then removed only the agent profile's `disabled_packs` from the set,
//! and even that never reached the evaluation order. So a disabled external
//! pack kept denying commands, and `dcg packs --enabled` and `dcg config`
//! kept listing it.
//!
//! Runs the real binary, since the report did.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

/// Two packs in one category, each with a rule on a string found nowhere else.
const GUARD_PACK: &str = r"schema_version: 1
id: repro588.guard
name: Repro 588 guard
version: 1.0.0
keywords:
  - dcg-repro-588-guard
destructive_patterns:
  - name: blocked-guard
    pattern: dcg-repro-588-guard
    severity: high
    description: Reproduction rule
";

const OTHER_PACK: &str = r"schema_version: 1
id: repro588.other
name: Repro 588 other
version: 1.0.0
keywords:
  - dcg-repro-588-other
destructive_patterns:
  - name: blocked-other
    pattern: dcg-repro-588-other
    severity: high
    description: Reproduction rule
";

const GUARD_COMMAND: &str = "dcg-repro-588-guard";
const OTHER_COMMAND: &str = "dcg-repro-588-other";

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().to_path_buf();
        fs::create_dir_all(root.join("packs")).expect("packs dir");
        fs::write(root.join("packs/guard.yaml"), GUARD_PACK).expect("write guard pack");
        fs::write(root.join("packs/other.yaml"), OTHER_PACK).expect("write other pack");
        Self { _dir: dir, root }
    }

    /// A config that loads both packs and adds `extra` below `[packs]`.
    fn config(&self, name: &str, extra: &str) -> PathBuf {
        let glob = self.root.join("packs").join("*.yaml");
        let body = format!(
            "[packs]\ncustom_paths = [{}]\n{extra}",
            serde_json::to_string(&glob).expect("glob")
        );
        let path = self.root.join(name);
        fs::write(&path, body).expect("write config");
        path
    }

    fn command(&self, config: &Path, args: &[&str]) -> Command {
        let mut command = Command::new(dcg_binary());
        command
            .env_clear()
            .args(args)
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("xdg_config"))
            .env("DCG_CONFIG", config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_HISTORY_DISABLED", "1")
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_HOOK_TIMEOUT_MS", "10000")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.root.join("pending_exceptions.jsonl"),
            )
            .env("NO_COLOR", "1")
            .current_dir(&self.root);
        command
    }

    fn stdout(&self, config: &Path, args: &[&str]) -> String {
        let output = self
            .command(config, args)
            .stdin(Stdio::null())
            .output()
            .expect("run dcg");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn feed(&self, config: &Path, args: &[&str], input: &str) -> String {
        let mut child = self
            .command(config, args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn dcg");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("write input");
        let output = child.wait_with_output().expect("wait for dcg");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn payload(&self, command: &str) -> String {
        serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "cwd": self.root.to_string_lossy(),
        })
        .to_string()
    }

    /// The enforcing surface: bare hook mode, optionally as a named agent.
    fn hook_denies(&self, config: &Path, agent: Option<&str>, command: &str) -> bool {
        let args = agent.map_or_else(|| vec!["hook"], |agent| vec!["--agent", agent]);
        let stdout = self.feed(config, &args, &self.payload(command));
        stdout.contains(r#""permissionDecision":"deny""#)
    }

    /// `dcg hook --batch`, which builds its pack set once for the stream.
    fn batch_denies(&self, config: &Path, command: &str) -> bool {
        let stdout = self.feed(
            config,
            &["hook", "--batch"],
            &format!("{}\n", self.payload(command)),
        );
        let line = stdout
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_else(|| panic!("dcg hook --batch produced no line for {command:?}"));
        let json: serde_json::Value = serde_json::from_str(line).expect("batch JSON");
        json["decision"] == "deny"
    }

    /// `dcg test --format json`, as the report ran it.
    fn test_denies(&self, config: &Path, extra_args: &[&str], command: &str) -> bool {
        let mut args = vec!["test", "--dialect", "posix", "--format", "json"];
        args.extend_from_slice(extra_args);
        args.push(command);
        let stdout = self.stdout(config, &args);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"));
        json["decision"] == "deny"
    }

    fn explain_denies(&self, config: &Path, command: &str) -> bool {
        let stdout = self.stdout(config, &["explain", "--format", "json", command]);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"));
        json["decision"] == "deny"
    }

    /// Every surface that evaluates a command, as one verdict per surface.
    fn verdicts(&self, config: &Path, command: &str) -> [(&'static str, bool); 4] {
        [
            ("hook", self.hook_denies(config, None, command)),
            ("hook --batch", self.batch_denies(config, command)),
            ("test", self.test_denies(config, &[], command)),
            ("explain", self.explain_denies(config, command)),
        ]
    }

    /// IDs `dcg packs --enabled --format json` reports as enabled.
    fn listed_enabled(&self, config: &Path) -> Vec<String> {
        let stdout = self.stdout(config, &["packs", "--enabled", "--format", "json"]);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"));
        json["packs"]
            .as_array()
            .expect("packs array")
            .iter()
            .filter(|pack| pack["enabled"] == true)
            .filter_map(|pack| pack["id"].as_str().map(str::to_string))
            .collect()
    }

    /// IDs `dcg config --format json` reports as enabled.
    fn config_enabled(&self, config: &Path) -> Vec<String> {
        let stdout = self.stdout(config, &["config", "--format", "json"]);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"));
        json["packs"]["enabled"]
            .as_array()
            .expect("enabled array")
            .iter()
            .filter_map(|id| id.as_str().map(str::to_string))
            .collect()
    }
}

fn assert_all(verdicts: [(&'static str, bool); 4], denied: bool, what: &str) {
    for (surface, verdict) in verdicts {
        assert_eq!(
            verdict,
            denied,
            "{surface}: {what} should be {}",
            if denied { "denied" } else { "allowed" }
        );
    }
}

#[test]
fn a_loaded_pack_is_enabled_until_disabled() {
    let fixture = Fixture::new();
    let config = fixture.config("plain.toml", "");
    assert_all(fixture.verdicts(&config, GUARD_COMMAND), true, "guard rule");
    assert_all(fixture.verdicts(&config, OTHER_COMMAND), true, "other rule");
    for listing in [
        fixture.listed_enabled(&config),
        fixture.config_enabled(&config),
    ] {
        assert!(
            listing.contains(&"repro588.guard".to_string()),
            "{listing:?}"
        );
        assert!(
            listing.contains(&"repro588.other".to_string()),
            "{listing:?}"
        );
    }
}

#[test]
fn packs_disabled_removes_an_external_pack_by_exact_id() {
    let fixture = Fixture::new();
    let config = fixture.config("exact.toml", "disabled = [\"repro588.guard\"]\n");

    // The reporter's case: the disabled pack's rule no longer participates.
    assert_all(
        fixture.verdicts(&config, GUARD_COMMAND),
        false,
        "a disabled pack's rule",
    );
    // Its sibling, which nothing disabled, still evaluates.
    assert_all(
        fixture.verdicts(&config, OTHER_COMMAND),
        true,
        "an enabled sibling's rule",
    );
    // Core protection is untouched by external-pack exclusions.
    assert_all(
        fixture.verdicts(&config, "git reset --hard"),
        true,
        "a core rule",
    );

    for listing in [
        fixture.listed_enabled(&config),
        fixture.config_enabled(&config),
    ] {
        assert!(
            !listing.contains(&"repro588.guard".to_string()),
            "{listing:?}"
        );
        assert!(
            listing.contains(&"repro588.other".to_string()),
            "{listing:?}"
        );
    }
}

#[test]
fn packs_disabled_removes_external_packs_by_category() {
    let fixture = Fixture::new();
    let config = fixture.config("category.toml", "disabled = [\"repro588\"]\n");
    assert_all(
        fixture.verdicts(&config, GUARD_COMMAND),
        false,
        "guard rule",
    );
    assert_all(
        fixture.verdicts(&config, OTHER_COMMAND),
        false,
        "other rule",
    );
    for listing in [
        fixture.listed_enabled(&config),
        fixture.config_enabled(&config),
    ] {
        assert!(
            !listing.iter().any(|id| id.starts_with("repro588.")),
            "{listing:?}"
        );
    }
}

#[test]
fn a_disabled_entry_must_name_a_whole_id_or_category() {
    let fixture = Fixture::new();
    // Neither entry is the pack's ID or its category: a bare string prefix,
    // a longer ID, and `core` (mandatory, and not this pack's category) must
    // all leave the pack enforcing.
    for (name, disabled) in [
        ("prefix.toml", "\"repro588.gua\", \"repro58\""),
        ("longer.toml", "\"repro588.guard.extra\""),
        ("core.toml", "\"core\""),
    ] {
        let config = fixture.config(name, &format!("disabled = [{disabled}]\n"));
        assert_all(
            fixture.verdicts(&config, GUARD_COMMAND),
            true,
            &format!("guard rule with disabled = [{disabled}]"),
        );
        assert_all(
            fixture.verdicts(&config, "git reset --hard"),
            true,
            &format!("core rule with disabled = [{disabled}]"),
        );
    }
}

#[test]
fn agent_profiles_apply_to_external_packs_in_evaluation() {
    let fixture = Fixture::new();

    // The profile's `disabled_packs` used to leave the pack in the
    // evaluation order, so it kept denying for that agent.
    let profile_disabled = fixture.config(
        "profile_disabled.toml",
        "\n[agents.claude-code]\ndisabled_packs = [\"repro588.guard\"]\n",
    );
    assert!(!fixture.hook_denies(&profile_disabled, Some("claude-code"), GUARD_COMMAND));
    assert!(fixture.hook_denies(&profile_disabled, Some("claude-code"), OTHER_COMMAND));
    assert!(fixture.hook_denies(&profile_disabled, Some("claude-code"), "git reset --hard"));

    // A profile cannot remove core protection even when it names `core`.
    let profile_core = fixture.config(
        "profile_core.toml",
        "\n[agents.claude-code]\ndisabled_packs = [\"core\"]\n",
    );
    assert!(fixture.hook_denies(&profile_core, Some("claude-code"), "git reset --hard"));
    assert!(fixture.hook_denies(&profile_core, Some("claude-code"), GUARD_COMMAND));

    // `extra_packs` puts a globally disabled pack back for that agent only,
    // as it does for built-in packs. (Another agent is named explicitly: an
    // unnamed hook may detect the agent from its process ancestry.)
    let restored = fixture.config(
        "restored.toml",
        "disabled = [\"repro588\"]\n\n[agents.claude-code]\nextra_packs = [\"repro588.guard\"]\n",
    );
    assert!(fixture.hook_denies(&restored, Some("claude-code"), GUARD_COMMAND));
    assert!(!fixture.hook_denies(&restored, Some("claude-code"), OTHER_COMMAND));
    assert!(!fixture.hook_denies(&restored, Some("codex-cli"), GUARD_COMMAND));
}

#[test]
fn with_packs_reenables_a_disabled_external_pack_for_one_test_run() {
    let fixture = Fixture::new();
    let config = fixture.config("exact.toml", "disabled = [\"repro588.guard\"]\n");
    assert!(!fixture.test_denies(&config, &[], GUARD_COMMAND));
    assert!(fixture.test_denies(&config, &["--with-packs", "repro588.guard"], GUARD_COMMAND));
}
