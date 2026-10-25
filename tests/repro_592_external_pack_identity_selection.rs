//! Issue #592: an external pack keyed on a program name was skipped when that
//! program was not spelled out in the command text, so none of its rules ran.
//!
//! External packs are selected by their keywords, and the keyword gate reads
//! text. A program named by a variable, a command substitution, a glob, an
//! expansion inside the word, or behind a launcher with quotes inside its
//! operand never showed the keyword, and the command was allowed without the
//! pack being consulted. Pre-selection now resolves each segment's program
//! with the shared wrapper stripping and quote removal, and evaluates every
//! enabled external pack when some segment's program cannot be resolved. In a
//! shell known to be POSIX, a quoted or escaped plain word after the program
//! is read without its quotes, so a rule or keyword naming a subcommand sees
//! it too.
//!
//! Every pack and command here is synthetic: `frobtool` and its `zap`
//! subcommand do not exist. Commands are classified by the real binary, never
//! executed.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Keyed on the program name; its one rule reads only the subcommand, so it
/// fires exactly when the pack is selected for a command that says `zap`.
const PROGRAM_KEYED_PACK: &str = r"schema_version: 1
id: synthetic.frob
name: Synthetic program-keyed pack
version: 1.0.0
keywords:
  - frobtool
destructive_patterns:
  - name: zap-subcommand
    pattern: \bzap\b
    severity: critical
    description: synthetic rule on a made-up subcommand
";

/// Keyed on the subcommand; its rule spells the program and the subcommand.
const SUBCOMMAND_KEYED_PACK: &str = r"schema_version: 1
id: synthetic.zapall
name: Synthetic subcommand-keyed pack
version: 1.0.0
keywords:
  - zapall
destructive_patterns:
  - name: frobtool-zapall
    pattern: \bfrobtool\s+zapall\b
    severity: critical
    description: synthetic rule naming a made-up program and subcommand
";

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
}

impl Fixture {
    fn new(pack: &str) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().to_path_buf();
        let pack_path = root.join("pack.yaml");
        fs::write(&pack_path, pack).expect("write pack");
        let config = root.join("config.toml");
        fs::write(
            &config,
            format!(
                "[packs]\ncustom_paths = [{}]\n",
                serde_json::to_string(&pack_path).expect("pack path")
            ),
        )
        .expect("write config");
        fs::create_dir_all(root.join("cwd")).expect("cwd");
        Self {
            _dir: dir,
            root,
            config,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("xdg"))
            .env("DCG_CONFIG", &self.config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_HISTORY_DISABLED", "1")
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.root.join("pending.jsonl"),
            )
            .current_dir(self.root.join("cwd"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// `(decision, rule_id)` from `dcg test` in `dialect`.
    fn classify(&self, command: &str, dialect: &str) -> (String, String) {
        let mut child = self
            .command()
            .args(["test", "--stdin", "--dialect", dialect, "--format", "json"])
            .spawn()
            .expect("spawn dcg test");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(command.as_bytes())
            .expect("write command");
        let output = child.wait_with_output().expect("dcg test output");
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
                panic!(
                    "dcg test JSON for {command:?}: {err}: {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        (
            json["decision"].as_str().unwrap_or_default().to_string(),
            json["rule_id"].as_str().unwrap_or_default().to_string(),
        )
    }

    /// Whether the hook (a Bash tool payload, so POSIX) denies `command`.
    fn hook_denies(&self, command: &str) -> bool {
        let payload = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}})
            .to_string();
        let mut child = self
            .command()
            .args(["--agent", "claude-code"])
            .spawn()
            .expect("spawn dcg hook");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.as_bytes())
            .expect("write payload");
        let output = child.wait_with_output().expect("hook output");
        String::from_utf8_lossy(&output.stdout).contains("\"permissionDecision\":\"deny\"")
    }
}

fn assert_all(fixture: &Fixture, rows: &[(&str, &str)], expected: (&str, &str)) {
    assert_in(fixture, &["posix", "unknown"], rows, expected);
}

fn assert_in(fixture: &Fixture, dialects: &[&str], rows: &[(&str, &str)], expected: (&str, &str)) {
    let mut failures = Vec::new();
    for &dialect in dialects {
        for (category, command) in rows {
            let got = fixture.classify(command, dialect);
            if (got.0.as_str(), got.1.as_str()) != expected {
                failures.push(format!("[{dialect}] {category}: {command:?} -> {got:?}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "expected {expected:?} for every row:\n{}",
        failures.join("\n")
    );
}

const DENIED: (&str, &str) = ("deny", "synthetic.frob:zap-subcommand");
const ALLOWED: (&str, &str) = ("allow", "");

#[test]
#[allow(clippy::literal_string_with_formatting_args)] // shell `${…}`, not a format
fn program_words_the_text_does_not_spell_select_the_external_pack() {
    let fixture = Fixture::new(PROGRAM_KEYED_PACK);
    let rows = [
        ("variable", "$F zap"),
        ("variable", "${F} zap"),
        ("variable", "\"$F\" zap"),
        ("variable", "${F:-frobtool} zap"),
        ("variable", "F=frobtool && $F zap"),
        ("variable", "export F=frobtool; $F zap"),
        ("command substitution", "$(printf %s frob tool) zap"),
        ("command substitution", "frob$(echo tool) zap"),
        ("expansion inside the word", "frob${EMPTY}tool zap"),
        ("expansion inside the word", "frob${x:0:0}tool zap"),
        ("expansion inside the word", "frob${x:+}tool zap"),
        ("expansion inside the word", "frob$@tool zap"),
        ("expansion inside the word", "frob\"$@\"tool zap"),
        ("expansion inside the word", "frob$()tool zap"),
        ("expansion inside the word", "frob``tool zap"),
        ("locale quoting", "$\"frobtool\" zap"),
        ("glob", "frobtoo[l] zap"),
        ("glob", "frob?ool zap"),
        ("glob", "/usr/local/bin/frob*ool zap"),
        ("glob", "frob[[:alpha:]]ool zap"),
        ("brace expansion", "frobtoo{l,} zap"),
        ("extended glob", "frob+(t)ool zap"),
        ("extended glob", "frob@(t|x)ool zap"),
        ("extended glob", "frobtoo!(x)l zap"),
        ("zsh alternation", "frob(t|x)ool zap"),
        ("heredoc run by a shell", "bash <<EOF\n$F zap\nEOF"),
        ("compound", "true && $F zap"),
        ("compound", "x | $F zap"),
        ("compound", "if true; then $F zap; fi"),
        ("compound", "( frobtoo[l] zap )"),
    ];
    assert_all(&fixture, &rows, DENIED);
}

#[test]
fn programs_behind_wrappers_and_launchers_select_the_external_pack() {
    let fixture = Fixture::new(PROGRAM_KEYED_PACK);
    let rows = [
        ("stripped wrapper", "sudo $F zap"),
        ("stripped wrapper", "env X=1 $F zap"),
        ("stripped wrapper", "nice -n 5 frobtoo[l] zap"),
        ("stripped wrapper", "timeout 5 frob${x:0:0}tool zap"),
        ("stripped wrapper", "command $F zap"),
        ("wrapper left in place", "nice --unmodeled $F zap"),
        ("wrapper left in place", "sudo -p prompt $F zap"),
        ("wrapper left in place", "builtin command $F zap"),
        ("option where the program goes", "time --unmodeled $F zap"),
        // A program word whose second byte is an option letter of `time`
        // (`-fFORMAT`, `-oFILE`) is still the program.
        ("stripped wrapper", "time /opt/bin/frobtool zap"),
        ("stripped wrapper", "time -o t.txt /fs/frobtool zap"),
        ("stripped wrapper", "time -f%E /opt/frob''tool zap"),
        ("launcher", "xargs $F zap"),
        ("launcher", "xargs frob''tool zap"),
        ("launcher", "xargs fr\\obtool zap"),
        ("launcher", "echo a | xargs -n1 frob\"tool\" zap"),
        ("launcher", "find . -exec $F zap {} +"),
        ("launcher", "find . -exec 'frob'tool zap {} \\;"),
        ("launcher", "flock /tmp/l $F zap"),
        ("launcher", "watch -n 1 frob?ool zap"),
        ("launcher through a wrapper", "xargs sudo $F zap"),
        ("launcher through a wrapper", "sudo xargs frob''tool zap"),
        (
            "assignment does not reach its own word",
            "F=frobtool xargs $F zap",
        ),
    ];
    assert_all(&fixture, &rows, DENIED);
}

#[test]
fn argument_text_and_known_programs_keep_the_pack_unselected() {
    let fixture = Fixture::new(PROGRAM_KEYED_PACK);
    let rows = [
        // Argument text stays argument text: the program is `echo`, `grep`.
        ("argument text", "echo frobtool zap"),
        ("argument text", "echo \"$F zap\""),
        ("argument text", "grep -r 'frobtool zap' ."),
        ("argument text", "git commit -m \"frobtool zap\""),
        ("argument text", "ls zap"),
        // A known program that is not the pack's.
        ("other program", "ls $DIR zap"),
        ("other program", "\"/usr/bin/ls\" zap"),
        ("other program", "l''s zap"),
        ("other program", "xargs ls zap"),
        // Parentheses that are not a pattern attached to a word.
        ("function definition", "f() { ls zap; }"),
        ("substitution", "echo $(ls zap)"),
        ("process substitution", "diff <(ls) <(ls zap)"),
        ("array", "arr=(a zap) && ls"),
        ("heredoc data", "cat <<'EOF'\nprint(zap(1))\nEOF"),
        ("quoted", "python3 -c \"print(zap)\""),
        // Selected, but the rule does not match: selection decides nothing.
        ("selected, no match", "frobtool status"),
        ("selected, no match", "$EDITOR notes.txt"),
        ("selected, no match", "frob*ool status"),
    ];
    assert_all(&fixture, &rows, ALLOWED);
}

#[test]
fn quoted_and_escaped_plain_words_reach_rules_and_keywords() {
    let fixture = Fixture::new(SUBCOMMAND_KEYED_PACK);
    let denied = ("deny", "synthetic.zapall:frobtool-zapall");
    let rows = [
        ("plain", "frobtool zapall"),
        (
            "quoted Windows path",
            "\"C:\\Program Files\\frobtool.exe\" zapall",
        ),
    ];
    assert_all(&fixture, &rows, denied);

    // The shell removes quotes and escapes inside a word. Read that way only
    // where the shell is known to be POSIX.
    let rows = [
        ("quotes inside the word", "frobtool zap''all"),
        ("quotes inside the word", "frobtool \"zap\"all"),
        ("quotes inside the word", "frobtool z\"a\"pall"),
        ("quotes inside the word", "frobtool 'zap'\"all\""),
        ("escape inside the word", "frobtool zap\\all"),
        ("behind a wrapper", "sudo frobtool zap''all"),
        ("behind a launcher", "xargs fr''obtool zapall"),
        ("behind a launcher", "xargs frobtool zap\\all"),
        ("compound", "true && frobtool zap''all"),
    ];
    assert_in(&fixture, &["posix"], &rows, denied);
    // Elsewhere a backslash may separate the words of a Windows path, which
    // stay apart.
    let rows = [("Windows path", "C:\\Program Files\\frobtool zapall")];
    assert_in(&fixture, &["unknown"], &rows, denied);

    let rows = [
        // `echo` arguments are data, and are left exactly as written.
        ("data argument", "echo frobtool zap''all"),
        // Not one plain word once unquoted.
        ("not a plain word", "frobtool \"zap all\""),
        ("not a plain word", "frobtool \"$X\"all"),
        ("different word", "frobtool zap''al"),
    ];
    assert_all(&fixture, &rows, ALLOWED);
}

#[test]
fn the_hook_selects_the_pack_for_unresolved_programs() {
    let fixture = Fixture::new(PROGRAM_KEYED_PACK);
    for command in [
        "$F zap",
        "frob${x:0:0}tool zap",
        "frobtoo[l] zap",
        "xargs frob''tool zap",
        "sudo $(printf %s frob tool) zap",
    ] {
        assert!(fixture.hook_denies(command), "hook must deny {command:?}");
    }
    for command in ["echo frobtool zap", "frobtool status", "ls zap"] {
        assert!(!fixture.hook_denies(command), "hook must allow {command:?}");
    }
}

/// The fixtures are self-describing; keep the pack files honest.
#[test]
fn synthetic_packs_validate() {
    for pack in [PROGRAM_KEYED_PACK, SUBCOMMAND_KEYED_PACK] {
        let fixture = Fixture::new(pack);
        let path: &Path = &fixture.root.join("pack.yaml");
        let output = fixture
            .command()
            .args(["pack", "validate"])
            .arg(path)
            .output()
            .expect("dcg pack validate");
        assert!(
            output.status.success(),
            "synthetic pack must validate: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
