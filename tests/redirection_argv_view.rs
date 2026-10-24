//! A redirection is never an argument. The shell removes it from the argv
//! wherever it stands: before the command word, glued to it, or after the
//! last operand. Pack rules that read argv positions saw it as a word, so a
//! redirect in one of those places hid the command from its rule. Packs now
//! also read the command's argv view, with every redirection blank-filled.
//!
//! Each destructive shape here was allowed before; each benign twin differs
//! from it only in the argv and must stay allowed.

use std::process::Command;

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, LayeredAllowlist};

/// The default pack set, read under `dialect`.
fn evaluate(command: &str, dialect: ShellDialect) -> destructive_command_guard::EvaluationResult {
    evaluate_with_packs(command, dialect, &[])
}

/// The default pack set plus `extra`, read under `dialect`.
fn evaluate_with_packs(
    command: &str,
    dialect: ShellDialect,
    extra: &[&str],
) -> destructive_command_guard::EvaluationResult {
    let config = Config::default();
    let mut enabled_packs = config.enabled_pack_ids();
    enabled_packs.extend(extra.iter().map(|pack| (*pack).to_string()));
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY
        .build_enabled_keyword_index(&ordered_packs)
        .expect("keyword index should build for enabled pack set");
    let compiled_overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let heredoc_settings = config.heredoc_settings();
    evaluate_command_with_pack_order_at_path_in_dialect(
        command,
        &enabled_keywords,
        &ordered_packs,
        Some(&keyword_index),
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
        None,
        dialect,
    )
}

/// The real binary in hook mode, with the default pack set and no ambient
/// configuration, as an agent's Bash tool call reaches it.
fn hook_decision(command: &str) -> String {
    hook_decision_for("Bash", command)
}

/// The same for a call of the named shell tool.
fn hook_decision_for(tool: &str, command: &str) -> String {
    let input = serde_json::json!({
        "tool_name": tool,
        "tool_input": { "command": command },
    });
    let sandbox = tempfile::tempdir().expect("failed to create hook sandbox");
    let root = sandbox.path();
    let mut hook = Command::new(env!("CARGO_BIN_EXE_dcg"));
    for (key, _) in std::env::vars_os() {
        if key
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("DCG_")
        {
            hook.env_remove(key);
        }
    }
    hook.current_dir(root)
        .env("HOME", root)
        .env("USERPROFILE", root)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("APPDATA", root.join("appdata"))
        .env("LOCALAPPDATA", root.join("localappdata"))
        .env("TMPDIR", root)
        .env("TEMP", root)
        .env("TMP", root)
        .env(
            "DCG_ALLOWLIST_SYSTEM_PATH",
            root.join("system-allowlist.toml"),
        )
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = hook.spawn().expect("failed to spawn dcg");
    {
        let stdin = child.stdin.take().expect("failed to open stdin");
        serde_json::to_writer(stdin, &input).expect("failed to write json");
    }
    let output = child.wait_with_output().expect("failed to wait for dcg");
    assert!(
        output.status.success(),
        "{tool} hook failed for {command:?}: status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("hook stdout must be UTF-8");
    if stdout.trim().is_empty() {
        return "allow".to_string();
    }
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("hook stdout must be JSON");
    json["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("missing")
        .to_string()
}

const DIALECTS: [ShellDialect; 2] = [ShellDialect::Posix, ShellDialect::Unknown];

fn assert_denied(commands: &[&str], pack: &str) {
    for command in commands {
        for dialect in DIALECTS {
            let result = evaluate(command, dialect);
            assert!(
                result.is_denied(),
                "{command:?} must be denied under {dialect:?}, got {result:?}"
            );
            assert_eq!(
                result
                    .pattern_info
                    .as_ref()
                    .and_then(|info| info.pack_id.as_deref()),
                Some(pack),
                "{command:?} under {dialect:?}: {result:?}"
            );
            // The finding keeps its place in the command's own text.
            if let Some(info) = result.pattern_info.as_ref()
                && let Some(span) = info.matched_span
            {
                let text = command
                    .get(span.start..span.end)
                    .expect("span lies on the command's character boundaries");
                assert_eq!(
                    info.matched_text_preview.as_deref(),
                    Some(text),
                    "{command:?} under {dialect:?}"
                );
            }
        }
        assert_eq!(
            hook_decision(command),
            "deny",
            "{command:?} through the hook"
        );
    }
}

/// The shell tool whose calls the hook evaluates in `dialect`.
fn windows_tool(dialect: ShellDialect) -> &'static str {
    match dialect {
        ShellDialect::Cmd => "cmd.exe",
        ShellDialect::PowerShell => "PowerShell",
        ShellDialect::Posix | ShellDialect::Unknown => unreachable!("Windows dialects only"),
    }
}

fn assert_denied_in(dialect: ShellDialect, commands: &[&str], pack: &str) {
    for command in commands {
        let result = evaluate(command, dialect);
        assert!(
            result.is_denied(),
            "{command:?} must be denied under {dialect:?}, got {result:?}"
        );
        assert_eq!(
            result
                .pattern_info
                .as_ref()
                .and_then(|info| info.pack_id.as_deref()),
            Some(pack),
            "{command:?} under {dialect:?}: {result:?}"
        );
        let tool = windows_tool(dialect);
        assert_eq!(
            hook_decision_for(tool, command),
            "deny",
            "{command:?} through the hook as a {tool} call"
        );
    }
}

fn assert_allowed_in(dialect: ShellDialect, commands: &[&str]) {
    for command in commands {
        let result = evaluate(command, dialect);
        assert!(
            result.is_allowed(),
            "{command:?} must stay allowed under {dialect:?}, got {result:?}"
        );
        let tool = windows_tool(dialect);
        assert_eq!(
            hook_decision_for(tool, command),
            "allow",
            "{command:?} through the hook as a {tool} call"
        );
    }
}

fn assert_allowed(commands: &[&str]) {
    for command in commands {
        for dialect in DIALECTS {
            let result = evaluate(command, dialect);
            assert!(
                result.is_allowed(),
                "{command:?} must stay allowed under {dialect:?}, got {result:?}"
            );
        }
        assert_eq!(
            hook_decision(command),
            "allow",
            "{command:?} through the hook"
        );
    }
}

#[test]
fn redirect_at_the_command_word_does_not_hide_git() {
    assert_denied(
        &[
            "git>/dev/null reset --hard",
            "\"git\">/dev/null reset --hard",
            "git>/tmp/log reset --hard",
            "git>log reset --hard",
            "git>&2 reset --hard",
            "git&>log reset --hard",
            "git</dev/null reset --hard",
            "git<<<x reset --hard",
            "git<<EOF reset --hard\nx\nEOF",
            "</dev/null git reset --hard",
            ">/dev/null git reset --hard",
            "2>/dev/null git reset --hard",
            "sudo git>/dev/null reset --hard",
            "git>/dev/null clean -fdx",
            "git>/dev/null push --force origin main",
            "echo start; git>/dev/null reset --hard",
            "git>/dev/null reset --hard # it's done",
            "ls # it's fine\ngit>/dev/null reset --hard",
            "cat <<'EOF' >notes.md\nit's fine\nEOF\ngit>/dev/null reset --hard",
            // A `#` after an expansion's `)` is part of its word, no comment.
            "echo $(date)#1; git>/dev/null reset --hard",
            "echo $((1+1))#x; git>/dev/null reset --hard",
            // So is one inside `${…}`, or after a carriage return, which is
            // no blank to the shell.
            "echo ${x:- #}; git>/dev/null reset --hard",
            "echo ${x:-${y} #}; git>/dev/null reset --hard",
            "echo a\r#b; git>/dev/null reset --hard",
        ],
        "core.git",
    );
}

#[test]
fn redirect_at_the_command_word_keeps_benign_git_allowed() {
    assert_allowed(&[
        "git>/dev/null status",
        "\"git\">/dev/null fetch",
        "git>/tmp/log log --oneline -5",
        "git</dev/null diff --stat",
        ">/dev/null git status",
        "2>/dev/null git stash list",
        "git>/dev/null reset --soft HEAD~1",
        "git>/dev/null clean -n",
        "echo 'git>/dev/null reset --hard'",
        "cat <<'EOF' >notes.md\ngit>/dev/null reset --hard is dangerous\nEOF",
        "echo $(date)#1; git>/dev/null status",
        "echo ${x:- #}; git>/dev/null status",
        "ls # git>/dev/null reset --hard",
    ]);
}

#[test]
fn trailing_redirect_does_not_hide_the_device_operand() {
    assert_denied(
        &[
            "cp x /dev/sda 2>/dev/null",
            "cp x /dev/sda >log",
            "cp x /dev/sda 2>&1",
            "cp x /dev/sda &>/dev/null",
            "cp x /dev/sda >>log",
            "cp x /dev/sda </dev/null",
            "cp x /dev/sda <<<x",
            "install x /dev/sdb 2> err.txt",
            "cp x /dev/sda 2>/dev/null; echo ok",
            "echo ${x:- #}; cp x /dev/sda 2>/dev/null",
        ],
        "system.disk",
    );
}

#[test]
fn trailing_redirect_keeps_benign_copies_allowed() {
    assert_allowed(&[
        "cp x /dev/null 2>/dev/null",
        "cp /dev/sda backup.img 2>/dev/null",
        "cp x y.img 2>/dev/null",
        "cp x ./out >log 2>&1",
        "install -m 755 x ./bin/x 2>/dev/null",
        "echo ${x:- #}; cp x y.img 2>/dev/null",
    ]);
}

/// The inline-script readers take their view of the command from the same
/// redirect blanker, so a `#` it took for a comment where the shell does not
/// also hid a redirect standing between a shell and its `-c`.
#[test]
fn shell_command_strings_after_a_non_comment_hash_are_judged() {
    for command in [
        "echo ${x:- #}; bash 2>/dev/null -c 'git reset --hard'",
        "echo $(date)#1; sh 2>&1 -c 'git reset --hard'",
    ] {
        for dialect in DIALECTS {
            let result = evaluate(command, dialect);
            assert!(
                result.is_denied(),
                "{command:?} must be denied under {dialect:?}, got {result:?}"
            );
        }
        assert_eq!(
            hook_decision(command),
            "deny",
            "{command:?} through the hook"
        );
    }
    assert_allowed(&["echo ${x:- #}; bash 2>/dev/null -c 'ls -la'"]);
}

/// Cmd and PowerShell take a redirection out of the argv wherever it stands
/// too, so each has an argv view of its own, built with its own syntax.
#[test]
fn windows_redirect_at_the_command_word_does_not_hide_git() {
    assert_denied_in(
        ShellDialect::Cmd,
        &[
            "git>nul reset --hard",
            "git>log.txt reset --hard",
            "git>>log.txt reset --hard",
            "git<nul reset --hard",
            "git>\"x y.txt\" reset --hard",
            "git>nul 2>&1 reset --hard",
            "@git>nul reset --hard",
            "(git>nul reset --hard)",
            "git.exe>nul reset --hard",
            "git>nul reset --hard & echo ok",
            "git>nul clean -fdx",
        ],
        "core.git",
    );
    assert_denied_in(
        ShellDialect::PowerShell,
        &[
            "git>$null reset --hard",
            "git>nul reset --hard",
            "git>>log.txt reset --hard",
            ">$null git reset --hard",
            "& git>$null reset --hard",
            "git.exe>$null reset --hard",
            "git>$null push --force origin main",
            "git>$null clean -fdx",
        ],
        "core.git",
    );
}

#[test]
fn windows_redirect_at_the_command_word_keeps_benign_git_allowed() {
    assert_allowed_in(
        ShellDialect::Cmd,
        &[
            "git>nul status",
            "git>nul fetch origin",
            "git>nul reset --soft HEAD~1",
            "git log --oneline -5 >log.txt 2>&1",
            "git status >nul 2>&1 && echo clean",
            "echo git>nul reset --hard",
            "echo git^>nul reset --hard",
            "echo \"git>nul reset --hard\"",
            "findstr /c:\"a>b\" file.txt",
        ],
    );
    assert_allowed_in(
        ShellDialect::PowerShell,
        &[
            "git>$null status",
            "git>$null fetch origin",
            "git>$null reset --soft HEAD~1",
            "git log --oneline -5 > log.txt",
            "Write-Output 'git>$null reset --hard'",
            "Write-Output \"a>b\" > out.txt",
            "Set-Content -Path notes.md -Value 'git>$null reset --hard'",
            "$x = 5; if ($x -gt 3) { Write-Output big > out.txt }",
        ],
    );
}

/// The argv view blanks the heredocs and input redirections that feed a
/// command, but where its input comes from is still read from the full
/// command: a client whose verified input the view leaves out must not be
/// refused for want of it, and a destructive payload must still be denied.
#[test]
fn argv_view_keeps_each_commands_input() {
    let packs = ["database.postgresql", "database.redis"];
    for command in [
        "cat <<'SQL' | psql app >out.log\nSELECT 1;\nSQL",
        "cat <<'SQL' | psql app 2>&1\nSELECT 1;\nSQL",
        "cat <<'EOF' | redis-cli >/dev/null\nGET account:1\nEOF",
        "psql app >out.log <<'SQL'\nSELECT 1;\nSQL",
    ] {
        for dialect in DIALECTS {
            let result = evaluate_with_packs(command, dialect, &packs);
            assert!(
                result.is_allowed(),
                "{command:?} must stay allowed under {dialect:?}, got {result:?}"
            );
        }
    }
    for command in [
        "cat <<'SQL' | psql app >out.log\nDROP TABLE users;\nSQL",
        "cat <<'EOF' | redis-cli >/dev/null\nFLUSHALL\nEOF",
    ] {
        for dialect in DIALECTS {
            let result = evaluate_with_packs(command, dialect, &packs);
            assert!(
                result.is_denied(),
                "{command:?} must be denied under {dialect:?}, got {result:?}"
            );
        }
    }
}

/// Neither Cmd nor PowerShell has a `<<` operator, and PowerShell has no
/// input redirection at all, so their argv views leave such words as written.
/// The full reading takes `<<` for the POSIX heredoc it spells, whose body is
/// data to a reader; blanking the operator left that body behind as command
/// text. The unknown dialect replays Cmd and PowerShell readings of POSIX
/// text, so a heredoc of notes met those views there as well.
#[test]
fn windows_argv_views_keep_posix_heredocs_as_data() {
    let readers = [
        "cat <<EOF\nrm -rf /home/user\nEOF",
        "git commit -F - <<'EOF'\ndocs: note that rm -rf /tmp/x is denied\nEOF",
        "tee /private/tmp/sink.md <<'EOF'\n`rm -rf ~/foo`\nEOF\n",
        "tee /private/tmp/sink.md <<-'EOF'\n\t`rm -rf ~/foo`\n\tEOF\n",
    ];
    assert_allowed_in(ShellDialect::Cmd, &readers);
    assert_allowed_in(ShellDialect::PowerShell, &readers);
    for command in &readers[2..] {
        let result = evaluate(command, ShellDialect::Unknown);
        assert!(
            result.is_allowed(),
            "{command:?} must stay allowed under Unknown, got {result:?}"
        );
    }
    assert_allowed_in(ShellDialect::PowerShell, &["rm -ri ./tree <> /etc/passwd"]);
    // A heredoc fed to a shell is still read as that shell's source.
    let result = evaluate("bash <<'EOF'\nrm -rf ~/x\nEOF", ShellDialect::Unknown);
    assert!(result.is_denied(), "got {result:?}");
}
