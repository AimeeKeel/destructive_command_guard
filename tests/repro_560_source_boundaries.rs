//! Issue #560: interpreter source is not outer POSIX shell syntax.
//! All fixtures are classifier input only; no fixture is executed.

use std::io::Write;
use std::process::{Command, Stdio};

fn assert_decision(source: &str, expected: &str) {
    for hook in [false, true] {
        let temp = tempfile::tempdir().expect("isolated working directory");
        let home = temp.path().join("home");
        std::fs::create_dir(&home).expect("isolated home");
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
        let input = if hook {
            command.args(["hook", "--batch"]);
            serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": source},
            })
            .to_string()
        } else {
            command.args(["test", "--stdin", "--dialect", "posix", "--format", "json"]);
            source.to_string()
        };
        let mut child = command
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_NO_SELF_HEAL", "1")
            .env("DCG_HISTORY_ENABLED", "false")
            // Semantic tests use the existing #412/#438 test envelopes.
            // Production budgets remain unchanged; performance requires a
            // separate replay without these test-only timeout overrides.
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .env("DCG_AST_TIMEOUT_MS", "5000")
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn classifier");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input.as_bytes())
            .expect("write classifier input");
        let output = child.wait_with_output().expect("wait for classifier");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let verdict: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!("hook={hook}, {error}; stdout={stdout}; stderr={stderr}")
        });
        assert_eq!(
            verdict["decision"].as_str(),
            Some(expected),
            "hook={hook}, source={source:?}, status={}, verdict={verdict}, stderr={stderr}",
            output.status
        );
    }
}

#[test]
fn quoted_interpreter_source_does_not_acquire_posix_quote_state() {
    for source in [
        "python3 - <<'EOF'\nimport re\ns = re.sub(r'x$', \"it's `tool --help`\", 'x')\nEOF",
        "python3 - <<'EOF'\nimport re\ns = re.sub(r'x$', \"it's Vec<(&'static str, usize)>\", 'x')\nEOF",
        "node - <<'JS'\nconst pattern = /x$/;\nconst text = \"it's `tool --help`\";\nconsole.log(text.replace(pattern, 'x'));\nJS",
        "node - <<'JS'\nconst text = \"Vec<(&'static str, usize)>\";\nconsole.log(text);\nJS",
    ] {
        assert_decision(source, "allow");
    }
}

#[test]
fn quoted_delimiter_spellings_preserve_the_same_source_boundary() {
    for delimiter in ["'EOF'", "\"EOF\"", "E'OF'", "E\\OF"] {
        let source = format!(
            "python3 - <<{delimiter}\nimport re\ns = re.sub(r'x$', \"it's `tool --help`\", 'x')\nEOF"
        );
        assert_decision(&source, "allow");
    }
    assert_decision(
        "python3 - <<-'EOF'\n\timport re\n\ts = re.sub(r'x$', \"it's `tool --help`\", 'x')\n\tEOF",
        "allow",
    );
}

#[test]
fn interpreter_execution_sinks_remain_blocked() {
    for source in [
        "python3 - <<'PY'\nimport shutil\nshutil.rmtree('/etc')\nPY",
        "python3 - <<'PY'\nimport os\nos.system('git reset --hard')\nPY",
        "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['git', 'reset', '--hard'])\nPY",
        "python3 - <<'PY'\nimport os\ncommand = 'echo $(git reset --hard)'\nos.system(command)\nPY",
        "node - <<'JS'\nrequire('child_process').execSync('git reset --hard');\nJS",
        "node - <<'JS'\nrequire('fs').rmSync('/etc', {recursive:true, force:true});\nJS",
    ] {
        assert_decision(source, "deny");
    }
}

#[test]
fn shell_consumers_and_unquoted_expansions_remain_blocked() {
    for source in [
        "bash <<'SH'\ngit reset --hard\nSH",
        "cat <<'SH' | sh\ngit reset --hard\nSH",
        "cat <<EOF\n$(git reset --hard)\nEOF",
        "python3 - <<PY\nprint('$(git reset --hard)')\nPY",
        "python3 -c 'import os,sys; os.system(sys.stdin.read())' <<'EOF'\ngit reset --hard\nEOF",
        "python3(){ sh; }; python3 - <<'EOF'\ngit reset --hard\nEOF",
        "python3 - <<'EOF'\nprint('safe')\nEOF\ngit reset --hard",
        "git reset --hard; python3 - <<'EOF'\nprint('safe')\nEOF",
    ] {
        assert_decision(source, "deny");
    }
}

/// Keep each source below the byte/node caps while crossing the 128-literal
/// boundary. Escaped newlines trigger literal analysis even with no raw shell
/// substitution markers; the classifier must decode them as ordinary data.
fn literal_heavy_source(interpreter: &str, count: usize, tail: &str) -> String {
    let mut source = format!("{interpreter} - <<'DCG_LITERAL_560'\n");
    for index in 0..count {
        let statement = match interpreter {
            "python3" => format!("value_{index} = 'entry_{index}\\n'\n"),
            "node" => format!("const value_{index} = 'entry_{index}\\n';\n"),
            _ => panic!("unsupported test interpreter"),
        };
        source.push_str(&statement);
    }
    source.push_str(tail);
    source.push_str("\nDCG_LITERAL_560");
    source
}

#[test]
fn plain_literal_programs_cross_the_candidate_boundary_without_becoming_indeterminate() {
    for interpreter in ["python3", "node"] {
        for count in [127, 128, 129, 160] {
            assert_decision(&literal_heavy_source(interpreter, count, ""), "allow");
        }
    }
}

#[test]
fn literal_heavy_programs_retain_execution_and_protected_write_denials() {
    for (interpreter, tail) in [
        ("python3", "import os\nos.system('git reset --hard')"),
        (
            "python3",
            "import os\ncommand = 'echo $(git reset --hard)'\nos.system(command)",
        ),
        (
            "python3",
            "import os\ncommand = 'echo \\x24\\x28git reset --hard)'\nos.system(command)",
        ),
        ("python3", "import shutil\nshutil.rmtree('/etc')"),
        ("python3", "open('/etc/shadow', 'w').write('x')"),
        (
            "node",
            "require('child_process').execSync('git reset --hard');",
        ),
        (
            "node",
            "const command = 'echo $(git reset --hard)'; require('child_process').execSync(command);",
        ),
        (
            "node",
            "const command = 'echo \\u0024\\u0028git reset --hard)'; require('child_process').execSync(command);",
        ),
        (
            "node",
            "require('fs').rmSync('/etc', {recursive:true, force:true});",
        ),
        ("node", "require('fs').writeFileSync('/etc/shadow', 'x');"),
    ] {
        assert_decision(&literal_heavy_source(interpreter, 160, tail), "deny");
    }
}

#[test]
fn literal_heavy_programs_do_not_hide_following_shell_commands() {
    for interpreter in ["python3", "node"] {
        let mut source = literal_heavy_source(interpreter, 160, "");
        source.push_str("\ngit reset --hard");
        assert_decision(&source, "deny");
    }
}

#[test]
fn quoted_javascript_regex_text_edits_keep_literal_data() {
    for source in [
        "node - <<'JS'\nconst text = 'x'.replace(/x$/, \"it's `tool --help`\"); console.log(text);\nJS",
        "node - <<'JS'\nconst text = 'xx'.replaceAll(/x/g, '$(git reset --hard)'); console.log(text);\nJS",
        "node - <<'JS'\nconst pattern = /x/; const alias = pattern; const text = 'x'.replace(alias, '`git reset --hard`'); console.log(text);\nJS",
        "node - <<'JS'\nconst note = 'élève'; const pattern = /`git reset --hard`/g; const text = 'x'.replace(pattern, 'y'); console.log(text);\nJS",
    ] {
        assert_decision(source, "allow");
    }
}

#[test]
fn regex_edits_do_not_hide_executable_interpreter_work() {
    for source in [
        "node - <<'JS'\nconst text = 'x'.replace(/x/, () => require('child_process').execSync('git reset --hard'));\nJS",
        "node - <<'JS'\nconst text = 'x'.replace(/x/, 'echo $(git reset --hard)'); require('child_process').execSync(text);\nJS",
        "node - <<'JS'\nconst pattern = /x/; pattern[Symbol.replace] = () => require('child_process').execSync('git reset --hard'); 'x'.replace(pattern, 'text');\nJS",
        "node - <<'JS'\nconst fs = require('node:fs'); const text = 'x'.replace(/x/, '`git reset --hard`'); fs.writeFileSync('/etc/shadow', text);\nJS",
        "node - <<'JS'\nconst fs = require('node:fs'); const text = 'x'.replace(/x/, '`git reset --hard`'); fs.writeFileSync('.git/config', text);\nJS",
    ] {
        assert_decision(source, "deny");
    }
}

#[test]
fn regex_edit_data_does_not_suppress_outer_shell_execution() {
    for source in [
        "node - <<JS\nconst text = 'x'.replace(/x/, '$(git reset --hard)'); console.log(text);\nJS",
        "node - <<'JS' | sh\nconst text = 'x'.replace(/x/, 'echo $(git reset --hard)'); console.log(text);\nJS",
        "node - <<'JS'\nconst text = 'x'.replace(/x/, 'data'); console.log(text);\nJS\ngit reset --hard",
    ] {
        assert_decision(source, "deny");
    }
}

#[test]
fn tuples_and_text_helpers_do_not_promote_literal_data_to_shell() {
    for source in [
        "python3 - <<'PY'\ny = ('x', \"it's `tool --help`\")\nPY",
        "python3 - <<'PY'\ny = f('x', \"it's `tool --help`\")\nPY",
        "python3 - <<'PY'\nrep('''use core::fav;\n    fn with_store<R>(\n    /// The items `zone` belongs to (`list_items`).''')\nPY",
        "python3 - <<'PY'\nimport re\ns = re.match(r'x$', \"it's `tool --help`\")\nPY",
        "python3 - <<'PY'\nold = ''\nnew = ('echo $(date)\\n' '(task >\"$W/out.log\")\\n' + old)\nPY",
        "node - <<'JS'\nedit(\"it's `tool --help`\");\nJS",
        "node - <<'JS'\nconst pieces = ['x', \"it's `tool --help`\"];\nJS",
        "node - <<'JS'\nrep('fn with_store<R>( `zone`');\nJS",
    ] {
        assert_decision(source, "allow");
    }
}

#[test]
fn aliased_and_local_execution_helpers_retain_destructive_literals() {
    for source in [
        "python3 - <<'PY'\nfrom os import system as edit\ntext = 'echo $(git reset --hard)'\nedit(text)\nPY",
        "python3 - <<'PY'\nimport os\ndef edit(text):\n    os.system(text)\nedit('echo $(git reset --hard)')\nPY",
        "python3 - <<'PY'\nimport os\nedit = getattr(os, 'sys' + 'tem')\ntext = 'echo $(git reset --hard)'\nedit(text)\nPY",
        "node - <<'JS'\nconst cp = require('child_process'); const edit = cp.execSync; const text = 'echo $(git reset --hard)'; edit(text);\nJS",
        "node - <<'JS'\nconst cp = require('child_process'); function edit(text) { cp.execSync(text); } edit('echo $(git reset --hard)');\nJS",
        "node - <<'JS'\nconst cp = require('child_process'); const edit = cp['exe' + 'cSync']; const text = 'echo $(git reset --hard)'; edit(text);\nJS",
    ] {
        assert_decision(source, "deny");
    }
}

#[test]
fn known_shell_values_keep_non_substitution_grammar() {
    for source in [
        "python3 - <<'PY'\nimport os\ntext = 'echo $(date); git reset --hard'\nos.system(text)\nPY",
        "python3 - <<'PY'\nimport os\ntext = 'echo $(date); (task >\"$W/out.log\")'\nos.system(text)\nPY",
        "node - <<'JS'\nconst cp = require('child_process'); const text = 'echo $(date); git reset --hard'; cp.execSync(text);\nJS",
        "node - <<'JS'\nconst cp = require('child_process'); const text = 'echo $(date); (task >\"$W/out.log\")'; cp.execSync(text);\nJS",
    ] {
        assert_decision(source, "deny");
    }
}

#[test]
fn many_inert_shell_looking_literals_do_not_exhaust_recovery_budget() {
    for interpreter in ["python3", "node"] {
        let mut source = format!("{interpreter} - <<'LITERAL_DATA'\n");
        for index in 0..160 {
            use std::fmt::Write as _;
            let declaration = if interpreter == "node" { "const " } else { "" };
            writeln!(
                source,
                "{declaration}item_{index} = \"it's `tool --help` $(date)\";"
            )
            .expect("writing to a String cannot fail");
        }
        source.push_str("LITERAL_DATA");
        assert_decision(&source, "allow");
    }
}
