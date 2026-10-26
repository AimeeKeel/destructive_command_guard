//! Issue #560: interpreter source is not outer POSIX shell syntax.
//! All fixtures are classifier input only; no fixture is executed.

use std::io::Write;
use std::process::{Command, Stdio};

fn assert_decision(source: &str, expected: &str) {
    assert_decision_with_home_dirs(source, expected, &[]);
}

/// `home_dirs` are created under the isolated home first: whether a write
/// under `~` lands in an existing directory is part of the verdict.
fn assert_decision_with_home_dirs(source: &str, expected: &str, home_dirs: &[&str]) {
    for hook in [false, true] {
        let temp = tempfile::tempdir().expect("isolated working directory");
        let home = temp.path().join("home");
        std::fs::create_dir(&home).expect("isolated home");
        for dir in home_dirs {
            std::fs::create_dir_all(home.join(dir)).expect("directory under the isolated home");
        }
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

/// Shapes of quoted `python3 -` edit heredocs that agents run and 0.15.3
/// allows (#560 reopened): Markdown and Rust doc text with apostrophes,
/// backquotes and generics inside Python strings, shell text kept as data,
/// closed `subprocess.run` argument lists, and an ordinary command after the
/// heredoc. None of these bodies reaches a shell.
#[test]
fn quoted_python_edit_heredocs_followed_by_commands_are_allowed() {
    for source in [
        "python3 - <<'EOF'\ns = s.replace(a, '\\n// `model` is loaded through `#[path]`\\n')\nEOF\ncargo check",
        "python3 -I - <<'EOF'\nimport subprocess\nfrom pathlib import Path\nc = subprocess.run(['git', 'show', 'origin/main:DESIGN.md'], capture_output=True, text=True, check=True).stdout\nb = \"\"\"## Feature flags\n- The fallback path retries with the caller's `RunConfig` budget.\n\"\"\"\nPath('DESIGN.md').write_text(c.replace('## Feature flags\\n', b))\nEOF\ngit diff --stat origin/main -- DESIGN.md",
        "python3 -I - <<'PY'\nedits = [\n(\"\"\"    exit 3\n    echo \"COPY FAILED: $1 -> $DEST/$2\"\n\"\"\"),\n(\"\"\"esac\n\"\"\"),\n]\nPY",
        "cd tools && python3 -I - <<'PY'\nedits = [\n(\"\"\"    exit 3\n    echo \"COPY FAILED: $1 -> $DEST/$2\"\n\"\"\"),\n]\nPY\nbash -n copy.sh && shellcheck -S warning copy.sh; echo \"check rc=$?\"",
        "python3 -I - <<'EOF'\nimport re\nt = open('f.rs').read()\nt = t[:10] + '''/// `f_k(s)` on the reduced form, refused below the cutoff.\nfn scale_factor(mode: Mode) -> impl Fn(f64) -> Option<(f64, f64)> {\n''' + t[20:]\npattern = re.compile(r\"Some\\(Limits \\{\\s*mode: &mode_fn,\\s*\\}\\),\")\nt, n = pattern.subn(\"\"\"vec![\n        ],\"\"\", t)\nopen('f.rs', 'w').write(t)\nEOF",
        // A wrapper that runs a build tool, and a runner that starts Python
        // for pytest, are not programs that run what the heredoc printed.
        "cd crates/net && python3 -I - <<'EOF'\np = 'src/lib.rs'\ns = open(p).read()\ndef rep(old, new):\n    global s\n    assert s.count(old) == 1, old[:80]\n    s = s.replace(old, new)\nrep('''use x::LIMIT;\n''', '''use x::LIMIT;\n\n/// A pending item's wakeup can be missed under load: `poll_next`\n/// retries `recv()` on every poll.\n''')\nopen(p, 'w').write(s)\nprint('ok')\nEOF\ndevtool exec -- cargo test -p net --no-run > ../build.log 2>&1; echo build=$?; grep -E '^(error|warning)' -A6 ../build.log | head -24",
        "cat >> tests/test_spans.py <<'PYEOF'\n\ndef test_x():\n    assert True\nPYEOF\npython3 - <<'PYEOF'\nnew = \"`span_ref` (token → line spans; `origin` r2 \\\\| checked; owned by A2)\"\nprint(new)\nPYEOF\nuv run --no-project --with pytest python -m pytest -q tests/test_spans.py 2>&1 | tail -2",
        // Prose whose shell reading stops at its first line, then a later
        // script run.
        "python3 - <<'PY'\nopen('README.md', 'w').write(\"Don't run `make` here (see `docs/`).\\n\")\nPY\nsh scripts/check.sh",
    ] {
        assert_decision(source, "allow");
    }
}

/// The isolation proof is about where the body goes. Printed shell text that
/// a shell reads, a written script that a later command runs, and a program
/// that executes its own literal all stay denied.
#[test]
fn python_edit_heredocs_keep_shell_consumers_and_sinks_denied() {
    for source in [
        "python3 - <<'PY' | sh\ns = 'echo $(git reset --hard)'\nprint(s)\nPY\ncargo check",
        "python3 - <<'PY' | sh\nprint(\"git reset --hard it's\")\nPY",
        "python3 - <<'PY'\nopen('m.sh', 'w').write('echo $(git reset --hard)')\nPY\ncargo check && sh m.sh",
        "python3 -I - <<'PY'\nopen('m.sh', 'w').write('echo $(git reset --hard)')\nPY\ndevtool exec -- bash m.sh",
        "python3 -I - <<'PY'\nopen('m.sh', 'w').write('echo `git reset --hard`')\nPY\n. ./m.sh",
        "python3 - <<'PY'\nimport os\ns = \"it's `git reset --hard`\"\nos.system(s)\nPY\ncargo check",
        "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['sh', '-c', 'echo $(git reset --hard)'])\nPY",
        "python3 - <<'PY'\nimport subprocess\nrun = subprocess.run\ns = 'echo $(git reset --hard)'\nrun(s, shell=True)\nPY\ncargo check",
        // A fixed process call, or a later command, that runs the file the
        // program wrote.
        "python3 - <<'PY'\nimport subprocess\nopen('m.sh', 'w').write('echo $(git re' + 'set --hard)')\nsubprocess.run(['sh', 'm.sh'])\nPY",
        "python3 - <<'PY'\nimport subprocess\nopen('m.sh', 'w').write('echo $(git re' + 'set --hard)')\nsubprocess.run(['bash', 'm.sh'], check=True)\nPY\ncargo check",
        "python3 - <<'PY'\nimport os\nopen('m.sh', 'w').write('echo $(git re' + 'set --hard)')\nos.system('./m.sh')\nPY",
        "python3 - <<'PY'\nopen('ls', 'w').write('echo $(git re' + 'set --hard)')\nPY\nPATH=.:$PATH ls",
        // A shell runs the lines before a syntax error in the script.
        "python3 - <<'PY'\nopen('m.sh', 'w').write(\"git reset --hard\\necho it's `x`\")\nPY\nsh m.sh",
        // An empty backquote pair is no syntax error to a shell: a Markdown
        // fence around a command runs it.
        "python3 - <<'PY'\nopen('m.sh', 'w').write(\"```\\ngit re\\x73et --hard\\n```\")\nPY\nsh m.sh",
        "python3 - <<'PY'\nopen('m.sh', 'w').write('``git re\\x73et --hard``')\nPY\nsh m.sh",
        // A piece whose stray quote closes the previous piece's quote.
        "python3 - <<'PY'\nopen('m.sh', 'w').write('echo \\'x' + '\\' $(git re' + 'set --hard)')\nPY\nsh m.sh",
    ] {
        assert_decision(source, "deny");
    }
}

/// Issue #591: a quoted `cat` body written under `~` is data. A later
/// `python3 -` heredoc reads its own program, not that file, unless the
/// program can run something.
#[test]
fn quoted_note_body_followed_by_python_heredoc_is_allowed() {
    for source in [
        "cat > ~/notes/x.md <<'EOF'\na `b\nEOF\npython3 - <<'EOF'\nprint(1)\nEOF",
        "cat > ~/notes/x.md <<'EOF'\n# Note\nThe error was `Failed to fetch dynamically imported\nmodule` in the browser.\nEOF\npython3 - <<'EOF'\nfrom pathlib import Path\np = Path.home() / 'notes' / 'index.md'\nprint(p)\nEOF",
    ] {
        assert_decision_with_home_dirs(source, "allow", &["notes"]);
    }
}

#[test]
fn written_note_run_by_a_later_program_stays_denied() {
    for source in [
        "cat > ~/notes/x.sh <<'EOF'\ngit reset --hard\nEOF\npython3 - <<'EOF'\nimport subprocess\nsubprocess.run(['sh', 'x.sh'], cwd='/h/notes')\nEOF",
        "cat > ~/notes/x.sh <<'EOF'\ngit reset --hard `\nEOF\npython3 - <<'EOF'\nimport subprocess, os\nsubprocess.run(['sh', os.path.expanduser('~/notes/x.sh')])\nEOF",
        "cat > ~/notes/x.sh <<'EOF'\ngit reset --hard `\nEOF\npython3 - <<'EOF'\nprint(1)\nEOF\nsh ~/notes/x.sh",
    ] {
        assert_decision_with_home_dirs(source, "deny", &["notes"]);
    }
}
