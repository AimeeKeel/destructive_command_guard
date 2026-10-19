//! Regressions for #442: a Unicode scalar reached libc's byte-only isdigit
//! through tree-sitter-bash's brace-range scanner. Keep the actual ast-grep
//! entry point, original UTF-8, parser-cache reuse, and concurrent threads.

use ast_grep_core::AstGrep;
use ast_grep_language::SupportLang;

fn corpus() -> Vec<String> {
    let mut inputs = vec![
        "echo {1..9}".to_owned(),
        "echo {12..34}".to_owned(),
        "echo {1..".to_owned(),
        "cat <<EOF\nhello\nEOF\n".to_owned(),
    ];
    for cp in [
        0x100,
        0x130,
        0x660,
        0xff10,
        0x1f4a5,
        0x0010_fffd,
        0x0010_ffff,
    ] {
        let c = char::from_u32(cp).expect("valid Unicode scalar");
        for range in [
            format!("{{{c}..9}}"),
            format!("{{1{c}..9}}"),
            format!("{{1..{c}}}"),
            format!("{{1..2{c}}}"),
            format!("{{{c}"),
        ] {
            inputs.push(format!("echo {range}; rm -rf /"));
            inputs.push(format!("bash -c 'echo {range}; rm -rf /'"));
            inputs.push(format!("cat <<EOF\necho {range}\nEOF\nrm -rf /"));
        }
    }
    inputs
}

fn parse_corpus(inputs: &[String]) {
    for input in inputs {
        let ast = AstGrep::new(input, SupportLang::Bash);
        let root = ast.root();
        assert_eq!(
            root.text(),
            input.as_str(),
            "source bytes changed: {input:?}"
        );
        if input.ends_with("; rm -rf /") {
            assert!(
                root.find("rm -rf /").is_some(),
                "destructive command disappeared after Unicode brace: {input:?}"
            );
        }
    }
}

#[test]
fn bash_unicode_braces_preserve_source_and_destructive_commands() {
    let inputs = corpus();
    for _ in 0..8 {
        parse_corpus(&inputs);
    }
}

#[test]
fn bash_unicode_braces_are_safe_with_concurrent_cached_parsers() {
    let inputs = corpus();
    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                barrier.wait();
                for _ in 0..16 {
                    parse_corpus(&inputs);
                }
            });
        }
    });
}

#[test]
fn stdin_data_does_not_borrow_program_source_proof_560() {
    use crate::heredoc::{mask_inert_interpreter_stdin, range_is_inert_interpreter_stdin};
    for header in [
        "python3 -c 'import os,sys; os.system(sys.stdin.read())' <<'DCG_STDIN'",
        "python3 <<'DCG_STDIN' -c 'import os,sys; os.system(sys.stdin.read())'",
        "python3 script.py <<'DCG_STDIN'",
        "python3 <<'DCG_STDIN' script.py",
        "node -e 'process.stdin.on(\"data\", console.log)' <<'DCG_STDIN'",
        "node <<'DCG_STDIN' -e 'process.stdin.on(\"data\", console.log)'",
        "node <<'DCG_STDIN' script.js",
        "ruby <<'DCG_STDIN' -e 'puts STDIN.read'",
        "perl <<'DCG_STDIN' -e 'print <STDIN>'",
        "php <<'DCG_STDIN' -r 'echo stream_get_contents(STDIN);'",
    ] {
        for body in ["git reset --hard", "print('quoted shell-looking data')"] {
            let command = format!("{header}\n{body}\nDCG_STDIN");
            let range = header.len() + 1..header.len() + 1 + body.len();
            assert!(
                !range_is_inert_interpreter_stdin(&command, &range),
                "{header}"
            );
            assert_eq!(
                mask_inert_interpreter_stdin(&command).as_ref(),
                command,
                "{header}"
            );
        }
    }
}

#[test]
fn program_stdin_preserves_outer_shell_boundaries_560() {
    use crate::heredoc::{mask_inert_interpreter_stdin, range_is_inert_interpreter_stdin};
    for (header, body) in [
        (
            "python3 - <<'DCG_STDIN'",
            "print('literal shell-like text')",
        ),
        (
            "node - <<'DCG_STDIN'",
            "console.log('literal shell-like text');",
        ),
    ] {
        let command = format!("{header}\n{body}\nDCG_STDIN\ngit status");
        let range = header.len() + 1..header.len() + 1 + body.len();
        assert!(
            range_is_inert_interpreter_stdin(&command, &range),
            "{header}"
        );
        let masked = mask_inert_interpreter_stdin(&command);
        assert_eq!(masked.len(), command.len());
        assert_eq!(&masked[..range.start], &command[..range.start]);
        assert_eq!(&masked[range.end..], &command[range.end..]);
    }
}
