//! IFS-sensitive writer arguments must reach the native destination policy.
//!
//! This is an additional, bounded view of argv, not executable shell source.
//! It never executes a command, opens a path, or exempts the original source.

use super::{CredentialFileWrite, shell};
use crate::normalize::{NormalizeTokenKind, ShellDialect, strip_wrapper_prefixes};
use ast_grep_core::{AstGrep, Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use std::collections::HashMap;
use std::ops::Range;

#[cfg(test)]
const DEFAULT_IFS: &str = " \t\n";
const MAX_BYTES: usize = 64 * 1024;
const MAX_VALUE_BYTES: usize = 16 * 1024;
const MAX_FIELDS: usize = 128;
const MAX_EVENTS: usize = 256;
const MAX_BINDINGS: usize = 64;
const UNCERTAIN: &str = "Cannot verify writer destinations after an IFS change: an expansion, shell mutation, or analysis limit prevents bounded literal arguments. Quote scalar destinations or provide explicit arguments for review.";

#[derive(Default)]
struct State {
    values: HashMap<String, String>,
    ifs: Option<String>,
    changed: bool,
    attributes_unknown: bool,
}

impl State {
    fn forget(&mut self) {
        self.values.clear();
        self.ifs = None;
        self.changed = true;
    }

    fn value(&self, name: &str) -> Option<&str> {
        if name == "IFS" {
            self.ifs.as_deref()
        } else {
            self.values.get(name).map(String::as_str)
        }
    }

    fn assign(&mut self, raw: &str, certain: bool) {
        let Some((name, append, rhs)) = assignment(raw) else {
            self.forget();
            return;
        };
        let mut value = literal(rhs).or_else(|| {
            scalar(rhs).and_then(|(dependency, _)| self.value(dependency).map(str::to_owned))
        });
        if value.is_none() && scalar(rhs).is_none() {
            // Complex expansions can assign other variables while evaluating
            // an otherwise ordinary assignment, e.g. A=${IFS:=@}.
            self.forget();
        }
        if append {
            value = self
                .value(name)
                .zip(value.as_deref())
                .and_then(|(before, after)| {
                    (before.len().saturating_add(after.len()) <= MAX_VALUE_BYTES)
                        .then(|| format!("{before}{after}"))
                });
        }
        if !certain
            || self.attributes_unknown
            || maintained_variable(name)
            || value
                .as_ref()
                .is_some_and(|value| value.len() > MAX_VALUE_BYTES || value.contains('\0'))
        {
            value = None;
        }
        if name == "IFS" {
            self.ifs = value;
            self.changed = true;
        } else if let Some(value) = value {
            if self.values.len() >= MAX_BINDINGS && !self.values.contains_key(name) {
                self.values.clear();
            }
            self.values.insert(name.to_owned(), value);
        } else {
            self.values.remove(name);
        }
    }
}

fn maintained_variable(name: &str) -> bool {
    name.starts_with("BASH_")
        || matches!(
            name,
            "RANDOM"
                | "SRANDOM"
                | "SECONDS"
                | "LINENO"
                | "EPOCHSECONDS"
                | "EPOCHREALTIME"
                | "PIPESTATUS"
                | "FUNCNAME"
                | "DIRSTACK"
                | "GROUPS"
                | "PWD"
                | "OLDPWD"
                | "_"
        )
}

fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic() || byte == b'_' || index > 0 && byte.is_ascii_digit()
        })
}

fn assignment(raw: &str) -> Option<(&str, bool, &str)> {
    let (left, rhs) = raw.split_once('=')?;
    let name = left.strip_suffix('+').unwrap_or(left);
    identifier(name).then_some((name, left != name, rhs))
}

/// A complete scalar expansion only; mixed words, arrays, parameter operators
/// and substitutions need an expansion/provenance model, not text replacement.
fn scalar(raw: &str) -> Option<(&str, bool)> {
    let (raw, quoted) = match raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        Some(inner) => (inner, true),
        None => (raw, false),
    };
    let name = raw
        .strip_prefix("${")
        .and_then(|s| s.strip_suffix('}'))
        .or_else(|| raw.strip_prefix('$'))?;
    identifier(name).then_some((name, quoted))
}

/// Quote removal for static scalar assignments. Runtime expansions, tilde
/// expansion, locale/ANSI-C quotes and array initializers forfeit the proof.
/// This deliberately does not ask the host environment what a value means.
fn literal(raw: &str) -> Option<String> {
    let mut result = String::new();
    let mut quote = None;
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => result.push(ch),
            (None, '\'' | '"') => quote = Some(ch),
            (_, '\\') => {
                let next = chars.next()?;
                if next == '\n' {
                    continue;
                }
                if quote == Some('"') && !matches!(next, '$' | '`' | '"' | '\\') {
                    result.push('\\');
                }
                result.push(next);
            }
            (_, '$' | '`') | (None, '~' | '(' | ')') => return None,
            _ => result.push(ch),
        }
    }
    quote.is_none().then_some(result)
}

/// Double quotes suppress scalar field splitting, but not list-valued `@`
/// expansions and their parameter operators. Indirection can name `@` or an
/// array list, so it is not a scalar proof either. The AST supplies exactly
/// one live expansion here, not quoted argument data or a substring match.
fn parameter_can_produce_multiple_fields(raw: &str) -> bool {
    let Some(parameter) = raw.strip_prefix("${").and_then(|s| s.strip_suffix('}')) else {
        return raw == "$@";
    };
    if parameter.starts_with('#') {
        return false;
    }
    if parameter.starts_with('@') {
        return true;
    }
    let indirect = parameter.starts_with('!');
    let parameter = parameter.strip_prefix('!').unwrap_or(parameter);
    let name_end = parameter
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    if name_end == 0 {
        return false;
    }
    let operator = &parameter[name_end..];
    operator.starts_with("[@]") || indirect && !matches!(operator, "[*]" | "*")
}

/// Preserve the parser's quoting and execution boundaries. A `$@` inside
/// `"$(printf '%s' "$@")"` belongs to the nested command, not the outer argv;
/// its quoted output is one scalar. Nested commands are scanned separately.
/// Assignment and redirect words likewise do not supply this command's argv.
fn argv_needs_field_analysis(node: Node<'_, StrDoc<SupportLang>>) -> bool {
    let mut pending = vec![(node, false)];
    while let Some((part, quoted)) = pending.pop() {
        match part.kind().as_ref() {
            "variable_assignment"
            | "file_redirect"
            | "heredoc_redirect"
            | "herestring_redirect"
            | "process_substitution"
            | "raw_string"
            | "ansi_c_string"
            | "comment" => {}
            "string" => pending.extend(part.children().map(|child| (child, true))),
            "command_substitution" | "arithmetic_expansion" => {
                if !quoted {
                    return true;
                }
            }
            "simple_expansion" | "expansion" => {
                if !quoted || parameter_can_produce_multiple_fields(part.text().as_ref()) {
                    return true;
                }
                // An operator's replacement can itself contain a live list,
                // e.g. "${S:+$@}". Do not stop at the scalar parameter name.
                pending.extend(part.children().map(|child| (child, quoted)));
            }
            _ => pending.extend(part.children().map(|child| (child, quoted))),
        }
    }
    false
}

/// POSIX distinguishes IFS whitespace from other separators. Empty fields
/// before/interior to non-whitespace separators survive; a final separator
/// terminates the preceding field rather than inventing a final argument.
fn fields<'a>(value: &'a str, ifs: &str) -> Result<Vec<&'a str>, ()> {
    if value.len() > MAX_VALUE_BYTES
        || ifs.len() > MAX_VALUE_BYTES
        || !ifs.is_ascii()
        || value.contains('\0')
        || ifs.contains('\0')
    {
        return Err(());
    }
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let separator = |byte: u8| ifs.as_bytes().contains(&byte);
    let whitespace = |byte: u8| matches!(byte, b' ' | b'\t' | b'\n') && separator(byte);
    let bytes = value.as_bytes();
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && whitespace(bytes[start]) {
        start += 1;
    }
    while end > start && whitespace(bytes[end - 1]) {
        end -= 1;
    }
    let mut result = Vec::new();
    while start < end {
        let mut cursor = start;
        while cursor < end && !separator(bytes[cursor]) {
            cursor += 1;
        }
        let field = &value[start..cursor];
        // Pathname expansion happens after splitting, so a glob character
        // consumed as an IFS separator is not a glob in any resulting field.
        if field.contains(['*', '?', '[', '(']) || result.len() >= MAX_FIELDS {
            return Err(());
        }
        result.push(field);
        if cursor == end {
            break;
        }
        if whitespace(bytes[cursor]) {
            while cursor < end && whitespace(bytes[cursor]) {
                cursor += 1;
            }
            if cursor < end && separator(bytes[cursor]) {
                cursor += 1;
            }
        } else {
            cursor += 1;
        }
        while cursor < end && whitespace(bytes[cursor]) {
            cursor += 1;
        }
        start = cursor;
    }
    Ok(result)
}

fn expand(raw: &str, state: &State) -> Result<Vec<String>, ()> {
    if let Some((name, quoted)) = scalar(raw) {
        let value = state.value(name).ok_or(())?;
        if quoted {
            return Ok(vec![value.to_owned()]);
        }
        return fields(value, state.ifs.as_deref().ok_or(())?)
            .map(|fields| fields.into_iter().map(str::to_owned).collect());
    }
    let value = literal(raw).ok_or(())?;
    // A bare glob is not a literal argument, even without parameter expansion.
    // Leave ordinary literal commands to the existing shell classifier; an
    // argv reconstruction may not falsely quote away their expansion.
    if live_pattern(raw) {
        return Err(());
    }
    Ok(vec![value])
}

/// Mixed quoting does not neutralize a pattern in the unquoted portion:
/// `"/tmp/"*` is still a glob. Check provenance, not equality after decoding.
fn live_pattern(raw: &str) -> bool {
    let mut quote = None;
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => {}
            (None, '\'' | '"') => quote = Some(ch),
            (_, '\\') => {
                chars.next();
            }
            (None, '*' | '?' | '[' | '{' | '(') => return true,
            _ => {}
        }
    }
    false
}

fn uncertain(span: Range<usize>) -> Vec<CredentialFileWrite> {
    // Unknown destinations may name either protected family. A grant for
    // credentials must not silently grant an unverified .git destination.
    [
        shell::CREDENTIAL_FILE_WRITE_NAME,
        shell::GIT_INTERNALS_WRITE_NAME,
    ]
    .into_iter()
    .map(|rule| CredentialFileWrite {
        span: span.clone(),
        reason: UNCERTAIN.to_owned(),
        rule,
    })
    .collect()
}

fn render(argv: &[String]) -> String {
    argv.iter()
        .map(|word| shell_words::quote(word))
        .collect::<Vec<_>>()
        .join(" ")
}

fn classify(argv: &[String], span: Range<usize>) -> Result<Vec<CredentialFileWrite>, ()> {
    let Some(name) = argv.first() else {
        return Ok(Vec::new());
    };
    let basename = name.rsplit('/').next().unwrap_or(name);
    let mut hits = Vec::new();
    if matches!(basename, "tee" | "gtee") {
        let mut append = false;
        let mut options = true;
        let mut destinations = Vec::new();
        for word in &argv[1..] {
            if options && word == "--" {
                options = false;
                continue;
            }
            if options && matches!(word.as_str(), "--help" | "--version") {
                return Ok(hits);
            }
            if options && word.starts_with('-') && word != "-" {
                if word == "--append" {
                    append = true;
                } else if word == "--ignore-interrupts"
                    || word == "--output-error"
                    || word.starts_with("--output-error=")
                {
                    // These flags do not change destinations or append mode.
                } else if word[1..].chars().all(|ch| matches!(ch, 'a' | 'i' | 'p')) {
                    append |= word.contains('a');
                } else {
                    return Err(());
                }
            } else {
                // POSIXLY_CORRECT can stop getopt at the first operand. A
                // later --help is then a filename, not proof of no writes;
                // a later -a cannot prove earlier targets are append-only.
                // Retain this valid, more destructive reading even when a
                // GNU option-permuting invocation would do less damage.
                options = false;
                destinations.push(word);
            }
        }
        // Ask the same native path policy once for EACH tee destination. This
        // also keeps credential and Git rules independent under allowlisting.
        for path in destinations {
            let invocation = format!(
                "tee {}-- {}",
                if append { "-a " } else { "" },
                shell_words::quote(path)
            );
            if let Some(mut hit) =
                shell::classify_credential_file_write(&invocation, ShellDialect::Posix)
            {
                hit.span = span.clone();
                hits.push(hit);
            }
        }
    } else if let Some(mut hit) =
        shell::classify_credential_file_write(&render(argv), ShellDialect::Posix)
    {
        hit.span = span;
        hits.push(hit);
    }
    Ok(hits)
}

/// Bash's `%n` conversion assigns the byte count to a named shell variable.
/// Do not confuse it with `%%n`, an ordinary conversion followed by `n`, or
/// strftime's `%n` (a newline) inside `%(...)T`. Width, precision and length
/// modifiers do not make a count assignment harmless. Backslash escapes do
/// not protect a source `%`: `\%n` still performs the assignment, whereas
/// `\045n` only prints percent/n and must not be re-parsed as a conversion.
fn printf_format_may_assign(format: &str) -> bool {
    let bytes = format.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        index += 1;
        if bytes.get(index) == Some(&b'%') {
            index += 1;
            continue;
        }
        // This is a conservative conversion prefix, not a printf validator.
        // Invalid combinations can only add a refusal; they cannot conceal
        // an `n` accepted by Bash's width/precision/modifier parser.
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_digit() || b"#-+ '.*hlLjzt".contains(byte))
        {
            index += 1;
        }
        match bytes.get(index) {
            Some(b'n') => return true,
            Some(b'(') => {
                let mut depth = 1usize;
                index += 1;
                while depth > 0 {
                    match bytes.get(index) {
                        Some(b'(') => depth += 1,
                        Some(b')') => depth -= 1,
                        Some(_) => {}
                        None => return true,
                    }
                    index += 1;
                }
                // Only a complete time conversion owns the nested percent
                // sequences. Anything else is outside our bounded proof.
                if bytes.get(index) != Some(&b'T') {
                    return true;
                }
            }
            Some(conversion) if b"%bqQcCsSdiouxXaAeEfFgG".contains(conversion) => {}
            Some(_) => return true,
            None => break,
        }
        index += 1;
    }
    false
}

/// Both `-v` and a live `%n` in the format can mutate shell bindings. Find
/// the format after expanding leading arguments and the optional `--`;
/// unquoted empty words vanish, quoted empties do not. Arguments AFTER the
/// format are data, even when they contain `-v` or `%n`. Unknown leading
/// arguments can select either assignment form and forfeit the old values.
fn printf_may_assign(words: &[String], state: &State) -> bool {
    let mut options = true;
    for raw in words.iter().skip(1) {
        let Ok(fields) = expand(raw, state) else {
            return true;
        };
        for field in fields {
            if options && field == "--" {
                options = false;
                continue;
            }
            return options && field.starts_with("-v") || printf_format_may_assign(&field);
        }
    }
    false
}

fn mutates_shell(name: &str) -> bool {
    matches!(
        name,
        "read"
            | "mapfile"
            | "readarray"
            | "eval"
            | "."
            | "source"
            | "let"
            | "declare"
            | "typeset"
            | "local"
            | "readonly"
            // Bare export uses the declaration-command path. A quoted or
            // escaped spelling can instead be parsed as an ordinary command;
            // its decoded name still mutates variables (ex''port S=value).
            | "export"
            | "unset"
            | "getopts"
            | "trap"
            | "alias"
            | "unalias"
            | "set"
            | "shopt"
            | "enable"
            | "builtin"
            | "command"
    )
}

fn special_builtin(name: &str) -> bool {
    matches!(
        name,
        ":" | "."
            | "break"
            | "continue"
            | "eval"
            | "exec"
            | "exit"
            | "export"
            | "readonly"
            | "return"
            | "set"
            | "shift"
            | "times"
            | "trap"
            | "unset"
    )
}

/// Scan the original source, before segmentation discards earlier bindings.
/// Unsupported control flow removes facts instead of preserving stale paths.
pub(super) fn scan(command: &str, dialect: ShellDialect) -> Vec<CredentialFileWrite> {
    if !matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) || !candidate(command) {
        return Vec::new();
    }
    if command.len() > MAX_BYTES {
        return uncertain(0..command.len());
    }
    let Ok(ast) = AstGrep::try_new(command, SupportLang::Bash) else {
        return uncertain(0..command.len());
    };
    if ast.root().get_inner_node().has_error() {
        return uncertain(0..command.len());
    }
    let mut pending = vec![ast.root()];
    let mut events = Vec::new();
    let mut visited = 0;
    while let Some(node) = pending.pop() {
        visited += 1;
        if visited > MAX_EVENTS * 64 {
            return uncertain(0..command.len());
        }
        let kind = node.kind();
        let owned = kind == "variable_assignment"
            && node.parent().is_some_and(|parent| {
                matches!(parent.kind().as_ref(), "command" | "declaration_command")
            });
        let effect = matches!(
            kind.as_ref(),
            "command"
                | "variable_assignment"
                | "declaration_command"
                | "unset_command"
                | "arithmetic_expansion"
                | "test_command"
                | "for_statement"
                | "c_style_for_statement"
                | "if_statement"
                | "case_statement"
                | "while_statement"
                | "function_definition"
                | "compound_statement"
                | "subshell"
        );
        if !owned && effect || kind == "expansion" && scalar(node.text().as_ref()).is_none() {
            events.push(node.clone());
            if events.len() > MAX_EVENTS {
                return uncertain(0..command.len());
            }
        }
        pending.extend(node.children());
    }
    events.sort_by_key(|node| node.range().start);
    // Do not import the guard process's IFS, or assume a persistent caller
    // has its default value. An explicit assignment can establish the value;
    // appending to an unknown IFS must remain unknown (it may contain other
    // delimiters). This also preserves caller-side expansion of prefixes.
    let mut state = State::default();
    let mut hits = Vec::new();
    for node in events {
        let raw = node.text();
        let span = node.range();
        let mut ancestor = node.parent();
        let mut certain = true;
        let mut straight_line = true;
        while let Some(parent) = ancestor {
            match parent.kind().as_ref() {
                "program" | "variable_assignments" => {}
                // A redirection is part of command setup. If opening it fails,
                // an assignment-only command or a special/declaration builtin
                // may never establish the binding that follows. Treat the
                // state effect as uncertain while still analyzing the command
                // itself for protected writer destinations.
                "redirected_statement" | "pipeline" => certain = false,
                _ => {
                    certain = false;
                    straight_line = false;
                }
            }
            ancestor = parent.parent();
        }
        let following = command[span.end..].trim_start();
        certain &= !following.starts_with('&') || following.starts_with("&&");
        match node.kind().as_ref() {
            "variable_assignment" => state.assign(raw.as_ref(), certain),
            "declaration_command" => {
                let tokens =
                    crate::normalize::tokenize_for_shell_dialect(raw.as_ref(), ShellDialect::Posix);
                let words: Vec<_> = tokens
                    .iter()
                    .filter(|token| token.kind == NormalizeTokenKind::Word)
                    .filter_map(|token| token.text(raw.as_ref()))
                    .collect();
                // Export RHSs use the caller's environment, not values of
                // earlier arguments of the same declaration builtin.
                if words.first() == Some(&"export")
                    && words.iter().skip(1).all(|word| {
                        identifier(word)
                            || assignment(word).is_some_and(|(_, _, rhs)| literal(rhs).is_some())
                    })
                {
                    for word in words
                        .into_iter()
                        .skip(1)
                        .filter(|word| assignment(word).is_some())
                    {
                        state.assign(word, certain);
                    }
                } else {
                    state.forget();
                    state.attributes_unknown = true;
                }
            }
            "command" => {
                if !straight_line {
                    state.forget();
                }
                let prefixes: Vec<_> = node
                    .children()
                    .filter(|child| child.kind() == "variable_assignment")
                    .map(|child| child.text().into_owned())
                    .collect();
                let prefix_ifs = prefixes
                    .iter()
                    .any(|prefix| assignment(prefix).is_some_and(|(name, _, _)| name == "IFS"));
                let words: Vec<_> = node
                    .children()
                    .filter(|child| {
                        child.is_named()
                            && !matches!(
                                child.kind().as_ref(),
                                "variable_assignment"
                                    | "file_redirect"
                                    | "heredoc_redirect"
                                    | "herestring_redirect"
                                    | "comment"
                            )
                    })
                    .map(|child| child.text().into_owned())
                    .collect();
                let original_name = words.first().and_then(|word| literal(word));
                if prefixes.iter().any(|prefix| {
                    assignment(prefix)
                        .is_none_or(|(_, _, rhs)| literal(rhs).is_none() && scalar(rhs).is_none())
                }) || words.iter().any(|word| {
                    literal(word).is_none() && scalar(word).is_none() && word.contains(['$', '`'])
                }) {
                    state.forget();
                }
                let joined = words.join(" ");
                let stripped = strip_wrapper_prefixes(&joined);
                let tokens = crate::normalize::tokenize_for_shell_dialect(
                    stripped.normalized.as_ref(),
                    ShellDialect::Posix,
                );
                let arguments: Vec<_> = tokens
                    .iter()
                    .filter(|token| token.kind == NormalizeTokenKind::Word)
                    .filter_map(|token| token.text(stripped.normalized.as_ref()))
                    .collect();
                let name = arguments
                    .first()
                    .and_then(|raw| expand(raw, &state).ok())
                    .and_then(|argv| argv.into_iter().next());
                let writer = name
                    .as_deref()
                    .map(|name| name.rsplit('/').next().unwrap_or(name))
                    .is_none_or(shell::is_credential_writer);
                let active = state.changed
                    || prefix_ifs
                    || words
                        .iter()
                        .any(|word| assignment(word).is_some_and(|(name, _, _)| name == "IFS"));
                let expands = argv_needs_field_analysis(node.clone());
                if active && writer && expands {
                    // Temporary prefixes do not supply this invocation's argv.
                    let mut argv = Vec::new();
                    let mut complete = true;
                    let mut bytes = 0usize;
                    for argument in arguments {
                        let Ok(fields) = expand(argument, &state) else {
                            complete = false;
                            break;
                        };
                        for field in fields {
                            bytes = bytes.saturating_add(field.len());
                            argv.push(field);
                        }
                        if bytes > MAX_BYTES || argv.len() > MAX_FIELDS {
                            complete = false;
                            break;
                        }
                    }
                    if complete {
                        match classify(&argv, span.clone()) {
                            Ok(found) => hits.extend(found),
                            Err(()) => hits.extend(uncertain(span.clone())),
                        }
                    } else {
                        hits.extend(uncertain(span.clone()));
                    }
                }
                if original_name.as_deref().is_some_and(special_builtin) {
                    // POSIX mode can retain these values; ordinary Bash can
                    // restore them. Neither is a proven value for later argv.
                    for prefix in &prefixes {
                        state.assign(prefix, false);
                    }
                }
                if original_name.as_deref().is_none_or(mutates_shell)
                    || original_name.as_deref() == Some("printf")
                        && printf_may_assign(&words, &state)
                {
                    state.forget();
                    state.attributes_unknown = true;
                }
            }
            "function_definition" => {
                // A later literal command name can invoke this function and
                // mutate any binding. Until calls/scopes are modeled, do not
                // re-establish scalar facts after seeing the definition.
                state.forget();
                state.attributes_unknown = true;
            }
            _ => state.forget(),
        }
    }
    hits
}

/// A cheap candidate gate, NOT a claim that a write exists. Keep this at the
/// pack-selection boundary too: a runtime-only destination has no raw `/etc`
/// substring from which the keyword gate could select the filesystem pack.
pub(super) fn candidate(command: &str) -> bool {
    if !command.contains(['$', '`']) {
        return false;
    }
    if command.contains("IFS") {
        return true;
    }
    // Declaration builtins also accept quote-removed names: export I'F'S=@.
    // Ignore quote/escape characters only for this lexical superset; the AST
    // analyzer still treats an unmodeled declaration as unknown state.
    let mut prefix = 0;
    for ch in command
        .chars()
        .filter(|ch| !matches!(*ch, '\'' | '"' | '\\'))
    {
        prefix = match (prefix, ch) {
            (_, 'I') => 1,
            (1, 'F') => 2,
            (2, 'S') => return true,
            _ => 0,
        };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitting_preserves_posix_whitespace_and_empty_field_rules() {
        for (value, ifs, expected) in [
            ("", "@", vec![]),
            ("a@b", "@", vec!["a", "b"]),
            ("@a@@b@", "@", vec!["", "a", "", "b"]),
            ("@@", "@", vec!["", ""]),
            (" a \t b\n", DEFAULT_IFS, vec!["a", "b"]),
            ("  @ a @ @ b @  ", " @", vec!["", "a", "", "b"]),
            ("a@b", "", vec!["a@b"]),
            ("a b@c d", "@", vec!["a b", "c d"]),
            ("α@β", "@", vec!["α", "β"]),
            ("/tmp/a@/etc/profile", "@", vec!["/tmp/a", "/etc/profile"]),
            ("a*b", "*", vec!["a", "b"]),
        ] {
            assert_eq!(fields(value, ifs), Ok(expected), "{value:?}, {ifs:?}");
        }
    }

    #[test]
    fn expansion_bounds_and_unresolved_pathname_expansion_fail_closed() {
        for (value, ifs) in [("*.txt", "@"), ("x", "é"), ("x\0y", "@")] {
            assert!(fields(value, ifs).is_err());
        }
        assert!(fields(&"x".repeat(MAX_VALUE_BYTES + 1), "@").is_err());
        assert!(fields(&"x@".repeat(MAX_FIELDS + 1), "@").is_err());
        assert_eq!(
            fields(&"x@".repeat(MAX_FIELDS), "@").unwrap().len(),
            MAX_FIELDS
        );
    }

    #[test]
    fn assignment_quotes_do_not_protect_later_unquoted_fields() {
        let mut state = State {
            ifs: Some(DEFAULT_IFS.to_owned()),
            ..State::default()
        };
        state.assign("S='/tmp/a@/etc/profile'", true);
        state.assign("IFS+=@", true);
        assert_eq!(expand("$S", &state).unwrap(), ["/tmp/a", "/etc/profile"]);
        assert_eq!(expand(r#""$S""#, &state).unwrap(), ["/tmp/a@/etc/profile"]);
        state.assign("IFS=", true);
        assert_eq!(expand("${S}", &state).unwrap(), ["/tmp/a@/etc/profile"]);
    }

    #[test]
    fn static_quote_removal_retains_pattern_provenance() {
        let state = State::default();
        for raw in [r#""/tmp/"*"#, r"/tmp/\a?", r"/tmp/{a,b}"] {
            assert!(expand(raw, &state).is_err(), "{raw}");
        }
        for raw in [r"'/tmp/*'", r"/tmp/\*", r#""/tmp/*""#] {
            assert_eq!(expand(raw, &state).unwrap(), ["/tmp/*"]);
        }
        for (raw, expected) in [
            (r#""$S""#, false),
            (r"\$S", false),
            (r"'$S'", false),
            (r#""prefix"${S}"#, true),
            (r#""$S"$T"#, true),
        ] {
            let source = format!("tee {raw}");
            let ast = AstGrep::try_new(source.as_str(), SupportLang::Bash).unwrap();
            assert_eq!(argv_needs_field_analysis(ast.root()), expected, "{raw}");
        }
    }

    #[test]
    fn native_policy_sees_every_rebound_ifs_destination() {
        for source in [
            "S=/tmp/a@/etc/profile; IFS=@; echo x | tee $S",
            "IFS=@; S=/tmp/a@/etc/profile; tee $S",
            "S=/tmp/a@/etc/profile IFS=@; tee $S",
            "IFS=@ S=/tmp/a@/etc/profile; tee ${S}",
            "IFS=' '; S=/tmp/a@/etc/profile; IFS+=@; tee $S",
            "S=/tmp/a@/etc/profile; export IFS=@; tee $S",
            "export S=/tmp/a@/etc/profile IFS=@; tee $S",
            "S=/etc/profile@/tmp/a; IFS=@; tee $S",
            "S=/tmp/a@/tmp/b@/etc/profile; IFS=@; tee $S",
            "S=/tmp/a@/etc/profile; IFS=@; command tee -- $S",
            "S=/tmp/a@/etc/profile; IFS=@; /usr/bin/tee $S",
            "S=/tmp/a@/etc/profile; IFS=@; gtee $S",
            "S=/tmp/a@/etc/profile; IFS=@; tee -a $S",
        ] {
            let hits = scan(source, ShellDialect::Posix);
            assert!(
                hits.iter()
                    .any(|hit| hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME),
                "{source}: {hits:?}"
            );
            assert!(
                hits.iter().any(|hit| hit.reason != UNCERTAIN),
                "must resolve literal fields: {source}"
            );
            assert!(
                hits.iter()
                    .all(|hit| source[hit.span.clone()].contains("tee"))
            );
        }
    }

    #[test]
    fn each_native_rule_family_survives_the_same_tee_invocation() {
        let source = "S=/tmp/a@/etc/profile@.git/config; IFS=@; tee $S";
        let hits = scan(source, ShellDialect::Posix);
        assert!(
            hits.iter()
                .any(|hit| hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME)
        );
        assert!(
            hits.iter()
                .any(|hit| hit.rule == shell::GIT_INTERNALS_WRITE_NAME)
        );
    }

    #[test]
    fn quoted_scalars_read_idioms_and_safe_paths_remain_harmless() {
        for source in [
            "S=/tmp/scratch/a@/tmp/scratch/b; IFS=@; echo x | tee $S",
            "S=/tmp/a@/etc/profile; IFS=@; tee \"$S\"",
            "S=/tmp/a@/etc/profile; IFS=@; tee \"${S}\"",
            "S=/tmp/a@/etc/profile; IFS=; tee $S",
            "S=/tmp/a@/etc/profile; IFS=@; tee '$S'",
            "S=/tmp/a@/etc/profile; IFS=@; printf '%s' \"$S\"",
            "S=/tmp/a@/etc/profile; IFS=@; echo 'tee $S'",
            "S=/tmp/a@/etc/profile; IFS=@",
            "OIFS=$IFS",
            "while IFS= read -r l; do :; done < /etc/hostname",
            "IFS=, read a b <<< 'x,y'",
            "S=/tmp/safe; IFS=@; S=/tmp/a@/etc/profile IFS=: tee $S",
            "IFS=@; S=/tmp/a@/tmp/b; tee $S; tee /tmp/other",
        ] {
            assert!(scan(source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    #[test]
    fn unknown_state_and_unsupported_expansions_require_native_review() {
        for source in [
            "S=/tmp/a@/etc/profile; IFS+=@; tee $S",
            "S=/tmp/a@/etc/profile IFS=@ tee $S",
            "S=/tmp/a@/etc/profile; IFS=$CUSTOM; tee $S",
            "IFS=@; tee $UNKNOWN",
            "S=/tmp/a@/etc/profile; IFS=@; tee prefix${S}",
            "S=/tmp/a@/etc/profile; IFS=@; tee $S \"/tmp/\"*",
            "S=/tmp/safe; IFS=@; S=/tmp/a@/etc/profile :; tee $S",
            "S=/tmp/safe; IFS=@; printf -v S /tmp/a@/etc/profile; tee $S",
            "f() { S=/tmp/a@/etc/profile; }; S=/tmp/safe; IFS=@; f; tee $S",
            "declare -n S=T; T=/tmp/a@/etc/profile; IFS=@; tee $S",
            "IFS=@; A=(/tmp/a /etc/profile); tee \"${A[@]}\"",
            "S=/tmp/a@/etc/profile; export I'F'S=@; tee $S",
        ] {
            let hits = scan(source, ShellDialect::Posix);
            assert!(
                hits.iter().any(|hit| hit.reason == UNCERTAIN),
                "{source}: {hits:?}"
            );
        }
    }

    #[test]
    fn writer_arguments_are_not_limited_to_tee() {
        for source in [
            "S=/tmp/source@/etc/profile; IFS=@; cp $S",
            "S=/tmp/source@/etc/profile; IFS=@; mv $S",
            "S=if=/tmp/source@of=/etc/profile; IFS=@; dd $S",
        ] {
            let hits = scan(source, ShellDialect::Posix);
            assert!(
                hits.iter()
                    .any(|hit| hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME),
                "{source}: {hits:?}"
            );
        }
    }

    #[test]
    fn printf_assignment_options_follow_expansion_and_format_boundaries() {
        let mut state = State::default();
        state.assign("IFS=@", true);
        state.assign("F=-v", true);
        state.assign("A=-v@S", true);
        state.assign("E=", true);
        state.assign("FORMAT=%s", true);
        for (arguments, expected) in [
            (vec!["-v", "S", "%s", "value"], true),
            (vec!["'-v'", "S", "%s", "value"], true),
            (vec![r#""-v""#, "S", "%s", "value"], true),
            (vec!["-''v", "S", "%s", "value"], true),
            (vec![r"\-v", "S", "%s", "value"], true),
            (vec!["'-vS'", "%s", "value"], true),
            (vec!["$F", "S", "%s", "value"], true),
            (vec![r#""$F""#, "S", "%s", "value"], true),
            (vec!["$A", "%s", "value"], true),
            (vec!["$E", "'-v'", "S", "%s", "value"], true),
            (vec!["$UNKNOWN", "S", "%s", "value"], true),
            (vec![r#""$UNKNOWN""#, "S", "%s", "value"], true),
            (vec!["--", "-v", "S", "value"], false),
            (vec!["'%s'", "-v", "S", "value"], false),
            (vec![r#""$FORMAT""#, "-v", "S", "value"], false),
            (vec!["''", "-v", "S", "value"], false),
            (vec![r#""$E""#, "-v", "S", "value"], false),
            (vec!["$E"], false),
            (vec![], false),
        ] {
            let words: Vec<_> = std::iter::once("printf")
                .chain(arguments)
                .map(str::to_owned)
                .collect();
            assert_eq!(printf_may_assign(&words, &state), expected, "{words:?}");
        }
    }

    #[test]
    fn printf_count_conversions_preserve_format_ownership() {
        for format in [
            "%n", "abcde%n", "%5n", "%+05.2n", "%*.*n", "%hn", "%lln", "%zn", "%jn", "%tn", "%Ln",
            "%%%n", r"\%n", r"\\%n", "%(%n)T%n",
        ] {
            assert!(printf_format_may_assign(format), "{format}");
        }
        for format in [
            "",
            "%s",
            "%b",
            "%q",
            "n",
            "%%n",
            "%%%%n",
            "%dn",
            "%sn",
            "%s%%n",
            r"\045n",
            r"\x25n",
            "%(%n)T",
            "%(a(b)%n)T",
            "%10(%n)T",
            "%(%%n)T",
        ] {
            assert!(!printf_format_may_assign(format), "{format}");
        }
        for format in ["%(", "%(%n", "%(date)%n", "%I64n", "%Y"] {
            assert!(printf_format_may_assign(format), "{format}");
        }

        let mut state = State::default();
        state.assign("IFS=@", true);
        state.assign("F=abcde%n", true);
        state.assign("A=--@abcde%n@SEP", true);
        state.assign("E=", true);
        for arguments in [
            vec!["'abcde%n'", "SEP"],
            vec!["--", "'abcde%n'", "SEP"],
            vec![r#""$F""#, "SEP"],
            vec!["$A"],
            vec!["$E", "--", "'abcde%n'", "SEP"],
        ] {
            let words: Vec<_> = std::iter::once("printf")
                .chain(arguments)
                .map(str::to_owned)
                .collect();
            assert!(printf_may_assign(&words, &state), "{words:?}");
        }
    }

    #[test]
    fn printf_count_assignment_cannot_leave_stale_separator_facts() {
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
            let source =
                format!("SEP=@; IFS=@; S=/tmp/a5/etc/profile; {printing}; IFS=$SEP; tee $S");
            let hits = scan(&source, ShellDialect::Posix);
            for rule in [
                shell::CREDENTIAL_FILE_WRITE_NAME,
                shell::GIT_INTERNALS_WRITE_NAME,
            ] {
                assert!(
                    hits.iter()
                        .any(|hit| hit.rule == rule && hit.reason == UNCERTAIN),
                    "{source}: missing {rule}: {hits:?}"
                );
            }
        }
    }

    #[test]
    fn printf_literal_count_text_does_not_forfeit_safe_separator_facts() {
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
            let source =
                format!("SEP=@; IFS=@; S=/tmp/a5/etc/profile; {printing}; IFS=$SEP; tee $S");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    /// Exercise this Rust predicate against Bash's real builtin, not a model
    /// translated into another language. The constant script only mutates
    /// its private COUNT variable; neither shell source nor paths are input.
    #[test]
    #[cfg(unix)]
    fn printf_count_detection_matches_bash_builtin() {
        for (format, arguments) in [
            ("%n", vec!["COUNT"]),
            ("abcde%n", vec!["COUNT"]),
            ("%5n", vec!["COUNT"]),
            ("%*n", vec!["5", "COUNT"]),
            ("%.*n", vec!["2", "COUNT"]),
            ("%ln", vec!["COUNT"]),
            ("%%%n", vec!["COUNT"]),
            (r"\%n", vec!["COUNT"]),
            ("%%n", vec!["COUNT"]),
            ("%s", vec!["%n"]),
            ("%b", vec!["%n"]),
            ("%q", vec!["%n"]),
            ("%dn", vec!["5"]),
            (r"\045n", vec!["COUNT"]),
            ("%(%n)T", vec!["0"]),
            ("%(a(b)%n)T", vec!["0"]),
        ] {
            let output = std::process::Command::new("/bin/bash")
                .args([
                    "--noprofile",
                    "--norc",
                    "-c",
                    "COUNT=untouched; printf -- \"$@\" >/dev/null; printf '%s' \"$COUNT\"",
                    "dcg-printf-count-probe",
                    format,
                ])
                .args(arguments)
                .env_clear()
                .env("LC_ALL", "C")
                .output()
                .expect("Bash builtin count probe");
            assert!(output.status.success(), "{format}: {output:?}");
            assert_eq!(
                printf_format_may_assign(format),
                output.stdout.as_slice() != b"untouched",
                "{format}: {output:?}"
            );
        }
    }

    #[test]
    fn decoded_assignment_builtins_cannot_leave_stale_writer_destinations() {
        for mutation in [
            "ex''port S=/tmp/a@/etc/profile",
            r#""export" S=/tmp/a@/etc/profile"#,
            r"\export S=/tmp/a@/etc/profile",
            r#"e'x'p"o"rt S=/tmp/a@/etc/profile"#,
            "printf '-v' S '%s' /tmp/a@/etc/profile",
            r#"printf "-v" S %s /tmp/a@/etc/profile"#,
            "printf -''v S %s /tmp/a@/etc/profile",
            r"printf \-v S %s /tmp/a@/etc/profile",
            "printf '-vS' %s /tmp/a@/etc/profile",
            "F=-v; printf $F S %s /tmp/a@/etc/profile",
            r#"F=-v; printf "$F" S %s /tmp/a@/etc/profile"#,
            "F=-v@S; printf $F %s /tmp/a@/etc/profile",
            "E=; printf $E '-v' S %s /tmp/a@/etc/profile",
            "printf $UNKNOWN S %s /tmp/a@/etc/profile",
            "ex''port IFS=:; S=/tmp/a:/etc/profile",
            "printf '-v' IFS %s :; S=/tmp/a:/etc/profile",
        ] {
            let source = format!("S=/tmp/safe; IFS=@; {mutation}; tee $S");
            let hits = scan(&source, ShellDialect::Posix);
            for rule in [
                shell::CREDENTIAL_FILE_WRITE_NAME,
                shell::GIT_INTERNALS_WRITE_NAME,
            ] {
                assert!(
                    hits.iter()
                        .any(|hit| hit.rule == rule && hit.reason == UNCERTAIN),
                    "{source}: missing {rule}: {hits:?}"
                );
            }
        }
    }

    #[test]
    fn printf_data_arguments_do_not_invalidate_safe_destination_bindings() {
        for printing in [
            "printf '%s' '-v' S /tmp/a@/etc/profile",
            "printf -- '-v' S /tmp/a@/etc/profile",
            "printf '' '-v' S /tmp/a@/etc/profile",
            r#"F=%s; printf "$F" '-v' S /tmp/a@/etc/profile"#,
            r#"E=; printf "$E" -v S /tmp/a@/etc/profile"#,
            "printf '%s' '$@' '-v' S /tmp/a@/etc/profile",
        ] {
            let source = format!("S=/tmp/safe; IFS=@; {printing}; tee $S");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    #[test]
    fn redirected_state_changes_cannot_replace_older_dangerous_bindings() {
        for mutation in [
            "S=/tmp/safe >/definitely/missing/parent/file",
            "export S=/tmp/safe >/definitely/missing/parent/file",
            "IFS=: >/definitely/missing/parent/file",
            "export IFS=: >/definitely/missing/parent/file",
        ] {
            let source = format!("S=/tmp/a@/etc/profile; IFS=@; {mutation}; tee $S");
            let hits = scan(&source, ShellDialect::Posix);
            assert!(
                hits.iter().any(|hit| hit.reason == UNCERTAIN),
                "{source}: {hits:?}"
            );
        }
    }

    #[test]
    fn candidate_gate_and_original_source_entry_point_do_not_lose_bindings() {
        let source = "S=/tmp/a@/etc/profile; IFS=@; tee $S";
        let hits = super::super::classify_embedded_credential_file_writes(
            source,
            ShellDialect::Posix,
            |_, _| false,
        );
        assert!(
            hits.iter()
                .any(|hit| hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME)
        );
        assert!(super::super::may_name_protected_path("IFS=@; tee $UNKNOWN"));
        assert!(!candidate("tee /tmp/safe"));
        assert!(scan(source, ShellDialect::PowerShell).is_empty());
        assert!(scan(source, ShellDialect::Cmd).is_empty());
    }

    #[test]
    fn quoted_list_parameters_and_operators_are_not_scalar_proofs() {
        for raw in [
            "$@",
            "${@}",
            "${@:1}",
            "${@:1:2}",
            "${@#prefix}",
            "${@%suffix}",
            "${@/old/new}",
            "${@:-fallback}",
            "${@@Q}",
            "${A[@]:1}",
            "${!A[@]}",
            "${!prefix@}",
            "${!S}",
            "${!1}",
        ] {
            assert!(parameter_can_produce_multiple_fields(raw), "{raw}");
        }
        for raw in [
            "$S",
            "$*",
            "$!",
            "${S}",
            "${#@}",
            "${#A[@]}",
            "${A[*]}",
            "${!A[*]}",
            "${!prefix*}",
            "${!}",
            "${S@Q}",
        ] {
            assert!(!parameter_can_produce_multiple_fields(raw), "{raw}");
        }
    }

    #[test]
    fn argv_analysis_keeps_quote_and_execution_provenance() {
        for (raw, expected) in [
            (r#""${@:1}""#, true),
            (r#""${!S}""#, true),
            (r#""${S:+$@}""#, true),
            (r#""${S:-"$@"}""#, true),
            (r#""${S[@]:0:2}""#, true),
            (r#"é"${@:1}"ø"#, true),
            (r#"$(printf '%s' "$@")"#, true),
            (r#""$S"'${@:1}'"#, false),
            (r#""$S"'[@]'"#, false),
            (r#""\${@:1}""#, false),
            (r"'${@:1}'", false),
            (r"$'${@:1}'", false),
            (r#""${#@}""#, false),
            (r#""${#S[@]}""#, false),
            (r#""${S[*]}""#, false),
            (r#""${!S[*]}""#, false),
            (r#""$(printf '%s' "$@")""#, false),
            (r#""$((1 + ${#S[@]}))""#, false),
        ] {
            let source = format!("tee {raw}");
            let ast = AstGrep::try_new(source.as_str(), SupportLang::Bash).unwrap();
            assert!(!ast.root().get_inner_node().has_error(), "{raw}");
            assert_eq!(argv_needs_field_analysis(ast.root()), expected, "{raw}");
        }
    }

    #[test]
    fn quoted_list_destinations_require_native_review_without_custom_packs() {
        for source in [
            r#"set -- /tmp/a /etc/profile; IFS=@; tee "${@:1}""#,
            r#"set -- /tmp/a /etc/profile; IFS=@; tee "${@#/missing/}""#,
            r#"set -- /tmp/a /etc/profile; IFS=@; tee "${@%/missing}""#,
            r#"set -- /tmp/a /etc/profile; IFS=@; S=@; tee "${!S}""#,
            r#"IFS=@; A=(/tmp/a /etc/profile); S='A[@]'; tee "${!S}""#,
            r#"IFS=@; A=(/tmp/a /etc/profile); tee "${A[@]:0:2}""#,
            r#"set -- /tmp/a /etc/profile; IFS=@; tee "${S:-"$@"}""#,
        ] {
            let hits = scan(source, ShellDialect::Posix);
            for rule in [
                shell::CREDENTIAL_FILE_WRITE_NAME,
                shell::GIT_INTERNALS_WRITE_NAME,
            ] {
                assert!(
                    hits.iter()
                        .any(|hit| hit.rule == rule && hit.reason == UNCERTAIN),
                    "{source}: missing {rule}: {hits:?}"
                );
            }
        }
    }

    #[test]
    fn literal_list_text_and_quoted_scalar_results_do_not_trigger_ifs_refusal() {
        for source in [
            r#"IFS=@; S=ok; tee "$S"'[@]'"#,
            r#"IFS=@; S=ok; tee "$S"'${@:1}'"#,
            r#"IFS=@; tee "\${@:1}""#,
            r"IFS=@; tee '${@:1}'",
            r#"IFS=@; tee "${#@}""#,
            r#"IFS=@; tee "${#A[@]}""#,
            r#"IFS=@; tee "${A[*]}""#,
            r#"IFS=@; tee "$(printf '%s' "$@")""#,
        ] {
            assert!(scan(source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    #[test]
    fn later_tee_options_cannot_exempt_earlier_destinations() {
        for source in [
            "S=/tmp/a@/etc/profile@--help; IFS=@; POSIXLY_CORRECT=1 tee $S",
            "S=/tmp/a@/etc/profile@--version; IFS=@; env POSIXLY_CORRECT=1 tee $S",
            "S=/tmp/a@/etc/profile@--help; IFS=@; tee $S",
            "S=/home/example/.ssh/known_hosts@-a; IFS=@; POSIXLY_CORRECT=1 tee $S",
            "S=/home/example/.ssh/known_hosts@--append; IFS=@; tee $S",
        ] {
            let hits = scan(source, ShellDialect::Posix);
            assert!(
                hits.iter().any(|hit| {
                    hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME && hit.reason != UNCERTAIN
                }),
                "must check the concrete destination: {source}: {hits:?}"
            );
        }
        for argv in [
            vec!["tee", "--help", "/etc/profile"],
            vec!["tee", "--version", "/etc/profile"],
            vec!["tee", "-a", "/home/example/.ssh/known_hosts"],
            vec!["tee", "--append", "/home/example/.ssh/known_hosts"],
        ] {
            let argv: Vec<_> = argv.into_iter().map(str::to_owned).collect();
            assert!(classify(&argv, 0..0).unwrap().is_empty(), "{argv:?}");
        }
    }

    /// This checks the production Rust splitter against a real POSIX shell.
    /// The script is constant and only prints argv; values are passed as data
    /// in the child environment. No analyzed command or destination is run.
    #[test]
    #[cfg(unix)]
    fn field_splitting_matches_posix_shell_argv() {
        use std::process::Command;

        let values = [
            "",
            "a",
            "@",
            "@@",
            "@a",
            "a@",
            "a@@b@",
            " a ",
            " a b ",
            " a\tb\n",
            " @ a @ @ b @ ",
            "a,b:c",
            "α@β",
            "a'@'b",
            "/tmp/a@/etc/profile",
        ];
        for ifs in ["", DEFAULT_IFS, "@", " @", "@\t\n", ",:", "a", "/"] {
            for value in values {
                let output = Command::new("/bin/sh")
                    .args(["-c", "IFS=$DCG_TEST_IFS; set -- $DCG_TEST_VALUE; printf '%s\\0' \"$#\"; for arg; do printf '%s\\0' \"$arg\"; done"])
                    .env_clear()
                    .env("DCG_TEST_IFS", ifs)
                    .env("DCG_TEST_VALUE", value)
                    .output()
                    .expect("POSIX shell argv probe");
                assert!(output.status.success());
                let printed = String::from_utf8(output.stdout).expect("UTF-8 argv");
                let mut parts = printed.split_terminator('\0');
                let count: usize = parts.next().expect("argc").parse().expect("numeric argc");
                let actual: Vec<_> = parts.collect();
                assert_eq!(actual.len(), count);
                assert_eq!(
                    fields(value, ifs).unwrap(),
                    actual,
                    "IFS={ifs:?}, value={value:?}"
                );
            }
        }
    }
}
