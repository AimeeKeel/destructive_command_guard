//! Regression tests for issue #326: `ssh <host> '<command>'` treated the
//! quoted remote payload as opaque argv data, so a destructive payload passed
//! exactly when it was quoted while the unquoted spelling was denied.
//!
//! ssh concatenates every argv word after the destination and hands the result
//! to the remote login shell — it is an inline-shell wrapper like `sh -c`,
//! minus the flag. The heredoc pipeline now extracts that payload (skipping
//! value-taking options to locate the destination) and recursively evaluates
//! it, so the quoted and unquoted spellings reach the same decision.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, LayeredAllowlist};

fn evaluate(
    command: &str,
    extra_packs: &[&str],
    dialect: ShellDialect,
) -> destructive_command_guard::EvaluationResult {
    let config = Config::default();
    let mut enabled_packs = config.enabled_pack_ids();
    for pack in extra_packs {
        enabled_packs.insert((*pack).to_string());
    }
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

const DIALECTS: [ShellDialect; 2] = [ShellDialect::Posix, ShellDialect::Unknown];

/// The issue's reproduction table: every quoted spelling that was wrongly
/// allowed while its unquoted twin was denied.
#[test]
fn quoted_ssh_payloads_are_denied_like_their_unquoted_twins() {
    let denied = [
        "dropdb mydb",
        "ssh example-host dropdb mydb",
        "ssh example-host -- dropdb mydb",
        "ssh example-host sh -c 'dropdb mydb'",
        "ssh example-host \"dropdb mydb\"",
        "ssh example-host 'dropdb mydb'",
        "ssh user@10.0.0.5 'dropdb mydb'",
        "ssh example-host 'psql -c \"DROP TABLE t\"'",
    ];
    for command in denied {
        for dialect in DIALECTS {
            let result = evaluate(command, &["database.postgresql"], dialect);
            assert!(
                result.is_denied(),
                "{command:?} must be denied under {dialect:?}, got {result:?}"
            );
        }
    }
}

/// Core-pack payloads through option-bearing invocations.
#[test]
fn destructive_ssh_payloads_are_denied_with_core_packs_only() {
    let denied = [
        "ssh example-host 'sudo rm -rf /some/path'",
        "ssh example-host 'rm -rf /var/lib/data'",
        "ssh -i key.pem -p 2222 user@host 'git reset --hard'",
        "ssh -o StrictHostKeyChecking=no host 'rm -rf /srv'",
        "ssh -p2222 host 'rm -rf /srv'",
        "ssh -fnT -l root host 'rm -rf /srv/data'",
        "sudo ssh host 'rm -rf /srv/data'",
        "/usr/bin/ssh host 'rm -rf /srv/data'",
        "ssh a ssh b 'rm -rf /srv/data'",
        "ssh h uptime && ssh h 'rm -rf /srv/data'",
        "ssh h 'cd /app; git reset --hard'",
    ];
    for command in denied {
        for dialect in DIALECTS {
            let result = evaluate(command, &[], dialect);
            assert!(
                result.is_denied(),
                "{command:?} must be denied under {dialect:?}, got {result:?}"
            );
        }
    }
}

/// The issue's safe list: read-only remote diagnostics must stay allowed, and
/// the classic data contexts must not start firing because `ssh` appears.
#[test]
fn read_only_remote_commands_and_data_contexts_stay_allowed() {
    let allowed = [
        "ssh h 'uptime'",
        "ssh h 'df -h'",
        "ssh h 'cat /path/file'",
        "ssh h 'ls -la /path'",
        "ssh h 'grep -rn ERROR /var/log'",
        "ssh h 'systemctl status svc'",
        "ssh h 'journalctl -u svc -n 50'",
        "ssh h 'git -C /repo log --oneline -5'",
        "ssh h 'sqlite3 db \"SELECT count(*) FROM t;\"'",
        "ssh h 'pg_dump db > /tmp/db.sql'",
        // The payload's own quoting still classifies remote data as data.
        "ssh h 'echo \"dropdb mydb\"'",
        "ssh h 'echo rm -rf /srv/data'",
        // ssh mentioned as data, not executed.
        "echo ssh h 'rm -rf /'",
        "grep 'ssh h rm -rf' notes.md",
        "git commit -m \"fix ssh 'rm -rf' handling\"",
        "rsync -e 'ssh -p 22' src/ host:/dst/",
        // Interactive/relatives.
        "ssh h",
        "ssh -V",
        "ssh-keygen -t ed25519 -f key",
        "scp file.txt host:/tmp/",
        // Unmodeled option: extraction bails to the status quo.
        "ssh --fake h 'uptime'",
    ];
    for command in allowed {
        for dialect in DIALECTS {
            let result = evaluate(
                command,
                &["database.postgresql", "database.sqlite"],
                dialect,
            );
            assert!(
                result.is_allowed(),
                "{command:?} must be allowed under {dialect:?}, got {result:?}"
            );
        }
    }
}

/// Dynamic payload pieces get the same treatment the local spelling gets: a
/// dynamic rm target is denied, a bare variable command is (like local `$CMD`)
/// out of static reach.
#[test]
fn dynamic_payload_parity_with_local_treatment() {
    for dialect in DIALECTS {
        let result = evaluate("ssh h \"rm -rf $DIR\"", &[], dialect);
        assert!(
            result.is_denied(),
            "dynamic rm target must stay denied under {dialect:?}, got {result:?}"
        );
        let result = evaluate("ssh $HOST 'rm -rf /srv/data'", &[], dialect);
        assert!(
            result.is_denied(),
            "dynamic destination must not hide the payload under {dialect:?}, got {result:?}"
        );
    }
}

fn rule(result: &destructive_command_guard::EvaluationResult) -> Option<String> {
    result.pattern_info.as_ref().map(|info| {
        format!(
            "{}:{}",
            info.pack_id.as_deref().unwrap_or_default(),
            info.pattern_name.as_deref().unwrap_or_default()
        )
    })
}

/// #551: a payload whose only hazard is a dynamic executable before a delete
/// flag carries no pack keyword, so the remote recursion skipped it while the
/// same text run locally is denied as `core.git:branch-dynamic-token`, and
/// an unrelated word (`.FullName`) in the payload flipped the verdict. The
/// remote spelling must get the local verdict and rule whatever else the
/// payload contains; benign dynamic payloads stay allowed like their local
/// text.
#[test]
fn keyword_less_payloads_get_their_local_verdict_551() {
    for (local, remote) in [
        ("$G -D main", "ssh h '$G -D main'"),
        ("$p = x -d 1", "ssh h '$p = x -d 1'"),
        ("$p = x -d 1; $q.Name", "ssh h '$p = x -d 1; $q.Name'"),
        (
            "$p = x -d 1; $q.FullName",
            "ssh h '$p = x -d 1; $q.FullName'",
        ),
        ("$p -d 1", "ssh -p 2222 user@host '$p -d 1'"),
    ] {
        for dialect in DIALECTS {
            let local_result = evaluate(local, &[], dialect);
            let remote_result = evaluate(remote, &[], dialect);
            assert_eq!(
                rule(&local_result).as_deref(),
                Some("core.git:branch-dynamic-token"),
                "{local:?} under {dialect:?}: {local_result:?}"
            );
            assert!(
                remote_result.is_denied(),
                "{remote:?} must be denied like {local:?} under {dialect:?}, got {remote_result:?}"
            );
            assert_eq!(
                rule(&remote_result),
                rule(&local_result),
                "{remote:?} under {dialect:?}"
            );
        }
    }
    for (local, remote) in [
        ("echo $X", "ssh h 'echo $X'"),
        ("$CMD --help", "ssh h '$CMD --help'"),
        ("cd $D && make", "ssh h 'cd $D && make'"),
    ] {
        for dialect in DIALECTS {
            let local_result = evaluate(local, &[], dialect);
            let remote_result = evaluate(remote, &[], dialect);
            assert!(
                local_result.is_allowed() && remote_result.is_allowed(),
                "{remote:?} and {local:?} must stay allowed under {dialect:?}: \
                 {remote_result:?} / {local_result:?}"
            );
        }
    }
}

/// An ssh_config option can carry a command line: `ProxyCommand`,
/// `LocalCommand` and `KnownHostsCommand` run theirs on the local host,
/// `RemoteCommand` on the remote one. `ssh`, `scp` and `sftp` all take them
/// as `-o` options, and every spelling OpenSSH accepts (attached, after `=`
/// or a blank, any letter case, bundled behind flags, after the destination)
/// must reach the same verdict as the command line itself.
#[test]
fn ssh_config_option_commands_are_evaluated() {
    let denied = [
        "ssh -o ProxyCommand='rm -rf ~' host",
        "ssh -oProxyCommand='rm -rf ~' host true",
        "ssh -o PermitLocalCommand=yes -o LocalCommand='rm -rf ~' host",
        "ssh -o ProxyCommand='rm -rf ~' host 'rm -rf /tmp/probe'",
        "ssh -o 'ProxyCommand rm -rf ~' host",
        "ssh -o 'ProxyCommand = rm -rf ~' host",
        "ssh -o proxycommand='rm -rf ~' host",
        "ssh -nT -oProxyCommand='rm -rf ~' host",
        "ssh \"-o\"ProxyCommand='rm -rf ~' host",
        "ssh -o ProxyCommand=rm\\ -rf\\ ~ host",
        "ssh host -o ProxyCommand='rm -rf ~'",
        "ssh -F /dev/null -o ProxyCommand='rm -rf ~' host",
        "ssh -oLocalCommand='rm -rf ~' host",
        "ssh -o KnownHostsCommand='rm -rf /home/user' host",
        "ssh -o RemoteCommand='rm -rf ~' host",
        "ssh -o ProxyCommand='git reset --hard' host",
        "scp -o ProxyCommand='rm -rf ~' a host:b",
        "scp -qo ProxyCommand='rm -rf ~' a host:b",
        "sftp -o ProxyCommand='rm -rf ~' host",
        "/usr/bin/ssh -o ProxyCommand='rm -rf ~' host",
        // Code chosen at run time, like `sh -c "$X"`.
        "ssh -o \"ProxyCommand=$P\" host",
    ];
    for command in denied {
        for dialect in DIALECTS {
            let result = evaluate(command, &[], dialect);
            assert!(
                result.is_denied(),
                "{command:?} must be denied under {dialect:?}, got {result:?}"
            );
        }
    }
    let allowed = [
        "ssh -o ProxyCommand='ssh -W %h:%p bastion' host uptime",
        "ssh -o 'ProxyCommand nc -X 5 -x proxy:1080 %h %p' host",
        "ssh -o ProxyCommand=none host",
        "ssh -o ProxyJump=bastion host",
        "ssh -o BatchMode=yes -o ConnectTimeout=5 host uptime",
        "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null host",
        "ssh -o SendEnv='rm -rf ~' host",
        "scp -o ProxyCommand='ssh -W %h:%p bastion' a host:b",
        "sftp -o ProxyCommand='ssh -W %h:%p bastion' host",
        "ssh -o \"ProxyCommand=ssh -W %h:%p $JUMP\" host",
        "echo ssh -o ProxyCommand='rm -rf ~' host",
    ];
    for command in allowed {
        for dialect in DIALECTS {
            let result = evaluate(command, &[], dialect);
            assert!(
                result.is_allowed(),
                "{command:?} must stay allowed under {dialect:?}, got {result:?}"
            );
        }
    }
}
