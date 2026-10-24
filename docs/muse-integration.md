# Muse Code Integration

> Last updated: 2026-10-21 (first-party support, issue #572)

[Muse Code](https://dev.meta.ai/docs/muse-code) (Meta's terminal coding agent)
runs `PreToolUse` hooks declared in the `hooks` block of its user settings.
dcg registers itself there: Muse pipes each shell tool call to dcg's stdin
before running it, and refuses the call when dcg answers with a deny.

```bash
dcg install --muse            # ${XDG_CONFIG_HOME:-~/.config}/muse/settings.json
dcg install --muse --force    # rewrite dcg's entry (e.g. after moving the binary)
dcg uninstall --muse          # remove dcg's entry, keep everything else
```

Muse discovers hooks at session start, so start a new Muse session after
installing. User hooks need no trust step.

## What gets written

dcg merges one matcher group into `hooks.PreToolUse`, first in the list, and
leaves every other key, group and handler in the file alone:

```json
{
  "schema_version": 1,
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(shell|exec_command|bash)$",
        "hooks": [
          { "type": "command", "command": "/absolute/path/to/dcg --agent muse" }
        ]
      }
    ]
  }
}
```

- Muse requires `"schema_version": 1`. dcg adds it to a file that lacks it
  and refuses to edit a file that declares any other version.
- `matcher` is a regex tested against the tool name. It covers `shell` (the
  tool behind the `!` escape, whose payload is shown below), `exec_command`
  (the unified-exec tool, whose command argument is `cmd`) and `bash`: the
  three names Muse's own bundled tooling treats as shell tools.
- `command` is the absolute path of the dcg binary that ran the installer,
  followed by `--agent muse`. Muse runs hook commands in a cleared
  environment, so neither an environment marker nor an exported
  `DCG_CONFIG` reaches dcg. dcg's own config file is still found at its usual
  path under your home directory. A non-default config has to be named in the
  command itself (`DCG_CONFIG=/path/config.toml /path/to/dcg --agent muse`);
  dcg owns `command`, so rerunning `dcg install --muse` rewrites it to the
  plain form.
- Muse rejects unknown matcher-group fields, so dcg writes only `matcher` and
  `hooks`. If you add fields to dcg's handler yourself (a timeout, an
  `onFailure` fallback), a reinstall keeps them and refreshes only `type`
  and `command`.
- The file must be strict JSON. dcg never rewrites a file it cannot parse;
  fix it by hand and rerun the install.

Project hooks (`<project-root>/.muse/hooks.json`, loaded only for trusted
folders) and managed hooks (`managed_hooks_path`) are not written by
`dcg install`. The user-level entry already covers every project.

## The protocol

For a shell call Muse writes a Codex-shaped payload to the hook's stdin:

```json
{"cwd":"/repo","hook_event_name":"PreToolUse","model":"…","permission_mode":"default",
 "session_id":"…","tool_input":{"command":"git reset --hard"},"tool_name":"shell",
 "tool_use_id":"…","transcript_path":null,"turn_id":"…"}
```

That payload is the one captured from Muse 1.4.7 and 1.4.10 for the `!`
escape. Muse's own bundled tooling reads an `exec_command` call's command from
`cmd`, falling back to `command`, so dcg evaluates every command field it
finds (`command` and `cmd`); a harmless value in one cannot hide a
destructive value in the other.

Muse reads `hookSpecificOutput.permissionDecision` on exit 0. It requires a
non-empty `permissionDecisionReason` for a deny and rejects a bare `allow`
(an allow must carry `updatedInput`), so dcg answers in the minimal shape:

| dcg verdict | stdout | what Muse does |
|---|---|---|
| allow, warn | nothing | runs the command under its normal permission flow |
| deny | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"BLOCKED by dcg …"}}` | refuses the call and shows the reason |
| review (ask) or an indeterminate result | the same deny | refuses the call |

Muse could show `ask` decisions, but dcg answers them with a deny, as it does
for Codex, whose answer shape Muse shares.

`--agent muse` selects the `[agents.muse]` profile in dcg's config, labels
history rows `muse`, and keeps the answer in the shape above even when a
payload lacks `turn_id`. Without the flag, Muse's `turn_id` makes the payload
look like Codex, so `[agents.codex-cli]` would apply instead. The identity is
never taken from the payload or from a parent process name.

### Failing closed

Muse documents an `onFailure` fallback for a hook that exits non-zero, times
out or prints invalid output, but not what it does without one. So, with
`--agent muse`, dcg never leaves a request unanswered when it cannot verify
the command:

- A payload dcg cannot read (malformed JSON, invalid UTF-8, over
  `max_hook_input_bytes`, or a stdin read error) is denied, with or without
  `DCG_FAIL_CLOSED`.
- A matched shell call with no readable command (neither `command` nor `cmd`
  is a non-empty string) is denied, because dcg does not understand that
  payload shape.
- A deadline or size-limit result is denied (dcg's Codex-shape answers have
  no `ask`).

What dcg cannot control is a hook process that Muse itself kills or that
crashes before answering. If you want Muse to refuse the call in that case
too, declare an `onFailure` fallback on dcg's handler as Muse's documentation
describes; a reinstall keeps it.

### Known gaps

- Tools outside the matcher are not sent to dcg. If a Muse release adds or
  renames a shell tool, rerun `dcg install --muse` after updating dcg.
- An interactive process started through `exec_command` (for example a
  shell) can be fed further input with `write_stdin`. dcg sees only the
  `exec_command` call, not the input written to it later. The same limit
  applies to Codex.
- Muse appears to skip a hook whose input is too large (its 1.4.11 binary
  logs "skipping oversized hook input"). A command past that limit would never
  reach dcg.

## Checking it

When Muse appears to be installed (`~/.config/muse` exists, or `muse` is on
`PATH`), `dcg doctor` reports the `muse_hook` check: registered, missing, or
registered without the matcher or `--agent muse` dcg installs. `dcg doctor
--fix` registers or refreshes it. To test by hand without starting Muse:

```bash
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"git reset --hard"},"turn_id":"t1"}' \
  | dcg --agent muse
```

This prints the deny document above. The same payload with `git status`
prints nothing.
