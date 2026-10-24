# Performance Baselines

This directory stores JSON artifacts produced by `scripts/perf_baseline.py`.

## Key Improvements

### Repeated stdin-provenance scans (2026-10-12, #555)

`2026-10-12-issue-555-comparison.json` retains the live interleaved
incumbent/candidate samples: 25 measured pairs and 5 warmups for each of 33
command/history combinations, with wall time, child CPU, paired bypass floor,
binary hashes, verdict requirements and separate instrumented phase probes.
The candidate changes only necessary-byte gating of the existing stdin
readers. Its 300-line Python median improved from 106.9 to 78.0 ms with
history off; the short command and compound command were essentially unchanged.
The database controls use small fresh databases and explicit write locks,
not the reporter's 275 MB history database. The host load varied during the
run; these samples are diagnostic evidence, not an absolute-gate certificate.

The initial run during concurrent compilation was rejected on an unexpected
`ask`; the retained completed run validates every timed verdict. The retained
artifact's command/parameter/environment fields were annotated afterwards
from the exact fixture set and invocation; its measurements are unchanged.

Validation: all-target check and strict Clippy, formatting, 20 hook-output
tests, 48 harness assertions and 372 E2E checks passed. All ten Criterion
`issue_555` cases completed with their correctness prechecks (`--sample-size
10 --warm-up-time 0.2 --measurement-time 0.5`); the warmed 300-line Python
estimate was 58.8 ms, separate from fresh-process latency. The serial library
suite passed 4,634 tests with 4 ignored and these two existing failures:

- `placeholder_gt_in_quoted_interpreter_body_is_not_a_redirect_363`
- `quoted_heredoc_into_non_shell_interpreter_is_not_a_shell_launcher`

Incumbent and candidate diagnostic probes for those Markdown/interpreter
shapes both return conservative `indeterminate`. A shared-proof contention
failure in `transfers_cannot_replace_executables_used_by_the_data_proof_543`
passed in isolation and in the serial suite.

### Lazy Pack Registry + Lazy Regex Compilation (2026-01-11)

Before lazy compilation (175ms p50) vs After (3.1ms p50) = **56x improvement**

| Case | Before p50 | After p50 | Improvement |
|------|------------|-----------|-------------|
| quick_reject (ls -la) | ~175ms | 3.1ms | 56x |
| safe_keyword (git status) | ~175ms | 16ms | 11x |
| destructive_keyword | ~175ms | 16.7ms | 10x |
| bypass | 1.55ms | 1.8ms | same |

Max RSS reduced from ~15MB to ~5-7MB for common cases.

## Guidelines

- Use stable filenames (date or tag) so diffs are easy to review.
- Do not overwrite existing baselines; add new files when re-measuring.
- Record the command line and environment in the baseline JSON itself.

## Example

```
./scripts/perf_baseline.py --bin ./target/release/dcg --output perf/baselines/2026-01-10.json
```

## Integrated hook diagnostics (2026-10-12, #555)

The first integrated stage of AST, stdin-provenance, redaction, and profiling
changes was measured separately from the earlier isolated stdin-provenance
comparison.
The earlier artifacts and notes above are unchanged.

- [`2026-10-12-issue-555-integrated-diagnostic-disabled-enabled.json`](2026-10-12-issue-555-integrated-diagnostic-disabled-enabled.json)
  retains all 16 shapes across two history profiles, with 30 measured pairs
  and three warmups per shape/profile.
- [`2026-10-12-issue-555-integrated-diagnostic-seeded-locked.json`](2026-10-12-issue-555-integrated-diagnostic-seeded-locked.json)
  retains six shapes across seeded and writer-locked profiles, with 15
  measured pairs and three warmups. Each seeded database uses 247,625
  synthetic rows plus its initialization row.
- [`2026-10-12-issue-555-integrated-diagnostic-summary.json`](2026-10-12-issue-555-integrated-diagnostic-summary.json)
  contains the complete 44-row results appendix, including wall/CPU tails,
  paired differences, rule identities, phase data, and verification counts.
- [`2026-10-12-issue-555-integrated-diagnostic-host-storage.json`](2026-10-12-issue-555-integrated-diagnostic-host-storage.json)
  records CPU affinity/quota, memory limit, and filesystem type.
- [`2026-10-12-issue-555-development-phase2-profiles.json`](2026-10-12-issue-555-development-phase2-profiles.json)
  preserves the earlier development call-count observations. It is an
  instrumented development probe, not an untouched-incumbent certificate.

The raw integrated comparisons both passed: 4,560 measured invocations, 528
warmups, 88 separate phase invocations, and eight untimed security controls.
Candidate nested-heredoc denial is mandatory; the incumbent's known silent
allow remains recorded as an untimed gap. The 300-line Python wall median
decreased from 108.326 to 65.393 ms with history disabled and from 97.694 to
55.745 ms with a small enabled database. Large quoted data and commit-message
cases also showed substantial CPU reductions. Some tail measurements were
worse, and the writer lock still added roughly 49 ms of shutdown wait.

The measured candidate SHA-256 is
`77265aab4c6444a5094ca9408e6e0b038f9702dc3686460fef37cd11296bd89d`.
It was compiled from a dirty integrated tree containing upstream changes
through `ecf3fc08ccb04485aef58c584c8c24d81295c712` plus this investigation's
changes, before a separate robot-output-only correction, test repair, and
subsequent built-in filesystem regex preparation optimization.
Its embedded SHA is not an exact source attestation. These diagnostic
artifacts do not replace the absolute gate or certify the reporter's loaded
production environment. See the [measurement guide](../../docs/performance-issue-555.md)
for binary/compiler identities, the representative 24-row table, storage
results, remaining phase costs, and interpretation limits.
