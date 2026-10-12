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
