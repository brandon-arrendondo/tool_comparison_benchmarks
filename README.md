# tool_comparison_benchmarks

A reproducible harness for comparing [aurora-lint](https://github.com/brandon-arrendondo/aurora-lint)
with other C static analyzers (cppcheck, clang-tidy, Infer, Frama-C) on the
same pinned inputs, and for regenerating every table of the comparison
paper with one command each.

Everything a number depends on is named by a commit, a version or a hash
under `pins/`, and asserted before a run. A published result is
reproducible by citing:

| Input | Where it is pinned |
|---|---|
| aurora-lint commit (and version) | `pins/aurora_lint.json` |
| each comparison tool: version, install origin, resolved path | `pins/tools.json` |
| the real-world corpora at their commits, and the Juliet suite commit | `pins/corpus.json` |
| the adjudicated labels (`benchmark_adjudication` commit) | `pins/labels.json` |
| the competitor-check → CERT/CWE mapping | `mapping/` (hash printed on every table) |
| this repository's own commit | `git rev-parse HEAD` |

The environment a run was measured in (distro, glibc, CPU, installed
`*-dev` packages) is *recorded* into every run, not pinned: it is the one
input no commit names, and a reproducer diffs it before reading a
mismatch as a tool difference.

## Status

Phase 1 of 5 (see `docs/DESIGN.md`): pins, checks, environment record,
aurora-lint build, run-bundle format. Runners, mapping data, self-check,
timing protocol and tables follow in that order.

## Setup

Provision the corpora and tools as aurora-lint's
[benchmark-setup](https://github.com/brandon-arrendondo/aurora-lint/blob/main/docs/benchmark-setup.rst)
describes — the same `SQC_BENCH_ROOT` (default `~/toolchain`) serves both —
then:

```bash
python3 -m tcb build-aurora-lint         # clone + cargo build the pinned commit into .cache/
python3 -m tcb check --labels-repo ../benchmark_adjudication
```

`check` prints one row per assertion (tool version, resolved path, package
origin; every corpus at its pin, clean, no stray `.c`/`.h`; the Juliet
commit; the built aurora-lint's commit and version; the labels commit
reachable) and exits nonzero with a remedy on every row that is off. A run
refuses to start on any failed row and writes the rows it passed into its
bundle.

```bash
python3 -m tcb env                       # what a run bundle records about this machine
python3 -m tcb bundles                   # list run bundles under runs/
python3 -m unittest discover -s tests    # synthetic-input tests, no tools or corpora needed
```

## What is committed and what stays local

Raw runs — `runs/<tool>-<version>-<target>-<utc>/` with one record per
finding — stay local and gitignored: they locate findings in the pinned
corpora, and this repository is public. What may be committed is derived
and aggregate: per-CWE and per-project counts, rates and intervals, each
with a footer naming the pins and hashes it was computed from. Nothing
committed here carries a `(file, line)` of a real-world corpus; the labeled
sample of competitor findings, when it exists, lives in
`benchmark_adjudication` under that repository's review.

## License

Apache-2.0 (`LICENSE`, unmodified text; attribution in `NOTICE`). The tools
and corpora this harness drives are not part of it and are pinned, never
vendored; each carries its own license.
