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

All five phases of `docs/DESIGN.md` are built: pins and checks, adapters
and runners for aurora-lint (two modes), cppcheck and clang-tidy,
findings-level bundles, the check mapping, the self-check, the timing
protocol and the tables. Infer and Frama-C are pinned and checked but have
no adapter yet.

## Setup

Provision the corpora and tools as aurora-lint's
[benchmark-setup](https://github.com/brandon-arrendondo/aurora-lint/blob/main/docs/benchmark-setup.rst)
describes -- the same `SQC_BENCH_ROOT` (default `~/toolchain`) serves both
-- and clone `benchmark_adjudication` beside this repository. Then:

```bash
python3 -m tcb build-aurora-lint         # clone + cargo build the pinned commit into .cache/
python3 -m tcb check --labels-repo ../benchmark_adjudication
```

`check` prints one row per assertion (tool version, resolved path, package
origin; every corpus at its pin, clean, no stray `.c`/`.h`; the Juliet
commit; the built aurora-lint's commit, version, freshness and generated
per-CWE manifests; the labels commit reachable) and exits nonzero with a
remedy on every row that is off. A run refuses to start on any failed row
and writes the rows it passed into its bundle.

## Running

```bash
python3 -m tcb run juliet    --tool aurora-lint            # per-CWE manifest (fast mode)
python3 -m tcb run juliet    --tool aurora-lint-full       # rules-all.toml
python3 -m tcb run juliet    --tool cppcheck
python3 -m tcb run juliet    --tool clang-tidy
python3 -m tcb run realworld --tool cppcheck --codebase lua
```

Each run writes one bundle under `runs/` (see `tcb bundles`): `meta.json`
(the checks as they passed, the environment, every command line with its
exit status and CPU time, mapping digests and coverage), `findings.jsonl`
(one record per finding, sorted), `per_file.csv` and, for Juliet,
`per_cwe.csv`. The Juliet CWE list is `manifests/juliet_cwes.txt`, the
same for every tool; `--cwes` narrows it.

## Tables

One command per table, from bundles, CSV + Markdown, footer naming every
pin and hash:

```bash
python3 -m tcb table juliet-per-cwe      runs/*-juliet-2026*/ --out tables/
python3 -m tcb table juliet-summary      runs/*-juliet-2026*/ --out tables/
python3 -m tcb table realworld-counts    runs/*-lua-*/ runs/*-libcrc-*/ --out tables/
python3 -m tcb table realworld-precision runs/*-lua-*/ --labels-repo ../benchmark_adjudication --out tables/
python3 -m tcb table timing              runs/timing/*.json --out tables/
python3 -m tcb table environment         runs/*/ --out tables/
```

Juliet precision is reported twice: over every finding a tool emits on a
CWE's test cases (`precision_all`), and over the findings whose check the
mapping says reports *that* CWE (`precision_cwe`), which is the like-for-
like figure; `detection` is the share of test cases with a bad region in
which such a finding landed. Real-world precision for a competitor is a
proxy until its own findings are adjudicated (the table says `via
mapping` and prints the label coverage); aurora-lint's is direct.

## Checks that keep it honest

```bash
python3 -m tcb selfcheck                 # every tool on Juliet CWE-416 vs tests/golden/ (Juliet-only goldens)
python3 -m tcb timing --tool cppcheck --target lua --repeats 5   # the only source of a runtime figure
python3 -m tcb mapping-coverage runs/<bundle>                    # what the mapping does not speak for
python3 -m tcb env                                               # what a bundle records about this machine
python3 -m unittest discover -s tests                            # synthetic-input tests
```

`docs/reproducing.md` says what matches byte for byte on one machine,
what the environment moves across machines, and how to tell them apart.

## Open

- `pins/aurora_lint.json` pins commit `92eae76c` with `tag: null`; set the
  tag once `v0.5.2` is cut on that commit.
- `pins/tools.json`: the Debian 12 cppcheck row has no `package_version`
  yet; fill it from `dpkg-query -W cppcheck` on a bookworm node.
- Infer and Frama-C are pinned and checked but have no adapter.
- No timing table has been produced yet: `tcb timing` exists and was
  exercised on a small target; a full contention-free session (every tool,
  the large corpora, N repeats, one machine) is still to run.
- The bundle schema (`tcb-bundle/1`) is not yet agreed with the benchmark
  database's ingest; nothing ingest-facing exists here by design.

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
