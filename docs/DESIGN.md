# tool_comparison_benchmarks — design note (aurora_lint task 1391)

Status: approved 2026-09-20; phase 1 built. Public repo, so ADR-0007 (no
defect locations, no unfixed-disclosure detail), Apache-2.0 + NOTICE first,
Postgres-blind, no node names in committed content, no vendored tools.

## What it is

A standalone harness that runs aurora-lint and its competitors (cppcheck,
clang-tidy; Infer and Frama-C spec'd, run later) on the same pinned inputs
and produces, with **one command per table**, the numbers the comparison
paper (`cert_c_tool_comparison_paper`, task 1390) prints. Everything a
reproducer needs is named by a SHA or a hash and checked before a run:

| Input | Pinned by | Asserted by |
|---|---|---|
| aurora-lint | tag + SHA in `pins/aurora_lint.json`; built from source at that SHA into `.cache/` (or a release binary by sha256) | `tcb check` compares `aurora-lint --version` + the build's SHA |
| competitors | `pins/tools.json`: version, install origin (apt.llvm.org package version, distro package, opam switch, prebuilt sha256), expected resolved path | `tcb check` — version string **and** origin/path, since a PyPI shim and apt.llvm.org both print 21.x (aurora_lint 929) |
| corpora | `pins/corpus.json`: a copy of aurora-lint's `data/benchmark_repos.json` **at the pinned aurora-lint SHA** (name, URL, commit, scope globs) plus Juliet `f88433e`; the copy records which aurora-lint SHA it was taken from | `tcb check` = corpus-check semantics (detached at pin, clean, no gitignored `*.c`/`*.h`) |
| labels | `pins/labels.json`: `benchmark_adjudication` SHA | read through `git show <sha>:data/<project>/adjudication.csv`; competitor labels, when 1390 adjudicates them, come from the same repo keyed `(tool, project, commit, file, line, check_id)` |
| mapping | `mapping/<tool>.json` (competitor check id → CERT rule(s) / CWE(s), `source: hand-made`, unmapped counted never dropped) | its sha256 + git blob is written into every bundle and printed on every table |
| environment | recorded, not pinned: distro, kernel, glibc, CPU, RAM, tool versions+paths, `dpkg-query -W '*-dev'` list + hash (aurora_lint 903, 1362) | written to `meta.json`; tables print the hash |

## Repo layout

```
LICENSE  NOTICE  README.md            Apache-2.0, attribution, the how-to
pins/    aurora_lint.json tools.json corpus.json labels.json
mapping/ cppcheck.json clang-tidy.json infer.json frama-c.json
manifests/ juliet_cwes.txt           the one CWE list every tool runs
tcb/     Python package, CLI `python -m tcb`
  check.py   pins + tools + corpora + Juliet + environment; exit nonzero with the remedy per row
  env.py     environment record (one function, every run)
  tools/     one adapter per tool: build_cmd(), parse() -> findings; aurora_lint.py wraps
             `aurora-lint --export` (fast per-CWE manifest and full mode are two tool ids)
  runners/   juliet.py (per-CWE, section classification as bench/competitors.py does today),
             realworld.py (per codebase, scope globs applied)
  bundle.py  the run bundle writer/reader (below)
  timing.py  controlled timing protocol (aurora_lint 918)
  tables.py  one function per paper table
  selfcheck.py  reruns golden samples and cmp's
tests/   golden/ (tiny stored exports per tool), unit tests
docs/    DESIGN.md (this), reproducing.md (cross-machine check per tool)
runs/    gitignored run bundles
```

**How it consumes aurora-lint.** As a pinned *binary*, not as a library:
`tcb build-aurora-lint` clones the tag/SHA into `.cache/aurora-lint-<sha>`
and `cargo build --release`; the codebase configs (scan path, `-d`, `-I`,
`--exclude`, per-codebase manifests under `conf/realworld/`) are read from
that checkout at that SHA, so the invocation is the one aurora-lint's own
`bench/realworld_runner.py` makes and drifts with it, not with us. Importing
`bench` as a library would tie this repo to aurora-lint's Python internals
and its `data/benchmarks.db`; a binary + files at a SHA is what a stranger
can reproduce. The aurora-lint `bench/` code is unchanged by this task
(its `realworld_runner`/`competitors` keep working for aurora-lint's own
purposes; 766/903/929/1362/918 get closed by *this* harness, and their
task notes will say so).

## The run bundle (the seam to everything else)

`runs/<tool>-<version>-<utc>/` = `meta.json` (every pin as asserted, the
environment, the exact command lines, mapping hashes, wall/CPU time),
`findings.jsonl` (one record per finding: tool, project, codebase_commit,
file_path relative to the corpus root, line, column, check_id, severity,
message; Juliet adds cwe, testcase, section classification), `per_file.csv`,
and for Juliet `per_cwe.csv`. Sorted on the full key, byte-identical per
(pins, machine) — `tcb selfcheck` proves that on a small fixed sample per
tool against `tests/golden/`. This is what `benchmarking_db` ingests on its
side (schema agreed with the benchmark node first; nothing in this repo knows Postgres),
what 1390 adjudicates from, and what the paper's tables are computed from.

**Findings-level for every tool** (aurora_lint 766): cppcheck via
`--xml-version=2` per location; clang-tidy via `-export-fixes`/YAML or the
`file:line:col: warning: ... [check]` text, both parsed to records, never to
counts. Native ids stay native in the bundle; the mapping is applied only
when a table asks for CERT/CWE columns.

## What may be committed, and how a reader regenerates the rest

Raw runs are working data and never leave the machine that made them:
`runs/` is gitignored because a finding record locates a construct in a
pinned corpus, which is exactly what ADR-0007 keeps out of a public
repository until the upstream fix has landed. The same rule covers
`tests/golden/`: golden exports are built from **Juliet and synthetic
inputs only**, never from a real-world corpus. What may be committed is
derived and aggregate -- per-CWE and per-project counts, rates, confidence
intervals, timing distributions, environment hashes -- each with a footer
naming every pin and hash it was computed from, and never a per-finding
row. A reader regenerates the raw runs from the pins alone: `tcb check`,
`tcb build-aurora-lint`, then the runner commands the README lists, on any
machine that provisioned the pinned tools and corpora; the derived tables
must then reproduce to the decimal on a like environment, and the
environment record says how alike it was. A published result is cited by
five things: aurora-lint SHA, benchmark_adjudication SHA, this repository's
SHA, each tool's version (plus origin/digest) and the corpus pins.

The bundle schema (`tcb-bundle/1`, bundle.py) is agreed with the benchmark
node before anything ingest-facing is written; the seam stays a file.

## Determinism and timing

Sorted file walks in every invocation (`find | LC_ALL=C sort`, sorted
globs), one process per tool invocation, exports sorted on the key; the
reproducibility doc carries the cross-machine expectation per tool, in the
shape of aurora-lint's `docs/reproducing-published-numbers.rst`. Timing
only from `tcb timing --tool T --target C --repeats N [--cold]`: refuses
under contention (load average, other analyzer processes), one node,
sequential, per-repeat wall + user/sys, reports median/min/max/MAD, and is
the *only* source a timing table reads; `duration` in ordinary runs is
informational.

## Tables (one command each; the paper's Makefile calls these)

`tcb table juliet-per-cwe | juliet-summary | realworld-counts |
realworld-precision --labels <sha> | timing | environment --bundles ...`
→ CSV + Markdown + a `facts.json` the paper's `gen_facts_tex.py` pattern can
read. Every table footer names the pins and hashes it was computed from.

## Phases

1. Skeleton: LICENSE/NOTICE/README, `pins/*`, `tcb check` (tools, corpora,
   Juliet, aurora-lint build), `env.py`, bundle writer. Usable alone.
2. Adapters + runners for aurora-lint (both modes), cppcheck, clang-tidy;
   findings-level bundles for Juliet and real-world; mapping files.
3. `selfcheck` + golden samples; `reproducing.md`.
4. `timing`.
5. `tables`, README walkthrough verified command by command, demo run:
   three tools on Juliet + libcrc + lua, selfcheck green.

Not in scope: adjudicating competitor findings (1390), Postgres ingest
(benchmarking_db), re-measuring Infer/Frama-C (specs and checks only).
