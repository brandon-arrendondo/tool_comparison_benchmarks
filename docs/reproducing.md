# Reproducing a comparison result

A result of this harness is a function of five named things — the
aurora-lint commit, each tool's version and origin, the corpus pins, the
labels commit, and this repository's commit — plus one recorded thing, the
environment. This page says what a reproducer should expect to match
exactly, what varies with the machine, and how to tell the two apart.

## On one machine: byte-identical

Two runs of one tool id on one target, with `tcb check` clean both times,
write byte-identical `findings.jsonl` and `per_file.csv`/`per_cwe.csv`.
Every invocation walks its inputs in sorted order, runs with `LC_ALL=C`,
and the bundle sorts records on the full key, so neither the tool's own
output order nor the harness's parallelism can reach the file. `meta.json`
differs only in its timestamps and timings.

Check it:

```bash
python3 -m tcb selfcheck            # every tool id on Juliet CWE-416 vs tests/golden/
python3 -m tcb run realworld --tool cppcheck --codebase libcrc
python3 -m tcb run realworld --tool cppcheck --codebase libcrc
cmp runs/cppcheck-*-libcrc-*/findings.jsonl   # the two newest
```

`selfcheck` refuses to compare when the pins differ from the ones the
golden was made under, so a mismatch it does report is drift on this
machine, not a version change.

## Across machines: the environment

What no commit names is the host's toolchain headers and libraries. They
reach the tools differently:

- **clang-tidy** preprocesses each translation unit for real. A header the
  checkout expects from the system (`openssl/ssl.h`, a `-dev` package) that
  is absent fails that TU, which the bundle records under
  `coverage.failed_targets`; a different glibc declares the same function
  behind different feature macros and can move `cert-*` findings that
  depend on a prototype. Compare `coverage` first, then keys.
- **aurora-lint** does not preprocess but reads headers through `-I` for
  cross-file context; the effects are the ones aurora-lint's own
  `docs/reproducing-published-numbers.rst` measures (a missing `-dev`
  package turns into DCL31-C "called without prior declaration" findings,
  a different glibc or `sqlite3.h` moves a handful of cross-file EXP34-C /
  EXP36-C / DCL15-C decisions -- about 0.1 % of keys between two Linux
  distributions).
- **cppcheck** runs with `--suppress=missingIncludeSystem` and its own
  library configuration; it is the least header-sensitive of the three,
  and its version is distro-pinned (`pins/tools.json`), so two nodes on
  the same distribution release should match key for key.
- **Juliet** is self-contained (the suite's own `testcasesupport/`), so
  Juliet bundles are expected to match across machines for every tool;
  `selfcheck` is that expectation made executable.

Every bundle's `meta.json` carries `environment`: distro, kernel, glibc,
CPU, and the installed `*-dev` package list with its sha256. When two
machines disagree on a real-world target, diff those two records before
reading the key diff; a `dev_packages_sha256` that differs names the usual
suspect.

## Directory order

Before aurora-lint `4ac5710f` its finding set depended on the order the
filesystem listed a directory in (a name defined in more than one file
resolved to whichever the walk reached last), so a `cp` or a re-clone of
the same commit could change it. Pins at or after that commit are free of
it; a pin before it must be reproduced on the very checkout, not a copy.
cppcheck and clang-tidy are run one input at a time here and have no such
dependence in this harness.

## Timing

Never compared across machines, and never taken from an ordinary run:
only `tcb timing` (one node, repeated, contention-checked, median and
spread) produces a figure a table prints, and the table names the CPU.
