"""clang-tidy with `-checks=-*,cert-*,clang-analyzer-*`, `-- -std=c11` and
the codebase's include list, as aurora-lint's runner invokes it.

One invocation per translation unit, run in parallel and parsed
separately: the runner's `find | xargs -P` pipeline interleaves the
workers' stdout, which is fine for counting and not for records. A
diagnostic clang-tidy prints while compiling one TU that points into a
header is kept, attributed to the header; the same header diagnostic
repeated from several TUs collapses to one record (the bundle records
how many exact duplicates were dropped).
"""

import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import al_bench
from .base import BaseAdapter, Completed, relpath, run_timed

CHECKS = "-checks=-*,cert-*,clang-analyzer-*"
DIAG = re.compile(r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+): (?P<sev>warning|error): (?P<msg>.*?) \[(?P<check>[^\]]+)\]$")


def primary_check(bracket: str) -> str:
    """clang-tidy lists every alias a diagnostic belongs to,
    `[cert-dcl37-c,cert-dcl51-cpp]`; the record keeps the first one in the
    enabled families (cert-*, then clang-analyzer-*), which is the id the
    mapping is written against."""
    ids = [x.strip() for x in bracket.split(",") if x.strip()]
    for fam in ("cert-", "clang-analyzer-"):
        for x in ids:
            if x.startswith(fam):
                return x
    return ids[0] if ids else bracket


def parse_text(text: str, root: Path, only_file: Path | None = None) -> list[dict]:
    recs = []
    for line in text.splitlines():
        m = DIAG.match(line)
        if not m:
            continue
        if m.group("sev") == "error":
            continue          # a compile error, not a check finding
        if only_file is not None and Path(m.group("file")).name != only_file.name:
            continue
        recs.append(dict(file_path=relpath(m.group("file"), root), line=int(m.group("line")),
                         column=int(m.group("col")), check_id=primary_check(m.group("check")),
                         severity="warning", message=m.group("msg")))
    return recs


def _find_sources(source_dirs: list[str], excludes: list[str]) -> list[Path]:
    """The TUs the runner's `find` would pass, sorted."""
    out = []
    for sd in source_dirs:
        for p in Path(sd).rglob("*.c"):
            s = str(p)
            if any(_glob_match(pat, s) for pat in excludes):
                continue
            out.append(p)
    return sorted(set(out))


def _glob_match(pat: str, s: str) -> bool:
    # find's `! -path 'PAT'` is fnmatch over the whole path
    import fnmatch
    return fnmatch.fnmatch(s, pat)


class Adapter(BaseAdapter):
    def version(self) -> str:
        m = re.search(r"LLVM version (\d+\.\d+\.\d+)", run_timed(["clang-tidy", "--version"]).stdout)
        return m.group(1) if m else "unknown"

    def _run_files(self, files: list[Path], extra: list[str], root: Path, jobs: int,
                   only_own: bool) -> tuple[list[Completed], list[dict]]:
        def one(f: Path):
            done = run_timed(["clang-tidy", CHECKS, str(f), "--", "-std=c11", *extra], timeout=600)
            return done, parse_text(done.stdout, root, only_file=f if only_own else None)

        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(one, files))
        return [d for d, _ in results], [r for _, rs in results for r in rs]

    def run_realworld(self, cfg: dict, workdir: Path, jobs: int) -> tuple[list[Completed], list[dict]]:
        rr = al_bench.modules()["realworld_runner"]
        path = str(cfg["path"])
        ct = cfg["clang-tidy"]
        source_dirs = rr._expand(ct.get("source_dirs", []), path)
        includes = rr._expand(ct.get("includes", []), path)
        files = _find_sources(source_dirs, ct.get("exclude", []))
        return self._run_files(files, includes, Path(path), jobs, only_own=False)

    def run_juliet_cwe(self, cwe_dir: Path, support_dir: Path, workdir: Path, jobs: int) -> tuple[list[Completed], list[dict]]:
        files = sorted(cwe_dir.rglob("*.c"))
        return self._run_files(files, [f"-I{support_dir}"], cwe_dir.parent, jobs, only_own=True)
