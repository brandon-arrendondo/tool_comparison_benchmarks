"""Compilation databases for the two build-based tools, Infer and Frama-C.

Real-world: the checkout's own `compile_commands.json` (written by aurora-lint's
`playbooks/setup-compile-commands.yml`; not part of the corpus pin, so its
sha256 goes into the bundle), cut down to the comparison scope and to one
entry per source file. The scope is the fileset every other tool is measured
over: under one of the codebase's curated cppcheck `source_dirs`, and not hit
by one of aurora-lint's `--exclude` globs, both read from the pinned
aurora-lint checkout as the other adapters read them. A build that compiles a
TU twice (curl builds lib/ for the shared and the static library) would
otherwise be captured and analysed twice, inflating both the clock and the
finding count. Ported from aurora-lint's bench/realworld_runner.py
(`_filtered_compile_db`, `_in_comparison_scope`).

Juliet: there is no build, so a CWE directory gets a database of its own, one
`gcc -c -I<testcasesupport>` entry per test-case file -- the compile command
aurora-lint's bench/competitors.py handed `infer capture` file by file.
"""

import hashlib
import json
import os
from pathlib import Path

from . import al_bench

COMPILE_DB_NAME = "compile_commands.json"


def _in_scope(cfg: dict):
    rr = al_bench.modules()["realworld_runner"]
    path = str(cfg["path"])
    dirs = [os.path.realpath(d)
            for d in (rr._expand(cfg.get("cppcheck", {}).get("source_dirs", []), path) or [path])]
    excludes = rr._sqc_exclude_patterns(cfg)

    def ok(src: str) -> bool:
        real = os.path.realpath(src)
        if not any(real == d or real.startswith(d.rstrip("/") + "/") for d in dirs):
            return False
        return not any(p.search(real.replace("\\", "/")) for p in excludes)

    return ok


def entry_source(e: dict) -> Path:
    src = e.get("file", "")
    if not os.path.isabs(src):
        src = os.path.join(e.get("directory", ""), src)
    return Path(src)


def filtered(cfg: dict, dest: Path) -> dict:
    """Write the in-scope subset of a codebase's compile DB to `dest` and
    describe it: {'source', 'sha256', 'entries_total', 'entries_in_scope',
    'path'}; 'path' is None when the checkout has no database or nothing in
    it is in scope, and the tool then has nothing to run on."""
    src = Path(cfg["path"]) / COMPILE_DB_NAME
    info = {"source": COMPILE_DB_NAME, "sha256": None, "entries_total": 0,
            "entries_in_scope": 0, "path": None}
    if not src.is_file():
        info["source"] = None
        return info
    raw = src.read_bytes()
    info["sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        entries = json.loads(raw)
    except ValueError:
        return info
    in_scope = _in_scope(cfg)
    kept, seen = [], set()
    for e in entries:
        s = entry_source(e)
        if s.suffix != ".c":
            continue
        real = os.path.realpath(s)
        if real in seen or not in_scope(real):
            continue
        seen.add(real)
        kept.append(e)
    kept.sort(key=lambda e: os.path.realpath(entry_source(e)))
    info["entries_total"] = len(entries)
    info["entries_in_scope"] = len(kept)
    if kept:
        dest.write_text(json.dumps(kept, indent=1))
        info["path"] = str(dest)
    return info


def juliet(files: list[Path], support_dir: Path, dest: Path) -> Path:
    """A database compiling each Juliet test case on its own, as `gcc -c`
    with the suite's support directory on the include path."""
    entries = [{"directory": str(f.parent), "file": str(f),
                "arguments": ["gcc", "-c", f"-I{support_dir}", str(f), "-o", "/dev/null"]}
               for f in sorted(files)]
    dest.write_text(json.dumps(entries, indent=1))
    return dest
