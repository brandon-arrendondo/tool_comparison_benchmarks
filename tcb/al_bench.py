"""The pinned aurora-lint checkout's own benchmark conventions, loaded from
.cache/aurora-lint-<sha>/bench so this harness runs every tool the way
aurora-lint's benchmark does at that commit and cannot drift from it:

  * the per-codebase configuration (scan path, `-d`, `-I`, `--exclude`,
    the manifest under conf/realworld/, and cppcheck's / clang-tidy's
    include lists and source dirs) -- `bench.realworld_runner.CODEBASES`
    and its `_build_*_cmd` helpers;
  * Juliet's OMITBAD/OMITGOOD section parser -- `bench.analyzer.
    parse_c_file_sections` -- which decides whether a finding's line sits
    in a bad (defect) or good (fixed) region of a test case.

Nothing else of aurora-lint's bench package is used: no database, no
runner. The version of these conventions is therefore the pinned SHA.
"""

import importlib
import sys
from pathlib import Path

from .check import aurora_lint_checkout, aurora_lint_binary
from .pins import BENCH_ROOT

_loaded: dict = {}


def modules() -> dict:
    """{'realworld_runner': module, 'analyzer': module, 'config': module}."""
    if _loaded:
        return _loaded
    co = aurora_lint_checkout()
    if not (co / "bench").is_dir():
        raise RuntimeError(f"pinned aurora-lint checkout missing at {co}: run `tcb build-aurora-lint`")
    # aurora-lint's bench reads SQC_BENCH_ROOT itself; we share the default.
    import os
    os.environ.setdefault("SQC_BENCH_ROOT", str(BENCH_ROOT))
    sys.path.insert(0, str(co))
    try:
        for name in ("config", "realworld_runner", "analyzer"):
            _loaded[name] = importlib.import_module(f"bench.{name}")
    finally:
        sys.path.remove(str(co))
    # Point its notion of the sqc binary at the build under .cache/.
    _loaded["realworld_runner"].SQC_BIN = aurora_lint_binary()
    return _loaded


def codebase_config(name: str) -> dict:
    cfg = modules()["realworld_runner"].CODEBASES.get(name)
    if cfg is None:
        raise KeyError(f"{name!r} is not a codebase the pinned aurora-lint benchmarks")
    return cfg


def juliet_sections(c_file: Path) -> dict:
    """{'bad_lines': set, 'good_lines': set, 'flaw_lines': set} for one test case."""
    return modules()["analyzer"].parse_c_file_sections(c_file)


def per_cwe_manifest(cwe_dir_name: str) -> Path | None:
    """aurora-lint's fast-mode manifest for a Juliet CWE directory
    (rules_templates/cwe/CWE-<n>.toml at the pinned commit), or None when
    that commit has none for it."""
    import re
    m = re.match(r"CWE(\d+)_", cwe_dir_name)
    if not m:
        return None
    p = aurora_lint_checkout() / "rules_templates" / "cwe" / f"CWE-{m.group(1)}.toml"
    return p if p.exists() else None


def full_manifest() -> Path:
    return aurora_lint_checkout() / "rules_templates" / "rules-all.toml"
