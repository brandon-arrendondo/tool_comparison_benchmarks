"""Infer, default checkers, native bug types (mapping/infer.json is the bridge
to CERT/CWE). Ported from aurora-lint's bench/: Juliet from
bench/competitors.py, real-world from bench/realworld_runner.py.

Two phases, not `infer run`, so a capture failure is distinguishable from an
analysis failure: Infer exits 0 from `run` even when capture silently
produced nothing.

  capture  `infer capture --keep-going --compilation-database DB`
  analyze  `infer analyze --jobs N`

Real-world: the checkout's compile_commands.json cut to the comparison scope
(tcb/compile_db.py). Capture keeps going past a TU it cannot preprocess
(typically a build-generated header the checkout lacks), because aborting
would report zero findings for a codebase Infer could analyse most of. The
shortfall is recorded instead: `coverage.tool` carries captured against
in-scope TUs and names the ones that failed, and a finding count from a
partial capture is a floor.

Juliet: one CWE directory is one capture of a database holding a `gcc -c
-I<testcasesupport>` entry per test case -- the command bench/competitors.py
handed `infer capture --continue` one file at a time, here captured in one
parallel pass -- then one analysis.

`--jobs` above 1 makes the analysis nondeterministic: the order in which
procedures get their summaries changes what Pulse reports (lua at `--jobs
12` gave 37, 39 and 44 findings on three runs; at `--jobs 1`, 44 every
time). The findings of record therefore come from a `--jobs 1` run, and a
parallel run is for timing; `tool_options.deterministic` says which a
bundle is. Capture is not affected.

`--project-root` is the corpus root, so report paths are relative to it; a
bug Infer attributes outside it (a system header) keeps its absolute path
and a table drops it as out of scope. `infer-out/` is deleted after the
report is copied into the bundle's raw/ directory: on a large codebase it is
gigabytes and nothing reads it again.
"""

import json
import re
import shutil
from pathlib import Path

from .. import compile_db
from .base import BaseAdapter, Completed, relpath, run_timed

# Per phase. Real-world matches aurora-lint's INFER_BUDGET_S; one Juliet CWE
# is far below it.
REALWORLD_TIMEOUT_S = 4 * 3600
JULIET_TIMEOUT_S = 3600

_TRANSLATING_RE = re.compile(r"Starting translating (\d+) files")
# Infer's own "Found N source files to analyze" counts every TU it was handed,
# including ones whose capture died; the clang diagnostic is the honest signal.
_CAPTURE_FAIL_RE = re.compile(r"^(\S+):\d+:\d+: fatal error:", re.MULTILINE)


def parse_report(report: list[dict], root: Path) -> list[dict]:
    """Records from report.json. `column` is -1 when Infer has none."""
    recs = []
    for bug in report:
        f = bug.get("file", "")
        if f and not Path(f).is_absolute():
            f = str(root / f)
        col = bug.get("column", 0)
        recs.append(dict(file_path=relpath(f, root), line=int(bug.get("line", 0)),
                         column=int(col) if isinstance(col, int) and col > 0 else 0,
                         check_id=bug.get("bug_type", "unknown"),
                         severity=str(bug.get("severity", "")).lower(),
                         message=bug.get("qualifier", "")))
    return recs


def capture_coverage(capture_output: str, handed: int, root: Path) -> dict:
    m = _TRANSLATING_RE.search(capture_output)
    attempted = int(m.group(1)) if m else handed
    failed = sorted({relpath(f, root) for f in _CAPTURE_FAIL_RE.findall(capture_output)})
    captured = max(attempted - len(failed), 0)
    return {"tus_handed": handed, "tus_attempted": attempted, "tus_captured": captured,
            "tus_pct": round(100.0 * captured / handed, 1) if handed else 0.0,
            "capture_failures": failed, "partial": captured < handed}


class Adapter(BaseAdapter):
    def version(self) -> str:
        m = re.search(r"Infer version v(\d+\.\d+\.\d+)", run_timed(["infer", "--version"]).stdout)
        return m.group(1) if m else "unknown"

    def _capture_analyze(self, db: Path, root: Path, out: Path, raw: Path, tag: str,
                         jobs: int, timeout: int) -> tuple[list[Completed], list[dict], str]:
        self.tool_options["deterministic"] = jobs == 1
        if jobs > 1:
            self.tool_options["analysis_order"] = ("parallel: Pulse findings vary run to run; "
                                                   "a --jobs 1 run is the findings of record")
        dones = []
        cap = run_timed(["infer", "capture", "--results-dir", str(out), "--project-root", str(root),
                         "--keep-going", "--jobs", str(jobs), "--compilation-database", str(db)],
                        timeout=timeout)
        dones.append(cap)
        (raw / f"{tag}.capture.log").write_text(cap.stdout + cap.stderr)
        recs: list[dict] = []
        if cap.returncode != 124:
            an = run_timed(["infer", "analyze", "--results-dir", str(out), "--project-root", str(root),
                            "--no-progress-bar", "--jobs", str(jobs)], timeout=timeout)
            dones.append(an)
            (raw / f"{tag}.analyze.log").write_text(an.stdout + an.stderr)
            report = out / "report.json"
            if report.exists():
                shutil.copyfile(report, raw / f"{tag}.report.json")
                recs = parse_report(json.loads(report.read_text()), root)
        shutil.rmtree(out, ignore_errors=True)
        return dones, recs, cap.stdout + cap.stderr

    def run_realworld(self, cfg: dict, workdir: Path, jobs: int) -> tuple[list[Completed], list[dict]]:
        root = Path(cfg["path"])
        db = compile_db.filtered(cfg, workdir / "compile_commands.in_scope.json")
        self.tool_options["compile_db"] = {k: v for k, v in db.items() if k != "path"}
        if db["path"] is None:
            self.coverage = {"tus_handed": 0, "tus_captured": 0, "partial": True,
                             "reason": "no compile_commands.json" if db["source"] is None
                             else "no in-scope entries"}
            return [], []
        dones, recs, cap_out = self._capture_analyze(Path(db["path"]), root, workdir / "infer-out",
                                                     workdir, "infer", jobs, REALWORLD_TIMEOUT_S)
        self.coverage = capture_coverage(cap_out, db["entries_in_scope"], root)
        return dones, recs

    def run_juliet_cwe(self, cwe_dir: Path, support_dir: Path, workdir: Path, jobs: int) -> tuple[list[Completed], list[dict]]:
        files = sorted(cwe_dir.rglob("*.c"))
        root = cwe_dir.parent
        db = compile_db.juliet(files, support_dir, workdir / f"{cwe_dir.name}.compile_commands.json")
        dones, recs, cap_out = self._capture_analyze(db, root, workdir / f"{cwe_dir.name}.infer-out",
                                                     workdir, cwe_dir.name, jobs, JULIET_TIMEOUT_S)
        cov = capture_coverage(cap_out, len(files), root)
        self.coverage[cwe_dir.name] = cov
        return dones, recs
