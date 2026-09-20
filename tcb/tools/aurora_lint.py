"""aurora-lint, the pinned build under .cache/.

Real-world: the exact command aurora-lint's own bench/realworld_runner.py
builds for the codebase at the pinned commit (scan path, manifest under
conf/realworld/, -d/-I/--exclude), with `--export` JSON parsed to records.

Juliet: one invocation per CWE directory, `-d` on the directory and the
suite's support library, as bench/runner.py does. Two tool ids share this
adapter: `aurora-lint` runs the per-CWE manifest (fast mode -- only the
rules mapped to that CWE), `aurora-lint-full` runs rules-all.toml. Both are
reported, because the per-CWE manifest is an asymmetry no competitor has
(task 1390 item 4).
"""

import json
import re
from pathlib import Path

from .. import al_bench
from ..check import aurora_lint_binary
from .base import BaseAdapter, Completed, relpath, run_timed


class Adapter(BaseAdapter):
    def version(self) -> str:
        out = run_timed([str(aurora_lint_binary()), "--version"]).stdout
        m = re.search(r"(\d+\.\d+\.\d+)", out)
        return m.group(1) if m else "unknown"

    def _parse_export(self, path: Path, root: Path) -> list[dict]:
        if not path.exists():
            return []
        recs = []
        for v in json.loads(path.read_text() or "[]"):
            recs.append(dict(file_path=relpath(v["file"], root), line=int(v["line"]),
                             column=int(v.get("column") or 0), check_id=v["rule_id"],
                             severity=str(v.get("severity", "")), message=v.get("message", "")))
        return recs

    def run_realworld(self, cfg: dict, workdir: Path, jobs: int) -> tuple[list[Completed], list[dict]]:
        rr = al_bench.modules()["realworld_runner"]
        argv = rr._build_sqc_cmd(cfg, workdir, "aurora-lint")
        # the runner sizes --jobs to min(cpu, 8); honour the caller instead
        if "--jobs" in argv:
            argv[argv.index("--jobs") + 1] = str(jobs)
        done = run_timed(argv, timeout=4 * 3600)
        return [done], self._parse_export(workdir / "aurora-lint.json", Path(cfg["path"]))

    def run_juliet_cwe(self, cwe_dir: Path, support_dir: Path, workdir: Path, jobs: int) -> tuple[list[Completed], list[dict]]:
        if self.name == "aurora-lint-full":
            manifest = al_bench.full_manifest()
        else:
            manifest = al_bench.per_cwe_manifest(cwe_dir.name)
            if manifest is None:
                return [], []   # the runner records "no per-CWE manifest at this commit"
        out = workdir / f"{cwe_dir.name}.json"
        argv = [str(aurora_lint_binary()), str(cwe_dir), "-m", str(manifest),
                "-d", str(cwe_dir), "-d", str(support_dir), "-e", str(out), "-j", str(jobs)]
        done = run_timed(argv, timeout=2 * 3600)
        return [done], self._parse_export(out, cwe_dir.parent)
