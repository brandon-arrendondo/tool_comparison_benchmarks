"""cppcheck, `--enable=all --std=c11`, native check ids (the cert addon is
not enabled; mapping/cppcheck.json is the hand-made bridge to CERT/CWE).

Real-world: the command aurora-lint's bench/realworld_runner.py builds for
the codebase (its cppcheck include list and source dirs), one invocation,
XML v2 on stderr. With `-j` above 1 the invocation also gets a fresh, empty
`--cppcheck-build-dir` inside the run's workdir: without one, cppcheck 2.10
turns off its whole-program checks (`unusedFunction`, the cross-TU `ctu*`
checks) under `-j`, so a parallel run would report less than a serial one.
The directory is new for every run, so no analysis result is ever reused
from a previous run, which would falsify both the findings and the timing.
At `-j 1` no build dir is passed, as aurora-lint's own runner does. Juliet: one invocation per test-case file with the
suite's support directory on the include path, as bench/competitors.py
does; files run in parallel and the bundle sorts, so parallelism cannot
change the output.
"""

import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import al_bench
from .base import BaseAdapter, Completed, relpath, run_timed

JULIET_ARGS = ["--enable=all", "--std=c11", "--xml", "--xml-version=2",
               "--suppress=missingIncludeSystem"]


def parse_xml(text: str, root: Path, only_file: Path | None = None) -> list[dict]:
    """Records from cppcheck's XML v2 (on stderr). `information` rows are
    tool chatter, not findings, and are dropped as aurora-lint's runner
    drops them. With `only_file`, keep only diagnostics located in that
    file (a Juliet run per file must not credit a header's diagnostic to
    every test case that includes it)."""
    if not text.strip() or "<results" not in text:
        return []
    try:
        tree = ET.fromstring(text)
    except ET.ParseError:
        return []
    recs = []
    for err in tree.iter("error"):
        sev = err.get("severity", "")
        if sev == "information":
            continue
        loc = err.find("location")
        if loc is None:
            continue
        f = loc.get("file", "")
        if only_file is not None and Path(f).name != only_file.name:
            continue
        recs.append(dict(file_path=relpath(f, root), line=int(loc.get("line", 0)),
                         column=int(loc.get("column", 0) or 0), check_id=err.get("id", "unknown"),
                         severity=sev, message=err.get("msg", "")))
    return recs


class Adapter(BaseAdapter):
    def version(self) -> str:
        m = re.search(r"Cppcheck (\d+\.\d+(?:\.\d+)?)", run_timed(["cppcheck", "--version"]).stdout)
        return m.group(1) if m else "unknown"

    def realworld_argv(self, cfg: dict, workdir: Path, jobs: int) -> list[str]:
        rr = al_bench.modules()["realworld_runner"]
        argv = rr._build_cppcheck_cmd(cfg) + ["-j", str(jobs)]
        if jobs > 1:
            build = workdir / "cppcheck-build"
            build.mkdir()          # fails if it exists: never a warm build dir
            argv.append(f"--cppcheck-build-dir={build}")
            self.tool_options["cppcheck_build_dir"] = "fresh per run (whole-program checks under -j)"
        else:
            self.tool_options["cppcheck_build_dir"] = None
        return argv

    def run_realworld(self, cfg: dict, workdir: Path, jobs: int) -> tuple[list[Completed], list[dict]]:
        argv = self.realworld_argv(cfg, workdir, jobs)
        done = run_timed(argv, timeout=4 * 3600)
        (workdir / "cppcheck.xml").write_text(done.stderr)
        return [done], parse_xml(done.stderr, Path(cfg["path"]))

    def run_juliet_cwe(self, cwe_dir: Path, support_dir: Path, workdir: Path, jobs: int) -> tuple[list[Completed], list[dict]]:
        files = sorted(cwe_dir.rglob("*.c"))

        def one(f: Path):
            done = run_timed(["cppcheck", *JULIET_ARGS, f"-I{support_dir}", str(f)], timeout=120)
            return done, parse_xml(done.stderr, cwe_dir.parent, only_file=f)

        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(one, files))
        dones = [d for d, _ in results]
        recs = [r for _, rs in results for r in rs]
        return dones, recs
