"""Shared adapter machinery: timed subprocess runs recorded into the bundle,
and the relative-path convention every finding uses."""

import os
import resource
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Completed:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    wall_s: float
    user_s: float
    sys_s: float


def run_timed(argv: list[str], cwd: Path | None = None, timeout: int | None = None,
              env: dict | None = None) -> Completed:
    """Run one tool invocation, capturing output and the child's CPU time.
    Deterministic environment: LC_ALL=C so tool output and any sort inside a
    tool are locale-independent."""
    full_env = dict(os.environ)
    full_env["LC_ALL"] = "C"
    if env:
        full_env.update(env)
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    t0 = time.monotonic()
    try:
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, env=full_env, errors="replace")
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        rc = 124
        out = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = (e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
    wall = time.monotonic() - t0
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return Completed(list(argv), rc, out, err, wall,
                     after.ru_utime - before.ru_utime, after.ru_stime - before.ru_stime)


def relpath(path: str, root: Path) -> str:
    """A finding's file relative to the corpus root, the form the oracle key
    uses. Paths outside the root (system headers) are kept absolute so they
    stay distinguishable and a table can drop them as out of scope."""
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except ValueError:
        return path


class BaseAdapter:
    name: str

    def __init__(self, name: str):
        self.name = name

    def version(self) -> str:
        raise NotImplementedError

    # Real-world: one invocation per codebase; returns (Completed list, findings)
    def run_realworld(self, cfg: dict, workdir: Path, jobs: int) -> tuple[list[Completed], list[dict]]:
        raise NotImplementedError

    # Juliet: one CWE directory; returns (Completed list, findings without section)
    def run_juliet_cwe(self, cwe_dir: Path, support_dir: Path, workdir: Path, jobs: int) -> tuple[list[Completed], list[dict]]:
        raise NotImplementedError
