"""Shared adapter machinery: timed subprocess runs recorded into the bundle,
and the relative-path convention every finding uses."""

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .. import envelope


@dataclass
class Completed:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    wall_s: float
    user_s: float
    sys_s: float
    max_rss_kb: int | None = None


def _drain(stream, sink: list[bytes]) -> None:
    sink.append(stream.read())
    stream.close()


def run_timed(argv: list[str], cwd: Path | None = None, timeout: int | None = None,
              env: dict | None = None) -> Completed:
    """Run one tool invocation, capturing output, the child's CPU time and its
    peak resident set. Deterministic environment: LC_ALL=C so tool output and
    any sort inside a tool are locale-independent.

    The child is reaped with wait4, so its CPU time and ru_maxrss are its own
    (and those of the descendants it waited for). A before/after difference
    of RUSAGE_CHILDREN is not: the per-file adapters run a dozen invocations
    at once from a thread pool, and each difference would also count every
    other invocation that finished in between.

    The recorded argv is the tool's; the envelope prefix (cgroup join and
    CPU set) is applied here and recorded once in meta.json instead."""
    full_env = dict(os.environ)
    full_env["LC_ALL"] = "C"
    if env:
        full_env.update(env)
    t0 = time.monotonic()
    p = subprocess.Popen(envelope.wrap_argv(argv), cwd=cwd, env=full_env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out_b: list[bytes] = []
    err_b: list[bytes] = []
    readers = [threading.Thread(target=_drain, args=(p.stdout, out_b), daemon=True),
               threading.Thread(target=_drain, args=(p.stderr, err_b), daemon=True)]
    for r in readers:
        r.start()
    # The timeout kills from a timer thread. The child is first waited for
    # without being reaped (WNOWAIT), so its pid cannot be reused while the
    # timer can still fire; only then is it reaped for its rusage.
    lock = threading.Lock()
    state = {"exited": False, "timed_out": False}

    def expire() -> None:
        with lock:
            if not state["exited"]:
                state["timed_out"] = True
                os.kill(p.pid, signal.SIGKILL)

    timer = threading.Timer(timeout, expire) if timeout is not None else None
    if timer:
        timer.daemon = True
        timer.start()
    os.waitid(os.P_PID, p.pid, os.WEXITED | os.WNOWAIT)
    with lock:
        state["exited"] = True
    if timer:
        timer.cancel()
    _, status, ru = os.wait4(p.pid, 0)
    p.returncode = os.waitstatus_to_exitcode(status)   # reaped here; Popen must not wait again
    timed_out = state["timed_out"]
    wall = time.monotonic() - t0
    for r in readers:
        r.join()
    out = b"".join(out_b).decode(errors="replace")
    err = b"".join(err_b).decode(errors="replace")
    rc = 124 if timed_out else p.returncode
    return Completed(list(argv), rc, out, err, wall, ru.ru_utime, ru.ru_stime, ru.ru_maxrss)


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
