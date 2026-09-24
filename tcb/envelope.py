"""The resource envelope: every tool in a comparison runs on the same fixed
CPU set under the same hard memory cap, so a result cannot be put down to
one tool having more cores or more memory than another.

Two limits, applied to the tool processes and not to the harness:

  CPU set    `--cpus 0,2,4` (or `0-11`). Every tool invocation is started
             through `taskset -c`, so the affinity is inherited by every
             thread and child the tool spawns -- the cap holds even for a
             tool that sizes its own thread pool from the machine rather
             than from `--jobs`.
  memory     `--mem-max 32G`. A cgroup v2 limit (`memory.max`) with swap
             disabled inside it (`memory.swap.max` = 0), so the cap cannot
             be sidestepped by paging. It covers the whole tool run: every
             process of it at once, which is what matters for the per-file
             tools that run a dozen compiler processes in parallel.
             Exceeding it kills the tool; the run is recorded with status
             `oom`, a result in its own right, and is never retried with
             more.

The memory cap needs a cgroup the harness may write to. An unprivileged
user gets one from systemd: the harness re-executes itself as
`systemd-run --user --scope -p Delegate=yes`, moves itself into a
`harness` child of the scope, and gives each run its own `tools-N` child
carrying the limits, so the harness's own memory (the findings it holds)
is never charged to a tool. The CPU set works without systemd.

What is measured, per run, into meta.json:

  cgroup_memory_peak_bytes   `memory.peak` of the run's cgroup: the most
                             memory all the tool's processes held at once.
                             This is the figure the cap is enforced
                             against. It includes page cache the tool's
                             file reads were charged for, so it is an upper
                             bound on resident memory, not RSS.
  max_process_rss_bytes      the largest resident set any single tool
                             process reached (`ru_maxrss` from `wait4`).
                             Available with or without a cgroup.
  oom_kills                  `memory.events` oom_kill for the run.

The envelope itself -- the CPU list and count, the cap, the swap setting and
the mechanism -- goes into the same record, because a runtime or a memory
figure without the envelope it was measured under is not comparable.
"""

import os
import re
import shutil
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

SCOPE_ENV = "TCB_ENVELOPE_SCOPE"
CGROUP_FS = Path("/sys/fs/cgroup")


@dataclass
class Envelope:
    cpus: list[int] | None = None
    mem_max_bytes: int | None = None
    scope: Path | None = None          # the delegated cgroup directory, when a cap is set
    _runs: int = field(default=0, repr=False)

    def describe(self) -> dict:
        mech = []
        if self.cpus is not None:
            mech.append("taskset -c (CPU affinity, inherited by every tool thread and child)")
        if self.mem_max_bytes is not None:
            mech.append("cgroup v2 memory.max + memory.swap.max=0 via systemd-run --user --scope -p Delegate=yes")
        return {
            "cpus": format_cpus(self.cpus) if self.cpus is not None else None,
            "cpu_count": len(self.cpus) if self.cpus is not None else os.cpu_count(),
            "memory_max_bytes": self.mem_max_bytes,
            "memory_swap_max_bytes": 0 if self.mem_max_bytes is not None else None,
            "mechanism": "; ".join(mech) or "none (uncapped)",
        }


_ACTIVE = Envelope()


def active() -> Envelope:
    return _ACTIVE


# ── parsing ──

def parse_cpus(spec: str) -> list[int]:
    """`0,2,4` or `0-5` or a mix; sorted, no duplicates. Every CPU must be
    online, so a typo fails here rather than as a taskset error mid-run."""
    out: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not m:
            raise ValueError(f"bad CPU list element {part!r} in {spec!r}")
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if hi < lo:
            raise ValueError(f"bad CPU range {part!r}")
        out.update(range(lo, hi + 1))
    if not out:
        raise ValueError(f"empty CPU list {spec!r}")
    online = os.sched_getaffinity(0)
    missing = sorted(out - online)
    if missing:
        raise ValueError(f"CPUs {format_cpus(missing)} are not available to this process "
                         f"(available: {format_cpus(sorted(online))})")
    return sorted(out)


def format_cpus(cpus: list[int]) -> str:
    return ",".join(str(c) for c in cpus)


_UNITS = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}


def parse_bytes(spec: str) -> int:
    """`32G`, `512M`, `34359738368`; binary units, as cgroup and systemd
    read them."""
    m = re.fullmatch(r"\s*(\d+)\s*([KMGT]?)(?:I?B)?\s*", spec.upper())
    if not m:
        raise ValueError(f"bad memory size {spec!r} (use e.g. 32G)")
    return int(m.group(1)) * _UNITS[m.group(2)]


# ── activation ──

def reexec_argv(argv: list[str]) -> list[str]:
    """The command that re-runs this tcb invocation inside a delegated
    systemd user scope."""
    return ["systemd-run", "--user", "--scope", "--quiet", "-p", "Delegate=yes",
            sys.executable, "-m", "tcb", *argv]


def _own_cgroup() -> Path:
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            return CGROUP_FS / line[3:].lstrip("/")
    raise RuntimeError("no cgroup v2 entry in /proc/self/cgroup (cgroup v1 host?)")


def activate(cpus: list[int] | None, mem_max_bytes: int | None, argv: list[str]) -> Envelope:
    """Set the envelope for every tool this process runs. With a memory cap
    and not yet inside a delegated scope, re-executes itself inside one and
    does not return."""
    global _ACTIVE
    if cpus is not None and shutil.which("taskset") is None:
        sys.exit("--cpus needs taskset (util-linux)")
    scope = None
    if mem_max_bytes is not None:
        if os.environ.get(SCOPE_ENV) != "1":
            if shutil.which("systemd-run") is None:
                sys.exit("--mem-max needs systemd-run to obtain a delegated cgroup")
            os.environ[SCOPE_ENV] = "1"
            os.execvp("systemd-run", reexec_argv(argv))
        scope = _own_cgroup()
        controllers = (scope / "cgroup.controllers").read_text().split()
        if "memory" not in controllers:
            sys.exit(f"the scope's cgroup has no memory controller (controllers: {' '.join(controllers)}); "
                     "the user systemd instance must delegate memory")
        harness = scope / "harness"
        harness.mkdir(exist_ok=True)
        (harness / "cgroup.procs").write_text(f"{os.getpid()}\n")
        (scope / "cgroup.subtree_control").write_text("+memory\n")
    _ACTIVE = Envelope(cpus=cpus, mem_max_bytes=mem_max_bytes, scope=scope)
    return _ACTIVE


# ── per-run cgroup ──

@dataclass
class RunCgroup:
    path: Path | None
    procs: Path | None
    result: dict = field(default_factory=dict)


def _read_int(p: Path) -> int | None:
    try:
        return int(p.read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _oom_kills(p: Path) -> int | None:
    try:
        for line in p.read_text().splitlines():
            k, _, v = line.partition(" ")
            if k == "oom_kill":
                return int(v)
    except OSError:
        return None
    return 0


@contextmanager
def run_cgroup():
    """A fresh cgroup for one tool run (one bundle), so `memory.peak` is that
    run's own peak. Yields a RunCgroup whose `result` is filled in on exit
    with the peak and the OOM-kill count. Without a memory cap this yields
    an empty RunCgroup and the tool processes stay where the harness is."""
    env = _ACTIVE
    if env.scope is None:
        yield RunCgroup(None, None)
        return
    env._runs += 1
    path = env.scope / f"tools-{env._runs}"
    path.mkdir()
    (path / "memory.max").write_text(f"{env.mem_max_bytes}\n")
    (path / "memory.swap.max").write_text("0\n")
    rc = RunCgroup(path, path / "cgroup.procs")
    try:
        yield rc
    finally:
        rc.result = {
            "cgroup_memory_peak_bytes": _read_int(path / "memory.peak"),
            "oom_kills": _oom_kills(path / "memory.events"),
        }
        try:
            path.rmdir()
        except OSError:
            pass     # a straggler still inside; the scope goes when tcb exits


_CURRENT: RunCgroup | None = None


@contextmanager
def tool_run():
    """What run.py wraps a tool's invocations in: sets the cgroup that
    `wrap_argv` sends every tool process to, for the duration."""
    global _CURRENT
    with run_cgroup() as rc:
        prev, _CURRENT = _CURRENT, rc
        try:
            yield rc
        finally:
            _CURRENT = prev


def wrap_argv(argv: list[str]) -> list[str]:
    """The tool's argv, prefixed so the process joins the run's cgroup and
    takes the CPU set before it execs. One `sh` and one `taskset`, both
    replaced by the tool itself through exec, so the pid the harness waits
    on -- and the rusage it gets back -- is the tool's."""
    env = _ACTIVE
    procs = _CURRENT.procs if _CURRENT is not None else None
    if env.cpus is None and procs is None:
        return list(argv)
    cpus = format_cpus(env.cpus) if env.cpus is not None else ""
    script = ('p=$1; c=$2; shift 2; '
              'if [ -n "$p" ]; then echo $$ > "$p" || exit 125; fi; '
              'if [ -n "$c" ]; then exec taskset -c "$c" "$@"; fi; exec "$@"')
    return ["/bin/sh", "-c", script, "tcb-envelope", str(procs or ""), cpus, *argv]
