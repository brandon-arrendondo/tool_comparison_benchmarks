"""`tcb timing`: the only path a published runtime figure comes from.

Wall clock is the one figure that depends on the hardware, on what else
the machine is doing, and on whether the inputs were in the page cache,
so an ordinary run's `wall_s` is informational and never printed in a
table. This protocol (aurora-lint task 918) is what makes a runtime
comparable:

  1. one machine for every tool in the comparison -- the record names it;
  2. no contention: refuses to start while the 1-minute load average is
     above `--max-load` or another analyzer / compiler process is running;
  3. repeated: N sequential full runs, each a complete scan of the target,
     never two at once; `--warmup` untimed runs first so a warm-cache
     figure is measured warm, or `--cold` drops the page cache before
     every repeat (needs root; refused otherwise, never faked);
  4. a distribution, not a number: median, min, max and MAD of the scan's
     wall seconds (the tool invocations, harness overhead excluded), plus
     user and system CPU seconds, over the repeats;
  5. the findings of every repeat must be identical (count and keys); a
     repeat that differs invalidates the measurement, because a timing of
     runs that did different work is not a timing of one thing.

The scale that matters for real corpora is minutes versus tens of
minutes, so the default is 3 repeats; raise it when the spread says to.
Results go to runs/timing/<tool>-<target>-<utc>.json (local, like every
raw result) and `tcb table timing` reads them.
"""

import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from . import RUNS_DIR, envelope, pins
from . import env as env_mod
from .bundle import finding_keys, read_meta
from .run import run_juliet, run_realworld

ANALYZER_PROCS = ("aurora-lint", "cppcheck", "clang-tidy", "infer", "frama-c", "cargo", "rustc", "cc1", "make", "ninja")


def contention(max_load: float) -> list[str]:
    """Reasons not to start now: load average, or analyzer/compiler
    processes (other than this python) already running."""
    reasons = []
    load1 = os.getloadavg()[0]
    if load1 > max_load:
        reasons.append(f"1-minute load average {load1:.2f} > {max_load}")
    try:
        ps = subprocess.run(["ps", "-eo", "comm="], capture_output=True, text=True).stdout.split()
    except OSError:
        ps = []
    busy = sorted({p for p in ps if p in ANALYZER_PROCS})
    if busy:
        reasons.append(f"running: {', '.join(busy)}")
    return reasons


def _max_or_none(values) -> int | None:
    vals = [v for v in values if v is not None]
    return max(vals) if vals else None


def drop_caches() -> None:
    if os.geteuid() != 0:
        sys.exit("--cold needs root to write /proc/sys/vm/drop_caches; run under sudo or measure warm")
    subprocess.run(["sync"], check=True)
    Path("/proc/sys/vm/drop_caches").write_text("3\n")


def _one(tool: str, target: str, jobs: int, root: Path) -> tuple[Path, dict]:
    if target.startswith("juliet:"):
        d = run_juliet(tool, [target.split(":", 1)[1]], jobs, root=root)
    elif target == "juliet":
        d = run_juliet(tool, None, jobs, root=root)
    else:
        d = run_realworld(tool, target, jobs, root=root)
    m = read_meta(d)
    return d, m


def measure(tool: str, target: str, repeats: int, jobs: int, warmup: int, cold: bool,
            max_load: float, force: bool) -> Path:
    reasons = contention(max_load)
    if reasons and not force:
        sys.exit("refusing to time under contention: " + "; ".join(reasons) + " (--force overrides and records it)")
    started = datetime.now(timezone.utc).isoformat()
    record = {
        "schema": "tcb-timing/1", "tool": tool, "target": target, "jobs": jobs,
        "repeats": repeats, "warmup": warmup, "cache": "cold" if cold else "warm",
        "contention_at_start": reasons, "forced": bool(reasons and force),
        "environment": env_mod.record(), "pins": pins.pin_digests(),
        "envelope": envelope.active().describe(),
        "started_at": started, "runs": [], "findings_identical": None, "summary": {},
    }
    record["environment"].pop("dev_packages", None)   # the hash is enough here
    with tempfile.TemporaryDirectory(prefix="tcb-timing-") as tmp:
        root = Path(tmp)
        for i in range(warmup):
            if cold:
                drop_caches()
            _one(tool, target, jobs, root)
            print(f"warmup {i + 1}/{warmup} done", flush=True)
        keys0 = None
        for i in range(repeats):
            if cold:
                drop_caches()
            t0 = time.monotonic()
            d, m = _one(tool, target, jobs, root)
            wall = time.monotonic() - t0
            cmds = m["commands"]
            run = {
                "wall_s": round(m["timing"]["scan_wall_s"], 3),   # the scan itself, harness overhead excluded
                "harness_wall_s": round(wall, 3),
                "invocation_wall_sum_s": round(sum(c["wall_s"] for c in cmds), 3),
                "user_s": round(sum(c["user_s"] or 0 for c in cmds), 3),
                "sys_s": round(sum(c["sys_s"] or 0 for c in cmds), 3),
                "invocations": len(cmds), "findings": m["finding_count"], "status": m["status"],
                "load_before": os.getloadavg()[0],
                "cgroup_memory_peak_bytes": m.get("envelope", {}).get("cgroup_memory_peak_bytes"),
                "max_process_rss_bytes": m.get("envelope", {}).get("max_process_rss_bytes"),
                "oom_kills": m.get("envelope", {}).get("oom_kills"),
            }
            keys = finding_keys(d)
            if keys0 is None:
                keys0 = keys
            run["findings_identical_to_first"] = keys == keys0
            record["runs"].append(run)
            print(f"repeat {i + 1}/{repeats}: scan {run['wall_s']:.1f}s  (harness {wall:.1f}s)  "
                  f"cpu {run['user_s'] + run['sys_s']:.1f}s  findings {m['finding_count']}", flush=True)
    walls = [r["wall_s"] for r in record["runs"]]
    med = statistics.median(walls)
    record["findings_identical"] = all(r["findings_identical_to_first"] for r in record["runs"]) \
        and all(r["status"] == "ok" for r in record["runs"])
    record["summary"] = {
        "wall_median_s": round(med, 3), "wall_min_s": round(min(walls), 3), "wall_max_s": round(max(walls), 3),
        "wall_mad_s": round(statistics.median(abs(w - med) for w in walls), 3),
        "cpu_median_s": round(statistics.median(r["user_s"] + r["sys_s"] for r in record["runs"]), 3),
        "cgroup_memory_peak_max_bytes": _max_or_none(r["cgroup_memory_peak_bytes"] for r in record["runs"]),
        "max_process_rss_max_bytes": _max_or_none(r["max_process_rss_bytes"] for r in record["runs"]),
        "valid": record["findings_identical"] and not record["forced"],
    }
    record["finished_at"] = datetime.now(timezone.utc).isoformat()
    out_dir = RUNS_DIR / "timing"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in target)
    out = out_dir / f"{tool}-{safe}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    s = record["summary"]
    print(f"{tool} on {target}: median {s['wall_median_s']}s (min {s['wall_min_s']}, max {s['wall_max_s']}, "
          f"MAD {s['wall_mad_s']}), {record['cache']} cache, {repeats} repeats, valid={s['valid']} -> {out}")
    return out
