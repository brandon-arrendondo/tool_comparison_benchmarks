"""`tcb run realworld` and `tcb run juliet`: check, run one tool on one
target, write a bundle. Every run starts with the pins asserted and
refuses on any failed row; the passing rows go into the bundle."""

import csv
import re
import sys
import time
from pathlib import Path

from . import MANIFESTS_DIR, al_bench, check as check_mod, envelope, pins
from .bundle import Bundle
from . import mapping as mapping_mod
from .tools import adapter as get_adapter
from .tools.base import relpath


def _refuse_on_failed(rows) -> None:
    bad = check_mod.failed(rows)
    if bad:
        for r in bad:
            print(r.line(), file=sys.stderr)
        sys.exit(f"{len(bad)} check(s) failed; not running")


def _dedupe(recs: list[dict]) -> tuple[list[dict], int]:
    seen, out = set(), []
    for r in recs:
        k = (r["file_path"], r["line"], r["column"], r["check_id"], r["message"])
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out, len(recs) - len(out)


def _record(bundle: Bundle, dones, workdir_note: str = "", root: Path | None = None) -> None:
    """Every invocation goes into meta.json with its exit status and CPU
    time. Per-file tools (clang-tidy, cppcheck on Juliet) fail on files they
    cannot preprocess -- a build-generated header the checkout lacks -- and
    keep going; that is partial coverage, not a tool failure, and a table
    must be able to say how partial, so the failed targets are summarised."""
    failed = []
    for d in dones:
        bundle.record_command(d.argv, None, d.returncode, d.wall_s, d.user_s, d.sys_s, workdir_note,
                              max_rss_kb=d.max_rss_kb)
        if d.expected:
            continue
        if d.returncode not in (0, 1) or (d.returncode == 1 and ": error:" in d.stdout + d.stderr):
            target = next((a for a in d.argv[1:] if not a.startswith("-") and Path(a).suffix in (".c", ".h")), d.argv[-1])
            failed.append(relpath(target, root) if root else target)
    cov = bundle.meta.setdefault("coverage", {"invocations": 0, "failed": 0, "failed_targets": []})
    cov["invocations"] += len(dones)
    cov["failed"] += len(failed)
    cov["failed_targets"].extend(failed)


def _tool_coverage(bundle: Bundle, ad) -> None:
    """What a partial-by-design tool (Infer's capture, Frama-C's bounded
    entry points) reached, as the adapter measured it, next to the generic
    invocation counts. A finding count from a partial run is a floor."""
    if getattr(ad, "coverage", None):
        bundle.meta.setdefault("coverage", {})["tool"] = ad.coverage


def _attach_mapping(bundle: Bundle, tool: str, check_ids: list[str]) -> None:
    """The mapping is not applied to the records (they keep the native id);
    its digests and its coverage of this run are recorded so a table can
    print both."""
    bundle.meta["mapping"] = {"digests": mapping_mod.digests(),
                              "coverage": mapping_mod.coverage(tool, check_ids)}


def _tool_check_name(tool: str) -> str | None:
    return None if tool.startswith("aurora-lint") else tool


def _envelope_status(bundle: Bundle, rc, status: str, jobs: int) -> str:
    """Record the envelope and what the run used against it. A run the
    memory cap killed is status `oom`: a result for that tool on that
    target, never something to retry with more memory."""
    env = envelope.active()
    bundle.record_envelope(env.describe(), rc.result)
    if env.cpus is not None and jobs > len(env.cpus):
        bundle.note(f"--jobs {jobs} exceeds the {len(env.cpus)}-CPU envelope; the tool was oversubscribed")
    if rc.result.get("oom_kills"):
        bundle.note(f"memory cap exceeded: {rc.result['oom_kills']} process(es) OOM-killed under "
                    f"memory.max={env.mem_max_bytes}")
        return "oom"
    return status


def run_realworld(tool: str, codebase: str, jobs: int, root: Path | None = None) -> Path:
    tool_rows = check_mod.check_tools([_tool_check_name(tool)]) if _tool_check_name(tool) else []
    rows = tool_rows + check_mod.check_corpus([codebase]) + check_mod.check_aurora_lint()
    _refuse_on_failed(rows)

    entry = next(e for e in pins.corpus()["repos"] if e["name"] == codebase)
    cfg = dict(al_bench.codebase_config(codebase))
    cfg["path"] = pins.corpus_path(codebase)
    ad = get_adapter(tool)
    bundle = Bundle(tool, ad.version(), codebase, root=root)
    bundle.record_checks(rows)
    workdir = bundle.dir / "raw"
    workdir.mkdir()
    t0 = time.monotonic()
    with envelope.tool_run() as rc:
        dones, recs = ad.run_realworld(cfg, workdir, jobs)
    bundle.meta["timing"]["scan_wall_s"] = round(time.monotonic() - t0, 3)
    if ad.tool_options:
        bundle.meta["tool_options"] = dict(ad.tool_options)
    _record(bundle, dones, root=Path(cfg["path"]))
    _tool_coverage(bundle, ad)
    recs, dropped = _dedupe(recs)
    if dropped:
        bundle.note(f"{dropped} exact-duplicate records dropped (same file/line/column/check/message)")
    for r in recs:
        bundle.add_finding(project=codebase, codebase_commit=entry["version"], **r)
    status = "timeout" if any(d.returncode == 124 and not d.expected for d in dones) else "ok"
    status = _envelope_status(bundle, rc, status, jobs)
    _attach_mapping(bundle, tool, [r["check_id"] for r in recs])
    return bundle.finish(status)


def cwe_dirs(names: list[str] | None = None) -> list[Path]:
    """Juliet CWE directories from manifests/juliet_cwes.txt (or the given
    names), in file order; each must exist and hold .c files."""
    root = pins.juliet_root() / pins.corpus()["juliet"]["testcases_subdir"]
    if names is None:
        names = [l.strip() for l in (MANIFESTS_DIR / "juliet_cwes.txt").read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
    out = []
    for n in names:
        matches = [d for d in root.iterdir() if d.name == n or d.name.startswith(n + "_") or d.name.startswith(n)]
        exact = [d for d in matches if d.name == n] or matches
        if len(exact) != 1:
            sys.exit(f"CWE {n!r}: {len(exact)} matching directories under {root}")
        d = exact[0]
        if not any(d.rglob("*.c")):
            sys.exit(f"{d.name}: no .c files -- this suite is C-only; remove it from the manifest")
        out.append(d)
    return out


def run_juliet(tool: str, cwes: list[str] | None, jobs: int, root: Path | None = None) -> Path:
    tool_rows = check_mod.check_tools([_tool_check_name(tool)]) if _tool_check_name(tool) else []
    rows = tool_rows + check_mod.check_corpus(["juliet"]) + check_mod.check_aurora_lint()
    _refuse_on_failed(rows)

    j = pins.corpus()["juliet"]
    support = pins.juliet_root() / j["support_subdir"]
    dirs = cwe_dirs(cwes)
    ad = get_adapter(tool)
    bundle = Bundle(tool, ad.version(), "juliet" if cwes is None else "juliet-" + "+".join(d.name.split("_")[0] for d in dirs), root=root)
    bundle.record_checks(rows)
    workdir = bundle.dir / "raw"
    workdir.mkdir()
    per_cwe = []
    flaw_rows = []
    status = "ok"
    bundle.meta["timing"]["scan_wall_s"] = 0.0
    with envelope.tool_run() as rc:
        for d in dirs:
            cwe_id = re.match(r"(CWE\d+)", d.name).group(1)
            files = sorted(d.rglob("*.c"))
            sections = {f: al_bench.juliet_sections(f) for f in files}
            with_bad = sum(1 for s in sections.values() if s["bad_lines"])
            # Juliet marks each injected defect with a `FLAW:` comment. Only the
            # ones inside a bad region are defects -- the good variants carry
            # `POTENTIAL FLAW:` comments on code the fix makes safe -- so those
            # positions are the recall denominator that travels with the bundle
            # (a CWE-matched bad-region finding within one line of one is a hit,
            # as aurora-lint's own Juliet benchmark counts it).
            n_flaw = 0
            for f, sec in sections.items():
                for ln in sorted(sec["flaw_lines"] & sec["bad_lines"]):
                    flaw_rows.append([cwe_id, relpath(str(f), d.parent), ln])
                    n_flaw += 1
            t0 = time.monotonic()
            dones, recs = ad.run_juliet_cwe(d, support, workdir, jobs)
            bundle.meta["timing"]["scan_wall_s"] = round(bundle.meta["timing"]["scan_wall_s"] + time.monotonic() - t0, 3)
            if not dones and not recs:
                bundle.note(f"{d.name}: skipped -- {tool} has no per-CWE manifest for it at the pinned commit")
                per_cwe.append([d.name, cwe_id, len(files), with_bad, n_flaw, "skipped", 0, 0, 0, 0])
                continue
            _record(bundle, dones, d.name, root=d.parent)
            if any(x.returncode == 124 and not x.expected for x in dones):
                status = "timeout"
            recs, dropped = _dedupe(recs)
            if dropped:
                bundle.note(f"{d.name}: {dropped} exact-duplicate records dropped")
            by_name = {f.name: f for f in files}
            counts = {"bad": 0, "good": 0, "unknown": 0}
            for r in recs:
                f = by_name.get(Path(r["file_path"]).name)
                sec = "unknown"
                if f is not None:
                    s = sections[f]
                    sec = "bad" if r["line"] in s["bad_lines"] else "good" if r["line"] in s["good_lines"] else "unknown"
                elif Path(r["file_path"]).suffix == ".h" or "testcasesupport" in r["file_path"]:
                    sec = "support"
                counts[sec if sec in counts else "unknown"] += 1
                bundle.add_finding(project="juliet", codebase_commit=j["sha"], cwe=cwe_id,
                                   testcase=f.stem if f is not None else None, section=sec, **r)
            per_cwe.append([d.name, cwe_id, len(files), with_bad, n_flaw, "ok", len(recs),
                            counts["bad"], counts["good"], counts["unknown"]])
            print(f"{d.name:55s} files={len(files):5d} findings={len(recs):6d} bad={counts['bad']:5d} good={counts['good']:5d}", flush=True)
    status = _envelope_status(bundle, rc, status, jobs)
    if ad.tool_options:
        bundle.meta["tool_options"] = dict(ad.tool_options)
    _tool_coverage(bundle, ad)
    with open(bundle.dir / "per_cwe.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["cwe_dir", "cwe", "files", "files_with_bad_section", "flaw_lines", "status",
                    "findings", "in_bad_section", "in_good_section", "unclassified"])
        w.writerows(per_cwe)
    with open(bundle.dir / "flaw_lines.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["cwe", "file_path", "line"])
        w.writerows(sorted(flaw_rows))
    _attach_mapping(bundle, tool, [f["check_id"] for f in bundle._findings])
    return bundle.finish(status)
