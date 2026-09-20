"""The run bundle: one directory per (tool, target) run under runs/, the
only thing a table, a self-check, an ingest or an adjudication reads.

    runs/<tool>-<version>-<target>-<utc>/
        meta.json        pins as asserted (check rows), environment, the exact
                         command lines, timing, mapping digests, status
        findings.jsonl   one record per finding, sorted on the full key
        per_file.csv     findings per file (derived from findings.jsonl)

A finding record is the ground_truth key plus the tool:

    tool, project, codebase_commit, file_path (relative to the corpus root),
    line, column, check_id, severity, message
    -- Juliet adds: cwe, testcase, section (good | bad | support | unknown)

Sorted on (project, file_path, line, column, check_id, message) so two runs
of one tool on one machine over the same pins are byte-identical, which is
what `tcb selfcheck` asserts. Bundles are local working data (gitignored):
they locate findings in the pinned corpora, which is what ADR-0007 keeps out
of a public repository. Committed artifacts are aggregates derived from
them, with their pins in the footer.
"""

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import RUNS_DIR, pins
from . import env as env_mod

FINDING_FIELDS = ["tool", "project", "codebase_commit", "file_path", "line", "column",
                  "check_id", "severity", "message", "cwe", "testcase", "section"]
SORT_KEY = ("project", "file_path", "line", "column", "check_id", "message")


def _key(f: dict) -> tuple:
    return tuple((f.get(k) if f.get(k) is not None else "") for k in SORT_KEY)


class Bundle:
    def __init__(self, tool: str, tool_version: str, target: str, root: Path | None = None):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe = lambda s: "".join(c if c.isalnum() or c in "._-" else "_" for c in s)
        base = (root or RUNS_DIR) / f"{safe(tool)}-{safe(tool_version)}-{safe(target)}-{stamp}"
        self.dir = base
        n = 1
        while self.dir.exists():          # two runs started in the same second
            n += 1
            self.dir = base.with_name(f"{base.name}-{n}")
        self.dir.mkdir(parents=True, exist_ok=False)
        self.meta = {
            "schema": "tcb-bundle/1",
            "tool": tool,
            "tool_version": tool_version,
            "target": target,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "status": "running",
            "pins": pins.pin_digests(),
            "checks": [],
            "environment": env_mod.record(),
            "commands": [],
            "timing": {},
            "mapping": {},
            "notes": [],
        }
        self._findings: list[dict] = []
        self.write_meta()

    # ── recording ──
    def record_checks(self, rows) -> None:
        self.meta["checks"] = [r if isinstance(r, dict) else r.__dict__ for r in rows]
        self.write_meta()

    def record_command(self, argv: list[str], cwd: str | None, returncode: int,
                       wall_s: float, user_s: float | None = None, sys_s: float | None = None,
                       note: str = "") -> None:
        self.meta["commands"].append({
            "argv": list(argv), "cwd": cwd, "returncode": returncode,
            "wall_s": round(wall_s, 3),
            "user_s": None if user_s is None else round(user_s, 3),
            "sys_s": None if sys_s is None else round(sys_s, 3),
            "note": note,
        })

    def add_finding(self, **fields) -> None:
        unknown = set(fields) - set(FINDING_FIELDS)
        if unknown:
            raise ValueError(f"unknown finding fields: {sorted(unknown)}")
        rec = {k: fields.get(k) for k in FINDING_FIELDS}
        rec["tool"] = rec["tool"] or self.meta["tool"]
        self._findings.append(rec)

    def note(self, text: str) -> None:
        self.meta["notes"].append(text)

    # ── finishing ──
    def write_meta(self) -> None:
        (self.dir / "meta.json").write_text(json.dumps(self.meta, indent=2, sort_keys=True) + "\n")

    def finish(self, status: str = "ok") -> Path:
        self._findings.sort(key=_key)
        with open(self.dir / "findings.jsonl", "w") as fh:
            for f in self._findings:
                fh.write(json.dumps(f, sort_keys=True) + "\n")
        per_file = Counter((f["project"], f["file_path"]) for f in self._findings)
        with open(self.dir / "per_file.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["project", "file_path", "findings"])
            for (proj, fp), n in sorted(per_file.items()):
                w.writerow([proj, fp, n])
        self.meta["finished_at"] = datetime.now(timezone.utc).isoformat()
        self.meta["status"] = status
        self.meta["finding_count"] = len(self._findings)
        self.write_meta()
        return self.dir


# ── reading ──

def read_meta(bundle_dir: Path) -> dict:
    return json.loads((bundle_dir / "meta.json").read_text())


def read_findings(bundle_dir: Path) -> list[dict]:
    path = bundle_dir / "findings.jsonl"
    if not path.exists():
        return []
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def finding_keys(bundle_dir: Path) -> set[tuple]:
    """The oracle key of every finding: (project, codebase_commit, file_path,
    line, check_id) -- the unit a label attaches to."""
    return {(f["project"], f["codebase_commit"], f["file_path"], f["line"], f["check_id"])
            for f in read_findings(bundle_dir)}


def list_bundles(root: Path | None = None) -> list[Path]:
    root = root or RUNS_DIR
    if not root.exists():
        return []
    return sorted(p for p in root.iterdir() if (p / "meta.json").exists())
