"""`tcb selfcheck`: rerun a small fixed sample per tool and compare it to a
stored golden -- the proof that this machine, with these pins, produces
the same findings the goldens were produced with.

The sample is one Juliet CWE (the smallest in manifests/juliet_cwes.txt at
the time of writing, CWE-416, 150 files), run under every tool id. A
golden is Juliet-derived only: Juliet is a public synthetic suite, so its
findings locate nothing in shipped code and can sit in this public
repository (ADR-0007); a golden from a real-world corpus never can. What
is stored per tool: keys.csv (file, line, check id -- the oracle key of
each finding), per_check.csv (check id x section counts), per_cwe.csv,
and golden.json naming the pins the golden was made under, so a mismatch
under different pins is reported as "pins differ", not as drift.

`--update` rewrites the goldens from a fresh run; do that only with the
pins the goldens are meant to describe, and say why in the commit.
"""

import csv
import json
import shutil
import tempfile
from collections import Counter
from pathlib import Path

from . import REPO_ROOT, pins
from .bundle import read_findings, read_meta
from .run import run_juliet
from .tools import TOOLS

GOLDEN_DIR = REPO_ROOT / "tests" / "golden"
SAMPLE_CWE = "CWE416_Use_After_Free"


def _artifacts(bundle_dir: Path) -> dict:
    recs = read_findings(bundle_dir)
    keys = sorted({(r["file_path"], r["line"], r["check_id"]) for r in recs})
    per_check = Counter((r["check_id"], r["section"] or "") for r in recs)
    per_cwe = (bundle_dir / "per_cwe.csv").read_text()
    return {"keys": keys, "per_check": sorted(per_check.items()), "per_cwe": per_cwe}


def _write(tool: str, art: dict, meta: dict) -> Path:
    d = GOLDEN_DIR / tool / SAMPLE_CWE
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "keys.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["file_path", "line", "check_id"])
        w.writerows(art["keys"])
    with open(d / "per_check.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["check_id", "section", "findings"])
        for (cid, sec), n in art["per_check"]:
            w.writerow([cid, sec, n])
    (d / "per_cwe.csv").write_text(art["per_cwe"])
    (d / "golden.json").write_text(json.dumps({
        "tool": tool, "tool_version": meta["tool_version"], "sample": SAMPLE_CWE,
        "aurora_lint_sha": pins.aurora_lint()["sha"], "juliet_sha": pins.corpus()["juliet"]["sha"],
        "pins": meta["pins"], "made_on": {"distro_id": meta["environment"]["distro_id"],
                                            "glibc": meta["environment"]["glibc"]},
        "finding_count": meta["finding_count"],
    }, indent=2, sort_keys=True) + "\n")
    return d


def _read(tool: str) -> dict | None:
    d = GOLDEN_DIR / tool / SAMPLE_CWE
    if not (d / "golden.json").exists():
        return None
    with open(d / "keys.csv") as fh:
        keys = [(r["file_path"], int(r["line"]), r["check_id"]) for r in csv.DictReader(fh)]
    with open(d / "per_check.csv") as fh:
        per_check = [((r["check_id"], r["section"]), int(r["findings"])) for r in csv.DictReader(fh)]
    return {"keys": keys, "per_check": per_check, "per_cwe": (d / "per_cwe.csv").read_text(),
            "golden": json.loads((d / "golden.json").read_text())}


def run(tools: list[str] | None = None, update: bool = False, jobs: int = 8) -> int:
    tools = tools or list(TOOLS)
    failures = 0
    for tool in tools:
        with tempfile.TemporaryDirectory(prefix="tcb-selfcheck-") as tmp:
            bundle_dir = run_juliet(tool, [SAMPLE_CWE], jobs, root=Path(tmp))
            meta = read_meta(bundle_dir)
            art = _artifacts(bundle_dir)
            if update:
                d = _write(tool, art, meta)
                print(f"{tool:18s} golden written: {len(art['keys'])} keys -> {d.relative_to(REPO_ROOT)}")
                continue
            gold = _read(tool)
            if gold is None:
                print(f"{tool:18s} NO GOLDEN (run with --update to create it)")
                failures += 1
                continue
            g = gold["golden"]
            if g["aurora_lint_sha"] != pins.aurora_lint()["sha"] or g["juliet_sha"] != pins.corpus()["juliet"]["sha"] \
                    or g["tool_version"] != meta["tool_version"]:
                print(f"{tool:18s} PINS DIFFER from the golden's (golden: aurora-lint {g['aurora_lint_sha'][:12]}, "
                      f"{tool} {g['tool_version']}; now {pins.aurora_lint()['sha'][:12]}, {meta['tool_version']}) "
                      "-- regenerate with --update once the new pins are the intended ones")
                failures += 1
                continue
            got, want = set(art["keys"]), set(gold["keys"])
            same_counts = art["per_check"] == gold["per_check"]
            if got == want and same_counts:
                print(f"{tool:18s} OK  {len(want)} keys, per-check counts identical")
                continue
            failures += 1
            added, removed = sorted(got - want), sorted(want - got)
            print(f"{tool:18s} MISMATCH: +{len(added)} -{len(removed)} keys"
                  + ("" if same_counts else "; per-check counts differ"))
            for k in removed[:10]:
                print(f"    - {k[2]:40s} {k[0]}:{k[1]}")
            for k in added[:10]:
                print(f"    + {k[2]:40s} {k[0]}:{k[1]}")
            if len(added) + len(removed) > 20:
                print("    ...")
    return 1 if failures else 0
