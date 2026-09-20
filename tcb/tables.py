"""`tcb table <name>`: one command per result table, computed from run
bundles (and timing records) and nothing else.

Every table is an aggregate -- counts, rates, distributions -- and every
table ends with a footer naming what it was computed from: this
repository's commit, the aurora-lint commit, each bundle's tool version,
the corpus and label commits, the mapping digests and the environment
hash. That footer is what makes the table citable and what makes it safe
to commit (ADR-0007: aggregates with provenance, never per-finding rows).

  juliet-per-cwe        per CWE x tool: files, findings by section, precision
                        on all findings and on CWE-matched ones, detection
  juliet-summary        per tool over the CWEs every given bundle covers
  realworld-counts      per project x tool: in-scope findings, files, mapped share, coverage
  realworld-precision   per project x tool: labeled TP/FP and precision over
                        the labeled keys, coverage of the label set
  timing                per timing record: median / min / max / MAD, CPU
  environment           what each bundle was measured on
"""

import csv
import io
import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

from . import REPO_ROOT, pins
from . import mapping as mapping_mod
from . import scope as scope_mod
from .bundle import read_findings, read_meta

# ── helpers ────────────────────────────────────────────────────────────────

def _repo_sha() -> str:
    try:
        return subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "--short=12", "HEAD"],
                              capture_output=True, text=True).stdout.strip() or "unknown"
    except OSError:
        return "unknown"


def _rate(num: int, den: int) -> str:
    return f"{100.0 * num / den:.1f}" if den else ""


def _footer(metas: list[dict], extra: dict | None = None) -> list[str]:
    tools = sorted({f"{m['tool']} {m['tool_version']}" for m in metas})
    envs = sorted({(m["environment"]["cpu_model"], m["environment"]["distro"],
                    m["environment"]["glibc"], m["environment"].get("dev_packages_sha256", "")[:12]) for m in metas})
    lines = [
        f"tool_comparison_benchmarks {_repo_sha()}; aurora-lint {pins.aurora_lint()['sha'][:12]}"
        + (f" ({pins.aurora_lint()['tag']})" if pins.aurora_lint().get("tag") else ""),
        "tools: " + "; ".join(tools),
        f"corpus pins: {pins.corpus()['source']['sha256'][:12]} (benchmark_repos.json at aurora-lint "
        f"{pins.corpus()['source']['aurora_lint_sha'][:12]}); juliet {pins.corpus()['juliet']['sha'][:12]}",
        f"labels: benchmark_adjudication {pins.labels()['sha'][:12]}",
        "mapping: " + "; ".join(f"{k} {v[:12]}" for k, v in mapping_mod.digests().items()),
        "environment: " + "; ".join(f"{cpu}, {distro}, {glibc}, dev-packages {h}" for cpu, distro, glibc, h in envs),
    ]
    for k, v in (extra or {}).items():
        lines.append(f"{k}: {v}")
    return lines


def _emit(name: str, header: list[str], rows: list[list], footer: list[str], out_dir: Path | None) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    for f in footer:
        w.writerow(["#", f])
    text = buf.getvalue()
    md = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    md += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    md += [""] + [f"_{f}_  " for f in footer]
    md_text = "\n".join(md) + "\n"
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{name}.csv").write_text(text)
        (out_dir / f"{name}.md").write_text(md_text)
        (out_dir / f"{name}.footer.json").write_text(json.dumps(footer, indent=2) + "\n")
    return md_text


def _load(bundles: list[Path]) -> list[tuple[Path, dict, list[dict]]]:
    return [(b, read_meta(b), read_findings(b)) for b in bundles]


def _cwe_matched(tool: str, check_id: str, cwe: str) -> bool:
    """Does the mapping say this check reports the CWE the test case is
    about? The unit of Juliet precision that means the same for every tool."""
    want = "CWE-" + cwe[3:] if cwe.startswith("CWE") and "-" not in cwe else cwe
    return want in mapping_mod.resolve(tool, check_id)["cwe"]


# ── Juliet ─────────────────────────────────────────────────────────────────

def _juliet_rows(loaded) -> tuple[list[list], list[dict]]:
    rows = []
    metas = []
    for b, m, recs in loaded:
        if not m["target"].startswith("juliet"):
            continue
        metas.append(m)
        tool = m["tool"]
        per_cwe_meta = {}
        with open(b / "per_cwe.csv") as fh:
            for r in csv.DictReader(fh):
                per_cwe_meta[r["cwe"]] = r
        flaws = defaultdict(set)      # cwe -> {(file_path, line)}
        if (b / "flaw_lines.csv").exists():
            with open(b / "flaw_lines.csv") as fh:
                for r in csv.DictReader(fh):
                    flaws[r["cwe"]].add((r["file_path"], int(r["line"])))
        by_cwe = defaultdict(list)
        for f in recs:
            by_cwe[f["cwe"]].append(f)
        for cwe, info in sorted(per_cwe_meta.items()):
            fs = by_cwe.get(cwe, [])
            bad = sum(1 for f in fs if f["section"] == "bad")
            good = sum(1 for f in fs if f["section"] == "good")
            matched_bad = [f for f in fs if f["section"] == "bad" and _cwe_matched(tool, f["check_id"], cwe)]
            mb = len(matched_bad)
            mg = sum(1 for f in fs if f["section"] == "good" and _cwe_matched(tool, f["check_id"], cwe))
            # a flaw line is hit when a CWE-matched bad-region finding sits on
            # it or one line off, as aurora-lint's bench/analyzer.py counts it
            hit = set()
            fl = flaws.get(cwe, set())
            for f in matched_bad:
                for dl in (-1, 0, 1):
                    k = (f["file_path"], f["line"] + dl)
                    if k in fl:
                        hit.add(k)
            n_flaw = int(info.get("flaw_lines", 0) or len(fl))
            rows.append([cwe, tool, info["status"], int(info["files"]), n_flaw, len(fs), bad, good,
                         _rate(bad, bad + good), mb, mg, _rate(mb, mb + mg), len(hit), _rate(len(hit), n_flaw)])
    return rows, metas


def juliet_per_cwe(bundles: list[Path], out_dir: Path | None) -> str:
    rows, metas = _juliet_rows(_load(bundles))
    header = ["cwe", "tool", "status", "files", "flaw_lines", "findings", "in_bad", "in_good",
              "precision_all_%", "cwe_matched_bad", "cwe_matched_good", "precision_cwe_%",
              "flaw_lines_hit", "flaw_hit_%"]
    return _emit("juliet-per-cwe", header, rows, _footer(metas), out_dir)


def juliet_summary(bundles: list[Path], out_dir: Path | None) -> str:
    rows, metas = _juliet_rows(_load(bundles))
    by_tool = defaultdict(list)
    for r in rows:
        if r[2] == "ok":
            by_tool[r[1]].append(r)
    common = set.intersection(*[{r[0] for r in rs} for rs in by_tool.values()]) if by_tool else set()
    out = []
    for tool, rs in sorted(by_tool.items()):
        for label, sel in (("all-covered", rs), ("common", [r for r in rs if r[0] in common])):
            files = sum(r[3] for r in sel); n_flaw = sum(r[4] for r in sel)
            bad = sum(r[6] for r in sel); good = sum(r[7] for r in sel)
            mb = sum(r[9] for r in sel); mg = sum(r[10] for r in sel); hit = sum(r[12] for r in sel)
            out.append([tool, label, len(sel), files, n_flaw, bad + good, bad, good, _rate(bad, bad + good),
                        mb, mg, _rate(mb, mb + mg), hit, _rate(hit, n_flaw)])
    header = ["tool", "cwe_set", "cwes", "files", "flaw_lines", "findings", "in_bad", "in_good",
              "precision_all_%", "cwe_matched_bad", "cwe_matched_good", "precision_cwe_%",
              "flaw_lines_hit", "flaw_hit_%"]
    return _emit("juliet-summary", header, out,
                 _footer(metas, {"common CWE set": ", ".join(sorted(common)) or "(none)"}), out_dir)


# ── real-world ─────────────────────────────────────────────────────────────

def realworld_counts(bundles: list[Path], out_dir: Path | None) -> str:
    loaded = _load(bundles)
    rows = []
    metas = []
    for _, m, recs in loaded:
        if m["target"].startswith("juliet"):
            continue
        metas.append(m)
        proj, tool = m["target"], m["tool"]
        ins = [f for f in recs if scope_mod.in_scope(proj, f["file_path"])]
        keys = {(f["file_path"], f["line"], f["check_id"]) for f in ins}
        mapped = sum(1 for f in ins if mapping_mod.resolve(tool, f["check_id"])["via"] != "unmapped")
        cov = m.get("coverage", {})
        rows.append([proj, tool, len(recs), len(ins), len(keys), len({f["file_path"] for f in ins}),
                     len({f["check_id"] for f in ins}), _rate(mapped, len(ins)),
                     cov.get("invocations", ""), cov.get("failed", ""),
                     m.get("timing", {}).get("scan_wall_s", "")])
    header = ["project", "tool", "findings", "in_scope", "in_scope_keys", "files", "check_ids",
              "mapped_%", "invocations", "failed_invocations", "scan_wall_s(informational)"]
    return _emit("realworld-counts", header, rows, _footer(metas), out_dir)


def _labels(labels_repo: Path, project: str, commit: str) -> dict[tuple, str]:
    """(file_path, line, rule_id) -> verdict for one project at its commit,
    read at the pinned benchmark_adjudication commit through git show."""
    sha = pins.labels()["sha"]
    txt = subprocess.run(["git", "-C", str(labels_repo), "show", f"{sha}:data/{project}/adjudication.csv"],
                         capture_output=True, text=True)
    if txt.returncode != 0:
        return {}
    out = {}
    for r in csv.DictReader(io.StringIO(txt.stdout)):
        if r["codebase_commit"] == commit:
            out[(r["file_path"], int(r["line"]), r["rule_id"])] = r["verdict"]
    return out


def realworld_precision(bundles: list[Path], labels_repo: Path, out_dir: Path | None) -> str:
    """Precision over the labeled keys. For aurora-lint the key is direct.
    For a competitor the finding's native check id is mapped to CERT rule
    ids and a label is looked up under each; that is a proxy -- the label
    set was adjudicated for aurora-lint's findings, so a competitor's
    finding is 'labeled' only where aurora-lint also fired at that line
    under a rule the mapping names -- and the coverage column says how
    small the proxy is. A competitor's own adjudicated labels (task 1390)
    replace this the moment they exist."""
    loaded = _load(bundles)
    rows = []
    metas = []
    for _, m, recs in loaded:
        if m["target"].startswith("juliet"):
            continue
        metas.append(m)
        proj, tool = m["target"], m["tool"]
        commit = next((e["version"] for e in pins.corpus()["repos"] if e["name"] == proj), "")
        labels = _labels(labels_repo, proj, commit)
        ins = {(f["file_path"], f["line"], f["check_id"]) for f in recs if scope_mod.in_scope(proj, f["file_path"])}
        c = Counter()
        for fp, line, cid in ins:
            rules = mapping_mod.resolve(tool, cid)["cert"]
            verdicts = [labels[(fp, line, r)] for r in rules if (fp, line, r) in labels]
            if not verdicts:
                c["unlabeled"] += 1
            elif "TP" in verdicts:
                c["TP"] += 1
            elif "FP" in verdicts:
                c["FP"] += 1
            else:
                c["uncertain"] += 1
        labeled = c["TP"] + c["FP"]
        known_tp = sum(1 for v in labels.values() if v == "TP")
        rows.append([proj, tool, len(ins), c["TP"], c["FP"], c["uncertain"], c["unlabeled"],
                     _rate(c["TP"], labeled), _rate(labeled, len(ins)), known_tp,
                     "direct" if tool.startswith("aurora-lint") else "via mapping"])
    header = ["project", "tool", "in_scope_keys", "TP", "FP", "uncertain", "unlabeled",
              "precision_%", "label_coverage_%", "known_TP_in_labels", "label_lookup"]
    return _emit("realworld-precision", header, rows, _footer(metas), out_dir)


# ── timing and environment ─────────────────────────────────────────────────

def timing(records: list[Path], out_dir: Path | None) -> str:
    rows, metas = [], []
    for p in records:
        r = json.loads(p.read_text())
        s = r["summary"]
        rows.append([r["tool"], r["target"], r["repeats"], r["cache"], r["jobs"], s["wall_median_s"],
                     s["wall_min_s"], s["wall_max_s"], s["wall_mad_s"], s["cpu_median_s"],
                     r["environment"]["cpu_model"], "yes" if s["valid"] else "NO"])
        metas.append({"tool": r["tool"], "tool_version": "", "environment": r["environment"]})
    header = ["tool", "target", "repeats", "cache", "jobs", "wall_median_s", "wall_min_s", "wall_max_s",
              "wall_mad_s", "cpu_median_s", "cpu", "valid"]
    return _emit("timing", header, rows, _footer(metas), out_dir)


def environment(bundles: list[Path], out_dir: Path | None) -> str:
    rows, metas = [], []
    for b in bundles:
        m = read_meta(b)
        metas.append(m)
        e = m["environment"]
        rows.append([m["tool"], m["tool_version"], m["target"], e["distro"], e["kernel"], e["glibc"],
                     e["cpu_model"], e["cpu_cores"], e["ram_gb"], e["dev_packages_count"],
                     e["dev_packages_sha256"][:12]])
    header = ["tool", "version", "target", "distro", "kernel", "glibc", "cpu", "cores", "ram_gb",
              "dev_packages", "dev_packages_sha256"]
    return _emit("environment", header, rows, _footer(metas), out_dir)


TABLES = {
    "juliet-per-cwe": juliet_per_cwe, "juliet-summary": juliet_summary,
    "realworld-counts": realworld_counts, "realworld-precision": realworld_precision,
    "timing": timing, "environment": environment,
}
