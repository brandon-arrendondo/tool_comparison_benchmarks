"""Apply mapping/<tool>.json: native check id -> CERT rule ids + CWE ids.

The mapping is data with a hash. `resolve(tool, check_id)` returns
{'cert': [...], 'cwe': [...], 'via': 'entry' | 'pattern' | 'unmapped'} and
never raises for an unknown id: unmapped is a result a table reports, not
an error. aurora-lint's own rule ids resolve through the pinned checkout's
data/rule_cwe_map.json (rule -> CWEs), which is also what gives a
clang-tidy `cert-*` check its CWEs; that file's sha256 is recorded next
to the mapping's.
"""

import hashlib
import json
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

from . import MAPPING_DIR
from .check import aurora_lint_checkout


@lru_cache(maxsize=None)
def _load(tool: str) -> dict:
    p = MAPPING_DIR / f"{tool}.json"
    if not p.exists():
        return {"entries": {}, "patterns": [], "missing": True}
    return json.loads(p.read_text())


@lru_cache(maxsize=None)
def rule_cwe_map() -> dict:
    """aurora-lint's rule -> CWE list at the pinned commit."""
    p = aurora_lint_checkout() / "data" / "rule_cwe_map.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text()).get("rule_to_cwes", {})


def digests() -> dict:
    """sha256 of every mapping file plus aurora-lint's rule_cwe_map.json,
    for a bundle's meta.json and a table's footer."""
    out = {}
    for p in sorted(MAPPING_DIR.glob("*.json")):
        out[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    rcm = aurora_lint_checkout() / "data" / "rule_cwe_map.json"
    if rcm.exists():
        out["aurora-lint:data/rule_cwe_map.json"] = hashlib.sha256(rcm.read_bytes()).hexdigest()
    return out


def _apply_pattern(pat: dict, check_id: str) -> dict | None:
    m = re.match(pat["regex"], check_id)
    if not m:
        return None
    # the one substitution form the mapping files use: upper(\1)\2-C
    cert = pat["cert"]
    cert = re.sub(r"upper\(\\(\d)\)", lambda g: m.group(int(g.group(1))).upper(), cert)
    cert = re.sub(r"\\(\d)", lambda g: m.group(int(g.group(1))), cert)
    cwe = list(rule_cwe_map().get(cert, [])) if pat.get("cwe") == "aurora-lint rule_cwe_map" else list(pat.get("cwe", []))
    return {"cert": [cert], "cwe": cwe, "via": "pattern"}


def resolve(tool: str, check_id: str) -> dict:
    if tool.startswith("aurora-lint"):
        return {"cert": [check_id], "cwe": list(rule_cwe_map().get(check_id, [])), "via": "entry"}
    m = _load(tool)
    e = m.get("entries", {}).get(check_id)
    if e is not None:
        return {"cert": list(e.get("cert", [])), "cwe": list(e.get("cwe", [])), "via": "entry"}
    for pat in m.get("patterns", []):
        r = _apply_pattern(pat, check_id)
        if r:
            return r
    return {"cert": [], "cwe": [], "via": "unmapped"}


def coverage(tool: str, check_ids: list[str]) -> dict:
    """How much of a run the mapping speaks for: per distinct check id and
    per finding, how many resolved by entry, by pattern, or not at all."""
    by_id = Counter(check_ids)
    stats = {"entry": 0, "pattern": 0, "unmapped": 0}
    ids = {"entry": 0, "pattern": 0, "unmapped": 0}
    unmapped = Counter()
    for cid, n in by_id.items():
        via = resolve(tool, cid)["via"]
        stats[via] += n
        ids[via] += 1
        if via == "unmapped":
            unmapped[cid] += n
    return {"findings": stats, "check_ids": ids, "unmapped_top": unmapped.most_common(20)}
