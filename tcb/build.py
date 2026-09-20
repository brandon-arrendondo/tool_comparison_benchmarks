"""`tcb build-aurora-lint`: the pinned aurora-lint, built from source into
.cache/ so the binary every table cites is the one at pins/aurora_lint.json.

Built, not downloaded: the codebase configs (scan paths, `-d`, `-I`,
`--exclude`, the per-codebase manifests under conf/realworld/) are read from
the same checkout, so the invocation this harness makes is the one
aurora-lint's own benchmark makes at that commit and cannot drift from it.
"""

import subprocess
import sys

from . import CACHE_DIR, pins
from .check import aurora_lint_checkout, aurora_lint_binary


def build(jobs: int | None = None) -> int:
    pin = pins.aurora_lint()
    co = aurora_lint_checkout()
    CACHE_DIR.mkdir(exist_ok=True)
    if not (co / ".git").exists():
        print(f"cloning {pin['repo']} -> {co}")
        subprocess.run(["git", "clone", "--quiet", pin["repo"], str(co)], check=True)
    subprocess.run(["git", "-C", str(co), "fetch", "--quiet", "--tags", "origin"], check=True)
    subprocess.run(["git", "-C", str(co), "checkout", "--quiet", "--detach", pin["sha"]], check=True)
    head = subprocess.run(["git", "-C", str(co), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    if head != pin["sha"]:
        print(f"checkout is at {head}, pin is {pin['sha']}", file=sys.stderr)
        return 1
    argv = ["cargo", "build", "--release", "--quiet"]
    if jobs:
        argv += ["--jobs", str(jobs)]
    print(f"building aurora-lint {pin['version']} at {pin['sha'][:12]} (this takes a minute or two)")
    rc = subprocess.run(argv, cwd=co).returncode
    if rc != 0:
        return rc
    out = subprocess.run([str(aurora_lint_binary()), "--version"], capture_output=True, text=True).stdout
    print(f"built: {out.strip()} -> {aurora_lint_binary()}")
    return generate_cwe_manifests(co)


def generate_cwe_manifests(co) -> int:
    """aurora-lint's per-CWE Juliet manifests (rules_templates/cwe/CWE-<n>.toml,
    fast mode) are generated from the rule TOMLs by its own script and are
    not tracked, so a fresh checkout has none; its Juliet runner generates
    them before every run and so does this harness, from the pinned commit's
    script, so the fast-mode rule sets are the ones that commit defines."""
    script = co / "scripts" / "generate_rule_cwe_map.py"
    if not script.exists():
        print(f"no {script.name} at this commit; fast-mode Juliet runs will be skipped", file=sys.stderr)
        return 0
    r = subprocess.run(["python3", str(script)], cwd=co, capture_output=True, text=True, timeout=120)
    n = len(list((co / "rules_templates" / "cwe").glob("CWE-*.toml")))
    print(f"per-CWE manifests: {n} under rules_templates/cwe/ (rc={r.returncode})")
    return 0 if r.returncode == 0 else r.returncode
