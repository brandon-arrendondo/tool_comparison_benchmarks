"""`tcb check`: assert every pinned input before a run, and say how to fix
each one that is off.

The model is aurora-lint's `bench corpus-check`: provisioning pins a thing
once and nothing holds it there -- `apt upgrade` moves a tool the way `git
pull` moves a checkout -- and a runner that records whatever it finds
produces a plausible number from the wrong input. So nothing here records;
every row is OK or FAIL against pins/, a FAIL prints its remedy, and the
run refuses to start on any FAIL. The rows are also written into the run
bundle, so the bundle carries proof of what was asserted, not just what
was seen.
"""

import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path

from . import CACHE_DIR
from . import env as env_mod
from . import pins


@dataclass
class Row:
    check: str
    name: str
    status: str          # OK | FAIL | SKIP
    found: str
    expected: str
    remedy: str = ""

    def line(self) -> str:
        s = f"{self.status:4s} {self.check:11s} {self.name:12s} found={self.found!r:40s} expected={self.expected!r}"
        return s + (f"\n     remedy: {self.remedy}" if self.status == "FAIL" and self.remedy else "")


def _run(argv, timeout=30, cwd=None) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, (p.stdout + p.stderr)
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, "timeout"


# ── tools ──────────────────────────────────────────────────────────────────

def _dpkg_owner(path: str) -> tuple[str, str]:
    """(package, installed version) owning `path`, or ('', '')."""
    rc, out = _run(["dpkg", "-S", path])
    if rc != 0 or ":" not in out:
        return "", ""
    pkg = out.split(":", 1)[0].strip()
    rc, ver = _run(["dpkg-query", "-W", "-f=${Version}", pkg])
    return pkg, ver.strip() if rc == 0 else ""


def check_tool(name: str, spec: dict, distro: str) -> list[Row]:
    rows: list[Row] = []
    remedy = spec.get("remedy", "re-run the tool provisioning for this node "
                                "(aurora-lint playbooks/install-static-analyzers.yml) "
                                "and re-check")
    # 1. version string
    rc, out = _run(spec["version_cmd"], timeout=60)
    m = re.search(spec["version_regex"], out)
    found_ver = m.group(1) if m else ("not installed" if rc == 127 else "unparsed")
    policy = spec["version_policy"]
    if policy == "exact":
        exp_ver = spec["version"]
        ok = found_ver == exp_ver
    elif policy == "major":
        exp_ver = spec["version"] + ".x"
        ok = found_ver.split(".")[0] == spec["version"]
    elif policy == "distro":
        entry = spec["by_distro"].get(distro)
        if entry is None:
            rows.append(Row("tool", name, "FAIL", found_ver, f"no pin for distro {distro}",
                            "add this distro to pins/tools.json by_distro, from a node that "
                            "provisioned it"))
            return rows
        exp_ver = f"{entry['version']} ({distro})"
        ok = found_ver == entry["version"]
    else:
        raise ValueError(f"unknown version_policy {policy!r} for {name}")
    rows.append(Row("tool", name, "OK" if ok else "FAIL", found_ver, exp_ver, remedy))

    # 2. resolved path (a shim earlier on PATH must not shadow the pin)
    if spec.get("resolved_path"):
        which = shutil.which(spec["binary"])
        resolved = str(Path(which).resolve()) if which else "not on PATH"
        ok = resolved == spec["resolved_path"]
        rows.append(Row("tool-path", name, "OK" if ok else "FAIL", resolved,
                        spec["resolved_path"],
                        "put the pinned install first on PATH (or remove the shim) -- "
                        f"`which {spec['binary']}` resolves to {resolved}"))

    # 3. origin
    origin = spec["origin"]
    if origin["kind"] == "dpkg":
        pkg, pkg_ver = _dpkg_owner(spec["resolved_path"])
        exp_pkg = origin["package"]
        ok = pkg == exp_pkg
        rows.append(Row("tool-origin", name, "OK" if ok else "FAIL",
                        f"dpkg:{pkg or 'none'} {pkg_ver}", f"dpkg:{exp_pkg}", remedy))
        if ok:
            exp_pv = None
            if policy == "distro":
                exp_pv = spec["by_distro"][distro].get("package_version")
            elif "package_version_regex" in origin:
                ok = re.search(origin["package_version_regex"], pkg_ver) is not None
                rows.append(Row("tool-pkgver", name, "OK" if ok else "FAIL", pkg_ver,
                                origin["package_version_regex"], remedy))
            if exp_pv:
                rows.append(Row("tool-pkgver", name, "OK" if pkg_ver == exp_pv else "FAIL",
                                pkg_ver, exp_pv, remedy))
    elif origin["kind"] == "prebuilt":
        p = Path(spec["resolved_path"])
        rows.append(Row("tool-origin", name, "OK" if p.exists() else "FAIL",
                        str(p) if p.exists() else "missing", f"prebuilt at {origin['install_dir']}",
                        f"install the archive {origin['archive_url']} (sha256 "
                        f"{origin['sha256'][:12]}...) into {origin['install_dir']}"))
    elif origin["kind"] == "opam":
        rc, out = _run(["opam", "list", "--installed", "--columns=version", "--short", origin["package"]])
        found = out.strip() or ("opam not installed" if rc == 127 else "not in switch")
        rows.append(Row("tool-origin", name, "OK" if found == origin["package_version"] else "FAIL",
                        f"opam:{found}", f"opam:{origin['package_version']}",
                        f"`opam install {origin['package']}.{origin['package_version']}`"))
    return rows


def check_tools(only: list[str] | None = None) -> list[Row]:
    distro = env_mod.distro_id()
    rows = []
    for name, spec in pins.tools().items():
        if only and name not in only:
            continue
        rows.extend(check_tool(name, spec, distro))
    return rows


# ── corpora ────────────────────────────────────────────────────────────────

def _git(path: Path, *args) -> tuple[int, str]:
    return _run(["git", "-C", str(path), *args])


def check_repo(name: str, url: str, sha: str, path: Path) -> list[Row]:
    if not (path / ".git").exists():
        return [Row("corpus", name, "FAIL", "no checkout", sha[:12],
                    f"git clone {url} {path} && git -C {path} checkout --detach {sha}")]
    rc, head = _git(path, "rev-parse", "HEAD")
    head = head.strip()
    rows = [Row("corpus", name, "OK" if head == sha else "FAIL", head[:12], sha[:12],
                f"git -C {path} fetch origin && git -C {path} checkout --detach {sha}")]
    rc, status = _git(path, "status", "--porcelain", "--ignored")
    dirty = [l for l in status.splitlines() if l[:2] not in ("??", "!!")]
    stray_c = [l[3:] for l in status.splitlines()
               if l[:2] in ("??", "!!") and l.rstrip().endswith((".c", ".h"))]
    if dirty:
        rows.append(Row("corpus-clean", name, "FAIL", f"{len(dirty)} modified", "clean tree",
                        f"git -C {path} checkout -- . (after reading the diff)"))
    if stray_c:
        # aurora-lint dispatches on extension and never consults git, so an
        # untracked or gitignored .c/.h (a build's generated amalgamation, a
        # scratch file) is scanned and contaminates the finding set.
        rows.append(Row("corpus-stray", name, "FAIL", f"{len(stray_c)} untracked/ignored C files",
                        "none", f"remove: {' '.join(stray_c[:5])}{' ...' if len(stray_c) > 5 else ''}"))
    return rows


def check_corpus(only: list[str] | None = None) -> list[Row]:
    c = pins.corpus()
    rows = []
    for entry in c["repos"]:
        if only and entry["name"] not in only:
            continue
        rows.extend(check_repo(entry["name"], entry["repo"], entry["version"],
                               pins.corpus_path(entry["name"])))
    if not only or "juliet" in only:
        j = c["juliet"]
        rows.extend(check_repo("juliet", j["repo"], j["sha"], pins.juliet_root()))
    return rows


# ── aurora-lint ────────────────────────────────────────────────────────────

def aurora_lint_checkout() -> Path:
    return CACHE_DIR / f"aurora-lint-{pins.aurora_lint()['sha'][:12]}"


def aurora_lint_binary() -> Path:
    return aurora_lint_checkout() / "target" / "release" / "aurora-lint"


def check_aurora_lint() -> list[Row]:
    pin = pins.aurora_lint()
    co, binary = aurora_lint_checkout(), aurora_lint_binary()
    remedy = "python -m tcb build-aurora-lint"
    if not (co / ".git").exists():
        return [Row("aurora-lint", "checkout", "FAIL", "none", pin["sha"][:12], remedy)]
    rc, head = _git(co, "rev-parse", "HEAD")
    rows = [Row("aurora-lint", "checkout", "OK" if head.strip() == pin["sha"] else "FAIL",
                head.strip()[:12], pin["sha"][:12], remedy)]
    if not binary.exists():
        rows.append(Row("aurora-lint", "binary", "FAIL", "not built", pin["version"], remedy))
        return rows
    rc, out = _run([str(binary), "--version"])
    m = re.search(r"(\d+\.\d+\.\d+)", out)
    found = m.group(1) if m else out.strip()
    rows.append(Row("aurora-lint", "binary", "OK" if found == pin["version"] else "FAIL",
                    found, pin["version"], remedy))
    # A binary older than its sources is the mid-run-rebuild trap in reverse:
    # the checkout is right, the binary was built from something else.
    newest_src = max((p.stat().st_mtime for p in (co / "src").rglob("*.rs")), default=0)
    if binary.stat().st_mtime < newest_src:
        rows.append(Row("aurora-lint", "binary-fresh", "FAIL", "older than src/", "newer than src/", remedy))
    n_manifests = len(list((co / "rules_templates" / "cwe").glob("CWE-*.toml")))
    rows.append(Row("aurora-lint", "cwe-manifests", "OK" if n_manifests > 1 else "FAIL",
                    f"{n_manifests} generated", "> 1 (fast-mode Juliet manifests)", remedy))
    return rows


# ── labels ─────────────────────────────────────────────────────────────────

def check_labels(path: Path | None) -> list[Row]:
    pin = pins.labels()
    if path is None:
        return [Row("labels", "checkout", "SKIP", "no --labels-repo given", pin["sha"][:12],
                    "pass --labels-repo PATH to check the benchmark_adjudication clone")]
    rc, _ = _git(path, "cat-file", "-e", f"{pin['sha']}^{{commit}}")
    return [Row("labels", "commit", "OK" if rc == 0 else "FAIL",
                "present" if rc == 0 else "absent", pin["sha"][:12],
                f"git -C {path} fetch origin (the pinned commit must be reachable)")]


# ── all ────────────────────────────────────────────────────────────────────

def run_all(tools: list[str] | None = None, corpora: list[str] | None = None,
            labels_repo: Path | None = None, skip: set[str] = frozenset()) -> list[Row]:
    rows = []
    if "tools" not in skip:
        rows += check_tools(tools)
    if "corpus" not in skip:
        rows += check_corpus(corpora)
    if "aurora-lint" not in skip:
        rows += check_aurora_lint()
    if "labels" not in skip:
        rows += check_labels(labels_repo)
    return rows


def failed(rows: list[Row]) -> list[Row]:
    return [r for r in rows if r.status == "FAIL"]


def as_dicts(rows: list[Row]) -> list[dict]:
    return [asdict(r) for r in rows]
