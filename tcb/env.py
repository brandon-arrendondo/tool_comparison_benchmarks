"""The environment a run was measured in: the inputs no pin names.

A finding set depends on more than the analyzer, the corpus and the labels.
The host's headers decide which declarations a scan sees (a missing -dev
package turns into "called without prior declaration" findings; a different
glibc declares the same function behind different feature macros), and wall
clock depends on the CPU. So every run bundle carries this record, and a
reproducer diffs theirs against it before reading a mismatch as a tool
difference.

Everything here is *recorded*, never asserted -- the assertions are in
check.py, against pins/. The record goes into a bundle under runs/, which
is gitignored; nothing in it is committed.
"""

import hashlib
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path


def _run(argv: list[str], timeout: int = 30) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _os_release() -> dict:
    out = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v.strip().strip('"')
    except OSError:
        pass
    return out


def distro_id() -> str:
    """`ubuntu-24.04`, `debian-12`: the key pins/tools.json uses for a
    per-distro version policy."""
    osr = _os_release()
    return f"{osr.get('ID', 'unknown')}-{osr.get('VERSION_ID', 'unknown')}"


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _ram_gb() -> float:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return round(int(re.search(r"\d+", line).group()) / 1048576, 1)
    except OSError:
        pass
    return 0.0


def _glibc() -> str:
    name, ver = platform.libc_ver()
    return f"{name} {ver}".strip() or "unknown"


def dev_packages() -> tuple[list[str], str]:
    """Installed `*-dev` packages as `name version` lines, plus the sha256
    of that list. The list is what a reproducer diffs; the hash is what a
    table footer prints."""
    if not shutil.which("dpkg-query"):
        return [], ""
    out = _run(["dpkg-query", "-W", "-f=${Package} ${Version}\\n", "*-dev"])
    lines = sorted(l for l in out.splitlines() if l.strip())
    digest = hashlib.sha256("\n".join(lines).encode()).hexdigest()
    return lines, digest


def record() -> dict:
    """The full environment record for a run bundle's meta.json."""
    osr = _os_release()
    pkgs, pkgs_digest = dev_packages()
    return {
        "hostname": platform.node(),
        "distro": osr.get("PRETTY_NAME", platform.platform()),
        "distro_id": distro_id(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "glibc": _glibc(),
        "cpu_model": _cpu_model(),
        "cpu_cores": os.cpu_count() or 0,
        "ram_gb": _ram_gb(),
        "python": platform.python_version(),
        "dev_packages_sha256": pkgs_digest,
        "dev_packages_count": len(pkgs),
        "dev_packages": pkgs,
    }
