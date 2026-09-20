"""The pinned inputs, read from pins/ -- nothing else in the harness names a
version, a commit or a path that a table depends on."""

import hashlib
import json
import os
from pathlib import Path

from . import PINS_DIR

# Where the corpora and Juliet live on this machine. Same variable and
# default as aurora-lint's bench/config.py, so one provisioning serves both.
BENCH_ROOT = Path(os.environ.get("SQC_BENCH_ROOT", str(Path.home() / "toolchain"))).expanduser()


def _load(name: str) -> dict:
    path = PINS_DIR / f"{name}.json"
    with open(path) as fh:
        return json.load(fh)


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def aurora_lint() -> dict:
    return _load("aurora_lint")


def tools() -> dict:
    return _load("tools")["tools"]


def corpus() -> dict:
    return _load("corpus")


def labels() -> dict:
    return _load("labels")


def corpus_path(name: str) -> Path:
    """Checkout directory of one pinned real-world codebase."""
    return BENCH_ROOT / name


def juliet_root() -> Path:
    return BENCH_ROOT / "benchmarks" / "juliet-test-suite-c"


def pin_digests() -> dict:
    """sha256 of every pin file, recorded into each run bundle so a table can
    say exactly which pins it was computed under."""
    return {p.name: file_digest(p) for p in sorted(PINS_DIR.glob("*.json"))}
