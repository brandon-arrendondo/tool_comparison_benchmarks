"""tcb -- the tool-comparison benchmark harness.

Runs aurora-lint and its competitors on the same pinned inputs and derives
every comparison table from the resulting run bundles. `python -m tcb`.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PINS_DIR = REPO_ROOT / "pins"
MAPPING_DIR = REPO_ROOT / "mapping"
MANIFESTS_DIR = REPO_ROOT / "manifests"
RUNS_DIR = REPO_ROOT / "runs"
CACHE_DIR = REPO_ROOT / ".cache"
