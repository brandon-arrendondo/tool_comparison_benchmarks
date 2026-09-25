"""Frama-C's EVA plugin. Ported from aurora-lint's bench/: Juliet from
bench/competitors.py, real-world from bench/realworld_runner.py, whose design
note (aurora-lint docs/design/framac-realworld.md) is summarised here because
it is what a Frama-C number means.

EVA analyses from one named entry point with `-lib-entry` (unknown globals,
a hostile caller), so both modes run one invocation per (file, function):

  Juliet      each test case's `<name>_bad`, `<name>_good` and `goodN`,
              `-warn-signed-overflow -warn-signed-downcast`, the suite's
              support directory on the preprocessor path, 120 s each; only
              alarms located in the test case itself are kept.
  real-world  the functions each in-scope TU of the filtered compile DB
              (tcb/compile_db.py) defines, found by a cheap textual scan,
              externally-linked first; `-compilation-db` for the TU's flags.
              Three bounds, because unbounded EVA on a real codebase is not a
              job that finishes: a per-entry timeout, a cap on entries per TU,
              and a wall-clock budget for the codebase. Entries are visited
              ROUND-ROBIN across TUs (every TU's first entry before any TU's
              second), so an exhausted budget leaves a shallow scan of the
              whole codebase rather than a deep scan of its first files.

Invocations run `jobs` at a time inside the resource envelope, submitted in
that round-robin order; the budget is checked as each one starts. A proposed
entry EVA does not know ("cannot find entry point") is expected and cheap: it
is recorded, and counted neither as coverage nor as a failure. Only an entry
EVA finishes with exit 0 yields findings: one that ends in an error (a
deferred error such as a recursive call without an assigns clause, or a TU
that will not preprocess) is a failure, and the alarms it printed first go
with it. A per-entry timeout is a bound, not a failed run. `coverage.tool`
records entries analysed, timeouts, failures and whether the budget ran out.

What a real-world Frama-C row means: a PARTIAL scan. Its finding count is a
floor and not comparable as a volume to another tool's; its precision is
defensible, its recall is not expressible. Two runs compare only at identical
bounds, `--jobs` and envelope on like hardware: the timeout and the budget
are wall clock, so an entry near the limit lands either side of it, and
entries run side by side contend for memory bandwidth and run slower than
the same entries one at a time (on lua, 12 at once timed out 6 entries that
finish serially).

A finding's check id is EVA's alarm text ("out of bounds read", "signed
overflow"), the closest thing EVA has to a rule id, stable under the pinned
version; a precondition alarm, which carries a whole ACSL predicate,
collapses to "precondition of <callee>". The message keeps the asserted
predicate. The binary is resolved from the opam switch once (`opam var bin`)
and invoked directly, so no per-invocation `opam exec` sits between the
harness and the process it times.
"""

import json
import os
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import compile_db
from .base import BaseAdapter, Completed, relpath, run_timed

JULIET_ENTRY_TIMEOUT_S = 120
JULIET_FLAGS = ["-eva", "-eva-precision", "1", "-machdep", "gcc_x86_64",
                "-warn-signed-overflow", "-warn-signed-downcast"]

# aurora-lint's defaults (SQC_BENCH_FRAMAC_*); overridable for an experiment,
# and recorded in meta.json either way.
REALWORLD_ENTRY_TIMEOUT_S = int(os.environ.get("TCB_FRAMAC_ENTRY_TIMEOUT_S", 60))
REALWORLD_MAX_ENTRIES_PER_TU = int(os.environ.get("TCB_FRAMAC_MAX_ENTRIES_PER_TU", 8))
REALWORLD_BUDGET_S = int(os.environ.get("TCB_FRAMAC_BUDGET_S", 4 * 3600))
REALWORLD_PRECISION = int(os.environ.get("TCB_FRAMAC_PRECISION", 1))

# `-json-compilation-database` through 32.0, `-compilation-db` from 33.0; the
# pin is 33.0 exactly, and `tcb check` refuses any other version.
COMPILE_DB_FLAG = "-compilation-db"

_ALARM_RE = re.compile(r"\[eva:alarm\]\s+(?P<file>[^\s:]+):(?P<line>\d+):\s*Warning:\s*(?P<body>.*)", re.S)
_ASSERT_RE = re.compile(r"^(?P<kind>.*?)\.?\s*assert\s+(?P<pred>.*?);?$")
# `function f: precondition ...`, or with a named ACSL behavior,
# `function f, behavior complete: precondition ...`
_PRECOND_RE = re.compile(r"function ([A-Za-z_]\w*)(?:, behavior [A-Za-z_]\w*)?: precondition")
_UNKNOWN_MAIN_RE = re.compile(r"cannot find entry point|Unable to find function")
UNKNOWN_ENTRY = "entry point unknown to EVA"
ENTRY_TIMEOUT = "per-entry timeout (a bound, recorded in coverage)"


def alarm_kind(raw: str) -> str:
    kind = " ".join(raw.split())
    m = _PRECOND_RE.search(kind)
    if m:
        return f"precondition of {m.group(1)}"
    return kind[:80] or "eva_alarm"


def parse_output(text: str, root: Path, only_file: Path | None = None) -> list[dict]:
    """One record per `[eva:alarm]` message. A message runs from its `[...]`
    header to the next line that starts one; EVA wraps a long header, so the
    alarm text often starts on the following line."""
    recs = []
    for block in re.split(r"(?m)^(?=\[)", text):
        m = _ALARM_RE.match(block)
        if not m:
            continue
        f = m.group("file")
        if only_file is not None and Path(f).name != only_file.name:
            continue
        body = " ".join(m.group("body").split())
        a = _ASSERT_RE.match(body)
        kind, pred = (a.group("kind"), a.group("pred")) if a else (body.rstrip("."), "")
        recs.append(dict(file_path=relpath(f, root), line=int(m.group("line")), column=0,
                         check_id=alarm_kind(kind), severity="alarm",
                         message=f"{kind.strip()}. assert {pred}" if pred else kind.strip()))
    return recs


def juliet_entries(filepath: Path) -> list[str]:
    """A test case's `<name>_bad`, `<name>_good` and `goodN` functions."""
    try:
        text = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    out = []
    for name in (f"{filepath.stem}_bad", f"{filepath.stem}_good"):
        if re.search(rf"\b{re.escape(name)}\s*\(", text):
            out.append(name)
    out += [m.group(1) for m in re.finditer(r"\bvoid\s+(good\d+)\s*\(", text)]
    return list(dict.fromkeys(out))


_C_KEYWORD_CALLS = frozenset((
    "if", "while", "for", "switch", "return", "sizeof", "do", "else",
    "case", "goto", "typedef", "defined", "_Static_assert", "static_assert",
))

_C_FUNC_CANDIDATE_RE = re.compile(
    r"^(?P<static>static\s+)?"
    r"(?:(?:inline|__inline|__inline__|extern|const|volatile|unsigned|signed|"
    r"struct|union|enum|register|_Noreturn|__attribute__\s*\(\([^)]*\)\))\s+)*"
    r"[A-Za-z_][A-Za-z0-9_]*\s*"
    r"(?:\*\s*)*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)


def c_function_definitions(filepath: Path) -> list[str]:
    """Names of functions defined at top level in a .c file, externally-linked
    first. Textual, not a parse: it only proposes entry points, and EVA rejects
    a name it does not know at the cost of one fast invocation."""
    try:
        text = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    external, internal = [], []
    for m in _C_FUNC_CANDIDATE_RE.finditer(text):
        name = m.group("name")
        if name in _C_KEYWORD_CALLS:
            continue
        # A definition, not a declaration or a call: balance the parameter
        # list, then require '{' next.
        i, depth = m.end() - 1, 0
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        else:
            continue
        j = i + 1
        while j < len(text) and text[j].isspace():
            j += 1
        if j >= len(text) or text[j] != "{":
            continue
        (internal if m.group("static") else external).append(name)
    return list(dict.fromkeys(external + internal))


def round_robin(entries: dict[Path, list[str]]) -> list[tuple[Path, str]]:
    """Every TU's first entry, then every TU's second, and so on."""
    order = []
    depth = 0
    while True:
        row = [(tu, names[depth]) for tu, names in sorted(entries.items()) if depth < len(names)]
        if not row:
            return order
        order += row
        depth += 1


def _binary() -> str:
    try:
        out = subprocess.run(["opam", "var", "bin"], capture_output=True, text=True, timeout=60).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        out = ""
    cand = Path(out) / "frama-c" if out else None
    if cand is not None and cand.is_file():
        return str(cand)
    return shutil.which("frama-c") or "frama-c"


class Adapter(BaseAdapter):
    def __init__(self, name: str):
        super().__init__(name)
        self.bin = _binary()
        self.tool_options["binary"] = self.bin

    def version(self) -> str:
        m = re.search(r"(\d+\.\d+)", run_timed([self.bin, "-version"]).stdout)
        return m.group(1) if m else "unknown"

    def _one(self, argv: list[str], cwd: Path, timeout: int, root: Path,
             only_file: Path | None = None) -> tuple[Completed, list[dict]]:
        """One EVA invocation and its alarms. Only an analysis that exits 0
        yields findings: one that ends in an error (a deferred error such as a
        recursive call without an assigns clause, or a TU that will not
        preprocess) is a failure and never coverage, as in aurora-lint's
        runner, so the alarms it printed before failing are dropped with it."""
        done = run_timed(argv, cwd=cwd, timeout=timeout)
        if done.returncode == 124:
            done.expected = ENTRY_TIMEOUT
        elif done.returncode == 1 and _UNKNOWN_MAIN_RE.search(done.stdout + done.stderr):
            done.expected = UNKNOWN_ENTRY
        recs = parse_output(done.stdout + done.stderr, root, only_file) if done.returncode == 0 else []
        return done, recs

    @staticmethod
    def _tally(dones: list[Completed]) -> dict:
        return {"entries_run": len(dones),
                "entries_analyzed": sum(1 for d in dones if d.returncode == 0),
                "entries_unknown": sum(1 for d in dones if d.expected == UNKNOWN_ENTRY),
                "timeouts": sum(1 for d in dones if d.returncode == 124),
                "failures": sum(1 for d in dones if d.returncode not in (0, 124) and not d.expected)}

    def run_juliet_cwe(self, cwe_dir: Path, support_dir: Path, workdir: Path, jobs: int) -> tuple[list[Completed], list[dict]]:
        self.tool_options.update(flags=JULIET_FLAGS + ["-lib-entry"], entry_timeout_s=JULIET_ENTRY_TIMEOUT_S)
        root = cwe_dir.parent
        work = [(f, e) for f in sorted(cwe_dir.rglob("*.c")) for e in juliet_entries(f)]

        def one(item):
            f, entry = item
            return self._one([self.bin, *JULIET_FLAGS, "-lib-entry", f"-main={entry}",
                              f"-cpp-extra-args=-I {support_dir}", str(f)], workdir, JULIET_ENTRY_TIMEOUT_S,
                             root, only_file=f)

        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(one, work))
        dones = [d for d, _ in results]
        self.coverage[cwe_dir.name] = self._tally(dones)
        return dones, [r for _, rs in results for r in rs]

    def run_realworld(self, cfg: dict, workdir: Path, jobs: int) -> tuple[list[Completed], list[dict]]:
        root = Path(cfg["path"])
        db = compile_db.filtered(cfg, workdir / "compile_commands.in_scope.json")
        self.tool_options.update(
            compile_db={k: v for k, v in db.items() if k != "path"},
            flags=["-eva", "-eva-precision", str(REALWORLD_PRECISION), "-machdep", "gcc_x86_64",
                   "-lib-entry", COMPILE_DB_FLAG],
            entry_timeout_s=REALWORLD_ENTRY_TIMEOUT_S, max_entries_per_tu=REALWORLD_MAX_ENTRIES_PER_TU,
            budget_s=REALWORLD_BUDGET_S, order="round-robin across TUs, externally-linked functions first")
        if db["path"] is None:
            self.coverage = {"tus_total": 0, "entries_total": 0, "entries_analyzed": 0, "partial": True,
                             "reason": "no compile_commands.json" if db["source"] is None
                             else "no in-scope entries"}
            return [], []
        tus = sorted({compile_db.entry_source(e) for e in json.loads(Path(db["path"]).read_text())})
        entries = {tu: c_function_definitions(tu)[:REALWORLD_MAX_ENTRIES_PER_TU] for tu in tus}
        order = round_robin(entries)
        start = time.monotonic()

        def one(item):
            tu, entry = item
            if time.monotonic() - start >= REALWORLD_BUDGET_S:
                return None
            return self._one([self.bin, "-eva", "-eva-precision", str(REALWORLD_PRECISION),
                              "-machdep", "gcc_x86_64", "-lib-entry", f"-main={entry}",
                              COMPILE_DB_FLAG, db["path"], str(tu)], workdir, REALWORLD_ENTRY_TIMEOUT_S, root)

        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(one, order))
        ran = [r for r in results if r is not None]
        dones = [d for d, _ in ran]
        tally = self._tally(dones)
        proposed = len(order)
        effective = proposed - tally["entries_unknown"]
        self.coverage = {
            "tus_total": len(tus), "entries_proposed": proposed, **tally,
            "entries_pct": round(100.0 * tally["entries_analyzed"] / effective, 1) if effective else 0.0,
            "budget_s": REALWORLD_BUDGET_S, "budget_exhausted": len(ran) < proposed,
            "wall_s": round(time.monotonic() - start, 1),
        }
        self.coverage["partial"] = self.coverage["budget_exhausted"] or tally["entries_analyzed"] < effective
        return dones, [r for _, rs in ran for r in rs]
