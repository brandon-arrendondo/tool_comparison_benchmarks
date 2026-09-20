"""One adapter per tool. Each knows how to build the command for a real-world
codebase and for one Juliet test-case file (or CWE directory), and how to
parse the tool's own output into finding records. Nothing here classifies
or maps: a record carries the tool's native check id and the runner attaches
the Juliet section; the mapping is applied only when a table asks."""

from importlib import import_module

TOOLS = {
    "aurora-lint": "tcb.tools.aurora_lint",
    "aurora-lint-full": "tcb.tools.aurora_lint",   # full-mode manifest on Juliet; same binary
    "cppcheck": "tcb.tools.cppcheck",
    "clang-tidy": "tcb.tools.clang_tidy",
}


def adapter(name: str):
    if name not in TOOLS:
        raise KeyError(f"no adapter for {name!r}; known: {sorted(TOOLS)}")
    mod = import_module(TOOLS[name])
    return mod.Adapter(name)
