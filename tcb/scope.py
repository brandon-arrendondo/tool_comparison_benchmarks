"""The per-corpus scope predicate from pins/corpus.json: which files of a
checkout count as the shipped product (`scope_include`) minus what is
carved out (`scope_exclude`). Path-aware globs, the same semantics as
aurora-lint's bench/corpus.py: `*`, `?` and `[...]` stop at `/`, `**`
crosses it. No `scope_include` means unrestricted."""

import re
from functools import lru_cache

from . import pins


@lru_cache(maxsize=None)
def _compile(pat: str) -> re.Pattern:
    out, i = "", 0
    while i < len(pat):
        c = pat[i]
        if pat.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pat.startswith("**", i):
            out += ".*"
            i += 2
        elif c == "*":
            out += "[^/]*"
            i += 1
        elif c == "?":
            out += "[^/]"
            i += 1
        elif c == "[":
            j = pat.find("]", i)
            if j == -1:
                out += re.escape(c)
                i += 1
            else:
                out += "[" + pat[i + 1:j].replace("\\", "\\\\") + "]"
                i = j + 1
        else:
            out += re.escape(c)
            i += 1
    return re.compile("^" + out + "$")


def matches(relpath: str, pat: str) -> bool:
    return _compile(pat).match(relpath) is not None


@lru_cache(maxsize=None)
def _entry(project: str) -> dict:
    for e in pins.corpus()["repos"]:
        if e["name"] == project:
            return e
    return {}


def in_scope(project: str, relpath: str) -> bool:
    e = _entry(project)
    inc = e.get("scope_include")
    if inc and not any(matches(relpath, p) for p in inc):
        return False
    exc = e.get("scope_exclude") or []
    return not any(matches(relpath, p) for p in exc)
