"""python -m tcb -- the command line.

  tcb check [--tools T,T] [--corpora C,C] [--labels-repo PATH] [--skip tools,corpus,aurora-lint,labels] [--json]
  tcb build-aurora-lint [--jobs N]
  tcb env [--json]
  tcb bundles [--dir DIR]
  tcb run realworld --tool T --codebase C [--jobs N]
  tcb run juliet --tool T [--cwes CWE121_...,CWE476_...] [--jobs N]
  tcb mapping-coverage BUNDLE_DIR
  tcb selfcheck [--tools T,T] [--update] [--jobs N]
  tcb table NAME BUNDLE... [--out DIR] [--labels-repo PATH]
  tcb timing --tool T --target C|juliet|juliet:CWE... [--repeats N] [--warmup N] [--cold] [--jobs N]
"""

import argparse
import json
import sys
from pathlib import Path

from . import check as check_mod
from . import env as env_mod
from . import bundle as bundle_mod


def _csv(s: str | None) -> list[str] | None:
    return [x for x in s.split(",") if x] if s else None


def cmd_check(args) -> int:
    rows = check_mod.run_all(
        tools=_csv(args.tools), corpora=_csv(args.corpora),
        labels_repo=Path(args.labels_repo) if args.labels_repo else None,
        skip=set(_csv(args.skip) or []),
    )
    if args.json:
        print(json.dumps(check_mod.as_dicts(rows), indent=2))
    else:
        for r in rows:
            print(r.line())
        bad = check_mod.failed(rows)
        print(f"\n{len(rows)} checks, {len(bad)} failed" + ("" if not bad else " -- fix the rows above before running"))
    return 1 if check_mod.failed(rows) else 0


def cmd_build(args) -> int:
    from . import build
    return build.build(jobs=args.jobs)


def cmd_env(args) -> int:
    rec = env_mod.record()
    if args.json:
        print(json.dumps(rec, indent=2))
        return 0
    pkgs = rec.pop("dev_packages")
    for k, v in rec.items():
        print(f"{k:22s} {v}")
    print(f"{'dev_packages':22s} {len(pkgs)} (sha256 {rec['dev_packages_sha256'][:12]}...)")
    return 0


def cmd_bundles(args) -> int:
    root = Path(args.dir) if args.dir else None
    for b in bundle_mod.list_bundles(root):
        m = bundle_mod.read_meta(b)
        print(f"{b.name:60s} {m['status']:8s} findings={m.get('finding_count', '?'):>7} "
              f"host={m['environment']['hostname']}")
    return 0


def cmd_run(args) -> int:
    from . import run as run_mod
    if args.what == "realworld":
        d = run_mod.run_realworld(args.tool, args.codebase, args.jobs)
    else:
        d = run_mod.run_juliet(args.tool, _csv(args.cwes), args.jobs)
    m = bundle_mod.read_meta(d)
    print(f"bundle: {d}  status={m['status']} findings={m['finding_count']}")
    return 0 if m["status"] == "ok" else 2


def cmd_mapping(args) -> int:
    from . import mapping as mapping_mod
    b = Path(args.bundle)
    m = bundle_mod.read_meta(b)
    cov = mapping_mod.coverage(m["tool"], [f["check_id"] for f in bundle_mod.read_findings(b)])
    print(f"{m['tool']} {m['target']}: findings {cov['findings']}  check ids {cov['check_ids']}")
    for cid, n in cov["unmapped_top"]:
        print(f"  unmapped {n:6d}  {cid}")
    return 0


def cmd_selfcheck(args) -> int:
    from . import selfcheck
    return selfcheck.run(_csv(args.tools), update=args.update, jobs=args.jobs)


def cmd_timing(args) -> int:
    from . import timing
    timing.measure(args.tool, args.target, args.repeats, args.jobs, args.warmup, args.cold,
                   args.max_load, args.force)
    return 0


def cmd_table(args) -> int:
    from . import tables
    fn = tables.TABLES[args.name]
    out_dir = Path(args.out) if args.out else None
    paths = [Path(p) for p in args.inputs]
    if args.name == "realworld-precision":
        if not args.labels_repo:
            sys.exit("realworld-precision needs --labels-repo PATH (a benchmark_adjudication clone)")
        text = fn(paths, Path(args.labels_repo), out_dir)
    else:
        text = fn(paths, out_dir)
    print(text, end="")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="tcb", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="assert every pinned input; nonzero exit with remedies on drift")
    c.add_argument("--tools", help="comma-separated tool names (default: all in pins/tools.json)")
    c.add_argument("--corpora", help="comma-separated corpus names, 'juliet' included (default: all)")
    c.add_argument("--labels-repo", help="path to a benchmark_adjudication clone")
    c.add_argument("--skip", help="comma-separated sections to skip: tools,corpus,aurora-lint,labels")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_check)

    b = sub.add_parser("build-aurora-lint", help="clone + build the pinned aurora-lint into .cache/")
    b.add_argument("--jobs", type=int)
    b.set_defaults(func=cmd_build)

    e = sub.add_parser("env", help="print the environment record a run bundle would carry")
    e.add_argument("--json", action="store_true")
    e.set_defaults(func=cmd_env)

    l = sub.add_parser("bundles", help="list run bundles under runs/")
    l.add_argument("--dir")
    l.set_defaults(func=cmd_bundles)

    r = sub.add_parser("run", help="run one tool on one target and write a bundle under runs/")
    r.add_argument("what", choices=["realworld", "juliet"])
    r.add_argument("--tool", required=True, help="aurora-lint | aurora-lint-full | cppcheck | clang-tidy")
    r.add_argument("--codebase", help="realworld: a corpus name from pins/corpus.json")
    r.add_argument("--cwes", help="juliet: comma-separated CWE directory names (default: manifests/juliet_cwes.txt)")
    r.add_argument("--jobs", type=int, default=8)
    r.set_defaults(func=cmd_run)

    mp = sub.add_parser("mapping-coverage", help="how much of a bundle the check mapping speaks for")
    mp.add_argument("bundle")
    mp.set_defaults(func=cmd_mapping)

    sc = sub.add_parser("selfcheck", help="rerun the Juliet sample per tool and compare to tests/golden/")
    sc.add_argument("--tools", help="comma-separated tool ids (default: all)")
    sc.add_argument("--update", action="store_true", help="rewrite the goldens from this run")
    sc.add_argument("--jobs", type=int, default=8)
    sc.set_defaults(func=cmd_selfcheck)

    t = sub.add_parser("timing", help="controlled runtime measurement: repeated, sequential, contention-checked")
    t.add_argument("--tool", required=True)
    t.add_argument("--target", required=True, help="a corpus name, 'juliet', or 'juliet:CWE416_Use_After_Free'")
    t.add_argument("--repeats", type=int, default=3)
    t.add_argument("--warmup", type=int, default=1, help="untimed runs first (warm-cache figure); 0 with --cold")
    t.add_argument("--cold", action="store_true", help="drop the page cache before every repeat (root)")
    t.add_argument("--jobs", type=int, default=8)
    t.add_argument("--max-load", type=float, default=1.0)
    t.add_argument("--force", action="store_true", help="time under contention anyway (recorded, marked invalid)")
    t.set_defaults(func=cmd_timing)

    tb = sub.add_parser("table", help="one result table from bundles (or timing records), CSV + Markdown")
    tb.add_argument("name", choices=["juliet-per-cwe", "juliet-summary", "realworld-counts",
                                     "realworld-precision", "timing", "environment"])
    tb.add_argument("inputs", nargs="+", help="bundle directories (timing: runs/timing/*.json)")
    tb.add_argument("--labels-repo", help="realworld-precision: path to a benchmark_adjudication clone")
    tb.add_argument("--out", help="directory to write <name>.csv, <name>.md and <name>.footer.json")
    tb.set_defaults(func=cmd_table)

    args = p.parse_args(argv)
    if args.cmd == "run" and args.what == "realworld" and not args.codebase:
        p.error("run realworld needs --codebase")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
