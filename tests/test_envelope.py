"""The resource envelope and the invocation timer. No analyzer is invoked
and no corpus is read: the children are small Python programs.

The cgroup test needs a systemd user instance that delegates the memory
controller; where there is none it is skipped, not failed."""

import json
import os
import shutil
import subprocess
import sys
import textwrap
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from tcb import envelope
from tcb.tools.base import run_timed

REPO = Path(__file__).resolve().parent.parent
PY = sys.executable


class ParseTest(unittest.TestCase):
    def test_cpu_lists(self):
        online = sorted(os.sched_getaffinity(0))
        first = online[0]
        self.assertEqual(envelope.parse_cpus(str(first)), [first])
        self.assertEqual(envelope.parse_cpus(f"{first},{first}"), [first])
        if len(online) >= 2 and online[1] == first + 1:
            self.assertEqual(envelope.parse_cpus(f"{first}-{first + 1}"), [first, first + 1])
        for bad in ("", "a", "3-1", "1,,x"):
            with self.assertRaises(ValueError):
                envelope.parse_cpus(bad)

    def test_an_unavailable_cpu_is_refused(self):
        with self.assertRaises(ValueError):
            envelope.parse_cpus(str(max(os.sched_getaffinity(0)) + 4096))

    def test_sizes_are_binary(self):
        self.assertEqual(envelope.parse_bytes("32G"), 32 << 30)
        self.assertEqual(envelope.parse_bytes("512M"), 512 << 20)
        self.assertEqual(envelope.parse_bytes("1024"), 1024)
        self.assertEqual(envelope.parse_bytes("2GiB"), 2 << 30)
        with self.assertRaises(ValueError):
            envelope.parse_bytes("lots")


class WrapTest(unittest.TestCase):
    def tearDown(self):
        envelope._ACTIVE = envelope.Envelope()

    def test_no_envelope_leaves_argv_alone(self):
        envelope._ACTIVE = envelope.Envelope()
        self.assertEqual(envelope.wrap_argv(["tool", "-x"]), ["tool", "-x"])

    def test_cpu_set_goes_through_taskset(self):
        envelope._ACTIVE = envelope.Envelope(cpus=[0, 2])
        w = envelope.wrap_argv(["tool", "-x"])
        self.assertEqual(w[:2], ["/bin/sh", "-c"])
        self.assertEqual(w[-4:], ["", "0,2", "tool", "-x"])

    def test_describe_names_the_cap_and_the_mechanism(self):
        d = envelope.Envelope(cpus=[0, 2, 4], mem_max_bytes=32 << 30).describe()
        self.assertEqual(d["cpus"], "0,2,4")
        self.assertEqual(d["cpu_count"], 3)
        self.assertEqual(d["memory_max_bytes"], 32 << 30)
        self.assertEqual(d["memory_swap_max_bytes"], 0)
        self.assertIn("taskset", d["mechanism"])
        self.assertIn("memory.max", d["mechanism"])
        self.assertIn("uncapped", envelope.Envelope().describe()["mechanism"])


BUSY = "import time\nt = time.process_time()\nwhile time.process_time() - t < 0.6: pass\n"


class RunTimedTest(unittest.TestCase):
    def tearDown(self):
        envelope._ACTIVE = envelope.Envelope()

    def test_output_exit_status_and_rss(self):
        d = run_timed([PY, "-c", "import sys; b = bytearray(64 << 20); print('out'); "
                                 "print('err', file=sys.stderr); sys.exit(3)"])
        self.assertEqual(d.returncode, 3)
        self.assertEqual(d.stdout.strip(), "out")
        self.assertEqual(d.stderr.strip(), "err")
        self.assertGreater(d.max_rss_kb, 64 << 10)       # ru_maxrss is KiB on Linux

    def test_cpu_time_is_per_child_under_concurrency(self):
        """The regression the wait4 reaping fixes: an idle invocation that
        overlaps a busy one must not be billed the busy one's CPU."""
        with ThreadPoolExecutor(max_workers=2) as pool:
            busy = pool.submit(run_timed, [PY, "-c", BUSY])
            idle = pool.submit(run_timed, [PY, "-c", "import time; time.sleep(1.0)"])
            b, i = busy.result(), idle.result()
        self.assertGreater(b.user_s + b.sys_s, 0.5)
        self.assertLess(i.user_s + i.sys_s, 0.3)

    def test_timeout_is_124_and_does_not_hang(self):
        d = run_timed([PY, "-c", "import time; time.sleep(30)"], timeout=1)
        self.assertEqual(d.returncode, 124)
        self.assertLess(d.wall_s, 10)

    @unittest.skipUnless(shutil.which("taskset"), "taskset not installed")
    def test_the_cpu_set_reaches_the_tool(self):
        cpu = min(os.sched_getaffinity(0))
        envelope._ACTIVE = envelope.Envelope(cpus=[cpu])
        d = run_timed([PY, "-c", "import os; print(sorted(os.sched_getaffinity(0)))"])
        self.assertEqual(d.returncode, 0, d.stderr)
        self.assertEqual(json.loads(d.stdout), [cpu])
        self.assertEqual(d.argv, [PY, "-c", "import os; print(sorted(os.sched_getaffinity(0)))"])


CGROUP_PROBE = textwrap.dedent(f"""
    import json, os, sys
    sys.path.insert(0, {str(REPO)!r})
    os.environ[{envelope.SCOPE_ENV!r}] = "1"
    from tcb import envelope
    from tcb.tools.base import run_timed
    envelope.activate(None, 64 << 20, [])
    out = {{}}
    for name, size in (("small", 8 << 20), ("big", 256 << 20)):
        with envelope.tool_run() as rc:
            d = run_timed([sys.executable, "-c", f"b = bytearray({{size}}); b[::4096] = b'x' * len(b[::4096])"])
        out[name] = {{"rc": d.returncode, **rc.result}}
    print(json.dumps(out))
""")


def _user_scope_available() -> bool:
    if not shutil.which("systemd-run"):
        return False
    p = subprocess.run(["systemd-run", "--user", "--scope", "--quiet", "-p", "Delegate=yes", "true"],
                       capture_output=True, text=True)
    return p.returncode == 0


@unittest.skipUnless(sys.platform == "linux" and _user_scope_available(),
                     "needs a systemd user instance that can create a delegated scope")
class CgroupTest(unittest.TestCase):
    def test_each_run_gets_its_own_peak_and_the_cap_is_an_oom(self):
        p = subprocess.run(["systemd-run", "--user", "--scope", "--quiet", "-p", "Delegate=yes",
                            PY, "-c", CGROUP_PROBE], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertEqual(r["small"]["rc"], 0)
        self.assertEqual(r["small"]["oom_kills"], 0)
        self.assertGreater(r["small"]["cgroup_memory_peak_bytes"], 8 << 20)
        self.assertLessEqual(r["small"]["cgroup_memory_peak_bytes"], 64 << 20)
        self.assertNotEqual(r["big"]["rc"], 0)
        self.assertGreaterEqual(r["big"]["oom_kills"], 1)


if __name__ == "__main__":
    unittest.main()
