"""Synthetic-input tests for the pins, checks and bundle writer. Nothing
here touches a real corpus or tool: every input is built in a temp dir, so
the tests carry no finding that could locate a defect (ADR-0007) and run
on a machine with nothing installed."""

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tcb import bundle, check, pins


def _git(path, *args):
    return subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True, check=True).stdout.strip()


class PinsTest(unittest.TestCase):
    def test_every_pin_file_parses_and_is_digested(self):
        self.assertIn("sha", pins.aurora_lint())
        self.assertEqual(len(pins.aurora_lint()["sha"]), 40)
        self.assertEqual({e["name"] for e in pins.corpus()["repos"]} & {"libcrc", "lua"}, {"libcrc", "lua"})
        self.assertEqual(len(pins.corpus()["juliet"]["sha"]), 40)
        d = pins.pin_digests()
        self.assertEqual(set(d), {"aurora_lint.json", "corpus.json", "labels.json", "tools.json"})

    def test_corpus_pin_records_its_source(self):
        src = pins.corpus()["source"]
        self.assertEqual(src["path"], "data/benchmark_repos.json")
        self.assertEqual(src["aurora_lint_sha"], pins.aurora_lint()["sha"])

    def test_tool_specs_are_complete(self):
        for name, spec in pins.tools().items():
            for k in ("binary", "version_cmd", "version_regex", "version_policy", "origin", "license"):
                self.assertIn(k, spec, f"{name} lacks {k}")
            if spec["version_policy"] == "distro":
                self.assertIn("by_distro", spec)
            else:
                self.assertIn("version", spec)


class CheckToolTest(unittest.TestCase):
    def _fake_tool(self, tmp, prints):
        exe = Path(tmp) / "faketool"
        exe.write_text(f"#!/bin/sh\necho '{prints}'\n")
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
        return exe

    def test_exact_version_ok_and_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = self._fake_tool(tmp, "FakeTool version 1.2.3")
            spec = {"binary": str(exe), "version_cmd": [str(exe), "--version"],
                    "version_regex": r"version (\d+\.\d+\.\d+)", "version_policy": "exact",
                    "version": "1.2.3", "origin": {"kind": "prebuilt", "install_dir": tmp,
                                                    "archive_url": "x", "sha256": "0" * 64},
                    "resolved_path": str(exe.resolve())}
            rows = check.check_tool("fake", spec, "ubuntu-24.04")
            self.assertEqual([r.status for r in rows], ["OK", "OK", "OK"])
            spec["version"] = "9.9.9"
            rows = check.check_tool("fake", spec, "ubuntu-24.04")
            self.assertEqual(rows[0].status, "FAIL")
            self.assertTrue(rows[0].remedy)

    def test_resolved_path_shadowing_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = self._fake_tool(tmp, "FakeTool version 1.2.3")
            spec = {"binary": str(exe), "version_cmd": [str(exe), "--version"],
                    "version_regex": r"version (\d+\.\d+\.\d+)", "version_policy": "exact",
                    "version": "1.2.3", "origin": {"kind": "prebuilt", "install_dir": tmp,
                                                    "archive_url": "x", "sha256": "0" * 64},
                    "resolved_path": "/nonexistent/pinned/faketool"}
            rows = check.check_tool("fake", spec, "ubuntu-24.04")
            path_row = [r for r in rows if r.check == "tool-path"][0]
            self.assertEqual(path_row.status, "FAIL")

    def test_distro_policy_needs_a_pin_for_this_distro(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = self._fake_tool(tmp, "Cppcheck 2.13.0")
            spec = {"binary": str(exe), "version_cmd": [str(exe), "--version"],
                    "version_regex": r"Cppcheck (\d+\.\d+\.\d+)", "version_policy": "distro",
                    "by_distro": {"ubuntu-24.04": {"version": "2.13.0"}},
                    "origin": {"kind": "prebuilt", "install_dir": tmp, "archive_url": "x", "sha256": "0" * 64},
                    "resolved_path": str(exe.resolve())}
            self.assertEqual(check.check_tool("c", spec, "ubuntu-24.04")[0].status, "OK")
            self.assertEqual(check.check_tool("c", spec, "debian-12")[0].status, "FAIL")

    def test_missing_tool_fails_with_remedy(self):
        spec = {"binary": "no-such-tool-xyz", "version_cmd": ["no-such-tool-xyz", "--version"],
                "version_regex": r"(\d+)", "version_policy": "exact", "version": "1",
                "origin": {"kind": "prebuilt", "install_dir": "/nope", "archive_url": "x", "sha256": "0" * 64},
                "resolved_path": "/nope/no-such-tool-xyz"}
        rows = check.check_tool("gone", spec, "ubuntu-24.04")
        self.assertEqual(rows[0].status, "FAIL")
        self.assertEqual(rows[0].found, "not installed")


class CheckRepoTest(unittest.TestCase):
    def _repo(self, tmp):
        path = Path(tmp) / "repo"
        path.mkdir()
        _git(path, "init", "-q")
        _git(path, "config", "user.email", "t@example.invalid")
        _git(path, "config", "user.name", "t")
        (path / "a.c").write_text("int main(void) { return 0; }\n")
        _git(path, "add", "a.c")
        _git(path, "commit", "-q", "-m", "one")
        return path, _git(path, "rev-parse", "HEAD")

    def test_at_pin_clean_is_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, sha = self._repo(tmp)
            rows = check.check_repo("r", "url", sha, path)
            self.assertEqual([r.status for r in rows], ["OK"])

    def test_drift_stray_c_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, sha = self._repo(tmp)
            (path / "b.c").write_text("int x;\n")             # untracked C: scanned, invisible to git
            (path / "notes.txt").write_text("not scanned\n")  # untracked non-C: fine
            rows = check.check_repo("r", "url", "0" * 40, path)
            by = {r.check: r for r in rows}
            self.assertEqual(by["corpus"].status, "FAIL")
            self.assertIn("checkout --detach", by["corpus"].remedy)
            self.assertEqual(by["corpus-stray"].status, "FAIL")
            self.assertIn("b.c", by["corpus-stray"].remedy)
            rows = check.check_repo("r", "url", sha, Path(tmp) / "absent")
            self.assertEqual(rows[0].status, "FAIL")
            self.assertIn("git clone", rows[0].remedy)


class BundleTest(unittest.TestCase):
    def _make(self, root, order):
        b = bundle.Bundle("faketool", "0.0", "synthetic", root=root)
        recs = [dict(project="p", codebase_commit="c" * 40, file_path="src/z.c", line=3, column=1,
                     check_id="X1", severity="warning", message="m"),
                dict(project="p", codebase_commit="c" * 40, file_path="src/a.c", line=9, column=2,
                     check_id="X2", severity="warning", message="m"),
                dict(project="p", codebase_commit="c" * 40, file_path="src/a.c", line=9, column=1,
                     check_id="X2", severity="warning", message="m")]
        for i in order:
            b.add_finding(**recs[i])
        b.record_command(["faketool", "src"], None, 0, 1.5)
        return b.finish()

    def test_findings_are_sorted_and_byte_identical_regardless_of_insertion_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            d1 = self._make(Path(tmp), [0, 1, 2])
            d2 = self._make(Path(tmp), [2, 0, 1])
            self.assertEqual((d1 / "findings.jsonl").read_bytes(), (d2 / "findings.jsonl").read_bytes())
            self.assertEqual((d1 / "per_file.csv").read_bytes(), (d2 / "per_file.csv").read_bytes())
            recs = bundle.read_findings(d1)
            self.assertEqual([(r["file_path"], r["line"], r["column"]) for r in recs],
                             [("src/a.c", 9, 1), ("src/a.c", 9, 2), ("src/z.c", 3, 1)])
            self.assertEqual(len(bundle.finding_keys(d1)), 2)  # column is not part of the oracle key
            meta = bundle.read_meta(d1)
            self.assertEqual(meta["status"], "ok")
            self.assertEqual(meta["finding_count"], 3)
            self.assertIn("dev_packages_sha256", meta["environment"])
            self.assertEqual(set(meta["pins"]), {"aurora_lint.json", "corpus.json", "labels.json", "tools.json"})

    def test_unknown_field_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            b = bundle.Bundle("t", "0", "s", root=Path(tmp))
            with self.assertRaises(ValueError):
                b.add_finding(project="p", bogus=1)


if __name__ == "__main__":
    unittest.main()
