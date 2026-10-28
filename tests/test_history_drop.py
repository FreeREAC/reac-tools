# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""The history rewrite drops only what freereac-ops holds, and the check sees what it missed.

tools/history_drop.py is run by hand on a fresh clone, so these tests drive it on throwaway
repositories: an internal file added and later deleted, one brought in by a merge, a rewrite
that drops them, and an ops checkout that holds (or lacks) the dropped files. The name rules
come from a throwaway rules file with made-up names: the real ones are what the tool keeps out
of this tree.
"""
import io
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import history_drop  # noqa: E402

ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org",
       "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
RULES = "# made-up name rules for the tests\ninternal/\ndocs/private/\n\nPRIVATE.md\nTODO.md\n"


def git(repo, *args):
    p = subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main",
                        *args], cwd=repo, capture_output=True, text=True,
                       env={**os.environ, **ENV})
    if p.returncode != 0:
        raise AssertionError("git %s: %s" % (" ".join(args), p.stderr))
    return p.stdout.strip()


def write(repo, path, text):
    full = os.path.join(repo, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(text)


def rules_checkout(tmp):
    """An ops checkout under <tmp> that carries only the test rules; returns its path."""
    ops = os.path.join(tmp, "rules-ops")
    write(ops, history_drop.RULES, RULES)
    return ops


class HistoryRepo(unittest.TestCase):
    """main: README, a dated note added then deleted, a merge that brings in a plan."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = os.path.join(self.tmp.name, "reac-tools")
        os.makedirs(self.repo)
        git(self.repo, "init", "-q")
        write(self.repo, "README.md", "reac-tools\n")
        write(self.repo, "docs/session-2026-09-21.md", "who did what\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "start")
        self.note_base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "rm", "-q", "docs/session-2026-09-21.md")
        git(self.repo, "commit", "-q", "-m", "drop the note from the tip")
        git(self.repo, "checkout", "-q", "-b", "side")
        write(self.repo, "docs/next-plan.md", "what next\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "a plan")
        self.plan_base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "-q", "main")
        write(self.repo, "reac/cli.py", "print()\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "code")
        git(self.repo, "merge", "-q", "--no-ff", "-m", "merge side", "side")
        git(self.repo, "branch", "-q", "-D", "side")
        self.env = mock.patch.dict(os.environ, {"FREEREAC_OPS": rules_checkout(self.tmp.name)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def drops(self, *groups):
        text = "".join("# base %s\n%s\n" % (base, "\n".join(paths)) for base, paths in groups)
        write(self.repo, history_drop.DROPS, text)

    def full_list(self):
        self.drops((self.note_base, ["docs/session-2026-09-21.md"]),
                   (self.plan_base, ["docs/next-plan.md"]))

    def run_list(self):
        out, err = io.StringIO(), io.StringIO()
        n = history_drop.list_drops(("--all",), self.repo, out, err)
        return n, out.getvalue().split(), err.getvalue()

    def run_check(self):
        out, err = io.StringIO(), io.StringIO()
        return history_drop.check(("HEAD",), self.repo, out, err), out.getvalue()

    def rewrite(self):
        """What filter-repo --invert-paths does to these paths, with git alone."""
        paths = " ".join(p for _, p in history_drop.read_drops(self.repo))
        p = subprocess.run(["git", "-c", "commit.gpgsign=false", "filter-branch", "-f",
                            "--index-filter", "git rm -q --cached --ignore-unmatch " + paths,
                            "--", "--all"], cwd=self.repo, capture_output=True, text=True,
                           env={**os.environ, **ENV, "FILTER_BRANCH_SQUELCH_WARNING": "1"})
        self.assertEqual(p.returncode, 0, p.stderr)
        subprocess.run(["git", "update-ref", "--stdin"], cwd=self.repo, text=True,
                       input=git(self.repo, "for-each-ref", "--format=delete %(refname)",
                                 "refs/original/") + "\n", check=True)

    def test_list_names_deleted_and_merged_internal_files(self):
        self.full_list()
        n, paths, err = self.run_list()
        self.assertEqual(n, 0, err)
        self.assertEqual(paths, ["docs/next-plan.md", "docs/session-2026-09-21.md"])

    def test_list_refuses_an_internal_file_the_list_lacks(self):
        self.drops((self.note_base, ["docs/session-2026-09-21.md"]))
        n, paths, err = self.run_list()
        self.assertEqual(n, 1)
        self.assertIn("UNLISTED docs/next-plan.md", err)
        self.assertIn("docs/next-plan.md", paths)

    def test_check_fails_before_the_rewrite_and_passes_after(self):
        self.full_list()
        n, out = self.run_check()
        self.assertEqual(n, 2, out)
        self.assertIn("HISTORY-INTERNAL docs/session-2026-09-21.md", out)
        self.assertIn("HISTORY FAILED 2", out)
        self.rewrite()
        n, out = self.run_check()
        self.assertEqual(n, 0, out)
        self.assertIn("HISTORY OK 5 commits", out)
        self.assertEqual(git(self.repo, "ls-tree", "-r", "--name-only", "HEAD"),
                         "README.md\nreac/cli.py")

    def test_ops_confirm(self):
        self.full_list()
        ops = os.path.join(self.tmp.name, "freereac-ops")
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"FREEREAC_OPS": ""}):
            self.assertEqual(history_drop.ops_confirm(self.repo, out), 2)
        self.assertIn("OPS-ABSENT", out.getvalue())

        write(ops, "reac-tools/docs/session-2026-09-21.md", "who did what\n")
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"FREEREAC_OPS": ""}):  # the sibling rung
            self.assertEqual(history_drop.ops_confirm(self.repo, out), 1)
        self.assertIn("OPS-MISSING docs/next-plan.md", out.getvalue())

        write(ops, "reac-tools/docs/next-plan.md", "what next, edited\n")
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"FREEREAC_OPS": ops}):
            self.assertEqual(history_drop.ops_confirm(self.repo, out), 1)
        self.assertIn("OPS-DIFFERS docs/next-plan.md", out.getvalue())

        write(ops, "reac-tools/docs/next-plan.md", "what next\n")
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"FREEREAC_OPS": ops}):
            self.assertEqual(history_drop.ops_confirm(self.repo, out), 0)
        self.assertIn("OPS OK 2", out.getvalue())


class Classes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.rules = history_drop.read_rules(rules_checkout(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_rules_file(self):
        self.assertEqual(self.rules, (("internal/", "docs/private/"), ("PRIVATE.md", "TODO.md")))
        self.assertEqual(history_drop.read_rules(None), ((), ()))
        with self.assertRaises(SystemExit):  # a checkout without the file is not an empty rule set
            history_drop.read_rules(self.tmp.name)

    def test_internal(self):
        for p in ("docs/integrate-or-drop-2026-09-21.md", "internal/x.md", "PRIVATE.md",
                  "docs/private/a.md", "docs/TODO.md", "rollout-plan.md",
                  "defect-census-2026-08-23.md", "internal/skills/x/SKILL.md",
                  "firmware-findings.md", "spec/scene-8904.bin"):
            with self.subTest(path=p):
                self.assertTrue(history_drop.belongs_in_ops(p, self.rules))

    def test_public(self):
        for p in ("README.md", "wireshark/README.md", "reac/cli.py", "LICENSE",
                  "tests/fixtures/real_reac_stream.pcap", "tools/real_capture_payloads.json",
                  "internals.md", "docs/privateer.md"):
            with self.subTest(path=p):
                self.assertFalse(history_drop.belongs_in_ops(p, self.rules))

    def test_without_rules_only_the_patterns_classify(self):
        self.assertFalse(history_drop.belongs_in_ops("internal/x.md", ((), ())))
        self.assertTrue(history_drop.belongs_in_ops("internal/x-plan.md", ((), ())))
        with mock.patch.dict(os.environ, {"FREEREAC_OPS": rules_checkout(self.tmp.name)}):
            self.assertTrue(history_drop.belongs_in_ops("internal/x.md"))  # None reads the checkout


class ThisRepo(unittest.TestCase):
    def test_every_internal_path_in_the_history_is_on_the_drop_list(self):
        """An internal file committed here without an ops route fails, by name."""
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(history_drop.list_drops(("HEAD",), ROOT, out, err), 0, err.getvalue())

    def test_every_listed_base_carries_its_path(self):
        """Before the rewrite each base carries its path; after it, base and path are both gone
        (they live on under the backup tag)."""
        if git(ROOT, "rev-parse", "--is-shallow-repository") == "true":
            self.skipTest("shallow clone: the bases are not fetched")
        history = history_drop.history_paths(("HEAD",), ROOT)
        for base, p in history_drop.read_drops(ROOT):
            with self.subTest(path=p):
                present = subprocess.run(["git", "cat-file", "-e", base + "^{commit}"], cwd=ROOT,
                                         capture_output=True).returncode == 0
                if present:
                    git(ROOT, "cat-file", "-e", "%s:%s" % (base, p))
                else:
                    self.assertNotIn(p, history, "%s is in the history but its base %s is not"
                                     % (p, base[:12]))


if __name__ == "__main__":
    unittest.main()
