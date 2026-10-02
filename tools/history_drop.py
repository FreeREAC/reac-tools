#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""The drop list of reac-tools' history rewrite, and the check that keeps the history clean.

Internal material (dated working notes, audits, plans, agent tooling) lives in the private
FreeREAC/freereac-ops repository under reac-tools/<same path>, and the public history is
rewritten so that no commit carries it. tools/history-drop.txt lists every such path and the
commit its last version is taken from; a public file cites one by its bare slug (the file name
without its extension), never by path.

  history_drop.py list [<rev>...]    the internal paths in the history of <rev> (default: --all),
                                     one per line: the rewrite's --paths-from-file input. Refuses,
                                     by name, any internal path the drop list lacks (it would be
                                     dropped with no ops copy)
  history_drop.py ops-confirm        every listed path is in the freereac-ops checkout,
                                     byte-identical to its base: the rewrite may drop it
  history_drop.py check [<rev>...]   no commit reachable from <rev> (default: HEAD) carries an
                                     internal path: the public history stays rewritten

The ops checkout is found by one rule: $FREEREAC_OPS, else the sibling ../freereac-ops, else
absent. Absent, ops-confirm prints OPS-ABSENT and fails: nothing is dropped unconfirmed.

The rewrite, run by hand in a FRESH clone once the move has landed on main (never on a lane
checkout, never force-pushed by a lane):

  git tag -s -m 'before the docs-to-ops rewrite' backup/pre-rewrite-2026-10-01 origin/main
  git push origin backup/pre-rewrite-2026-10-01
  python3 tools/history_drop.py ops-confirm
  python3 tools/history_drop.py list > ../drop.txt
  git filter-repo --invert-paths --paths-from-file ../drop.txt
  python3 tools/history_drop.py check && make test
"""
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DROPS = "tools/history-drop.txt"
OPS_SUBDIR = "reac-tools"

INTERNAL_DIRS = ("docs/audits/", "docs/notes/", "docs/plans/", "docs/design/", "notes/",
                 "plans/", ".claude/")
INTERNAL_NAMES = ("ROADMAP.md", "CLAUDE.md", "AGENTS.md")
PLAN = re.compile(r"-plan(-[^/]*)?\.md$")
LEDGER = re.compile(r"(^|-)(audit|census)(-[^/]*)?\.md$")
DATED = re.compile(r"\d{4}-\d{2}-\d{2}[^/]*\.md$")  # a dated note is a session record, not a doc


def belongs_in_ops(path):
    """True when <path> is internal material or vendor RE: it lives in freereac-ops."""
    base = path.rsplit("/", 1)[-1]
    if base.startswith("firmware-") and base.endswith(".md"):
        return True
    if base.endswith(".bin"):
        return True  # a vendor binary
    return (path.startswith(INTERNAL_DIRS) or base in INTERNAL_NAMES
            or bool(PLAN.search(base) or LEDGER.search(base) or DATED.search(base)))


def git(*args, cwd=REPO):
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True)
    if p.returncode != 0:
        raise SystemExit("git %s: %s" % (" ".join(args), p.stderr.decode(errors="replace").strip()))
    return p.stdout


def read_drops(repo=REPO):
    """[(base sha, path)] from the drop list: each "# base <sha>" line names the commit the
    paths after it are taken from."""
    base, drops = None, []
    with open(os.path.join(repo, DROPS)) as f:
        for line in f:
            line = line.strip()
            if line.startswith("# base "):
                base = line.split()[2]
            elif line and not line.startswith("#"):
                if not base:
                    raise SystemExit("%s: %s comes before any \"# base <sha>\" line" % (DROPS, line))
                drops.append((base, line))
    if not drops:
        raise SystemExit("%s lists no path" % DROPS)
    return drops


def history_paths(revs, repo=REPO):
    """{path: the oldest commit that touches it} over every commit reachable from <revs>; merges
    are diffed against each parent, so a file a merge brings in is seen too."""
    data = git("log", "-m", "--no-renames", "--name-only", "-z", "--format=%x00%H", *revs, "--",
               cwd=repo).decode()
    # each record is NUL <sha> NUL, then "\n" and its NUL-terminated names; a name is never
    # empty, so the token after an empty one is a commit
    seen, commit, after_empty = {}, None, False
    for tok in data.split("\0"):
        if after_empty:
            commit, after_empty = tok, False
        elif not tok:
            after_empty = True
        else:
            seen[tok[1:] if tok.startswith("\n") else tok] = commit  # log is newest first
    return seen


def history_internal(revs, repo=REPO):
    """{internal path: the commit it entered by} in the history of <revs>: every listed path
    and every path the rule classes as internal."""
    listed = {p for _, p in read_drops(repo)}
    return {p: c for p, c in history_paths(revs, repo).items()
            if p in listed or belongs_in_ops(p)}


def list_drops(revs=("--all",), repo=REPO, out=sys.stdout, err=sys.stderr):
    """Print the rewrite's drop list; returns the count of internal paths the list lacks."""
    found = history_internal(revs, repo)
    listed = {p for _, p in read_drops(repo)}
    unlisted = sorted(p for p in found if p not in listed)
    for p in unlisted:
        print("UNLISTED %s (%s): internal, in the history, and not on %s: it has no ops copy"
              % (p, found[p][:12], DROPS), file=err)
    for p in sorted(found):
        print(p, file=out)
    return len(unlisted)


def ops_root(repo=REPO):
    """The freereac-ops checkout: $FREEREAC_OPS, else ../freereac-ops beside this repo, else None."""
    env = os.environ.get("FREEREAC_OPS")
    if env:
        return env if os.path.isdir(env) else None
    sib = os.path.join(os.path.dirname(os.path.abspath(repo)), "freereac-ops")
    return sib if os.path.isdir(sib) else None


def ops_confirm(repo=REPO, out=sys.stdout):
    """One line per listed path the ops checkout lacks or holds changed; returns the count
    (the whole list when the checkout is absent)."""
    drops = read_drops(repo)
    root = ops_root(repo)
    if root is None:
        print("OPS-ABSENT: no $FREEREAC_OPS and no ../freereac-ops; %d path(s) unconfirmed"
              % len(drops), file=out)
        return len(drops)
    fails = 0
    for base, p in drops:
        want = git("show", "%s:%s" % (base, p), cwd=repo)
        dest = os.path.join(root, OPS_SUBDIR, p)
        if not os.path.isfile(dest):
            print("OPS-MISSING %s: not at %s" % (p, dest), file=out)
            fails += 1
            continue
        with open(dest, "rb") as f:
            if f.read() != want:
                print("OPS-DIFFERS %s: %s is not %s:%s" % (p, dest, base[:12], p), file=out)
                fails += 1
    print("OPS OK %d" % len(drops) if not fails else "OPS FAILED %d" % fails, file=out)
    return fails


def check(revs=("HEAD",), repo=REPO, out=sys.stdout):
    """One HISTORY-INTERNAL line per internal path still in the history; returns the count."""
    found = history_internal(revs, repo)
    for p in sorted(found):
        print("HISTORY-INTERNAL %s: added in %s; the public history must not carry it (%s)"
              % (p, found[p][:12], DROPS), file=out)
    n = int(git("rev-list", "--count", *revs, cwd=repo).decode().strip() or 0)
    print("HISTORY OK %d commits" % n if not found else "HISTORY FAILED %d" % len(found), file=out)
    return len(found)


def main(argv):
    if argv and argv[0] == "list":
        return 1 if list_drops(tuple(argv[1:]) or ("--all",)) else 0
    if argv == ["ops-confirm"]:
        return 1 if ops_confirm() else 0
    if argv and argv[0] == "check":
        return 1 if check(tuple(argv[1:]) or ("HEAD",)) else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
