# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""The dependency-free property is load-bearing, so it is pinned here.

reac-tools gets copied onto an OpenWrt router mid-session, where there is no
package manager and no scientific stack. Every module must therefore import
nothing outside the standard library. Analysis that needs numpy or scipy lives
in FreeREAC/reac-labtools instead -- if a change here wants one of those, it
belongs in that repository, not in this one.
"""

import ast
import os
import pathlib
import sys
import unittest

PKG = pathlib.Path(__file__).resolve().parent.parent / "reac"

# Anything the interpreter ships. sys.stdlib_module_names is 3.10+; the tuple
# below covers what this package actually uses on older interpreters.
STDLIB = getattr(
    sys,
    "stdlib_module_names",
    frozenset(
        {
            "argparse", "binascii", "collections", "contextlib", "dataclasses",
            "io", "json", "os", "re", "statistics", "struct", "sys", "tempfile",
            "unittest",
        }
    ),
)

LOCAL = {"reac"}


def _top_level_imports(path):
    """Every distinct top-level module name imported by a source file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            # level > 0 is a relative import, i.e. this package
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


class TestNoDependencies(unittest.TestCase):
    def test_package_is_stdlib_only(self):
        modules = sorted(PKG.glob("*.py"))
        self.assertTrue(modules, "no modules found -- test is looking in the wrong place")

        for module in modules:
            with self.subTest(module=module.name):
                foreign = {
                    name
                    for name in _top_level_imports(module)
                    if name not in STDLIB and name not in LOCAL
                }
                self.assertEqual(
                    foreign,
                    set(),
                    f"{module.name} imports {sorted(foreign)}, which is outside the "
                    f"standard library. reac-tools must stay dependency-free so it "
                    f"runs on a busybox router; put this in reac-labtools instead.",
                )

    def test_numpy_and_scipy_are_absent_from_the_tree(self):
        """A grep-level backstop: neither name should appear in any source file."""
        root = PKG.parent
        offenders = []
        for path in root.rglob("*.py"):
            if ".git" in path.parts or path.name == os.path.basename(__file__):
                continue
            text = path.read_text(encoding="utf-8")
            if "numpy" in text or "scipy" in text:
                offenders.append(str(path.relative_to(root)))
        self.assertEqual(
            offenders,
            [],
            f"numpy/scipy referenced in {offenders}; that work belongs in reac-labtools",
        )


if __name__ == "__main__":
    unittest.main()
