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
import subprocess
import sys
import tempfile
import unittest

PKG = pathlib.Path(__file__).resolve().parent.parent / "reac"

# Anything the interpreter ships.
STDLIB = sys.stdlib_module_names

LOCAL = {"reac"}


_PROBE = """
import importlib, sys
sys.path[:0] = sys.argv[3:]
sys.path.insert(0, sys.argv[1])
importlib.import_module("reac." + sys.argv[2])
foreign = sorted({m.split(".")[0] for m in sys.modules} - sys.stdlib_module_names - {"reac", "__main__"})
print("\\n".join(foreign))
"""


def _import_in_bare_interpreter(root, name, extra_path=None):
    """Import reac.<name> in a fresh interpreter with no site-packages (-S, -I).

    Prints, on stdout, every loaded top-level module that is not the standard
    library and not this package. extra_path stands in for an installed
    third-party package so the check itself can be shown to see one.
    """
    extra = [str(extra_path)] if extra_path else []
    return subprocess.run(
        [sys.executable, "-I", "-S", "-c", _PROBE, str(root), name, *extra],
        capture_output=True,
        text=True,
        timeout=60,
    )


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

    def test_importing_each_module_loads_only_the_standard_library(self):
        """Behaviour, not source: import each module with only the stdlib on the path."""
        modules = sorted(p.stem for p in PKG.glob("*.py") if p.stem != "__init__")
        self.assertTrue(modules, "no modules found -- test is looking in the wrong place")
        for name in modules:
            with self.subTest(module=name):
                result = _import_in_bare_interpreter(PKG.parent, name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    result.stdout.split(),
                    [],
                    f"importing reac.{name} loaded modules outside the standard library",
                )

    def test_the_bare_import_check_catches_a_third_party_import(self):
        """Sabotage of the check itself: a planted third-party import must be seen."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            pkg = tmp / "reac"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("")
            (pkg / "planted.py").write_text("import thirdparty_probe\n")
            site = tmp / "site"
            site.mkdir()
            (site / "thirdparty_probe.py").write_text("")
            result = _import_in_bare_interpreter(tmp, "planted", extra_path=site)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.split(), ["thirdparty_probe"])
            # Without the module installed the planted import fails loudly.
            result = _import_in_bare_interpreter(tmp, "planted")
            self.assertNotEqual(result.returncode, 0)

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
