import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from bumpwatch import artifact, cli, lockfiles, report, signals
from bumpwatch.checks import HIGH, LOW, MEDIUM, Checker, Policy
from tests.fixtures import (LIB_JS, LIB_PY, PKG_JSON, PTH_LINE, STEALER_PY, WORM_JS, FakeRegistry, npm_release,
                            npm_tgz, pypi_release, sdist, wheel)


def rules(rep, min_sev=None):
    order = {LOW: 0, MEDIUM: 1, HIGH: 2}
    return {f.rule for f in rep.findings if min_sev is None or order[f.severity] >= order[min_sev]}


class AttackRecreations(unittest.TestCase):
    """Each 2026 attack pattern, rebuilt as an inert before/after pair."""

    def test_shai_hulud_style_worm(self):
        reg = FakeRegistry()
        reg.add(npm_release("demo-lib", "1.0.0"), {"lib.tgz": npm_tgz({"package.json": PKG_JSON, "index.js": LIB_JS})})
        reg.add(npm_release("demo-lib", "1.0.1", scripts={"postinstall": "node bundle.js"}, days_ago=0.5,
                            publisher="maintainer", trusted=False, provenance=False),
                {"lib.tgz": npm_tgz({"package.json": PKG_JSON, "index.js": LIB_JS, "bundle.js": WORM_JS})})
        rep = Checker(reg).compare("npm", "demo-lib", "1.0.0", "1.0.1")
        self.assertTrue({"BW001", "BW005", "BW007", "BW022", "BW023", "BW011", "BW014"} <= rules(rep), rules(rep))
        self.assertTrue({"BW001", "BW007", "BW022"} <= rules(rep, HIGH))
        self.assertIn("BW019", rules(rep, MEDIUM))  # fresh + serious = cooldown advice is medium

    def test_litellm_style_pth_implant(self):
        reg = FakeRegistry()
        src = {"demo/__init__.py": LIB_PY, "setup.py": "from setuptools import setup\nsetup()\n"}
        reg.add(pypi_release("demo", "1.0.0"), {
            "demo-1.0.0-py3-none-any.whl": wheel("demo", "1.0.0", {"demo/__init__.py": LIB_PY}),
            "demo-1.0.0.tar.gz": sdist("demo", "1.0.0", src)})
        reg.add(pypi_release("demo", "1.0.1", provenance=False), {
            "demo-1.0.1-py3-none-any.whl": wheel("demo", "1.0.1", {"demo/__init__.py": LIB_PY,
                                                                   "demo_init.pth": PTH_LINE,
                                                                   "demo/_telemetry.py": STEALER_PY}),
            "demo-1.0.1.tar.gz": sdist("demo", "1.0.1", src)})
        rep = Checker(reg).compare("pypi", "demo", "1.0.0", "1.0.1")
        self.assertTrue({"BW003", "BW016", "BW006", "BW007", "BW011"} <= rules(rep), rules(rep))
        self.assertTrue({"BW003", "BW016", "BW006", "BW007"} <= rules(rep, HIGH))

    def test_axios_style_new_dependency(self):
        reg = FakeRegistry()
        reg.packuments["plain-crypto-helper"] = {"_age_days": 1, "dist-tags": {"latest": "1.0.0"},
                                                 "versions": {"1.0.0": {"scripts": {"postinstall": "node setup.js"}}}}
        files = {"package.json": PKG_JSON, "index.js": LIB_JS}
        reg.add(npm_release("demo-lib", "1.0.0", recent=("ci-bot",), publisher="ci-bot"), {"t.tgz": npm_tgz(files)})
        reg.add(npm_release("demo-lib", "1.0.1", deps={"plain-crypto-helper": "^1.0.0"}, publisher="someone-else",
                            trusted=False, provenance=False), {"t.tgz": npm_tgz(files)})
        rep = Checker(reg).compare("npm", "demo-lib", "1.0.0", "1.0.1")
        self.assertTrue({"BW018", "BW011", "BW013", "BW014"} <= rules(rep), rules(rep))
        self.assertIn("BW018", rules(rep, HIGH))

    def test_pulled_version(self):
        reg = FakeRegistry()
        rel = npm_release("demo-lib", "1.0.0")
        reg.add(rel, {"t.tgz": npm_tgz({"package.json": PKG_JSON})})
        missing = reg.release("npm", "demo-lib", "1.0.1")
        missing.removed_versions = ["1.0.1"]
        reg.releases[("npm", "demo-lib", "1.0.1")] = missing
        rep = Checker(reg).compare("npm", "demo-lib", "1.0.0", "1.0.1")
        self.assertEqual(rules(rep, HIGH), {"BW015"})
        self.assertIn("removed", rep.findings[0].message)


class QuietOnHonestUpdates(unittest.TestCase):
    def test_ordinary_update(self):
        reg = FakeRegistry()
        reg.add(npm_release("demo-lib", "1.0.0"), {"t.tgz": npm_tgz({"package.json": PKG_JSON, "index.js": LIB_JS})})
        reg.add(npm_release("demo-lib", "1.1.0"), {"t.tgz": npm_tgz({"package.json": PKG_JSON,
                                                                      "index.js": LIB_JS + "// faster\n"})})
        self.assertEqual(Checker(reg).compare("npm", "demo-lib", "1.0.0", "1.1.0").findings, [])

    def test_existing_behaviour_is_not_news(self):
        # a package that always had an install script and network code: only changes count
        reg = FakeRegistry()
        files = {"package.json": PKG_JSON, "install.js": "require('https').get('https://example.com/bin')"}
        reg.add(npm_release("native", "1.0.0", scripts={"install": "node install.js"}), {"t.tgz": npm_tgz(files)})
        reg.add(npm_release("native", "1.0.1", scripts={"install": "node install.js"}), {"t.tgz": npm_tgz(files)})
        self.assertEqual(Checker(reg).compare("npm", "native", "1.0.0", "1.0.1").findings, [])

    def test_unchanged_pth_is_not_news(self):
        reg = FakeRegistry()
        pth = "import _distutils_hack; _distutils_hack.do_override()\n"
        for v in ("1.0.0", "1.0.1"):
            reg.add(pypi_release("tool", v), {f"tool-{v}-py3-none-any.whl": wheel("tool", v, {"hack.pth": pth, "tool/__init__.py": LIB_PY})})
        self.assertNotIn("BW003", rules(Checker(reg).compare("pypi", "tool", "1.0.0", "1.0.1")))

    def test_allowlisted_install_script(self):
        reg = FakeRegistry()
        reg.add(npm_release("esb", "1.0.0"), {"t.tgz": npm_tgz({"package.json": PKG_JSON})})
        reg.add(npm_release("esb", "1.0.1", scripts={"postinstall": "node install.js"}), {"t.tgz": npm_tgz({"package.json": PKG_JSON})})
        self.assertIn("BW001", rules(Checker(reg).compare("npm", "esb", "1.0.0", "1.0.1")))
        pol = Policy(allow_install_scripts={"esb"})
        self.assertNotIn("BW001", rules(Checker(reg, pol).compare("npm", "esb", "1.0.0", "1.0.1")))

    def test_publisher_change_with_ci_provenance_is_low(self):
        reg = FakeRegistry()
        files = {"package.json": PKG_JSON}
        reg.add(npm_release("lib", "1.0.0", publisher="alice", recent=("alice",)), {"t.tgz": npm_tgz(files)})
        reg.add(npm_release("lib", "1.0.1", publisher="GitHub Actions", trusted=True), {"t.tgz": npm_tgz(files)})
        rep = Checker(reg).compare("npm", "lib", "1.0.0", "1.0.1")
        self.assertEqual([(f.rule, f.severity) for f in rep.findings], [("BW013", LOW)])


class SignalTests(unittest.TestCase):
    def test_word_boundaries(self):
        found = {s.name for s in signals.scan("a.js", b"client.apiRequestBinary('x'); getRequestBin()")}
        self.assertNotIn("exfil_service", found)
        self.assertIn("exfil_service", {s.name for s in signals.scan("a.js", b"fetch('https://webhook.site/x')")})

    def test_pth_exec_lines(self):
        self.assertEqual(signals.pth_exec_lines(b"/some/path\nimport os; os.system('x')\n"), ["import os; os.system('x')"])
        self.assertEqual(signals.pth_exec_lines(b"/only/paths\n../more\n"), [])

    def test_new_signals_ignores_moves(self):
        old = {"a.js": signals.scan("a.js", b"require('child_process')")}
        new = {"b.js": signals.scan("b.js", b"require('child_process')")}
        self.assertEqual(signals.new_signals(old, new), [])


class ArtifactTests(unittest.TestCase):
    def test_paths_are_comparable_across_versions(self):
        w1 = artifact.read("wheel", wheel("x", "1.0", {"x/a.py": "1"}))
        w2 = artifact.read("wheel", wheel("x", "2.0", {"x/a.py": "1"}))
        self.assertEqual(set(w1), set(w2))
        self.assertEqual(set(artifact.read("sdist", sdist("x", "1.0", {"setup.py": ""}), "x-1.0.tar.gz")), {"setup.py"})
        self.assertEqual(set(artifact.read("npm", npm_tgz({"index.js": ""}))), {"index.js"})

    def test_pick_wheel(self):
        arts = [{"kind": "wheel", "filename": "x-1-cp312-cp312-win_amd64.whl"},
                {"kind": "wheel", "filename": "x-1-cp312-cp312-manylinux_2_17_x86_64.whl"}]
        self.assertIn("manylinux", artifact.pick_wheel(arts)["filename"])


class LockfileTests(unittest.TestCase):
    def test_package_lock(self):
        old = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/axios": {
            "version": "1.14.0", "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.0.tgz"}}})
        new = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/axios": {
            "version": "1.14.1", "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz"},
            "node_modules/plain-crypto-helper": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/x.tgz"},
            "node_modules/local": {"version": "0.0.1", "resolved": "file:../local"}}})
        ch = lockfiles.diff(lockfiles.parse("package-lock.json", old), lockfiles.parse("package-lock.json", new))
        self.assertEqual([(c.name, c.old, c.new) for c in ch],
                         [("axios", "1.14.0", "1.14.1"), ("plain-crypto-helper", None, "1.0.0")])

    def test_other_formats(self):
        yarn = '"@scope/pkg@^1.0.0":\n  version "1.2.3"\n\nlodash@^4:\n  version "4.17.21"\n'
        self.assertEqual(lockfiles.parse("yarn.lock", yarn), {("npm", "@scope/pkg"): "1.2.3", ("npm", "lodash"): "4.17.21"})
        pnpm = "lockfileVersion: '9.0'\n\npackages:\n\n  axios@1.14.0:\n    resolution: {}\n  '@babel/core@7.29.0':\n    resolution: {}\n"
        self.assertEqual(lockfiles.parse("pnpm-lock.yaml", pnpm), {("npm", "axios"): "1.14.0", ("npm", "@babel/core"): "7.29.0"})
        poetry = '[[package]]\nname = "LiteLLM"\nversion = "1.107.0"\n\n[[package]]\nname = "local-thing"\nversion = "0.1"\n\n[package.source]\ntype = "directory"\nurl = "../x"\n'
        self.assertEqual(lockfiles.parse("poetry.lock", poetry), {("pypi", "litellm"): "1.107.0"})
        uv = '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "requests"\nversion = "2.32.4"\nsource = { registry = "https://pypi.org/simple" }\n'
        self.assertEqual(lockfiles.parse("uv.lock", uv), {("pypi", "requests"): "2.32.4"})
        req = "Requests[socks]==2.32.4  # pinned\nflask>=3\n-e .\n"
        self.assertEqual(lockfiles.parse("requirements.txt", req), {("pypi", "requests"): "2.32.4"})
        pip = json.dumps({"default": {"Django": {"version": "==5.2.1"}}, "develop": {}})
        self.assertEqual(lockfiles.parse("Pipfile.lock", pip), {("pypi", "django"): "5.2.1"})

    def test_format_detected_from_content(self):
        lock = json.dumps({"lockfileVersion": 3, "packages": {"node_modules/a": {
            "version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}})
        self.assertEqual(lockfiles.parse("old.json", lock), {("npm", "a"): "1.0.0"})
        self.assertEqual(lockfiles.parse("base.txt", "requests==2.32.4\n"), {("pypi", "requests"): "2.32.4"})
        self.assertEqual(lockfiles.parse("x.lock", '[[package]]\nname = "a"\nversion = "1"\n'), {("pypi", "a"): "1"})

    def test_git_changes(self):
        if not shutil.which("git"):
            self.skipTest("git not installed")
        d = tempfile.mkdtemp()
        try:
            def git(*a):
                subprocess.run(["git", "-C", d, "-c", "user.email=t@t", "-c", "user.name=t", *a], check=True, capture_output=True)
            git("init", "-q")
            with open(os.path.join(d, "requirements.txt"), "w") as fh:
                fh.write("requests==2.32.3\n")
            git("add", "-A"); git("commit", "-qm", "base")
            with open(os.path.join(d, "requirements.txt"), "w") as fh:
                fh.write("requests==2.32.4\nlitellm==1.107.0\n")
            git("commit", "-qam", "bump")
            ch = lockfiles.changes_since("HEAD~1", d)
            self.assertEqual([(c.name, c.old, c.new) for c in ch], [("litellm", None, "1.107.0"), ("requests", "2.32.3", "2.32.4")])
        finally:
            shutil.rmtree(d, ignore_errors=True)


class ReportAndCliTests(unittest.TestCase):
    def _worm_report(self):
        reg = FakeRegistry()
        reg.add(npm_release("demo-lib", "1.0.0"), {"t.tgz": npm_tgz({"package.json": PKG_JSON})})
        reg.add(npm_release("demo-lib", "1.0.1", scripts={"postinstall": "node bundle.js"}),
                {"t.tgz": npm_tgz({"package.json": PKG_JSON, "bundle.js": WORM_JS})})
        return reg, Checker(reg).compare("npm", "demo-lib", "1.0.0", "1.0.1")

    def test_markdown(self):
        _, rep = self._worm_report()
        md = report.markdown([rep])
        self.assertIn("Hold this merge", md)
        self.assertIn("`demo-lib` 1.0.0 → 1.0.1", md)
        self.assertNotIn("\n|  |", md)

    def test_formats_parse(self):
        _, rep = self._worm_report()
        self.assertTrue(json.loads(report.as_json([rep]))["updates"][0]["findings"])
        self.assertEqual(json.loads(report.sarif([rep]))["version"], "2.1.0")
        self.assertTrue(report.github([rep]).startswith("::error title=BW"))

    def test_cli_check_with_policy(self):
        reg, _ = self._worm_report()
        d = tempfile.mkdtemp()
        try:
            cfg = os.path.join(d, ".bumpwatch.json")
            with open(cfg, "w") as fh:
                json.dump({"ignore_packages": ["demo-lib"]}, fh)
            with mock.patch("bumpwatch.cli.Registry", return_value=reg):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = cli.main(["check", "npm", "demo-lib", "1.0.0", "1.0.1", "--no-color"])
                self.assertEqual(code, 1)
                with redirect_stdout(io.StringIO()):
                    code = cli.main(["check", "npm", "demo-lib", "1.0.0", "1.0.1", "--config", cfg])
                self.assertEqual(code, 0)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
