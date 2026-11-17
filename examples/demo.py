"""See what bumpwatch reports for three inert recreations of 2026 attacks.

    python examples/demo.py

Runs offline against a fake registry. Nothing in the samples can execute:
payloads decode to a print() and hosts are reserved test addresses.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from bumpwatch import report  # noqa: E402
from bumpwatch.checks import Checker  # noqa: E402
from tests.fixtures import (LIB_JS, LIB_PY, PKG_JSON, PTH_LINE, STEALER_PY, WORM_JS, FakeRegistry,  # noqa: E402
                            npm_release, npm_tgz, pypi_release, sdist, wheel)

reg = FakeRegistry()

# 1. Shai-Hulud style: a patch release that adds a token-stealing, self-publishing postinstall
reg.add(npm_release("left-padder", "2.4.0"), {"t.tgz": npm_tgz({"package.json": PKG_JSON, "index.js": LIB_JS})})
reg.add(npm_release("left-padder", "2.4.1", scripts={"postinstall": "node bundle.js"}, days_ago=0.4,
                    trusted=False, provenance=False),
        {"t.tgz": npm_tgz({"package.json": PKG_JSON, "index.js": LIB_JS, "bundle.js": WORM_JS})})

# 2. LiteLLM style: a .pth startup hook and a stealer that exist only in the wheel
src = {"llmkit/__init__.py": LIB_PY, "setup.py": "from setuptools import setup\nsetup()\n"}
reg.add(pypi_release("llmkit", "1.8.0"), {
    "llmkit-1.8.0-py3-none-any.whl": wheel("llmkit", "1.8.0", {"llmkit/__init__.py": LIB_PY}),
    "llmkit-1.8.0.tar.gz": sdist("llmkit", "1.8.0", src)})
reg.add(pypi_release("llmkit", "1.8.1", provenance=False, days_ago=1), {
    "llmkit-1.8.1-py3-none-any.whl": wheel("llmkit", "1.8.1", {"llmkit/__init__.py": LIB_PY,
                                                               "llmkit_init.pth": PTH_LINE,
                                                               "llmkit/_telemetry.py": STEALER_PY}),
    "llmkit-1.8.1.tar.gz": sdist("llmkit", "1.8.1", src)})

# 3. An honest update, for comparison
reg.add(npm_release("tiny-utils", "3.1.0"), {"t.tgz": npm_tgz({"package.json": PKG_JSON, "index.js": LIB_JS})})
reg.add(npm_release("tiny-utils", "3.2.0"), {"t.tgz": npm_tgz({"package.json": PKG_JSON,
                                                              "index.js": LIB_JS + "// faster\n"})})

checker = Checker(reg)
reports = [checker.compare("npm", "left-padder", "2.4.0", "2.4.1"),
           checker.compare("pypi", "llmkit", "1.8.0", "1.8.1"),
           checker.compare("npm", "tiny-utils", "3.1.0", "3.2.0")]
fmt = sys.argv[1] if len(sys.argv) > 1 else "text"
print(report.markdown(reports) if fmt == "markdown" else report.text(reports, sys.stdout.isatty(), show_clean=True))
