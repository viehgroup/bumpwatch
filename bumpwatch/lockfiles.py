"""Read pinned versions out of lockfiles and work out what changed.

Supported: package-lock.json / npm-shrinkwrap.json, yarn.lock (v1 and berry),
pnpm-lock.yaml, requirements*.txt (== pins), poetry.lock, uv.lock,
Pipfile.lock. No third-party parsers: the formats are regular enough.
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .registry import normalize_pypi

Pins = Dict[Tuple[str, str], str]   # (ecosystem, name) -> version

LOCKFILES = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "poetry.lock": "pypi", "uv.lock": "pypi", "Pipfile.lock": "pypi",
}


@dataclass
class Change:
    ecosystem: str
    name: str
    old: Optional[str]
    new: str


def is_lockfile(path: str) -> bool:
    base = os.path.basename(path)
    return base in LOCKFILES or bool(re.match(r"requirements[\w.-]*\.txt$", base))


def sniff(text: str) -> Optional[str]:
    """Guess the lockfile format from its content, for files with other names."""
    head = text.lstrip()[:4000]
    if head.startswith("{"):
        if '"lockfileVersion"' in head:
            return "package-lock.json"
        if '"_meta"' in head and ('"default"' in text or '"develop"' in text):
            return "Pipfile.lock"
        return None
    if "# yarn lockfile" in head or re.search(r"^__metadata:", head, re.M):
        return "yarn.lock"
    if re.search(r"^lockfileVersion:", head, re.M):
        return "pnpm-lock.yaml"
    if re.search(r"^\[\[package\]\]", text, re.M):
        return "uv.lock" if re.search(r"^source\s*=\s*\{", text, re.M) else "poetry.lock"
    if re.search(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?\s*===?\s*\S", text, re.M):
        return "requirements.txt"
    return None


def parse(path: str, text: str) -> Pins:
    base = os.path.basename(path)
    if base not in LOCKFILES and not re.match(r"requirements[\w.-]*\.txt$", base):
        base = sniff(text) or base
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        return _npm_lock(text)
    if base == "yarn.lock":
        return _yarn_lock(text)
    if base == "pnpm-lock.yaml":
        return _pnpm_lock(text)
    if base in ("poetry.lock", "uv.lock"):
        return _toml_packages(text, skip_virtual=(base == "uv.lock"))
    if base == "Pipfile.lock":
        return _pipfile_lock(text)
    if re.match(r"requirements[\w.-]*\.txt$", base):
        return _requirements(text)
    return {}


def _npm_lock(text: str) -> Pins:
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    out: Pins = {}
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict) or meta.get("link") or not meta.get("version"):
            continue
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        resolved = meta.get("resolved", "")
        if resolved and not resolved.startswith("https://registry."):
            continue  # git, file: and tarball URLs aren't registry releases
        out[("npm", name)] = meta["version"]
    if not out:  # lockfile v1
        def walk(deps):
            for name, meta in (deps or {}).items():
                if isinstance(meta, dict) and meta.get("version") and not str(meta.get("version")).startswith(("git", "file:", "http")):
                    out[("npm", name)] = meta["version"]
                    walk(meta.get("dependencies"))
        walk(data.get("dependencies"))
    return out


def _yarn_lock(text: str) -> Pins:
    out: Pins = {}
    entry = None
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            first = line.split(",")[0].strip().strip('"').rstrip(":")
            m = re.match(r"^(@?[^@]+)@", first)
            entry = m.group(1) if m else None
        elif entry and re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line):
            v = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line).group(1)
            if not v.startswith("0.0.0-use.local"):
                out[("npm", entry)] = v
            entry = None
    return out


def _pnpm_lock(text: str) -> Pins:
    out: Pins = {}
    in_packages = False
    for line in text.splitlines():
        if re.match(r"^(packages|snapshots):\s*$", line):
            in_packages = line.startswith("packages")
            continue
        if re.match(r"^\S", line):
            in_packages = False
        if not in_packages:
            continue
        m = re.match(r"^  ['\"]?/?(@?[^@\s'\"]+)@([^(:'\"\s]+)", line)
        if m:
            out[("npm", m.group(1))] = m.group(2)
    return out


def _toml_packages(text: str, skip_virtual: bool = False) -> Pins:
    out: Pins = {}
    for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.M)[1:]:
        # keep [package.*] sub-tables (source, dependencies); stop at any other table
        block = re.split(r"^\[(?!\[?package[.\]])", block, maxsplit=1, flags=re.M)[0]
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        ver = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        if not name or not ver:
            continue
        source = re.search(r"^source\s*=\s*\{([^}]*)\}", block, re.M)
        if source and re.search(r"(?:editable|virtual|path|directory|git)\s*=", source.group(1)):
            continue  # local or VCS sources aren't PyPI releases
        if re.search(r'^\[package\.source\]', block, re.M) and re.search(r'^type\s*=\s*"(?:git|directory|file)"', block, re.M):
            continue
        out[("pypi", normalize_pypi(name.group(1)))] = ver.group(1)
    return out


def _pipfile_lock(text: str) -> Pins:
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    out: Pins = {}
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            v = (meta or {}).get("version", "")
            if v.startswith("=="):
                out[("pypi", normalize_pypi(name))] = v[2:]
    return out


def _requirements(text: str) -> Pins:
    out: Pins = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.+!_-]+)", line)
        if m:
            out[("pypi", normalize_pypi(m.group(1)))] = m.group(2)
    return out


def diff(old: Pins, new: Pins) -> List[Change]:
    out = []
    for key, ver in sorted(new.items()):
        before = old.get(key)
        if before != ver:
            out.append(Change(key[0], key[1], before, ver))
    return out


# ------------------------------------------------------------------ git

def git_show(ref: str, path: str, cwd: str = ".") -> Optional[str]:
    try:
        r = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=cwd, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None


def changed_lockfiles(base: str, cwd: str = ".") -> List[str]:
    try:
        r = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"], cwd=cwd,
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            r = subprocess.run(["git", "diff", "--name-only", base], cwd=cwd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return []
    return [p for p in r.stdout.splitlines() if is_lockfile(p)]


def changes_since(base: str, cwd: str = ".") -> List[Change]:
    out: List[Change] = []
    seen = set()
    for path in changed_lockfiles(base, cwd):
        before = git_show(base, path, cwd) or ""
        full = os.path.join(cwd, path)
        try:
            with open(full, encoding="utf-8") as fh:
                after = fh.read()
        except OSError:
            continue
        for c in diff(parse(path, before), parse(path, after)):
            key = (c.ecosystem, c.name, c.new)
            if key not in seen:
                seen.add(key)
                out.append(c)
    return out
