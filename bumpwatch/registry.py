"""Fetch release metadata and artifacts from npm and PyPI.

Read-only and stdlib-only. Downloads are cached by content address, and
nothing that's downloaded is ever executed or extracted to disk.
"""

import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import __version__

UA = f"bumpwatch/{__version__} (+https://github.com/viehgroup/bumpwatch)"
MAX_ARTIFACT = 150 * 1024 * 1024


class RegistryError(Exception):
    pass


@dataclass
class Provenance:
    repository: Optional[str] = None   # normalised "owner/repo"
    workflow: Optional[str] = None     # path or file name of the workflow
    raw: dict = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.repository or "", (self.workflow or "").rsplit("/", 1)[-1])


@dataclass
class Release:
    ecosystem: str
    name: str
    version: str
    exists: bool = True
    published: Optional[datetime] = None
    publisher: Optional[str] = None          # npm only
    trusted_publisher: Optional[bool] = None
    provenance: Optional[Provenance] = None
    has_provenance: Optional[bool] = None
    repository: Optional[str] = None         # what the package claims as its source
    install_scripts: Dict[str, str] = field(default_factory=dict)
    dependencies: Dict[str, str] = field(default_factory=dict)
    artifacts: List[dict] = field(default_factory=list)   # {"url", "filename", "kind", "sha256"}
    yanked: bool = False
    removed_versions: List[str] = field(default_factory=list)
    recent_publishers: List[str] = field(default_factory=list)
    manifest: dict = field(default_factory=dict)


def _ts(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _repo_slug(url) -> Optional[str]:
    if isinstance(url, dict):
        url = url.get("url")
    if not isinstance(url, str):
        return None
    m = re.search(r"github\.com[/:]([^/\s]+)/([^/\s#?]+?)(?:\.git)?(?:[/#?].*)?$", url, re.I)
    return f"{m.group(1)}/{m.group(2)}".lower() if m else None


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class Registry:
    NPM = "https://registry.npmjs.org"
    PYPI = "https://pypi.org"

    def __init__(self, cache_dir: Optional[str] = None, timeout: float = 60):
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
        self.cache_dir = cache_dir or os.path.join(base, "bumpwatch")
        self.timeout = timeout
        self._meta: Dict[str, Optional[dict]] = {}

    # ---------------------------------------------------------------- http

    def _get(self, url: str, accept: str = "application/json", limit: int = 50 * 1024 * 1024) -> Optional[bytes]:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(limit + 1)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise RegistryError(f"{url}: HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise RegistryError(f"{url}: {e}") from e
        if len(body) > limit:
            raise RegistryError(f"{url}: response larger than {limit // 2**20} MB")
        return body

    def _json(self, url: str, accept: str = "application/json") -> Optional[dict]:
        if url in self._meta:
            return self._meta[url]
        raw = self._get(url, accept)
        try:
            data = json.loads(raw) if raw else None
        except ValueError as e:
            raise RegistryError(f"{url}: bad JSON") from e
        self._meta[url] = data
        return data

    def download(self, artifact: dict) -> bytes:
        """Fetch an artifact, checking it against the digest the registry published."""
        digest = artifact.get("sha256") or artifact.get("sha512") or hashlib.sha256(artifact["url"].encode()).hexdigest()
        path = os.path.join(self.cache_dir, "artifacts", digest[:2], re.sub(r"[^A-Za-z0-9]", "", digest)[:80])
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except OSError:
            pass
        data = self._get(artifact["url"], "*/*", MAX_ARTIFACT)
        if data is None:
            raise RegistryError(f"{artifact['url']}: not found")
        if artifact.get("sha256") and hashlib.sha256(data).hexdigest() != artifact["sha256"]:
            raise RegistryError(f"{artifact['filename']}: checksum mismatch")
        if artifact.get("sha512") and base64.b64encode(hashlib.sha512(data).digest()).decode() != artifact["sha512"]:
            raise RegistryError(f"{artifact['filename']}: checksum mismatch")
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path + ".tmp", "wb") as fh:
                fh.write(data)
            os.replace(path + ".tmp", path)
        except OSError:
            pass
        return data

    # ---------------------------------------------------------------- npm

    def npm_packument(self, name: str) -> Optional[dict]:
        return self._json(f"{self.NPM}/{name.replace('/', '%2F')}")

    def npm(self, name: str, version: str) -> Release:
        doc = self.npm_packument(name)
        rel = Release("npm", name, version)
        if not doc or version not in (doc.get("versions") or {}):
            rel.exists = False
            if doc and version in (doc.get("time") or {}):
                rel.removed_versions = [version]
            return rel
        m = doc["versions"][version]
        times = doc.get("time") or {}
        rel.manifest = m
        rel.published = _ts(times.get(version))
        user = m.get("_npmUser") or {}
        rel.publisher = user.get("name")
        rel.trusted_publisher = bool(user.get("trustedPublisher"))
        dist = m.get("dist") or {}
        att = dist.get("attestations") or {}
        rel.has_provenance = bool(att.get("provenance"))
        if rel.has_provenance and att.get("url"):
            rel.provenance = self._npm_provenance(att["url"])
        rel.repository = _repo_slug(m.get("repository") or doc.get("repository"))
        scripts = m.get("scripts") or {}
        rel.install_scripts = {k: str(v) for k, v in scripts.items() if k in ("preinstall", "install", "postinstall")}
        if m.get("gypfile") and "install" not in rel.install_scripts:
            # npm runs `node-gyp rebuild` for packages with binding.gyp and no install script
            rel.install_scripts["install"] = "node-gyp rebuild (implicit, binding.gyp)"
        rel.dependencies = {k: str(v) for k, v in (m.get("dependencies") or {}).items()}
        rel.dependencies.update({k: str(v) for k, v in (m.get("optionalDependencies") or {}).items()})
        sha512 = None
        integ = dist.get("integrity", "")
        if integ.startswith("sha512-"):
            sha512 = integ[7:]
        rel.artifacts = [{"url": dist.get("tarball"), "filename": os.path.basename(dist.get("tarball") or "pkg.tgz"),
                          "kind": "npm", "sha512": sha512}]
        rel.removed_versions = [v for v in times if v not in doc["versions"] and v not in ("created", "modified")]
        # who published the last few versions before this one
        ordered = sorted((times[v], v) for v in doc["versions"] if v in times and times[v] < times.get(version, ""))
        rel.recent_publishers = [((doc["versions"][v].get("_npmUser") or {}).get("name") or "") for _, v in ordered[-15:]]
        return rel

    def _npm_provenance(self, url: str) -> Optional[Provenance]:
        try:
            doc = self._json(url)
        except RegistryError:
            return None
        for a in (doc or {}).get("attestations") or []:
            if "slsa.dev/provenance" not in a.get("predicateType", ""):
                continue
            try:
                payload = json.loads(base64.b64decode(a["bundle"]["dsseEnvelope"]["payload"]))
                pred = payload["predicate"]
                wf = (pred.get("buildDefinition") or {}).get("externalParameters", {}).get("workflow") or {}
                if wf:
                    return Provenance(_repo_slug(wf.get("repository")), wf.get("path"), wf)
                inv = (pred.get("invocation") or {}).get("configSource") or {}  # SLSA v0.2
                return Provenance(_repo_slug(inv.get("uri")), inv.get("entryPoint"), inv)
            except (KeyError, ValueError, TypeError):
                continue
        return None

    def npm_age_days(self, name: str) -> Optional[float]:
        doc = self.npm_packument(name)
        created = _ts((doc or {}).get("time", {}).get("created"))
        return (datetime.now(timezone.utc) - created).total_seconds() / 86400 if created else None

    # ---------------------------------------------------------------- PyPI

    def pypi(self, name: str, version: str) -> Release:
        rel = Release("pypi", name, version)
        meta = self._json(f"{self.PYPI}/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
        simple = self._json(f"{self.PYPI}/simple/{normalize_pypi(name)}/", "application/vnd.pypi.simple.v1+json")
        if not meta:
            rel.exists = False
            return rel
        info = meta.get("info") or {}
        rel.manifest = info
        files = meta.get("urls") or []
        rel.yanked = bool(info.get("yanked"))
        times = [_ts(f.get("upload_time_iso_8601")) for f in files]
        times = [t for t in times if t]
        rel.published = min(times) if times else None
        urls = info.get("project_urls") or {}
        rel.repository = next((s for s in (_repo_slug(v) for v in urls.values()) if s), None) or _repo_slug(info.get("home_page"))
        rel.dependencies = {}
        for req in info.get("requires_dist") or []:
            if "extra ==" in req:
                continue  # optional extras aren't installed by default
            m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", req)
            if m:
                rel.dependencies[normalize_pypi(m.group(1))] = req
        prov_urls = {}
        for f in (simple or {}).get("files") or []:
            if f.get("provenance"):
                prov_urls[f["filename"]] = f["provenance"]
        for f in files:
            kind = "wheel" if f.get("packagetype") == "bdist_wheel" else "sdist" if f.get("packagetype") == "sdist" else None
            if kind:
                rel.artifacts.append({"url": f["url"], "filename": f["filename"], "kind": kind,
                                      "sha256": (f.get("digests") or {}).get("sha256")})
        if simple is not None:
            rel.has_provenance = bool(files) and all(f["filename"] in prov_urls for f in files)
            first = next((prov_urls[f["filename"]] for f in files if f["filename"] in prov_urls), None)
            if first:
                rel.provenance = self._pypi_provenance(first)
        return rel

    def _pypi_provenance(self, url: str) -> Optional[Provenance]:
        try:
            doc = self._json(url)
        except RegistryError:
            return None
        for b in (doc or {}).get("attestation_bundles") or []:
            pub = b.get("publisher") or {}
            if pub.get("repository"):
                return Provenance(pub["repository"].lower(), pub.get("workflow"), pub)
        return None

    def pypi_age_days(self, name: str) -> Optional[float]:
        try:
            doc = self._json(f"{self.PYPI}/pypi/{urllib.parse.quote(name)}/json")
        except RegistryError:
            return None
        if not doc:
            return None
        times = [_ts(f.get("upload_time_iso_8601")) for fs in (doc.get("releases") or {}).values() for f in fs]
        times = [t for t in times if t]
        return (datetime.now(timezone.utc) - min(times)).total_seconds() / 86400 if times else None

    def pypi_exists(self, name: str) -> bool:
        return self._json(f"{self.PYPI}/pypi/{urllib.parse.quote(name)}/json") is not None

    # ---------------------------------------------------------------- generic

    def release(self, ecosystem: str, name: str, version: str) -> Release:
        if ecosystem == "npm":
            return self.npm(name, version)
        if ecosystem == "pypi":
            return self.pypi(name, version)
        raise ValueError(f"unsupported ecosystem: {ecosystem}")

    def latest_before(self, ecosystem: str, name: str, version: str) -> Optional[str]:
        """The version published just before `version`, for `bumpwatch inspect`."""
        if ecosystem == "npm":
            doc = self.npm_packument(name) or {}
            t = doc.get("time") or {}
            if version not in t:
                return None
            earlier = sorted((t[v], v) for v in (doc.get("versions") or {}) if v in t and t[v] < t[version]
                             and not re.search(r"-(?:alpha|beta|rc|next|canary|dev)", v))
            return earlier[-1][1] if earlier else None
        doc = self._json(f"{self.PYPI}/pypi/{urllib.parse.quote(name)}/json") or {}
        rels = doc.get("releases") or {}
        def first(v):
            ts = [_ts(f.get("upload_time_iso_8601")) for f in rels.get(v) or []]
            ts = [x for x in ts if x]
            return min(ts) if ts else None
        mine = first(version)
        if not mine:
            return None
        earlier = sorted((first(v), v) for v in rels if first(v) and first(v) < mine
                         and not re.search(r"(?:a|b|rc|dev)\d*$", v))
        return earlier[-1][1] if earlier else None
