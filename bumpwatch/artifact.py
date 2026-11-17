"""Read package archives into memory with normalised paths.

Nothing is written to disk and nothing is executed. Limits guard against
archives that expand to absurd sizes.
"""

import io
import re
import tarfile
import zipfile
from typing import Dict

MAX_TOTAL = 400 * 1024 * 1024
MAX_FILE = 40 * 1024 * 1024
MAX_FILES = 60_000


class ArtifactError(Exception):
    pass


def _norm(path: str) -> str:
    path = path.replace("\\", "/").lstrip("/")
    parts = [p for p in path.split("/") if p not in ("", ".", "..")]
    return "/".join(parts)


def _strip_versioned(path: str) -> str:
    """Make paths comparable across versions.

    npm tarballs start with package/; sdists with name-1.2.3/; wheels have a
    name-1.2.3.dist-info/ folder. Version numbers in those names would make
    every file look new, so they're replaced with stable placeholders.
    """
    path = re.sub(r"^[^/]+\.dist-info/", "<dist-info>/", path)
    path = re.sub(r"^[^/]+\.data/", "<data>/", path)
    return path


def read_npm(data: bytes) -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            for m in tf:
                if not m.isfile():
                    continue
                if len(out) >= MAX_FILES:
                    raise ArtifactError("too many files")
                if m.size > MAX_FILE:
                    out[_norm(m.name).split("/", 1)[-1]] = b""  # keep the name, skip the content
                    continue
                total += m.size
                if total > MAX_TOTAL:
                    raise ArtifactError("archive expands beyond the size limit")
                fh = tf.extractfile(m)
                if fh is None:
                    continue
                name = _norm(m.name)
                # first path component is "package/" (or occasionally the package name)
                name = name.split("/", 1)[1] if "/" in name else name
                out[name] = fh.read()
    except (tarfile.TarError, EOFError, OSError) as e:
        raise ArtifactError(f"bad npm tarball: {e}") from e
    return out


def read_wheel(data: bytes) -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_FILES:
                raise ArtifactError("too many files")
            for info in infos:
                if info.is_dir():
                    continue
                name = _strip_versioned(_norm(info.filename))
                if info.file_size > MAX_FILE:
                    out[name] = b""
                    continue
                total += info.file_size
                if total > MAX_TOTAL:
                    raise ArtifactError("archive expands beyond the size limit")
                out[name] = zf.read(info)
    except (zipfile.BadZipFile, OSError, RuntimeError) as e:
        raise ArtifactError(f"bad wheel: {e}") from e
    return out


def read_sdist(data: bytes, filename: str = "") -> Dict[str, bytes]:
    if filename.endswith(".zip"):
        files = read_wheel(data)
    else:
        files = {}
        total = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                for m in tf:
                    if not m.isfile():
                        continue
                    if len(files) >= MAX_FILES:
                        raise ArtifactError("too many files")
                    name = _norm(m.name)
                    if m.size > MAX_FILE:
                        files[name] = b""
                        continue
                    total += m.size
                    if total > MAX_TOTAL:
                        raise ArtifactError("archive expands beyond the size limit")
                    fh = tf.extractfile(m)
                    if fh is not None:
                        files[name] = fh.read()
        except (tarfile.TarError, EOFError, OSError) as e:
            raise ArtifactError(f"bad sdist: {e}") from e
    # drop the leading name-version/ folder
    return {(k.split("/", 1)[1] if "/" in k else k): v for k, v in files.items()}


def read(kind: str, data: bytes, filename: str = "") -> Dict[str, bytes]:
    if kind == "npm":
        return read_npm(data)
    if kind == "wheel":
        return read_wheel(data)
    if kind == "sdist":
        return read_sdist(data, filename)
    raise ArtifactError(f"unknown artifact kind {kind}")


def pick_wheel(artifacts: list) -> dict:
    """Prefer a pure-Python wheel, then manylinux x86_64, then anything."""
    wheels = [a for a in artifacts if a["kind"] == "wheel"]
    for pat in (r"-none-any\.whl$", r"manylinux[^-]*x86_64\.whl$", r"\.whl$"):
        for a in wheels:
            if re.search(pat, a["filename"]):
                return a
    return {}


def wheel_tag(filename: str) -> str:
    """The platform part of a wheel name, so we compare like with like across versions."""
    m = re.search(r"-([^-]+-[^-]+-[^-]+)\.whl$", filename)
    return m.group(1) if m else ""
