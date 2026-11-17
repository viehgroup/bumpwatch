"""Compare two releases of a package and report what the update introduced."""

import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from . import artifact, signals
from .registry import Registry, RegistryError, Release

HIGH, MEDIUM, LOW = "high", "medium", "low"
SEVERITY_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}

RULES = {
    "BW001": ("New install script", "The update adds code that runs automatically when the package is installed."),
    "BW002": ("Changed install script", "The update changes what runs at install time."),
    "BW003": ("New Python startup hook", "A .pth file now runs code every time Python starts, in every program."),
    "BW004": ("New sitecustomize module", "sitecustomize/usercustomize run automatically at Python startup."),
    "BW005": ("Risky install-time code", "Code that runs automatically (install scripts, setup.py, .pth files) gained network or process access."),
    "BW006": ("Hidden code added", "The update adds code that decodes and executes a payload, or obfuscated code."),
    "BW007": ("Reads secrets and sends data", "New code both reaches for credentials and talks to the network."),
    "BW008": ("New access to secrets", "New code references SSH keys, cloud credentials, tokens, wallets or browser data."),
    "BW009": ("Suspicious new endpoint", "New code talks to a raw IP, an exfiltration service, or looks up the public IP."),
    "BW010": ("Persistence or remote access", "New code installs startup items, opens a reverse shell or runs a downloaded script."),
    "BW011": ("Build provenance missing", "Earlier versions had a verified build attestation; this one doesn't."),
    "BW012": ("Built somewhere else", "The provenance names a different repository or workflow than before."),
    "BW013": ("Published by a new account", "None of the recent versions were published by this account."),
    "BW014": ("Trusted publishing dropped", "Earlier versions were published by CI via trusted publishing; this one by a person or token."),
    "BW015": ("Version missing or pulled", "The version isn't available, was removed from the registry, or is yanked."),
    "BW016": ("Wheel has files the source doesn't", "Code in the wheel that isn't in the source distribution."),
    "BW017": ("New binary files", "The update ships compiled executables or native libraries it didn't have before."),
    "BW018": ("Risky new dependency", "A newly added dependency is brand new, missing, or runs install scripts."),
    "BW019": ("Very recent release", "Published in the last few days. Most hijacked releases are caught and pulled within days."),
    "BW020": ("New capabilities", "New code starts processes or makes network calls."),
    "BW021": ("Source repository changed", "The repository the package points to changed."),
    "BW022": ("Self-publishing code", "New code publishes packages or touches registry tokens, the way worms spread."),
    "BW023": ("Touches CI internals", "New code reads GitHub Actions runtime tokens or writes workflow files."),
}

SECRET_SIGS = {"ssh_keys", "cloud_creds", "pkg_tokens", "browser_data", "crypto_wallets", "keychain",
               "js_env_harvest", "py_env_harvest"}
NET_SIGS = {"js_net", "py_net", "exfil_service", "raw_ip_url"}
BINARY_EXT = (".node", ".so", ".dll", ".dylib", ".exe", ".bin")
BINARY_MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf")
FRESH_DAYS = 3


@dataclass
class Finding:
    rule: str
    severity: str
    package: str
    location: str
    message: str
    fix: str = ""


@dataclass
class Report:
    ecosystem: str
    name: str
    old: Optional[str]
    new: str
    findings: List[Finding] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def label(self) -> str:
        return f"{self.name} {self.old or '(new)'} → {self.new}" + (f" ({self.ecosystem})" if self.ecosystem else "")

    @property
    def worst(self) -> Optional[str]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])


@dataclass
class Policy:
    """Per-project tuning, read from .bumpwatch.json."""
    allow_install_scripts: Set[str] = field(default_factory=set)
    ignore_rules: Set[str] = field(default_factory=set)
    ignore_packages: Set[str] = field(default_factory=set)
    fresh_days: float = FRESH_DAYS


# ------------------------------------------------------------------ helpers

def _days(ts: Optional[datetime]) -> Optional[float]:
    if not ts:
        return None
    return (datetime.now(timezone.utc) - ts).total_seconds() / 86400


def _script_targets(cmd: str, files: Dict[str, bytes]) -> List[str]:
    """Files an install script runs, e.g. `node setup.js` -> setup.js."""
    out = []
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()
    for p in parts:
        p = p.strip("'\"").lstrip("./")
        if p in files:
            out.append(p)
        elif p + ".js" in files:
            out.append(p + ".js")
    return out


def _is_binary(path: str, data: bytes) -> bool:
    return path.lower().endswith(BINARY_EXT) or data[:4].startswith(BINARY_MAGIC)


def _signal_summary(sigs: List[signals.Signal], limit: int = 5) -> str:
    """`bundle.js: .npmrc, NPM_TOKEN, https.request(` rather than overlapping excerpts."""
    by_file: Dict[str, List[str]] = {}
    for s in sigs:
        items = by_file.setdefault(s.file, [])
        t = s.text if len(s.text) <= 60 else s.text[:57] + "..."
        if t not in items:
            items.append(t)
    parts = []
    for f, items in list(by_file.items())[:3]:
        shown = ", ".join(items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")
        parts.append(f"{f}: {shown}")
    if len(by_file) > 3:
        parts.append(f"and {len(by_file) - 3} more file(s)")
    return "; ".join(parts)


class Checker:
    def __init__(self, registry: Optional[Registry] = None, policy: Optional[Policy] = None):
        self.reg = registry or Registry()
        self.policy = policy or Policy()

    # ---------------------------------------------------------------- entry points

    def compare(self, ecosystem: str, name: str, old: Optional[str], new: str) -> Report:
        rep = Report(ecosystem, name, old, new)
        if name.lower() in self.policy.ignore_packages:
            return rep
        try:
            self._compare(rep)
        except (RegistryError, artifact.ArtifactError) as e:
            rep.error = str(e)
        rep.findings = [f for f in rep.findings if f.rule not in self.policy.ignore_rules]
        return rep

    # ---------------------------------------------------------------- the work

    def _compare(self, rep: Report) -> None:
        eco, name = rep.ecosystem, rep.name
        new = self.reg.release(eco, name, rep.new)
        old = self.reg.release(eco, name, rep.old) if rep.old else None
        add = self._adder(rep)

        if not new.exists:
            pulled = rep.new in new.removed_versions
            add("BW015", HIGH, "registry",
                f"version {rep.new} " + ("was published and then removed from the registry, which is what happens to "
                                         "hijacked releases" if pulled else "doesn't exist on the registry"),
                "Don't install it. Pin to a version that's still published.")
            return
        if new.yanked:
            add("BW015", MEDIUM, "registry", f"version {rep.new} is yanked on PyPI",
                "Yanked releases are usually broken or unsafe. Pick another version.")
        if old is not None and not old.exists:
            old = None  # comparing against nothing; treat as a new dependency

        self._metadata_checks(rep, old, new, add)
        self._content_checks(rep, old, new, add)

        # Context makes a fresh release worse: give the cooldown advice teeth
        days = _days(new.published)
        if days is not None and days < self.policy.fresh_days:
            serious = any(SEVERITY_ORDER[f.severity] >= 1 for f in rep.findings)
            add("BW019", MEDIUM if serious else LOW, "registry",
                f"published {days * 24:.0f} hours ago",
                "Waiting a few days before taking new releases avoids most hijacked versions.")

    def _adder(self, rep: Report):
        def add(rule, sev, location, msg, fix=""):
            rep.findings.append(Finding(rule, sev, rep.label, location, msg, fix))
        return add

    # ---------------------------------------------------------------- metadata

    def _metadata_checks(self, rep: Report, old: Optional[Release], new: Release, add) -> None:
        allowed = rep.name.lower() in self.policy.allow_install_scripts

        # install scripts (npm)
        old_scripts = old.install_scripts if old else {}
        for hook, cmd in new.install_scripts.items():
            if allowed:
                continue
            if hook not in old_scripts:
                add("BW001", HIGH if old else MEDIUM, f"package.json scripts.{hook}",
                    f"{'adds' if old else 'has'} a {hook} script: {cmd[:120]}",
                    "Check what it runs before installing. If it's expected (native builds), add the package to "
                    "allow_install_scripts in .bumpwatch.json.")
            elif old_scripts[hook] != cmd:
                add("BW002", MEDIUM, f"package.json scripts.{hook}",
                    f"{hook} changed from `{old_scripts[hook][:60]}` to `{cmd[:80]}`",
                    "Check what the new command runs.")

        if not old:
            return

        # provenance and publishing
        if old.has_provenance and new.has_provenance is False:
            add("BW011", MEDIUM, "registry",
                f"{old.version} was published with build provenance, {new.version} wasn't",
                "This can be a maintainer publishing by hand, or a stolen token. Check the project's release notes "
                "and repository before upgrading.")
        if old.provenance and new.provenance and old.provenance.key() != new.provenance.key():
            add("BW012", HIGH, "registry",
                f"built from {new.provenance.repository} ({new.provenance.workflow}); "
                f"{old.version} was built from {old.provenance.repository} ({old.provenance.workflow})",
                "A release built from a different repository or workflow needs an explanation from the maintainers.")
        if old.trusted_publisher and new.trusted_publisher is False:
            add("BW014", MEDIUM, "registry",
                f"{old.version} was published by CI through trusted publishing; {new.version} by "
                f"'{new.publisher or 'unknown'}'",
                "Confirm with the project that this release is genuine.")
        if new.publisher and rep.ecosystem == "npm":
            recent = {u for u in old.recent_publishers + [old.publisher or ""] if u}
            if recent and new.publisher not in recent:
                # A release CI built from the project's own repository is much less worrying
                vouched = new.trusted_publisher or (new.provenance and new.repository
                                                    and new.provenance.repository == new.repository)
                add("BW013", LOW if vouched else MEDIUM, "registry",
                    f"published by '{new.publisher}'; the previous releases came from "
                    f"{', '.join(sorted(recent))[:80]}" + (" (but built by CI with provenance)" if vouched else ""),
                    "New maintainers happen, but so do account takeovers. Check the project's announcements.")
        if old.repository and new.repository and old.repository != new.repository:
            add("BW021", MEDIUM, "package metadata",
                f"source repository changed from {old.repository} to {new.repository}",
                "Make sure the project really moved.")

        # dependencies
        added = sorted(set(new.dependencies) - set(old.dependencies))
        for dep in added[:15]:
            self._check_new_dependency(rep, dep, add)

    def _check_new_dependency(self, rep: Report, dep: str, add) -> None:
        try:
            if rep.ecosystem == "npm":
                doc = self.reg.npm_packument(dep)
                if not doc:
                    add("BW018", HIGH, "dependencies", f"adds dependency '{dep}', which doesn't exist on npm",
                        "A missing dependency can be registered by anyone. Don't install this update.")
                    return
                age = self.reg.npm_age_days(dep)
                latest = (doc.get("dist-tags") or {}).get("latest")
                scripts = ((doc.get("versions") or {}).get(latest) or {}).get("scripts") or {}
                hooks = [k for k in ("preinstall", "install", "postinstall") if k in scripts]
            else:
                if not self.reg.pypi_exists(dep):
                    add("BW018", HIGH, "dependencies", f"adds dependency '{dep}', which doesn't exist on PyPI",
                        "A missing dependency can be registered by anyone. Don't install this update.")
                    return
                age = self.reg.pypi_age_days(dep)
                hooks = []
        except RegistryError:
            return
        reasons = []
        if age is not None and age < 30:
            reasons.append(f"first published {age:.0f} day(s) ago")
        if hooks:
            reasons.append(f"runs {', '.join(hooks)} scripts")
        if reasons:
            add("BW018", HIGH if (age is not None and age < 7) else MEDIUM, "dependencies",
                f"adds dependency '{dep}', which {' and '.join(reasons)}",
                "New dependencies that are themselves new are how several 2026 attacks were delivered.")

    # ---------------------------------------------------------------- content

    def _artifacts(self, rel: Release, prefer_tag: str = "") -> Dict[str, Dict[str, bytes]]:
        out = {}
        if rel.ecosystem == "npm":
            a = rel.artifacts[0] if rel.artifacts and rel.artifacts[0].get("url") else None
            if a:
                out["npm"] = artifact.read("npm", self.reg.download(a))
            return out
        wheel = None
        if prefer_tag:
            wheel = next((a for a in rel.artifacts if a["kind"] == "wheel" and artifact.wheel_tag(a["filename"]) == prefer_tag), None)
        wheel = wheel or artifact.pick_wheel(rel.artifacts)
        if wheel:
            out["wheel"] = artifact.read("wheel", self.reg.download(wheel))
            out["_wheel_tag"] = {artifact.wheel_tag(wheel["filename"]): b""}
        sdist = next((a for a in rel.artifacts if a["kind"] == "sdist"), None)
        if sdist:
            out["sdist"] = artifact.read("sdist", self.reg.download(sdist), sdist["filename"])
        return out

    def _content_checks(self, rep: Report, old: Optional[Release], new: Release, add) -> None:
        new_art = self._artifacts(new)
        tag = next(iter(new_art.get("_wheel_tag", {})), "")
        old_art = self._artifacts(old, tag) if old else {}

        main = "npm" if rep.ecosystem == "npm" else ("wheel" if "wheel" in new_art else "sdist")
        new_files = new_art.get(main, {})
        old_files = old_art.get(main, {}) if old else {}
        if not new_files:
            return
        added = [p for p in new_files if p not in old_files]
        changed = [p for p in new_files if p in old_files and new_files[p] != old_files[p]]
        rep.stats = {"files": len(new_files), "added": len(added), "changed": len(changed),
                     "removed": len([p for p in old_files if p not in new_files])}
        touched = set(added) | set(changed)

        # Python startup hooks
        if rep.ecosystem == "pypi":
            for art_name in ("wheel", "sdist"):
                files = new_art.get(art_name, {})
                before = old_art.get(art_name, {})
                for p, data in files.items():
                    base = p.rsplit("/", 1)[-1]
                    if base.endswith(".pth"):
                        lines = signals.pth_exec_lines(data)
                        old_lines = signals.pth_exec_lines(before.get(p, b""))
                        fresh = [ln for ln in lines if ln not in old_lines]
                        if fresh:
                            add("BW003", HIGH if old else MEDIUM, f"{art_name}:{p}",
                                f"{'adds' if old else 'has'} a .pth file that runs code at every Python start: {fresh[0][:120]}",
                                "This is the technique used in both 2026 LiteLLM compromises. Don't install until "
                                "you know why it's there.")
                    if base in ("sitecustomize.py", "usercustomize.py") and p not in before:
                        add("BW004", HIGH if old else MEDIUM, f"{art_name}:{p}",
                            f"ships {base}, which Python runs automatically at startup",
                            "Packages almost never need this. Treat it as suspicious.")

            # wheel content the source distribution doesn't explain
            if "wheel" in new_art and "sdist" in new_art:
                gap_new = self._wheel_only(new_art["wheel"], new_art["sdist"])
                gap_old = self._wheel_only(old_art.get("wheel", {}), old_art.get("sdist", {})) if old_art.get("sdist") else set()
                fresh = sorted(gap_new - gap_old)
                if fresh and old:
                    risky = [p for p in fresh if p.endswith(".pth") or signals.scan(p, new_art["wheel"][p])]
                    add("BW016", HIGH if risky else LOW, "wheel",
                        f"{len(fresh)} file(s) in the wheel aren't in the source distribution: {', '.join(fresh[:5])}",
                        "Code that only exists in the built wheel can't be reviewed from source. That's how the "
                        "LiteLLM implant hid.")

        # what new code can do
        old_sigs = signals.scan_all(old_files) if old else {}
        new_sigs = signals.scan_all({p: new_files[p] for p in touched}) if old else signals.scan_all(new_files)
        install_time = self._install_time_files(rep, new, new_files)
        for p in install_time:  # always look at install-time code, even inside test folders
            if p in touched or not old:
                new_sigs.setdefault(p, signals.scan(p, new_files[p]))
        fresh = signals.new_signals(old_sigs, new_sigs)
        self._judge_signals(rep, fresh, install_time, add, has_old=bool(old))

        # binaries
        if old:
            had_bin = any(_is_binary(p, d) for p, d in old_files.items())
            new_bins = [p for p in added if _is_binary(p, new_files[p])]
            if new_bins and not had_bin:
                add("BW017", MEDIUM, new_bins[0],
                    f"adds {len(new_bins)} binary file(s) where there were none: {', '.join(new_bins[:4])}",
                    "Compiled code can't be reviewed. Make sure the project announced native components.")

    @staticmethod
    def _wheel_only(wheel: Dict[str, bytes], sdist: Dict[str, bytes]) -> Set[str]:
        src_names = {p.rsplit("/", 1)[-1] for p in sdist}
        src_paths = set(sdist)
        out = set()
        for p in wheel:
            if p.startswith(("<dist-info>/", "<data>/")) or not p.endswith((".py", ".pth", ".js", ".sh")):
                continue
            if p in src_paths or any(sp.endswith("/" + p) for sp in src_paths):
                continue
            if p.rsplit("/", 1)[-1] in src_names:
                continue  # moved or generated under a different folder layout
            out.add(p)
        return out

    def _install_time_files(self, rep: Report, rel: Release, files: Dict[str, bytes]) -> Set[str]:
        out = set()
        if rep.ecosystem == "npm":
            for cmd in rel.install_scripts.values():
                out.update(_script_targets(cmd, files))
        else:
            for p in files:
                base = p.rsplit("/", 1)[-1]
                if base in ("setup.py", "sitecustomize.py", "usercustomize.py") or base.endswith(".pth"):
                    out.add(p)
        return out

    def _judge_signals(self, rep, fresh: List[signals.Signal], install_time: Set[str], add, has_old: bool) -> None:
        if not fresh:
            return
        by_file: Dict[str, List[signals.Signal]] = {}
        for s in fresh:
            by_file.setdefault(s.file, []).append(s)
        names_by_file = {f: {s.name for s in ss} for f, ss in by_file.items()}
        verb = "adds" if has_old else "contains"

        def pick(*names):
            return [s for s in fresh if s.name in names]

        hidden = pick("js_eval_decode", "py_eval_decode", "py_marshal", "js_obfuscator")
        if hidden:
            add("BW006", HIGH, hidden[0].file, f"{verb} code that decodes and runs a hidden payload: {_signal_summary(hidden)}",
                "Legitimate libraries rarely need this. Don't install until it's explained.")

        combo = [f for f, n in names_by_file.items() if n & SECRET_SIGS and n & NET_SIGS]
        if combo:
            ss = [s for s in by_file[combo[0]] if s.name in SECRET_SIGS | NET_SIGS]
            add("BW007", HIGH, combo[0], f"{verb} code that reads secrets and talks to the network: {_signal_summary(ss)}",
                "This is the shape of a credential stealer. Don't install until it's explained.")

        secrets_ = [s for s in pick(*SECRET_SIGS) if s.file not in combo]
        strong = [s for s in secrets_ if s.name in ("ssh_keys", "browser_data", "crypto_wallets", "keychain")]
        if strong:
            add("BW008", HIGH if any(s.file in install_time for s in strong) else MEDIUM, strong[0].file,
                f"{verb} references to sensitive files: {_signal_summary(strong)}",
                "Check why a library update needs these.")
        weak = [s for s in secrets_ if s not in strong]
        if weak and any(s.file in install_time for s in weak):
            add("BW008", HIGH, weak[0].file, f"code that runs at install or startup {verb} access to credentials: {_signal_summary(weak)}",
                "Code that runs during install shouldn't touch credentials.")

        endpoints = pick("exfil_service", "raw_ip_url", "ip_lookup")
        if endpoints:
            hot = any(names_by_file.get(s.file, set()) & SECRET_SIGS for s in endpoints) or any(s.file in install_time for s in endpoints)
            add("BW009", HIGH if hot else MEDIUM, endpoints[0].file, f"{verb} suspicious endpoints: {_signal_summary(endpoints)}",
                "Find out what is sent there.")

        remote = pick("persistence", "reverse_shell", "shell_pipe")
        if remote:
            add("BW010", HIGH, remote[0].file, f"{verb} persistence or remote-access code: {_signal_summary(remote)}",
                "Libraries shouldn't install startup items or open shells. Don't install.")

        worm = pick("self_publish")
        if worm:
            add("BW022", HIGH, worm[0].file, f"{verb} code that publishes packages or uses registry tokens: {_signal_summary(worm)}",
                "This is how the Shai-Hulud worm spread between packages.")

        ci = pick("github_actions_abuse")
        if ci:
            add("BW023", HIGH if any(s.file in install_time for s in ci) else MEDIUM, ci[0].file,
                f"{verb} code that touches CI internals: {_signal_summary(ci)}",
                "Fine for CI tooling; suspicious for anything else.")

        if install_time:
            caps = [s for s in fresh if s.file in install_time and s.name in ("js_exec", "py_exec", "js_net", "py_net")]
            if caps:
                add("BW005", HIGH, caps[0].file, f"code that runs at install or startup {verb} process or network calls: "
                    f"{_signal_summary(caps)}",
                    "Code that runs automatically is the riskiest place for this. Review it.")

        if has_old:
            caps = [s for s in fresh if s.name in ("js_exec", "py_exec", "js_net", "py_net") and s.file not in install_time]
            if caps:
                kinds = sorted({"processes" if "exec" in s.name else "network" for s in caps})
                add("BW020", LOW, caps[0].file, f"new code uses {' and '.join(kinds)} in {len({s.file for s in caps})} file(s)",
                    "Usually ordinary. Worth a glance alongside the release notes.")

        blobs = [s for s in pick("encoded_blob") if s.file.endswith((".py", ".pth")) or s.file in install_time]
        if blobs:
            add("BW006", MEDIUM, blobs[0].file, f"{verb} a large encoded string in Python or install-time code: {blobs[0].snippet}",
                "Large encoded blobs are a common way to hide payloads.")
