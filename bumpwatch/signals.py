"""Risky patterns in package code, as comparable fingerprints.

Each hit becomes a (signal, normalised text) pair. Comparing the sets for
the old and new version shows what an update *added*, which is what
matters: a package that has always spawned processes isn't news, one
that just started doing it is.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

CODE_EXT = (".js", ".cjs", ".mjs", ".ts", ".py", ".pyw", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".pth")

_COMMON = {
    "ssh_keys": r"\.ssh[/\\]+(?:id_(?:rsa|ed25519|ecdsa|dsa)|authorized_keys)|authorized_keys",
    "cloud_creds": (r"\.aws[/\\]+credentials|\.config[/\\]+gcloud|application_default_credentials|"
                    r"\.azure[/\\]+|\.kube[/\\]+config|\.docker[/\\]+config\.json"),
    "pkg_tokens": r"\.npmrc|\.pypirc|\.git-credentials|\.netrc\b|NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_TOKEN|TWINE_PASSWORD|GITHUB_TOKEN|GH_TOKEN",
    "browser_data": r"Login Data|Local State|key4\.db|logins\.json|Cookies\.binarycookies",
    "crypto_wallets": r"\.electrum|Exodus[/\\]+exodus\.wallet|\bmetamask\b|wallet\.dat|nkbihfbeogaeaoehlefnkodbefgpgknn",
    "keychain": r"security\s+find-(?:generic|internet)-password|login\.keychain|secret-tool\s+lookup",
    "exfil_service": (r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com|webhook\.site|"
                      r"\.ngrok(?:-free)?\.(?:io|app)|transfer\.sh|pipedream\.net|requestbin\.(?:com|net)|\.requestbin\.|interact\.sh|"
                      r"oast\.(?:pro|live|fun|site|online)|burpcollaborator|\.trycloudflare\.com|filebin\.net"),
    "ip_lookup": r"ifconfig\.me|api\.ipify\.org|ipinfo\.io|icanhazip\.com|checkip\.amazonaws",
    "raw_ip_url": r"https?://(?!(?:10|127|0)\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?",
    "shell_pipe": r"(?:curl|wget)\s[^\n\"'|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\biex\s*\(|Invoke-Expression|powershell(?:\.exe)?\s+[^\n]{0,40}-(?:e|enc|encodedcommand)\s",
    "persistence": (r"Library/LaunchAgents|launchctl\s+(?:load|bootstrap)|@reboot|crontab\s|"
                    r"Start Menu[/\\]+Programs[/\\]+Startup|schtasks(?:\.exe)?\s+/create|CurrentVersion\\+Run\b|"
                    r"systemctl\s+--user\s+enable|\.config/systemd/user"),
    "reverse_shell": r"/dev/tcp/|\bnc\s+(?:-\w+\s+)*-e\s|\bsocat\b[^\n]{0,60}exec|bash\s+-i\s+>&",
    "github_actions_abuse": r"actions/runner|ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST|\.github/workflows/[^\"'\s]*\.ya?ml",
    "self_publish": r"npm\s+publish|twine\s+upload|registry\.npmjs\.org/-/(?:npm/v1/)?(?:user|tokens)|upload\.pypi\.org",
}

_JS = {
    "js_exec": r"""require\(\s*["'](?:node:)?child_process["']\s*\)|from\s*["'](?:node:)?child_process["']""",
    "js_eval_decode": (r"eval\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent)\s*\(|"
                       r"(?:new\s+)?Function\(\s*(?:atob|Buffer\.from)\s*\(|"
                       r"eval\(\s*[\w$.]+\.toString\(\s*[\"'](?:base64|hex)?[\"']?\s*\)\s*\)|vm\.runIn(?:New|This)Context\("),
    "js_env_harvest": r"JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries)\(\s*process\.env\s*\)",
    "js_net": r"https?\.request\s*\(|https?\.get\s*\(|\bfetch\s*\(|net\.connect|new\s+WebSocket|dns\.(?:resolve|lookup)\w*\s*\(",
    "js_obfuscator": r"_0x[0-9a-f]{4,6}\s*\(|\b_0x[0-9a-f]{4,6}\[",
}

_PY = {
    "py_exec": r"\bsubprocess\.(?:Popen|run|call|check_output|check_call)\b|\bos\.(?:system|popen|exec[lv]p?e?)\s*\(|\bpty\.spawn\b",
    "py_eval_decode": (r"\b(?:exec|eval)\s*\(\s*(?:base64\.\w+|codecs\.decode|zlib\.decompress|marshal\.loads|"
                       r"bytes\.fromhex|__import__\(\s*['\"](?:base64|zlib|marshal)['\"]\s*\))|"
                       r"\bexec\s*\(\s*compile\s*\(\s*(?:base64|zlib|marshal)"),
    "py_marshal": r"\bmarshal\.loads\s*\(",
    "py_env_harvest": r"\bos\.environ\.(?:items|copy)\s*\(\s*\)|dict\(\s*os\.environ\s*\)|json\.dumps\(\s*(?:dict\()?os\.environ",
    "py_net": r"\burllib\.request\.urlopen\b|\brequests\.(?:get|post|put)\s*\(|\bhttpx\.(?:get|post)\b|\bsocket\.socket\s*\(|\bhttp\.client\.HTTPS?Connection\b|\burlopen\s*\(",
    "py_import_hook": r"sys\.meta_path\.insert|sys\.path_hooks|builtins\.__import__\s*=",
}

_BLOB = re.compile(r"[\"'`][A-Za-z0-9+/]{2000,}={0,2}[\"'`]")
_HEX_BLOB = re.compile(r"[\"'](?:[0-9a-fA-F]{2}){1500,}[\"']")

COMPILED: Dict[str, Dict[str, re.Pattern]] = {
    "common": {k: re.compile(v, re.I) for k, v in _COMMON.items()},
    "js": {k: re.compile(v) for k, v in _JS.items()},
    "py": {k: re.compile(v) for k, v in _PY.items()},
}
# case-sensitive on purpose: env var names and Python identifiers
for _k in ("pkg_tokens",):
    COMPILED["common"][_k] = re.compile(_COMMON[_k])


@dataclass(frozen=True)
class Signal:
    name: str
    text: str      # normalised match, used to compare versions
    file: str
    snippet: str


def lang(path: str) -> str:
    p = path.lower()
    if p.endswith((".js", ".cjs", ".mjs", ".ts")):
        return "js"
    if p.endswith((".py", ".pyw", ".pth")):
        return "py"
    return "other"


def _norm(s: str) -> str:
    s = re.sub(r"\s+", " ", s.strip())
    return s[:120]


def _snip(text: str, a: int, b: int) -> str:
    return " ".join(text[max(0, a - 40): b + 40].split())[:140]


def scan(path: str, data: bytes) -> List[Signal]:
    if not path.lower().endswith(CODE_EXT) and not path.endswith(("setup.py",)):
        if not (data[:2] == b"#!" and len(data) < 2_000_000):
            return []
    text = data.decode("utf-8", "replace")
    groups = ["common"]
    lg = lang(path)
    if lg in ("js", "py"):
        groups.append(lg)
    elif data[:2] == b"#!":
        groups += ["py"] if b"python" in data[:80] else []
    out: List[Signal] = []
    for g in groups:
        for name, rx in COMPILED[g].items():
            n = 0
            for m in rx.finditer(text):
                out.append(Signal(name, _norm(m.group(0)), path, _snip(text, m.start(), m.end())))
                n += 1
                if n >= 10:
                    break
    for rx, name in ((_BLOB, "encoded_blob"), (_HEX_BLOB, "encoded_blob")):
        m = rx.search(text)
        if m:
            out.append(Signal(name, f"{len(m.group(0)) // 1000}k:{m.group(0)[1:41]}", path, f"{len(m.group(0)):,} character encoded string"))
    return out


def fingerprint(signals: List[Signal]) -> Set[Tuple[str, str]]:
    return {(s.name, s.text) for s in signals}


def new_signals(old: Dict[str, List[Signal]], new: Dict[str, List[Signal]]) -> List[Signal]:
    """Signals present in the new version that the old one didn't have anywhere."""
    before = set()
    for sigs in old.values():
        before |= fingerprint(sigs)
    out, seen = [], set()
    for sigs in new.values():
        for s in sigs:
            key = (s.name, s.text)
            if key in before or (key, s.file) in seen:
                continue
            seen.add((key, s.file))
            out.append(s)
    return out


_TEST_DIR = re.compile(r"(?:^|/)(?:tests?|__tests__|spec|fixtures?)/", re.I)


def scan_all(files: Dict[str, bytes]) -> Dict[str, List[Signal]]:
    out = {}
    for path, data in files.items():
        if not data or path.endswith((".map", ".d.ts")) or _TEST_DIR.search(path):
            continue
        sigs = scan(path, data)
        if sigs:
            out[path] = sigs
    return out


PTH_EXEC = re.compile(r"^\s*import[\s;]", re.M)


def pth_exec_lines(data: bytes) -> List[str]:
    """Lines in a .pth file that Python executes at startup (those starting with `import`)."""
    return [ln.strip()[:160] for ln in data.decode("utf-8", "replace").splitlines() if PTH_EXEC.match(ln)]
