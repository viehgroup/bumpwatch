import json
import shutil
import textwrap
from typing import List

from . import __version__
from .checks import HIGH, LOW, MEDIUM, RULES, SEVERITY_ORDER, Report

_C = {HIGH: "31", MEDIUM: "33", LOW: "36", "dim": "2", "bold": "1", "ok": "32"}
_ICON = {HIGH: "🔴", MEDIUM: "🟠", LOW: "🔵"}


def _p(on: bool):
    return lambda s, k: f"\033[{_C[k]}m{s}\033[0m" if on else s


def _counts(reports: List[Report]) -> dict:
    c = {HIGH: 0, MEDIUM: 0, LOW: 0}
    for r in reports:
        for f in r.findings:
            c[f.severity] += 1
    return c


def _ordered(reports: List[Report]) -> List[Report]:
    return sorted(reports, key=lambda r: (-(SEVERITY_ORDER[r.worst] if r.worst else -1), r.name))


def text(reports: List[Report], color: bool, show_clean: bool = False) -> str:
    p = _p(color)
    width = min(100, shutil.get_terminal_size((80, 24)).columns)
    out = []
    for r in _ordered(reports):
        if not r.findings and not r.error and not show_clean:
            continue
        out.append(p(r.label, "bold"))
        if r.error:
            out.append("  " + p(f"could not check: {r.error}", MEDIUM))
        if not r.findings and not r.error:
            out.append("  " + p("nothing new to worry about", "ok"))
        for f in sorted(r.findings, key=lambda x: -SEVERITY_ORDER[x.severity]):
            out.append(f"  {p(f'{f.severity:<6}', f.severity)} {f.rule}  {RULES[f.rule][0]}")
            for line in textwrap.wrap(f"{f.message} [{f.location}]", width - 4, break_on_hyphens=False):
                out.append("    " + line)
            if f.fix:
                for i, line in enumerate(textwrap.wrap(f.fix, width - 9, break_on_hyphens=False)):
                    out.append(("    fix: " if i == 0 else "         ") + p(line, "dim"))
        out.append("")
    c = _counts(reports)
    errors = sum(1 for r in reports if r.error)
    summary = f"{len(reports)} update{'s' if len(reports) != 1 else ''} checked"
    parts = [f"{n} {s}" for s, n in c.items() if n]
    if errors:
        parts.append(f"{errors} couldn't be checked")
    out.append(summary + (": " + ", ".join(parts) if parts else ". " + p("Nothing new to worry about.", "ok")))
    return "\n".join(out)


def markdown(reports: List[Report]) -> str:
    """For a pull request comment or the job summary."""
    c = _counts(reports)
    errors = [r for r in reports if r.error]
    flagged = [r for r in _ordered(reports) if r.findings]
    lines = ["## bumpwatch"]
    if not flagged and not errors:
        lines.append(f"✅ {len(reports)} dependency update(s) checked. Nothing new to worry about.")
        return "\n".join(lines) + "\n"
    head = ", ".join(f"{_ICON[s]} {n} {s}" for s, n in c.items() if n)
    lines.append(f"{len(reports)} dependency update(s) checked: {head or 'see below'}")
    if c[HIGH]:
        lines.append("\n> **Hold this merge** until the high-severity items are explained.")
    for r in flagged:
        lines.append(f"\n### {_ICON[r.worst]} `{r.name}` {r.old or '(new)'} → {r.new} ({r.ecosystem})")
        lines.append("| | Rule | Finding |")
        lines.append("|---|---|---|")
        for f in sorted(r.findings, key=lambda x: -SEVERITY_ORDER[x.severity]):
            msg = (f.message + f" <br><sub>{f.fix}</sub>" if f.fix else f.message).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {_ICON[f.severity]} | {f.rule} {RULES[f.rule][0]} | {msg} |")
    if errors:
        lines.append("\n**Couldn't check:** " + ", ".join(f"`{r.name}` ({r.error[:80]})" for r in errors))
    lines.append(f"\n<sub>bumpwatch {__version__} · compares each release with the one it replaces</sub>")
    return "\n".join(lines) + "\n"


def as_json(reports: List[Report]) -> str:
    return json.dumps({"version": __version__, "updates": [{
        "ecosystem": r.ecosystem, "name": r.name, "old": r.old, "new": r.new, "error": r.error,
        "stats": r.stats, "findings": [f.__dict__ for f in r.findings]} for r in reports]}, indent=2)


def sarif(reports: List[Report], lockfile: str = "") -> str:
    level = {HIGH: "error", MEDIUM: "warning", LOW: "note"}
    findings = [f for r in reports for f in r.findings]
    used = sorted({f.rule for f in findings})
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "bumpwatch", "version": __version__,
                "informationUri": "https://github.com/viehgroup/bumpwatch",
                "rules": [{"id": r, "name": RULES[r][0].replace(" ", ""),
                           "shortDescription": {"text": RULES[r][0]},
                           "fullDescription": {"text": RULES[r][1]}} for r in used],
            }},
            "results": [{
                "ruleId": f.rule, "level": level[f.severity],
                "message": {"text": f"{f.package}: {f.message}" + (f" Fix: {f.fix}" if f.fix else "")},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": lockfile or "package.json"}}}],
            } for f in findings],
        }],
    }, indent=2)


def github(reports: List[Report]) -> str:
    kind = {HIGH: "error", MEDIUM: "warning", LOW: "notice"}

    def esc(s):
        return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    def prop(s):
        return esc(s).replace(":", "%3A").replace(",", "%2C")

    return "\n".join(
        f"::{kind[f.severity]} title={prop(f.rule + ' ' + RULES[f.rule][0])}::{esc(f.package + ': ' + f.message)}"
        for r in reports for f in r.findings)
