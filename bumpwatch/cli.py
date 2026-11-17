import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import List

from . import __version__, lockfiles, report
from .checks import RULES, SEVERITY_ORDER, Checker, Policy, Report
from .registry import Registry, RegistryError, normalize_pypi

CONFIG = ".bumpwatch.json"


def load_policy(path: str) -> Policy:
    pol = Policy()
    if not path or not os.path.exists(path):
        return pol
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        raise SystemExit(f"bumpwatch: can't read {path}: {e}")
    pol.allow_install_scripts = {str(x).lower() for x in data.get("allow_install_scripts", [])}
    pol.ignore_rules = {str(x).upper() for x in data.get("ignore_rules", [])}
    pol.ignore_packages = {str(x).lower() for x in data.get("ignore_packages", [])}
    if "fresh_days" in data:
        pol.fresh_days = float(data["fresh_days"])
    return pol


def build_parser():
    p = argparse.ArgumentParser(
        prog="bumpwatch",
        description="Check dependency updates for hijacked releases before you merge them.",
    )
    p.add_argument("--version", action="version", version=f"bumpwatch {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json", "sarif", "github", "markdown"], default="text")
    common.add_argument("-o", "--output", help="write the report to a file")
    common.add_argument("--summary", metavar="FILE", help="also append a Markdown summary here (e.g. $GITHUB_STEP_SUMMARY)")
    common.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high")
    common.add_argument("--config", default=CONFIG, help=f"policy file (default: {CONFIG})")
    common.add_argument("-j", "--jobs", type=int, default=4, help="updates to check in parallel (default 4)")
    common.add_argument("--max", type=int, default=60, help="check at most this many updates (default 60)")
    common.add_argument("--all", action="store_true", help="also list updates with nothing to report")
    common.add_argument("--no-color", action="store_true")

    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", parents=[common], help="compare two versions of a package")
    c.add_argument("ecosystem", choices=["npm", "pypi"])
    c.add_argument("name")
    c.add_argument("old", help="current version (use - for a brand-new dependency)")
    c.add_argument("new", help="version you're about to install")

    i = sub.add_parser("inspect", parents=[common], help="compare a version with the release before it")
    i.add_argument("ecosystem", choices=["npm", "pypi"])
    i.add_argument("name")
    i.add_argument("version")

    d = sub.add_parser("diff", parents=[common], help="check every change between two lockfiles")
    d.add_argument("old_lockfile")
    d.add_argument("new_lockfile")

    r = sub.add_parser("pr", parents=[common], help="check lockfile changes since a git ref (for CI)")
    r.add_argument("--base", default=os.environ.get("GITHUB_BASE_REF") and f"origin/{os.environ['GITHUB_BASE_REF']}" or "origin/main",
                   help="git ref to compare against (default: the PR base, or origin/main)")
    r.add_argument("--repo", default=".", help="repository path (default: .)")

    sub.add_parser("rules", help="list all rules")
    return p


def main(argv=None) -> int:
    try:
        return _main(argv)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        return 130


def _main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "rules":
        for rid, (title, desc) in RULES.items():
            print(f"{rid}  {title}\n       {desc}")
        return 0

    policy = load_policy(args.config)
    checker = Checker(Registry(), policy)

    if args.cmd == "check":
        name = normalize_pypi(args.name) if args.ecosystem == "pypi" else args.name
        changes = [lockfiles.Change(args.ecosystem, name, None if args.old == "-" else args.old, args.new)]
    elif args.cmd == "inspect":
        name = normalize_pypi(args.name) if args.ecosystem == "pypi" else args.name
        try:
            prev = checker.reg.latest_before(args.ecosystem, name, args.version)
        except RegistryError as e:
            print(f"bumpwatch: {e}", file=sys.stderr)
            return 2
        changes = [lockfiles.Change(args.ecosystem, name, prev, args.version)]
    elif args.cmd == "diff":
        changes = []
        try:
            with open(args.old_lockfile, encoding="utf-8") as fh:
                old_text = fh.read()
            with open(args.new_lockfile, encoding="utf-8") as fh:
                new_text = fh.read()
        except OSError as e:
            print(f"bumpwatch: {e}", file=sys.stderr)
            return 2
        changes = lockfiles.diff(lockfiles.parse(args.old_lockfile, old_text),
                                 lockfiles.parse(args.new_lockfile, new_text))
    else:  # pr
        changes = lockfiles.changes_since(args.base, args.repo)

    skipped = max(0, len(changes) - args.max)
    changes = changes[:args.max]
    progress = args.format == "text" and not args.output and sys.stderr.isatty() and len(changes) > 1

    def run(ch):
        return checker.compare(ch.ecosystem, ch.name, ch.old, ch.new)

    reports: List[Report] = []
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for n, rep in enumerate(pool.map(run, changes), 1):
            reports.append(rep)
            if progress:
                print(f"\rchecking updates {n}/{len(changes)}", end="", file=sys.stderr, flush=True)
    if progress:
        print("\r" + " " * 40 + "\r", end="", file=sys.stderr)

    if args.format == "json":
        out = report.as_json(reports)
    elif args.format == "sarif":
        out = report.sarif(reports)
    elif args.format == "github":
        out = report.github(reports)
    elif args.format == "markdown":
        out = report.markdown(reports)
    else:
        color = not args.output and sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        out = report.text(reports, color, show_clean=args.all or len(reports) == 1)
        if not changes:
            out = "No dependency changes found."
        if skipped:
            out += f"\n({skipped} more update(s) not checked; raise --max to include them)"

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    elif out:
        print(out)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(report.markdown(reports) + "\n")

    if args.fail_on == "never":
        return 0
    t = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= t for r in reports for f in r.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
