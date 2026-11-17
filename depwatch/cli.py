"""depwatch command line."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
from pathlib import Path

from . import __version__
from .osv import OSVClient
from .parsers import find_dependency_files, parse_file

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "CVSS": 4, "UNKNOWN": 5}
SEV_COLOR = {"CRITICAL": "\033[95m", "HIGH": "\033[91m", "MODERATE": "\033[93m", "MEDIUM": "\033[93m"}


def run(target: str, client: OSVClient):
    files = find_dependency_files(Path(target))
    if not files:
        raise SystemExit("No requirements.txt, package.json or package-lock.json found.")
    deps, skipped = [], []
    for f in files:
        d, s = parse_file(f)
        deps += d
        skipped += s
    deps = list(dict.fromkeys(deps))  # remove duplicates, keep order
    hits = client.query(deps)
    report = []
    for dep, ids in hits.items():
        for vid in ids:
            v = client.details(vid, dep)
            report.append((dep, v))
    report.sort(key=lambda x: (SEV_ORDER.get(x[1].severity, 9), x[0].name))
    return files, deps, skipped, report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="depwatch",
                                description="List known vulnerabilities (CVE) in your Python and npm dependencies.")
    p.add_argument("path", nargs="?", default=".", help="project folder or dependency file (default: .)")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    try:
        files, deps, skipped, report = run(args.path, OSVClient())
    except urllib.error.URLError as exc:
        print(f"error: cannot reach api.osv.dev ({exc.reason}). Check your Internet connection.", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({
            "files": [str(f) for f in files],
            "dependencies_checked": len(deps),
            "unpinned_skipped": skipped,
            "vulnerabilities": [{
                "package": d.name, "version": d.version, "ecosystem": d.ecosystem, "file": d.source,
                "id": v.id, "cve": v.aliases, "severity": v.severity, "summary": v.summary,
                "fixed_in": v.fixed_versions, "url": v.url} for d, v in report],
        }, indent=2))
    else:
        color = not args.no_color and sys.stdout.isatty()
        print(f"Files: {', '.join(str(f) for f in files)}")
        print(f"Dependencies checked: {len(deps)}\n")
        for dep, v in report:
            c, r = (SEV_COLOR.get(v.severity, ""), "\033[0m") if color else ("", "")
            cve = f" ({', '.join(v.aliases)})" if v.aliases else ""
            fix = f"upgrade to {v.fixed_versions[-1]}" if v.fixed_versions else "no fix yet"
            print(f"{c}[{v.severity:<8}]{r} {dep.name} {dep.version}  {v.id}{cve}")
            print(f"           {v.summary}")
            print(f"           -> {fix}   {v.url}")
        vulnerable = len({d for d, _ in report})
        print(f"\n{len(report)} vulnerabilities in {vulnerable} package(s)." if report
              else "No known vulnerabilities found.")
        if skipped:
            print(f"Note: {len(skipped)} dependencies without an exact version were skipped: "
                  + ", ".join(skipped[:5]) + (" ..." if len(skipped) > 5 else ""))
            print("Pin versions (pip freeze > requirements.txt) or use a lockfile for a complete scan.")
    return 1 if report else 0


if __name__ == "__main__":
    sys.exit(main())
