"""Tests use a fake HTTP function, so they run without Internet."""

import json
from pathlib import Path

from depwatch.cli import run
from depwatch.osv import OSVClient, parse_vulnerability
from depwatch.parsers import Dependency, find_dependency_files, parse_package_json, parse_package_lock, parse_requirements

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

FAKE_VULN = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "summary": "SQL injection in QuerySet.order_by",
    "aliases": ["CVE-2021-35042"],
    "database_specific": {"severity": "CRITICAL"},
    "affected": [{"package": {"name": "django", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.2"}, {"fixed": "3.2.5"}]}]}],
}


def fake_http(method, url, payload=None):
    if url.endswith("/querybatch"):
        results = []
        for q in payload["queries"]:
            if q["package"]["name"] == "django":
                results.append({"vulns": [{"id": FAKE_VULN["id"]}]})
            else:
                results.append({})
        return {"results": results}
    assert url.endswith(FAKE_VULN["id"])
    return FAKE_VULN


def test_parse_requirements():
    deps, skipped = parse_requirements(SAMPLES / "requirements.txt")
    names = {d.name: d.version for d in deps}
    assert names["django"] == "3.2.0" and names["pyyaml"] == "5.3"
    assert skipped == ["flask>=2.0"]


def test_parse_package_json():
    deps, skipped = parse_package_json(SAMPLES / "package.json")
    names = {d.name: d.version for d in deps}
    assert names == {"lodash": "4.17.15", "express": "4.16.0", "minimist": "1.2.0", "jest": "26.0.0"}
    assert skipped == ["axios@latest"]


def test_parse_package_lock(tmp_path):
    lock = {"lockfileVersion": 3, "packages": {
        "": {"name": "app"},
        "node_modules/lodash": {"version": "4.17.15"},
        "node_modules/a/node_modules/minimist": {"version": "0.0.8"}}}
    f = tmp_path / "package-lock.json"
    f.write_text(json.dumps(lock))
    deps, _ = parse_package_lock(f)
    assert {(d.name, d.version) for d in deps} == {("lodash", "4.17.15"), ("minimist", "0.0.8")}


def test_lockfile_preferred_over_package_json(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    assert [p.name for p in find_dependency_files(tmp_path)] == ["package-lock.json"]


def test_parse_vulnerability():
    v = parse_vulnerability(FAKE_VULN, Dependency("PyPI", "django", "3.2.0", "x"))
    assert v.severity == "CRITICAL" and v.fixed_versions == ["3.2.5"] and v.aliases == ["CVE-2021-35042"]


def test_full_run_with_fake_api():
    files, deps, skipped, report = run(str(SAMPLES / "requirements.txt"), OSVClient(http=fake_http))
    assert len(report) == 1
    dep, vuln = report[0]
    assert dep.name == "django" and vuln.id == FAKE_VULN["id"]
