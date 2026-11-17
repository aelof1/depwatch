"""Tiny client for the free OSV.dev API (https://osv.dev) - no API key needed."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from .parsers import Dependency

API = "https://api.osv.dev/v1"
BATCH_SIZE = 500


@dataclass
class Vulnerability:
    id: str
    summary: str
    severity: str
    aliases: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.id}"


def default_http(method: str, url: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "User-Agent": "depwatch"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # honours HTTPS_PROXY
        return json.loads(resp.read().decode())


class OSVClient:
    def __init__(self, http: Callable[..., dict] = default_http):
        self.http = http
        self._cache: dict[str, Vulnerability] = {}

    def query(self, deps: list[Dependency]) -> dict[Dependency, list[str]]:
        """Return the vulnerability IDs affecting each dependency."""
        result: dict[Dependency, list[str]] = {}
        for i in range(0, len(deps), BATCH_SIZE):
            chunk = deps[i:i + BATCH_SIZE]
            body = {"queries": [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                                for d in chunk]}
            answer = self.http("POST", f"{API}/querybatch", body)
            for dep, res in zip(chunk, answer.get("results", [])):
                ids = [v["id"] for v in res.get("vulns", [])]
                if ids:
                    result[dep] = ids
        return result

    def details(self, vuln_id: str, dep: Dependency | None = None) -> Vulnerability:
        if vuln_id not in self._cache:
            data = self.http("GET", f"{API}/vulns/{vuln_id}")
            self._cache[vuln_id] = parse_vulnerability(data, dep)
        return self._cache[vuln_id]


def parse_vulnerability(data: dict, dep: Dependency | None = None) -> Vulnerability:
    severity = (data.get("database_specific") or {}).get("severity", "")
    fixed = []
    for affected in data.get("affected", []):
        pkg = affected.get("package", {})
        if dep and pkg.get("name", "").lower() != dep.name.lower():
            continue
        severity = severity or (affected.get("ecosystem_specific") or {}).get("severity", "")
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event and event["fixed"] not in fixed:
                    fixed.append(event["fixed"])
    if not severity and data.get("severity"):
        severity = "CVSS"  # only a vector is given; see the advisory link
    return Vulnerability(
        id=data.get("id", "?"),
        summary=data.get("summary") or (data.get("details") or "")[:120].replace("\n", " "),
        severity=(severity or "UNKNOWN").upper(),
        aliases=[a for a in data.get("aliases", []) if a.startswith("CVE-")],
        fixed_versions=fixed,
    )
