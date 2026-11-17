"""Read dependency files and return (ecosystem, name, version) tuples."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Dependency:
    ecosystem: str   # "PyPI" or "npm" (names used by OSV)
    name: str
    version: str
    source: str      # file it came from


REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)")


def parse_requirements(path: Path) -> tuple[list[Dependency], list[str]]:
    deps, skipped = [], []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = REQ_LINE.match(line)
        if m:
            deps.append(Dependency("PyPI", m.group(1).lower(), m.group(2), path.name))
        else:
            skipped.append(line)  # unpinned (>=, ~=, no version): we can't know the real version
    return deps, skipped


def _clean_npm_version(spec: str) -> str | None:
    spec = spec.strip()
    m = re.match(r"^[\^~=v]?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)$", spec)
    return m.group(1) if m else None


def parse_package_json(path: Path) -> tuple[list[Dependency], list[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    deps, skipped = [], []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            version = _clean_npm_version(str(spec))
            if version:
                deps.append(Dependency("npm", name, version, path.name))
            else:
                skipped.append(f"{name}@{spec}")
    return deps, skipped


def parse_package_lock(path: Path) -> tuple[list[Dependency], list[str]]:
    """package-lock.json v2/v3 lists every installed package with its exact version."""
    data = json.loads(path.read_text(encoding="utf-8"))
    deps = []
    for key, info in (data.get("packages") or {}).items():
        if not key or "version" not in info:
            continue
        name = info.get("name") or key.split("node_modules/")[-1]
        deps.append(Dependency("npm", name, info["version"], path.name))
    if not deps:  # lockfile v1
        def walk(tree):
            for name, info in (tree or {}).items():
                if "version" in info:
                    deps.append(Dependency("npm", name, info["version"], path.name))
                walk(info.get("dependencies"))
        walk(data.get("dependencies"))
    return sorted(set(deps), key=lambda d: d.name), []


PARSERS = {
    "requirements.txt": parse_requirements,
    "package-lock.json": parse_package_lock,
    "package.json": parse_package_json,
}


def find_dependency_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    found = []
    for name in PARSERS:
        found += [p for p in target.rglob(name) if "node_modules" not in p.parts and ".venv" not in p.parts]
    # if a lockfile exists next to package.json, it is more precise: skip package.json
    locks = {p.parent for p in found if p.name == "package-lock.json"}
    return sorted(p for p in found if not (p.name == "package.json" and p.parent in locks))


def parse_file(path: Path) -> tuple[list[Dependency], list[str]]:
    name = path.name
    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements(path)
    if name in PARSERS:
        return PARSERS[name](path)
    raise ValueError(f"unsupported file: {path.name}")
