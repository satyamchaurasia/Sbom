"""purls for binary files (DLL, JAR, ...) from the package-cache path they were found in.

Scanners of binaries (Syft, Trivy, file scans) report a DLL or JAR as a file component: the name is the file name and
the version is the assembly or manifest version, which is not the package version. The path the file came from often
names the exact package, because package managers lay out their caches by id and version:

    ~/.nuget/packages/newtonsoft.json/13.0.3/lib/net6.0/Newtonsoft.Json.dll   -> pkg:nuget/newtonsoft.json@13.0.3
    packages/Newtonsoft.Json.13.0.3/lib/net45/Newtonsoft.Json.dll             -> pkg:nuget/Newtonsoft.Json@13.0.3
    ~/.m2/repository/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar            -> pkg:maven/org.slf4j/slf4j-api@2.0.9
    ~/.gradle/caches/modules-2/files-2.1/org.slf4j/slf4j-api/2.0.9/<sha1>/... -> pkg:maven/org.slf4j/slf4j-api@2.0.9

Only these layouts are used; a path that does not match one of them gives no purl (never a guess).
"""

from __future__ import annotations

import re
from typing import Any

from packageurl import PackageURL

FILE_SUFFIXES = (".dll", ".exe", ".jar", ".war", ".ear", ".so", ".dylib", ".nupkg", ".whl", ".tgz", ".tar.gz", ".zip")

_VERSION = r"\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.\-]+)?"
_SEP = r"[\\/]"
_NUGET_CACHE = re.compile(rf"(?:^|{_SEP})\.?nuget{_SEP}packages{_SEP}([^\\/]+){_SEP}({_VERSION}){_SEP}", re.IGNORECASE)
_NUGET_FOLDER = re.compile(rf"(?:^|{_SEP})packages{_SEP}([A-Za-z_][\w.\-]*?)\.({_VERSION}){_SEP}(?:lib|runtimes|build|tools)"
                           rf"{_SEP}.*\.(?:dll|exe)$", re.IGNORECASE)
_M2 = re.compile(rf"(?:^|{_SEP})\.m2{_SEP}repository{_SEP}((?:[^\\/]+{_SEP})+?)([^\\/]+){_SEP}({_VERSION}){_SEP}"
                 rf"[^\\/]+\.(?:jar|war|ear)$", re.IGNORECASE)
_GRADLE = re.compile(rf"(?:^|{_SEP})files-2\.1{_SEP}([^\\/]+){_SEP}([^\\/]+){_SEP}({_VERSION}){_SEP}[0-9a-f]+{_SEP}", re.IGNORECASE)


def looks_like_file(name: Any) -> bool:
    """True when a component name is a file name (Newtonsoft.Json.dll), not a package name."""
    return isinstance(name, str) and name.lower().endswith(FILE_SUFFIXES)


def purl_from_path(path: str) -> PackageURL | None:
    """Exact purl from a package-cache path; None when the path is not in a known cache layout."""
    m = _NUGET_CACHE.search(path)
    if m:
        return PackageURL(type="nuget", name=m.group(1), version=m.group(2))
    m = _GRADLE.search(path)
    if m:
        return PackageURL(type="maven", namespace=m.group(1), name=m.group(2), version=m.group(3))
    m = _M2.search(path)
    if m:
        group = re.split(_SEP, m.group(1).strip("\\/"))
        return PackageURL(type="maven", namespace=".".join(group), name=m.group(2), version=m.group(3))
    m = _NUGET_FOLDER.search(path)
    if m:
        return PackageURL(type="nuget", name=m.group(1), version=m.group(2))
    return None


def component_paths(c: dict[str, Any]) -> list[str]:
    """Strings of a component that can hold the file path: properties (syft:location:*, aquasecurity:trivy:FilePath,
    ...), evidence.occurrences[].location, bom-ref and name."""
    out: list[str] = []
    for prop in c.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("value"), str):
            out.append(prop["value"])
    evidence = c.get("evidence")
    if isinstance(evidence, dict):
        for occ in evidence.get("occurrences") or []:
            if isinstance(occ, dict) and isinstance(occ.get("location"), str):
                out.append(occ["location"])
    for key in ("bom-ref", "name"):
        if isinstance(c.get(key), str):
            out.append(c[key])
    return out


def purl_from_component_paths(c: dict[str, Any]) -> PackageURL | None:
    for path in component_paths(c):
        found = purl_from_path(path)
        if found is not None:
            return found
    return None
