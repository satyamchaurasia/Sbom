"""fix: purls of DLL/JAR files from package-cache paths, a second run changes nothing, the root component is always kept
blank (never invented), registry-URL purls only for the same package, and Markdown-safe reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sbom_fixer.binpath import looks_like_file, purl_from_path
from sbom_fixer.cli import app
from sbom_fixer.validate import validate

runner = CliRunner()


def run_fix(doc: Any, tmp_path: Path, name: str = "in") -> tuple[dict[str, Any], str, Path]:
    src = tmp_path / f"{name}.json"
    src.write_text(json.dumps(doc), encoding="utf-8")
    out = tmp_path / f"out-{name}"
    res = runner.invoke(app, ["fix", str(src), "--out", str(out), "--no-audit"])
    assert res.exit_code in (0, 1, 7), res.output
    fixed = json.loads((out / f"{name}.corrected.cdx.json").read_text(encoding="utf-8"))
    assert validate(fixed, "cyclonedx", fixed["specVersion"]) == []
    return fixed, res.output, out


# ---------------------------------------------------------------- package-cache paths


@pytest.mark.parametrize("path,purl", [
    (r"C:\Users\x\.nuget\packages\newtonsoft.json\13.0.3\lib\net6.0\Newtonsoft.Json.dll", "pkg:nuget/newtonsoft.json@13.0.3"),
    ("/root/.nuget/packages/microsoft.extensions.logging/8.0.0/lib/net8.0/Microsoft.Extensions.Logging.dll",
     "pkg:nuget/microsoft.extensions.logging@8.0.0"),
    (r"D:\src\app\packages\Newtonsoft.Json.13.0.3\lib\net45\Newtonsoft.Json.dll", "pkg:nuget/Newtonsoft.Json@13.0.3"),
    (r"packages\Microsoft.AspNet.Mvc.5.2.9\lib\net45\System.Web.Mvc.dll", "pkg:nuget/Microsoft.AspNet.Mvc@5.2.9"),
    ("/home/u/.m2/repository/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar", "pkg:maven/org.slf4j/slf4j-api@2.0.9"),
    ("/home/u/.gradle/caches/modules-2/files-2.1/org.slf4j/slf4j-api/2.0.9/abc123def/slf4j-api-2.0.9.jar",
     "pkg:maven/org.slf4j/slf4j-api@2.0.9"),
])
def test_purl_from_cache_path(path: str, purl: str) -> None:
    found = purl_from_path(path)
    assert found is not None and found.to_string() == purl


@pytest.mark.parametrize("path", ["/app/publish/Newtonsoft.Json.dll", "Newtonsoft.Json.dll",
                                  r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.dll",
                                  "/usr/lib/node_modules/packages/x.1.2/lib/a.js",
                                  "/home/u/.m2/repository/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.pom"])
def test_no_purl_outside_a_cache_layout(path: str) -> None:
    assert purl_from_path(path) is None


def test_looks_like_file() -> None:
    assert looks_like_file("Newtonsoft.Json.dll") and looks_like_file("app.EXE") and looks_like_file("x.jar")
    assert not looks_like_file("Newtonsoft.Json") and not looks_like_file(None)


DLL_SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
    "metadata": {"tools": {"components": [{"type": "application", "name": "syft", "version": "1.0"}]},
                 "component": {"type": "application", "name": "MyApp", "version": "2.0"}},
    "components": [
        {"type": "library", "bom-ref": "a", "name": "Newtonsoft.Json.dll", "version": "13.0.0.0",
         "properties": [{"name": "syft:location:0:path",
                         "value": "/root/.nuget/packages/newtonsoft.json/13.0.3/lib/net6.0/Newtonsoft.Json.dll"}]},
        {"type": "file", "bom-ref": "b", "name": "Serilog.dll", "version": "2.0.0.0", "purl": "pkg:generic/Serilog.dll@2.0.0.0",
         "evidence": {"occurrences": [{"location": "C:\\src\\packages\\Serilog.3.1.1\\lib\\net45\\Serilog.dll"}]}},
        {"type": "library", "bom-ref": "c", "name": "MyCompany.Core.dll", "version": "1.0.0.0"},
        {"type": "library", "bom-ref": "d", "name": "Polly", "version": "8.2.0", "purl": "pkg:nuget/Polly@8.2.0"},
    ],
}


def test_dll_components_get_the_package_purl_and_version(tmp_path: Path) -> None:
    out, _, folder = run_fix(DLL_SBOM, tmp_path, "app")
    got = {c["name"]: (c["version"], c["purl"]) for c in out["components"]}
    assert got["Newtonsoft.Json.dll"] == ("13.0.3", "pkg:nuget/newtonsoft.json@13.0.3")
    assert got["Serilog.dll"] == ("3.1.1", "pkg:nuget/Serilog@3.1.1")  # a generic purl is upgraded too
    # no cache path: the file name is never turned into pkg:nuget/MyCompany.Core.dll
    assert got["MyCompany.Core.dll"] == ("1.0.0.0", "pkg:generic/MyCompany.Core.dll@1.0.0.0")
    assert got["Polly"] == ("8.2.0", "pkg:nuget/Polly@8.2.0")
    advice = (folder / "app.suggestions.md").read_text(encoding="utf-8")
    assert "| DLL/JAR without a package purl (found in the package cache) | 2 | Newtonsoft.Json.dll@13.0.3, Serilog.dll@3.1.1 |" in advice


# ---------------------------------------------------------------- a second run changes nothing


@pytest.mark.parametrize("doc", [
    {"bomFormat": "CycloneDX", "specVersion": "1.3", "version": 1,
     "metadata": {"component": {"type": "application", "name": "x"}},
     "components": [{"type": "library", "name": "a", "version": "1"}]},
    {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"tools": [{"name": "rebar3_sbom"}]},
     "components": [{"type": "library", "name": "cowboy", "version": "2.10.0"},
                    {"type": "library", "name": "phoenix", "version": "1.7.0", "purl": "pkg:hex/phoenix@1.7.0"}]},
    DLL_SBOM,
])
def test_second_run_is_identical(doc: dict[str, Any], tmp_path: Path) -> None:
    first, _, folder = run_fix(doc, tmp_path, "one")
    second, output, _ = run_fix(first, tmp_path, "two")
    assert second == first and "changes    : 0 " in output
    # every component (and the root) has a dependencies entry
    refs = {c["bom-ref"] for c in first["components"]}
    assert refs <= {d["ref"] for d in first["dependencies"]}


# ---------------------------------------------------------------- the root component


def test_root_component_written_as_a_string_keeps_its_name(tmp_path: Path) -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"component": "app"},
           "components": []}
    out, _, _ = run_fix(doc, tmp_path)
    assert out["metadata"]["component"] == {"type": "application", "name": "app"}


def test_root_version_on_13_is_blank_not_invented(tmp_path: Path) -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.3", "version": 1,
           "metadata": {"component": {"type": "application", "name": "x"}}, "components": []}
    out, _, _ = run_fix(doc, tmp_path)
    assert out["metadata"]["component"]["version"] == ""


# ---------------------------------------------------------------- registry URLs


def test_registry_url_of_another_package_is_not_used(tmp_path: Path) -> None:
    ref = [{"type": "distribution", "url": "https://repo.hex.pm/tarballs/jason-1.4.0.tar"}]
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "components": [{"type": "library", "name": "b", "version": "2", "externalReferences": ref},
                          {"type": "library", "name": "jason", "version": "1.4.1", "externalReferences": ref},
                          {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
                          {"type": "library", "name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"}]}
    out, _, _ = run_fix(doc, tmp_path)
    purls = {c["name"]: c["purl"] for c in out["components"]}
    assert purls["b"] == "pkg:generic/b@2"
    assert purls["jason"] == "pkg:hex/jason@1.4.1"  # the component's own version wins


# ---------------------------------------------------------------- reports


def test_pipes_in_paths_do_not_break_tables(tmp_path: Path) -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "a|b": 1, "components": []}
    _, _, folder = run_fix(doc, tmp_path)
    for name in ("in.tech-notes.md", "in.suggestions.md"):
        for line in (folder / name).read_text(encoding="utf-8").splitlines():
            if line.startswith("| ") and "a" in line and "b" in line and "removed" in line:
                assert "a\\|b" in line


def test_non_sbom_json_says_it_was_not_validated(tmp_path: Path) -> None:
    _, output, folder = run_fix({}, tmp_path)
    assert "not validated as it is" in output and "0 schema error(s)" not in output
    assert "not validated as it is" in (folder / "in.tech-notes.md").read_text(encoding="utf-8")
