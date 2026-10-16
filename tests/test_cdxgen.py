"""cdxgen-fix: any SBOM -> cdxgen-layout CycloneDX -> Checkmarx canonical form with the ecosystem's tool name."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sbom_fixer.cdxgen import spdx_licenses, spdx_to_cyclonedx, to_cdxgen
from sbom_fixer.cli import app
from sbom_fixer.ecosystem import detect_ecosystem, ecosystem_of_generator
from sbom_fixer.errors import ProfileError
from sbom_fixer.profile import CanonicalPolicy, load_profile, parse_profile
from sbom_fixer.validate import validate

from .conftest import CORPUS, ROOT, bom, run

runner = CliRunner()


def comp(purl: str, name: str = "x", version: str = "1.0") -> dict[str, Any]:
    return {"bom-ref": purl, "type": "library", "name": name, "version": version, "purl": purl}


def eco_profile(**kw: Any):  # type: ignore[no-untyped-def]
    prof = load_profile("checkmarx")
    assert prof.canonical is not None
    return replace(prof, canonical=replace(prof.canonical, tool_per_ecosystem=True, **kw))


def tool_name(doc: dict[str, Any]) -> str:
    tools = doc["metadata"]["tools"]
    assert len(tools) == 1 and tools[0]["vendor"] == "AppThreat" and tools[0]["version"] == "0.8.0"
    return str(tools[0]["name"])


# ---------------------------------------------------------------- ecosystem detection


@pytest.mark.parametrize(("purls", "expected"), [
    (["pkg:nuget/Newtonsoft.Json@13.0.1", "pkg:nuget/Serilog@3.0.0"], "cyclonedx-dotnet"),
    (["pkg:maven/org.a/b@1.0", "pkg:maven/org.a/c@1.0"], "cyclonedx-java"),
    (["pkg:npm/lodash@4.17.21"], "cyclonedx-node"),
    (["pkg:pypi/requests@2.31.0"], "cyclonedx-python"),
    (["pkg:golang/github.com/pkg/errors@v0.9.1"], "cyclonedx-go"),
    (["pkg:gem/rails@7.1.2"], "cyclonedx-ruby"),
    (["pkg:composer/laravel/framework@10.0.0"], "cyclonedx-php"),
    (["pkg:cargo/serde@1.0.0"], "cyclonedx-rust"),
    (["pkg:hex/phoenix@1.7.0"], "cyclonedx-erlang"),
    (["pkg:maven/org.a/b@1.0", "pkg:npm/a@1", "pkg:npm/b@1", "pkg:generic/c@1", "pkg:rpm/d@1"], "cyclonedx-node"),
])
def test_tool_follows_majority_ecosystem(purls: list[str], expected: str) -> None:
    doc = bom("1.5", components=[comp(p, f"n{i}") for i, p in enumerate(purls)])
    out, res, log = run(doc, eco_profile())
    assert res.ok and tool_name(out) == expected
    assert any(c.rule_id == "CXN-011" and c.path == "/metadata/tools" and "ecosystem" in c.reason for c in log.changes)


def test_tie_broken_by_root_component() -> None:
    doc = bom("1.5", components=[comp("pkg:npm/a@1", "a"), comp("pkg:nuget/b@1", "b")])
    doc["metadata"]["component"] = {"type": "application", "bom-ref": "app", "name": "app", "purl": "pkg:nuget/app@1"}
    out, _, _ = run(doc, eco_profile())
    assert tool_name(out) == "cyclonedx-dotnet"


def test_generator_used_when_no_package_purl() -> None:
    doc = bom("1.5", components=[{"type": "library", "name": "thing", "version": "1"}])
    doc["metadata"]["tools"] = [{"vendor": "CycloneDX", "name": "cyclonedx-gradle-plugin", "version": "1.10.0"}]
    out, _, _ = run(doc, eco_profile())
    assert tool_name(out) == "cyclonedx-java"


def test_no_evidence_keeps_default_tool() -> None:
    doc = bom("1.5", components=[{"type": "library", "name": "thing", "version": "1"}])
    out, _, log = run(doc, eco_profile())
    assert tool_name(out) == "cyclonedx-dotnet"
    assert any("no ecosystem detected" in c.reason for c in log.changes if c.rule_id == "CXN-011")


def test_forced_ecosystem() -> None:
    doc = bom("1.5", components=[comp("pkg:npm/a@1")])
    out, _, _ = run(doc, eco_profile(ecosystem="java"))
    assert tool_name(out) == "cyclonedx-java"


def test_generator_words_are_whole_words() -> None:
    assert ecosystem_of_generator(["google-sbom-tool"]) is None
    assert ecosystem_of_generator(["cyclonedx-gomod 1.4"]) == "go"
    assert ecosystem_of_generator(["@cyclonedx/cyclonedx-npm"]) == "node"
    assert ecosystem_of_generator(["CycloneDX cyclonedx-dotnet"]) == "dotnet"


def test_detect_reports_counts() -> None:
    found = detect_ecosystem({"components": [comp("pkg:npm/a@1"), comp("pkg:npm/b@1"), comp("pkg:maven/o/c@1")]})
    assert found.ecosystem == "node" and found.counts == {"node": 2, "java": 1} and found.total == 3
    assert "2 of 3" in found.describe() and "java 1" in found.describe()


def test_without_tool_per_ecosystem_fix_is_unchanged() -> None:
    out, _, _ = run(bom("1.5", components=[comp("pkg:maven/org.a/b@1.0")]), load_profile("checkmarx"))
    assert tool_name(out) == "cyclonedx-dotnet"


def test_profile_keys() -> None:
    base = {"name": "x", "cyclonedx": {"accepted_versions": ["1.5"]}}
    p = parse_profile(dict(base, canonical={"tool_per_ecosystem": True, "ecosystem_tools": {"java": "cyclonedx-maven"},
                                            "ecosystem": "java"}))
    assert p.canonical is not None and p.canonical.tool_per_ecosystem and p.canonical.ecosystem == "java"
    assert p.canonical.ecosystem_tools["java"] == "cyclonedx-maven" and p.canonical.ecosystem_tools["node"]
    with pytest.raises(ProfileError):
        parse_profile(dict(base, canonical={"ecosystem": "cobol"}))
    with pytest.raises(ProfileError):
        parse_profile(dict(base, canonical={"ecosystem_tools": {"java": ""}}))
    assert not CanonicalPolicy().tool_per_ecosystem


# ---------------------------------------------------------------- step 1: cdxgen layout


def spdx(packages: list[dict[str, Any]], relationships: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    doc = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "app-doc",
           "documentNamespace": "https://example.com/app", "creationInfo": {
               "created": "2026-10-02T10:00:00Z", "creators": ["Tool: syft-1.4.1", "Organization: Acme"]},
           "packages": packages, "relationships": relationships}
    doc.update(extra)
    return doc


def pkg(sid: str, name: str, purl: str | None = None, **extra: Any) -> dict[str, Any]:
    p: dict[str, Any] = {"SPDXID": sid, "name": name, "versionInfo": "1.0", "downloadLocation": "NOASSERTION"}
    if purl:
        p["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]
    p.update(extra)
    return p


def test_spdx_described_package_becomes_root_and_relationships_dependencies() -> None:
    doc = spdx([pkg("SPDXRef-app", "app", "pkg:maven/acme/app@1.0", primaryPackagePurpose="APPLICATION"),
                pkg("SPDXRef-a", "a", "pkg:maven/org.x/a@1.0", licenseConcluded="Apache-2.0",
                    checksums=[{"algorithm": "SHA256", "checksumValue": "A" * 64}], supplier="Organization: X (x@x.org)"),
                pkg("SPDXRef-b", "b", None, licenseConcluded="NOASSERTION", licenseDeclared="MIT OR Apache-2.0")],
               [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-app"},
                {"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-a"},
                {"spdxElementId": "SPDXRef-b", "relationshipType": "DEV_DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-a"}])
    notes: list[str] = []
    out = spdx_to_cyclonedx(doc, "1.6", notes)
    assert validate(out, "cyclonedx", "1.6") == []
    assert out["metadata"]["component"]["bom-ref"] == "pkg:maven/acme/app@1.0"
    assert out["metadata"]["tools"] == {"components": [{"type": "application", "name": "syft", "version": "1.4.1"}]}
    a, b = out["components"]
    assert a["bom-ref"] == "pkg:maven/org.x/a@1.0" and a["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    assert a["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}] and a["supplier"] == {"name": "X"}
    assert b["bom-ref"] == "SPDXRef-b" and "purl" not in b and b["licenses"][0]["expression"]
    deps = {d["ref"]: d["dependsOn"] for d in out["dependencies"]}
    assert deps == {"pkg:maven/acme/app@1.0": ["pkg:maven/org.x/a@1.0"], "pkg:maven/org.x/a@1.0": ["SPDXRef-b"],
                    "SPDXRef-b": []}


def test_spdx_without_single_described_package_gets_document_root() -> None:
    doc = spdx([pkg("SPDXRef-a", "a", "pkg:npm/a@1.0"), pkg("SPDXRef-b", "b", "pkg:npm/b@1.0")],
               [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-a"},
                {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-b"}])
    out = spdx_to_cyclonedx(doc, "1.6", [])
    assert out["metadata"]["component"] == {"bom-ref": "SPDXRef-DOCUMENT", "type": "application", "name": "app-doc"}
    assert len(out["components"]) == 2
    assert out["dependencies"][0] == {"ref": "SPDXRef-DOCUMENT", "dependsOn": ["pkg:npm/a@1.0", "pkg:npm/b@1.0"]}


def test_spdx_licenses() -> None:
    assert spdx_licenses("NOASSERTION", "mit") == [{"license": {"id": "MIT"}}]
    assert spdx_licenses("LicenseRef-acme") == [{"license": {"name": "LicenseRef-acme"}}]
    assert spdx_licenses("NONE", None) == []


@pytest.mark.parametrize("rel", ["minimal/min-spdx-2.2.json", "minimal/min-spdx-2.3.json", "sbom-tool/service.spdx.json",
                                 "purl/spdx-issues.spdx.json"])
def test_corpus_spdx_converts_to_valid_cdx16(rel: str) -> None:
    conv = to_cdxgen((CORPUS / rel).read_bytes())
    assert conv.source_spec == "spdx" and conv.target_version == "1.6"
    assert validate(conv.doc, "cyclonedx", "1.6") == [] or rel.startswith("purl/")  # bad purls are fixed in step 2


def test_cyclonedx_keeps_version_and_gets_cdxgen_layout() -> None:
    doc = bom("1.4", components=[{"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1"}])
    conv = to_cdxgen(json.dumps(doc).encode())
    assert conv.target_version == "1.4" and conv.doc["specVersion"] == "1.4"
    assert conv.doc["components"][0]["bom-ref"] == "pkg:npm/a@1"
    assert conv.doc["dependencies"] == [{"ref": "pkg:npm/a@1", "dependsOn": []}]


def test_bare_component_array_is_read() -> None:
    conv = to_cdxgen(json.dumps([{"type": "library", "name": "a", "version": "1", "purl": "pkg:pypi/a@1"}]).encode())
    assert conv.doc["bomFormat"] == "CycloneDX" and conv.target_version == "1.6"


# ---------------------------------------------------------------- the command


def test_cli_ratecard_java(tmp_path: Path) -> None:
    res = runner.invoke(app, ["fix", str(ROOT / "ratecard-sbom.json"), "--out", str(tmp_path), "--no-audit"])
    assert res.exit_code == 1, res.output
    assert "cyclonedx-java" in res.output
    # exactly three files: the fixed SBOM, the tech notes and the suggestions
    assert {p.name for p in tmp_path.iterdir()} == {"ratecard-sbom.corrected.cdx.json", "ratecard-sbom.tech-notes.txt",
                                                     "ratecard-sbom.suggestions.txt"}
    out = json.loads((tmp_path / "ratecard-sbom.corrected.cdx.json").read_text(encoding="utf-8"))
    assert tool_name(out) == "cyclonedx-java" and out["specVersion"] == "1.5"
    assert list(out)[:4] == ["bomFormat", "specVersion", "serialNumber", "version"]
    assert validate(out, "cyclonedx", "1.5") == []
    assert all(set(c) <= {"bom-ref", "type", "name", "version", "purl", "licenses"} for c in out["components"])
    notes = (tmp_path / "ratecard-sbom.tech-notes.txt").read_text(encoding="utf-8")
    assert "1. SUMMARY" in notes and "Tool cyclonedx-java" in notes and "CXN-040 -" in notes
    advice = (tmp_path / "ratecard-sbom.suggestions.txt").read_text(encoding="utf-8")
    # one short entry per problem: what is missing, how many, which components, how to fix it
    assert "1. No licence" + "\n   How many      : 13 component(s)" + "\n   Which         : antlr-runtime@3.4" in advice
    assert "How to fix    :" in advice and "|" not in advice and "`" not in advice
    # NTIA gaps of the original: 248 of 320 components without supplier, no SBOM author
    assert ("No supplier (NTIA)" + "\n   How many      : 248 of 320 components"
            + "\n   Which         : bean-matchers@0.13") in advice
    assert ". No SBOM author (NTIA)" in advice
    # qualifiers dropped for Checkmarx are not an issue of the original
    assert "?type=jar" not in advice
    assert "ntia       : original FAIL - supplier 72/320, author missing" in res.output
    assert re.search(r"Supplier name\s+72 / 320  \(gap\)\s+0 / 320  \(gap\)", notes)
    again = runner.invoke(app, ["fix", str(tmp_path / "ratecard-sbom.corrected.cdx.json"), "--out",
                                str(tmp_path / "again"), "--no-audit", "--name", "out.json"])
    assert again.exit_code == 0, again.output
    assert json.loads((tmp_path / "again" / "out.json").read_text(encoding="utf-8")) == out
    # nothing left to repair; only the NTIA gaps of the canonical form (it keeps no supplier or author)
    again_advice = next((tmp_path / "again").glob("*.suggestions.txt")).read_text(encoding="utf-8")
    assert "No licence" not in again_advice and "No supplier (NTIA)" in again_advice


def test_cli_empty_components_kept(tmp_path: Path) -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"component": {"type": "application", "name": "app", "version": "1.0"}}}
    src = tmp_path / "empty.json"
    src.write_text(json.dumps(doc), encoding="utf-8")
    res = runner.invoke(app, ["fix", str(src), "--out", str(tmp_path / "o"), "--no-audit"])
    assert res.exit_code == 7, res.output  # nothing Checkmarx can scan, but the file is written
    out = json.loads((tmp_path / "o" / "empty.corrected.cdx.json").read_text(encoding="utf-8"))
    assert out["components"] == [] and out["metadata"]["component"]["name"] == "app"
    assert validate(out, "cyclonedx", "1.6") == []


def test_cli_keep_converted(tmp_path: Path) -> None:
    res = runner.invoke(app, ["fix", str(CORPUS / "minimal" / "min-cdx-1.6.json"), "--out", str(tmp_path),
                              "--no-audit", "--keep-converted"])
    assert res.exit_code in (0, 1), res.output
    assert (tmp_path / "min-cdx-1.6.converted.cdx.json").exists()


def test_cli_spdx_and_options(tmp_path: Path) -> None:
    src = CORPUS / "sbom-tool" / "service.spdx.json"
    res = runner.invoke(app, ["fix", str(src), "--out", str(tmp_path), "--no-audit", "--ecosystem", "dotnet",
                              "--name", "x.json"])
    assert res.exit_code == 1, res.output
    out = json.loads((tmp_path / "x.json").read_text(encoding="utf-8"))
    assert out["bomFormat"] == "CycloneDX" and out["specVersion"] == "1.6" and tool_name(out) == "cyclonedx-dotnet"


def test_cli_errors(tmp_path: Path) -> None:
    res = runner.invoke(app, ["fix", str(CORPUS / "unsupported" / "bom.xml"), "--out", str(tmp_path)])
    assert res.exit_code == 2
    res = runner.invoke(app, ["fix", str(ROOT / "ratecard-sbom.json"), "--out", str(tmp_path), "--ecosystem", "cobol"])
    assert res.exit_code == 2 and "--ecosystem" in res.output


# ---------------------------------------------------------------- no web URL in any purl


URL_COMPONENTS = [
    {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "https://www.npmjs.com/package/lodash/v/4.17.21"},
    {"type": "library", "name": "core", "version": "15.0.0", "purl": "https://www.npmjs.com/package/@angular/core"},
    {"type": "library", "name": "errors", "version": "v0.9.1", "purl": "https://github.com/pkg/errors"},
    {"type": "library", "name": "mylib", "version": "1.0", "purl": "https://downloads.example.com/mylib-1.0.tar.gz"},
    {"type": "library", "name": "foo", "version": "1.0", "purl": "pkg:generic/foo@1.0?download_url=https://example.com/f.tgz"},
    {"type": "library", "name": "https://example.com/bar", "version": "2.0"},
    {"type": "library", "name": "commons-lang3", "version": "3.12.0",
     "purl": "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"},
    {"type": "library", "name": "requests", "version": "2.31.0", "bom-ref": "https://pypi.org/project/requests/2.31.0/"},
    {"type": "library", "name": "slf4j-api", "version": "2.0.9", "purl": "https://mvnrepository.com/artifact/org.slf4j/slf4j-api/2.0.9"},
]


def test_cli_no_url_in_any_purl_or_bom_ref(tmp_path: Path) -> None:
    doc = bom("1.6", components=URL_COMPONENTS,
              dependencies=[{"ref": "https://pypi.org/project/requests/2.31.0/", "dependsOn": []}])
    doc["metadata"]["component"] = {"type": "application", "name": "app", "bom-ref": "https://example.com/app",
                                    "purl": "https://www.npmjs.com/package/app/v/1.0.0"}
    src = tmp_path / "urls.cdx.json"
    src.write_text(json.dumps(doc), encoding="utf-8")
    res = runner.invoke(app, ["fix", str(src), "--out", str(tmp_path / "o"), "--no-audit"])
    assert res.exit_code == 1, res.output
    out = json.loads((tmp_path / "o" / "urls.corrected.cdx.json").read_text(encoding="utf-8"))
    purls = {c["name"]: c["purl"] for c in out["components"]}
    assert purls["lodash"] == "pkg:npm/lodash@4.17.21"
    assert purls["core"] == "pkg:npm/%40angular/core@15.0.0"
    assert purls["commons-lang3"] == "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
    assert purls["requests"] == "pkg:pypi/requests@2.31.0"
    assert purls["slf4j-api"] == "pkg:maven/org.slf4j/slf4j-api@2.0.9"
    assert purls["https://example.com/bar"] == "pkg:generic/bar@2.0"
    assert purls["foo"] == "pkg:generic/foo@1.0"
    for c in out["components"]:
        assert "http" not in c["purl"].lower() and "http" not in c["bom-ref"].lower(), c
    root = out["metadata"]["component"]
    assert root["purl"] == "pkg:npm/app@1.0.0" and root["bom-ref"] == "pkg:npm/app@1.0.0"
    for d in out["dependencies"]:
        assert "http" not in d["ref"] and not any("http" in t for t in d["dependsOn"])
    assert validate(out, "cyclonedx", "1.6") == []


def test_spdx_url_locator_becomes_purl() -> None:
    doc = spdx([pkg("SPDXRef-a", "lodash", "https://www.npmjs.com/package/lodash/v/4.17.21")], [])
    out = to_cdxgen(json.dumps(doc).encode()).doc
    assert out["components"][0]["purl"] == "pkg:npm/lodash@4.17.21"


def test_cli_reports_schema_validation_of_converted_file(tmp_path: Path) -> None:
    res = runner.invoke(app, ["fix", str(CORPUS / "maven" / "orders-service.bom.json"), "--out", str(tmp_path),
                              "--no-audit"])
    assert res.exit_code == 1, res.output
    assert "original   : 5 schema error(s)" in res.output
    assert "schema: 5 error(s) -> repaired" in res.output
    assert "schema-valid CycloneDX 1.5" in res.output
    notes = (tmp_path / "orders-service.tech-notes.txt").read_text(encoding="utf-8")
    assert "CycloneDX 1.5 schema: 5 error(s)" in " ".join(notes.split())
    advice = (tmp_path / "orders-service.suggestions.txt").read_text(encoding="utf-8")
    assert advice.count(". Schema error at ") >= 3  # 5 errors, grouped by cause


def test_tool_bookkeeping_and_layout_are_not_issues(tmp_path: Path) -> None:
    res = runner.invoke(app, ["fix", str(CORPUS / "vendor" / "acme-portal.cdx.json"), "--out", str(tmp_path),
                              "--no-audit"])
    assert res.exit_code == 1, res.output
    advice = (tmp_path / "acme-portal.suggestions.txt").read_text(encoding="utf-8")
    # the schema errors (serialNumber, unknown field, null) and the data problems of the original
    assert "Schema error at /serialNumber" in advice
    assert ". Dependency on a component that is not in the SBOM" in advice
    assert ". No root component (metadata.component)" in advice
    # repairs of those schema errors are not listed twice; layout trims and sbom-fixer's bookkeeping are not issues
    for text in ("serialNumber is not urn:uuid", "provenance", "metadata.tools", "not read by Checkmarx", "REP-", "CXN-"):
        assert text not in advice, text


@pytest.mark.parametrize("version,blank", [("1.6", {"type": "application", "name": ""}),
                                           ("1.3", {"type": "application", "name": "", "version": ""})])
def test_root_component_always_written(version: str, blank: dict, tmp_path: Path) -> None:
    doc = {"bomFormat": "CycloneDX", "specVersion": version, "version": 1,
           "components": [{"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1"}]}
    src = tmp_path / "noroot.json"
    src.write_text(json.dumps(doc), encoding="utf-8")
    res = runner.invoke(app, ["fix", str(src), "--out", str(tmp_path / "o"), "--no-audit"])
    assert res.exit_code == 1, res.output
    out = json.loads((tmp_path / "o" / "noroot.corrected.cdx.json").read_text(encoding="utf-8"))
    assert out["metadata"]["component"] == blank
    assert validate(out, "cyclonedx", version) == []
    # a root without a name gets a blank name, the rest is kept
    doc["metadata"] = {"component": {"type": "application", "version": "2.0"}}
    src.write_text(json.dumps(doc), encoding="utf-8")
    runner.invoke(app, ["fix", str(src), "--out", str(tmp_path / "p"), "--no-audit"])
    out = json.loads((tmp_path / "p" / "noroot.corrected.cdx.json").read_text(encoding="utf-8"))
    assert out["metadata"]["component"] == {"type": "application", "version": "2.0", "name": ""}


ERLANG_COMPONENTS = [
    {"type": "library", "bom-ref": "a", "name": "phoenix", "version": "1.7.0", "purl": "pkg:hex/phoenix@1.7.0"},
    {"type": "library", "bom-ref": "b", "name": "cowboy", "version": "2.10.0"},
    {"type": "library", "bom-ref": "c", "name": "plug", "version": "1.15.0",
     "externalReferences": [{"type": "distribution", "url": "https://repo.hex.pm/tarballs/plug-1.15.0.tar"}]},
]


def test_erlang_components_without_purl_become_hex(tmp_path: Path) -> None:
    doc = bom("1.5", components=ERLANG_COMPONENTS)
    doc["metadata"]["tools"] = [{"name": "rebar3_sbom", "version": "0.7.0"}]
    src = tmp_path / "erl.json"
    src.write_text(json.dumps(doc), encoding="utf-8")
    res = runner.invoke(app, ["fix", str(src), "--out", str(tmp_path / "o"), "--no-audit"])
    out = json.loads((tmp_path / "o" / "erl.corrected.cdx.json").read_text(encoding="utf-8"))
    assert {c["name"]: c["purl"] for c in out["components"]} == {
        "phoenix": "pkg:hex/phoenix@1.7.0", "cowboy": "pkg:hex/cowboy@2.10.0", "plug": "pkg:hex/plug@1.15.0"}
    assert tool_name(out) == "cyclonedx-erlang", res.output


def test_generator_alone_names_the_ecosystem(tmp_path: Path) -> None:
    doc = bom("1.5", components=[{"type": "library", "bom-ref": "b", "name": "cowboy", "version": "2.10.0"}])
    doc["metadata"]["tools"] = [{"name": "mix_sbom", "version": "1"}]
    src = tmp_path / "mix.json"
    src.write_text(json.dumps(doc), encoding="utf-8")
    runner.invoke(app, ["fix", str(src), "--out", str(tmp_path / "o"), "--no-audit"])
    out = json.loads((tmp_path / "o" / "mix.corrected.cdx.json").read_text(encoding="utf-8"))
    assert out["components"][0]["purl"] == "pkg:hex/cowboy@2.10.0"


def test_mixed_ecosystems_do_not_guess(tmp_path: Path) -> None:
    comps = [{"type": "library", "bom-ref": "a", "name": "phoenix", "version": "1.7.0", "purl": "pkg:hex/phoenix@1.7.0"},
             {"type": "library", "bom-ref": "n", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
             {"type": "library", "bom-ref": "b", "name": "cowboy", "version": "2.10.0"}]
    src = tmp_path / "mixed.json"
    src.write_text(json.dumps(bom("1.5", components=comps)), encoding="utf-8")
    runner.invoke(app, ["fix", str(src), "--out", str(tmp_path / "o"), "--no-audit"])
    out = json.loads((tmp_path / "o" / "mixed.corrected.cdx.json").read_text(encoding="utf-8"))
    assert {c["name"]: c["purl"] for c in out["components"]}["cowboy"] == "pkg:generic/cowboy@2.10.0"
