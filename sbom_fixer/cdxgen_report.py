"""The two plain-text files of the fix command: tech notes (what changed, with a summary) and suggestions (issues of the
original SBOM, to fix at the generator). Plain .txt, short lines, no Markdown: they are meant to be read as they are."""

from __future__ import annotations

import json
import re
import textwrap
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .audit.ntia import COMPONENT_FIELDS, DOC_FIELDS, NtiaReport, ntia_check
from .changes import Change
from .rules import rule_by_id
from .rules.canonical import is_reduction
from .validate import Issue, group

if TYPE_CHECKING:
    from .cdxgen import Conversion
    from .pipeline import RunResult

_EXIT_TEXT = {
    0: "nothing to change",
    1: "fixed",
    2: "could not be fixed",
    3: "fixed, with data loss the profile does not allow",
    4: "fixed, quality gate failed",
    7: "fixed, but no component has a purl type Checkmarx scans",
}

# schema keyword -> what the generator should do
_SCHEMA_HINTS = {
    "required": "Write the missing required field.",
    "type": "Write the value with the JSON type the schema expects (string, number, array, object).",
    "enum": "Use one of the values the schema allows.",
    "format": "Write the value in the expected format (for example date-time, iri-reference, email).",
    "pattern": "Write the value in the expected pattern (for example urn:uuid:... for serialNumber).",
    "additionalProperties": "Remove fields that are not part of this CycloneDX / SPDX version.",
    "uniqueItems": "Remove duplicate entries (for example the same bom-ref twice).",
    "oneOf": "The object mixes two alternatives (for example license id and expression); write only one.",
    "anyOf": "The object matches none of the allowed shapes; check its fields against the schema.",
    "const": "Write the fixed value the schema requires.",
    "minItems": "Leave the array out instead of writing it empty.",
}

# pipeline steps that are not registered rules: (title, fix at the source)
_PIPELINE_STEPS = {
    "PRUNE-001": ("Fields the schema of this version does not allow",
                  "Write only fields of this CycloneDX / SPDX version; custom data belongs in properties."),
    "COERCE-001": ("Value converted to the JSON type the schema expects",
                   "Write numbers, booleans and arrays with their JSON type, not as strings."),
    "COERCE-002": ("Value the schema rejects removed", "Write only values the schema allows."),
    "ENC-001": ("File re-encoded to UTF-8", "Write the SBOM as UTF-8."),
    "ENC-002": ("Byte order mark removed", "Write UTF-8 without a byte order mark."),
    "ENC-003": ("Encoding repaired", "Write the SBOM as UTF-8."),
    "CDX-VER": ("specVersion repaired", "Write specVersion as the CycloneDX version the file follows (for example 1.6)."),
    "SPDX-VER": ("spdxVersion repaired", "Write spdxVersion as SPDX-2.2 or SPDX-2.3."),
}
# registered rules without a source_fix of their own
_SOURCE_FIX = {
    "REP-005": "Leave a field out instead of writing null or an empty value.",
    "REP-007": "Write serialNumber as urn:uuid:<uuid>.",
    "SAN-001": "Write only fields of this CycloneDX / SPDX version.",
    "SAN-002": "Leave a field out instead of writing an empty object or array.",
    "SAN-020": "Give every component a unique bom-ref (cdxgen uses the purl).",
    "SAN-022": "List each package once; merge duplicates in the build before generating the SBOM.",
}
# changes that are sbom-fixer's own bookkeeping, not issues of the input
_NOT_ISSUES = {"SAN-090"}


def is_issue(change: Change) -> bool:
    return change.rule_id not in _NOT_ISSUES and not is_reduction(change)


def source_fix(rule_id: str) -> str | None:
    r = rule_by_id(rule_id)
    if r is not None and r.source_fix:
        return r.source_fix
    return _SOURCE_FIX.get(rule_id) or _PIPELINE_STEPS.get(rule_id, ("", None))[1]


@dataclass
class OriginalCheck:
    """The original file validated against its own schema, before any conversion."""

    name: str = ""
    spec: str = ""
    version: str = ""
    generator: str | None = None
    issues: list[Issue] = field(default_factory=list)
    error: str | None = None
    components: int = 0
    ntia: NtiaReport | None = None  # NTIA minimum elements of the original
    labels: dict[str, str] = field(default_factory=dict)  # bom-ref / SPDXID -> name@version


_WIDTH = 78


def _plain(text: str) -> str:
    """A path or value on one line."""
    return text.replace("\r", " ").replace("\n", " ")


def _short(value: Any, limit: int = 90) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    text = _plain(text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _wrap(text: str, first: str = "", rest: str | None = None) -> str:
    """Wrap to the page width; long words (paths, purls) are never broken."""
    return textwrap.fill(text, _WIDTH, initial_indent=first, subsequent_indent=first if rest is None else rest,
                         break_long_words=False, break_on_hyphens=False)


def _field(label: str, value: str, indent: int = 3, width: int = 14) -> str:
    """'   Label         : value', wrapped under the value."""
    return _wrap(value, " " * indent + f"{label:<{width}}: ", " " * (indent + width + 2))


def _heading(title: str) -> list[str]:
    return [title, "-" * len(title)]


def _by_rule(changes: list[Change]) -> list[tuple[str, list[Change]]]:
    out: dict[str, list[Change]] = {}
    for c in changes:
        out.setdefault(c.rule_id, []).append(c)
    return sorted(out.items(), key=lambda kv: (-len(kv[1]), kv[0]))


def _title(rule_id: str) -> str:
    r = rule_by_id(rule_id)
    if r is not None and r.title:
        return r.title
    return _PIPELINE_STEPS.get(rule_id, (rule_id, None))[0]


def _example(c: Change) -> str:
    if c.action == "removed":
        return f"{_plain(c.path)} removed: {_short(c.before, 60)}"
    if c.before is None:
        return f"{_plain(c.path)} = {_short(c.after, 60)}"
    return f"{_plain(c.path)}: {_short(c.before, 45)} -> {_short(c.after, 45)}"


def _components(doc: Any) -> int:
    comps = doc.get("components") if isinstance(doc, dict) else None
    return len(comps) if isinstance(comps, list) else 0


def tech_notes(result: RunResult, conv: Conversion, original: OriginalCheck, sbom_name: str, tool_line: str) -> str:
    doc = result.fixed_doc if result.ok else None
    issues = [c for c in result.log.changes if is_issue(c)]
    reductions = [c for c in result.log.changes if not is_issue(c)]
    L: list[str] = ["WHAT SBOM-FIXER CHANGED", "=" * 23, f"File: {original.name}", ""]
    L += _heading("1. SUMMARY")
    L.append(_field("Input", f"{conv.source_spec} {conv.source_version}"
                    + (f", made by {original.generator}" if original.generator else "")
                    + f", {original.components:,} component(s)"))
    if doc is not None:
        deps = doc.get("dependencies")
        L.append(_field("Output", f"{sbom_name} - CycloneDX {result.final_version}, schema-valid, "
                        f"{_components(doc):,} component(s), {len(deps) if isinstance(deps, list) else 0:,} dependency entries"))
    else:
        L.append(_field("Output", f"{sbom_name} was NOT written: {result.error or 'schema errors remain'}"))
    L.append(_field("Tool name", tool_line))
    L.append(_field("Changes", f"{len(result.log.changes):,} in total: {len(issues):,} repairs of problems in your file, "
                    f"{len(reductions):,} layout changes for Checkmarx"))
    L.append(_field("Schema errors", f"not validated as it is ({original.error})" if original.error
                    else f"{len(original.issues):,} in your original file (see the suggestions file)"))
    L.append(_field("Result", f"exit code {result.exit_code} - {_EXIT_TEXT.get(result.exit_code, 'see README')}"))
    corrected_ntia = corrected_ntia_of(result)
    if original.ntia is not None:
        L.append(_field("NTIA original", ntia_summary(original.ntia)))
    if corrected_ntia is not None:
        L.append(_field("NTIA corrected", ntia_summary(corrected_ntia)
                        + (f"  (sbomqs score {result.quality.after_score:.1f} of 10)"
                           if result.quality is not None and result.quality.after_score is not None else "")))
    L.append("")
    if original.ntia is not None or corrected_ntia is not None:
        L += _heading("2. NTIA MINIMUM ELEMENTS") + _ntia_table(original.ntia, corrected_ntia)
        L += ["", _wrap("The corrected file keeps only what Checkmarx reads (no supplier, no author), so its NTIA "
                        "result is usually FAIL. Use the original file for NTIA, and close the gaps of the original at "
                        "the source (see the suggestions file)."), ""]

    L += _heading("3. WHAT WAS DONE")
    L.append(_wrap(f"Step 1 - Converted: {conv.source_spec} {conv.source_version} -> CycloneDX {conv.target_version}."))
    L += [_wrap(n, "   - ", "     ") for n in conv.notes]
    L.append(_wrap(f"Step 2 - Checked the converted file against the CycloneDX {conv.target_version} schema: "
                   f"{len(result.original_issues):,} error(s)."))
    for kw, pth, n, msg in group(result.original_issues)[:10]:
        L.append(_wrap(f"{n:,} x {kw} at {_plain(pth)}: {_short(msg, 100)}", "   - ", "     "))
    L.append(_wrap("Step 3 - Repaired it and reduced it to the layout Checkmarx reads, on the same CycloneDX version "
                   "(the version is never changed). The result looks like this:"))
    L += [_wrap(t, "   - ", "     ") for t in (
        "top level: bomFormat, specVersion, serialNumber, version, metadata, components, dependencies "
        "(components is always there, [] when the input has none)",
        "metadata: timestamp, tools, component (the root application)",
        "each component: bom-ref, type, name, version, purl, licenses (NOASSERTION when unknown)",
        "removed: externalReferences, properties, evidence, description, and any purl or bom-ref with http(s)",
        "dependencies only between components in the file, no self-dependencies")] + [""]

    L += _heading("4. CHANGES MADE (one entry per rule)")
    L += [_wrap("FIX    = a problem in your file that was repaired."),
          _wrap("LAYOUT = reshaped for Checkmarx. Data Checkmarx does not read is dropped from this copy only; "
                "your original file keeps it."), ""]
    for kind, items_of_kind in (("FIX", issues), ("LAYOUT", reductions)):
        for rid, items in _by_rule(items_of_kind):
            L.append(_wrap(f"[{kind}] {rid} - {_title(rid)} ({len(items):,}x)"))
            L.append(_wrap(f"Example: {_example(items[0])}", "      ", "               "))
            L.append("")
    if not result.log.changes:
        L += ["No changes were needed.", ""]
    if result.log.findings:
        L += _heading("5. NOTICED BUT NOT CHANGED")
        for f in result.log.findings[:30]:
            L.append(_wrap(f"[{f.rule_id}] {_plain(f.path or '/')}: {f.message}", "- ", "  "))
        if len(result.log.findings) > 30:
            L.append(f"- ... {len(result.log.findings) - 30:,} more")
        L.append("")
    return "\n".join(L) + "\n"


# reason of a change (start of the text) -> (what is missing or wrong, how to fix it at the source)
_SHORT: list[tuple[str, str, str]] = [
    ("No licence", "No licence", "Add the licence (SPDX id, e.g. MIT, Apache-2.0) to the package manifest (pom, csproj, "
                                 "package.json); for own libraries set it in the build."),
    ("no purl; built for the SBOM", "No purl", "Use a generator that writes a purl for every package."),
    ("no ecosystem known", "No purl and no ecosystem (written as pkg:generic, Checkmarx skips it)",
     "Use a generator that writes a purl for every package."),
    ("purl taken from the package-cache path", 'DLL/JAR without a package purl (found in the package cache)',
     'Generate the SBOM from the project (dotnet CycloneDX, CycloneDX Maven/Gradle plugin), not from binaries.'),
    ("version set to the package version from the cache path", 'DLL/JAR without a package purl (found in the package cache)',
     'Generate the SBOM from the project (dotnet CycloneDX, CycloneDX Maven/Gradle plugin), not from binaries.'),
    ("purl built from verified component data", "No purl", 'Use a generator that writes a purl for every package.'),
    ("serialNumber identifies", "No serialNumber", "Let the generator write serialNumber (urn:uuid:...)."),
    ("No tool named", "No tool in metadata.tools",
     "Let the generator record itself in metadata.tools (CycloneDX) or creationInfo.creators (SPDX)."),
    ("does not exist", "Dependency on a component that is not in the SBOM",
     "List dependencies only between components that are in the SBOM."),
    ("is not an SPDX license ID", "Licence name instead of the SPDX id", "Use SPDX licence ids (Apache-2.0, MIT, ...)."),
    ("license was written as a plain string", "Licence written as plain text", "Write licences as {\"license\": {\"id\": \"MIT\"}}."),
    ("No timezone given", "Timestamp without timezone", "Write timestamps with a timezone, e.g. 2026-10-12T10:00:00Z."),
    ("purl taken from the component's registry URL", "No purl (only a registry URL)",
     "Let the generator write the purl, not only the download URL."),
    ("purl taken from the bom-ref", "No purl (only in bom-ref)", "Write the purl in the purl field too."),
    ("purl built from the ecosystem named by the generator", "No purl", "Use a generator that writes a purl for every package."),
    ("No metadata.component", "No root component (metadata.component)",
     "Let the generator write the application itself as metadata.component (name, version)."),
    ("metadata.component has no", "Root component without name/type/version",
     "Set name and version of the application in the generator / build."),
    ("Version is required at this spec version and is unknown", "Component without version",
     "Write the resolved version of every package."),
    ("No serialNumber", "No serialNumber", "Let the generator write serialNumber (urn:uuid:...)."),
    ("serialNumber must match", "serialNumber is not urn:uuid:...", "Write serialNumber as urn:uuid:<uuid>."),
    ("No timestamp", "No timestamp", "Let the generator write metadata.timestamp."),
    ("BOM version", "No BOM version", "Write version: 1."),
    ("ref is not a component", "Dependency for a component that is not in the SBOM",
     "List dependencies only for components that are in the SBOM."),
    ("dependsOn points at a component that does not exist", "Dependency on a component that is not in the SBOM",
     "List dependencies only between components that are in the SBOM."),
    ("self-dependency", "Component depends on itself", "Remove self-dependencies in the generator output."),
    ("bom-ref must be unique", "Same bom-ref used twice", "Give every component a unique bom-ref."),
    ("Duplicate component", "Same package listed twice", "List each package once."),
    ("Value was null or empty", "null or empty values", "Leave a field out instead of writing null or \"\"."),
    ("Field is not allowed by the schema", "Fields that are not in the schema", "Remove custom fields (or put them in properties)."),
]


_NTIA_ROWS = {
    "Supplier name": ("No supplier (NTIA)",
                      "Let the generator write the supplier of every package (from the package metadata: the organization element "
                      "of the pom, authors in the nuspec or package.json); for own libraries set your company."),
    "Component name": ("No component name (NTIA)", "Write the name of every package."),
    "Component version": ("No component version (NTIA)", "Write the resolved version of every package."),
    "Unique identifier": ("No unique identifier: purl, CPE or SWID (NTIA)",
                          "Use a generator that writes a purl for every package."),
    "Dependency relationships": ("No dependency relationships (NTIA)",
                                 "Let the generator write the dependency graph (CycloneDX dependencies, SPDX DEPENDS_ON)."),
    "Author of SBOM data": ("No SBOM author (NTIA)", "Set metadata.authors (CycloneDX) or a Person/Organization creator "
                                                     "(SPDX) to the team that produced the SBOM."),
    "Timestamp": ("No timestamp (NTIA)", "Let the generator write metadata.timestamp (SPDX: creationInfo.created)."),
}


def _ntia_label(label: str) -> str:
    """name@version for a purl label (pkg:maven/g/a@1?type=jar -> a@1); other labels as they are."""
    from .purlmap import try_purl

    p = try_purl(label) if label.startswith("pkg:") else None
    return f"{p.name}@{p.version}" if p is not None and p.version else (p.name if p is not None else label)


def ntia_summary(report: NtiaReport) -> str:
    """One line: PASS, or FAIL with what is missing (supplier 72/320, author missing)."""
    if report.passed:
        return "PASS"
    gaps = [f"{name.split()[0].lower()} {cov.covered}/{cov.total}" for name, cov in report.components.items()
            if not cov.complete]
    gaps += [f"{name.split()[0].lower()} missing" if name != "Author of SBOM data" else "author missing"
             for name, ok in report.document.items() if not ok]
    return "FAIL - " + ", ".join(gaps)


def _ntia_table(original: NtiaReport | None, corrected: NtiaReport | None) -> list[str]:
    def cell(report: NtiaReport | None, name: str) -> str:
        if report is None:
            return "-"
        if name in report.components:
            cov = report.components[name]
            return f"{cov.covered:,} / {cov.total:,}" + ("" if cov.complete else "  (gap)")
        return "yes" if report.document.get(name) else "NO  (gap)"

    names = COMPONENT_FIELDS + DOC_FIELDS
    rows = [(name, cell(original, name), cell(corrected, name)) for name in names]
    verdict = [("PASS" if r.passed else "FAIL") if r is not None else "-" for r in (original, corrected)]
    rows.append(("RESULT", verdict[0], verdict[1]))
    w0 = max(len(r[0]) for r in [*rows, ("NTIA element", "", "")])
    w1 = max(len(r[1]) for r in [*rows, ("", "Original", "")])
    out = [f"   {'NTIA element':<{w0}}   {'Original':<{w1}}   Corrected", f"   {'-' * w0}   {'-' * w1}   {'-' * 12}"]
    out += [f"   {a:<{w0}}   {b:<{w1}}   {c}" for a, b, c in rows]
    return out


def _short_issue(change: Change) -> tuple[str, str]:
    for start, issue, fix in _SHORT:
        if change.reason.startswith(start) or start in change.reason:
            return issue, fix
    return change.reason.rstrip("."), source_fix(change.rule_id) or "-"


def _which(change: Change, doc: dict[str, Any] | None) -> str | None:
    """name@version of the component a change belongs to, from the corrected document."""
    if change.path.startswith("/metadata/component"):
        return "root component"
    m = re.match(r"^/components/(\d+)", change.path)
    comps = doc.get("components") if isinstance(doc, dict) else None
    if not m or not isinstance(comps, list) or int(m.group(1)) >= len(comps):
        return None
    c = comps[int(m.group(1))]
    if not isinstance(c, dict) or not c.get("name"):
        return None
    return f"{c['name']}@{c['version']}" if c.get("version") else str(c["name"])


# rules that only repair schema errors: their problem is already a "Schema error" row
_SCHEMA_REPAIRS = ("REP-", "PRUNE-", "COERCE-", "CDX-VER", "SPDX-VER")


def suggestions(result: RunResult, original: OriginalCheck) -> str:
    """Short list: what is missing or wrong in the original, how many, which components, how to fix it."""
    doc = result.fixed_doc if result.ok else None
    rows: dict[tuple[str, str], list[str | None]] = {}
    for c in result.log.changes:
        if is_issue(c) and not (original.issues and c.rule_id.startswith(_SCHEMA_REPAIRS)):
            rows.setdefault(_short_issue(c), []).append(_which(c, doc))
    # (what is wrong, how many, which components, how to fix it)
    found: list[tuple[str, str, str, str]] = []
    for kw, pth, cnt, msg in group(original.issues):
        found.append((f"Schema error at {_plain(pth)}: {_short(msg, 70)}", f"{cnt:,} time(s)", "",
                      _SCHEMA_HINTS.get(kw, "Check the field against the schema.")))
    for (issue, fix), names in sorted(rows.items(), key=lambda kv: -len(kv[1])):
        known = sorted({x for x in names if x})
        count = len(known) if known and None not in names else len(names)
        shown = ", ".join(_short(x, 40) for x in known[:5]) + (f" ... and {len(known) - 5} more" if len(known) > 5 else "")
        found.append((_short(issue, 90), f"{count:,} component(s)", shown, fix))
    if original.ntia is not None:
        for name in COMPONENT_FIELDS:
            cov = original.ntia.components.get(name)
            if cov is None or cov.complete:
                continue
            issue, fix = _NTIA_ROWS[name]
            shown = ", ".join(_short(original.labels.get(x) or _ntia_label(x), 40) for x in cov.missing_examples[:5])
            more = cov.missing - min(len(cov.missing_examples), 5)
            found.append((issue, f"{cov.missing:,} of {cov.total:,} components", shown + (f" ... and {more} more" if more > 0 else ""), fix))
        for name in DOC_FIELDS:
            if not original.ntia.document.get(name, True):
                issue, fix = _NTIA_ROWS[name]
                found.append((issue, "", "", fix))
    fixes = {fix for _, _, _, fix in found} | {fix for _, fix in rows}
    found += [("Pipeline", "", "", hint) for hint in _generator_hints(result, original) if hint not in fixes]

    L: list[str] = ["WHAT TO FIX IN YOUR SBOM", "=" * 24, f"File: {original.name}", ""]
    if original.error:
        L += [_wrap(f"Not checked against a schema: {original.error}"), ""]
    if not found and not original.error:
        return "\n".join(L + ["No issues found. Nothing to fix.", ""])
    L += [_wrap(f"{len(found)} problem(s) found in your original file. Fix them in the tool that creates the SBOM "
                f"(your generator or build), then run sbom-fixer again."), ""]
    for n, (issue, count, shown, fix) in enumerate(found, 1):
        L.append(_wrap(f"{n}. {issue}", "", "   "))
        if count:
            L.append(_field("How many", count))
        if shown:
            L.append(_field("Which", shown))
        L += [_field("How to fix", fix), ""]
    return "\n".join(L) + "\n"


def _generator_hints(result: RunResult, original: OriginalCheck) -> list[str]:
    out: list[str] = []
    if any(c.rule_id.startswith("ENC-") for c in result.log.changes):
        out.append("Write the SBOM with the tool's own --output option, not with shell redirection "
                   "(PowerShell 5.1 '>' writes UTF-16).")
    if original.spec == "spdx":
        out.append("Checkmarx reads CycloneDX best: if the generator can write CycloneDX JSON, use that instead of SPDX.")
    if not original.generator:
        out.append("Let the generator record itself in metadata.tools (CycloneDX) or creationInfo.creators (SPDX).")
    return out


def _labels(doc: dict[str, Any], spec: str) -> dict[str, str]:
    """The NTIA check names components by bom-ref (SPDX: SPDXID); the suggestions show name@version."""
    from .jsonutil import iter_components

    out: dict[str, str] = {}
    if spec == "spdx":
        items = [(p.get("SPDXID"), p.get("name"), p.get("versionInfo")) for p in doc.get("packages") or []
                 if isinstance(p, dict)]
    else:
        items = [(c.get("bom-ref"), c.get("name"), c.get("version")) for _, c in iter_components(doc)]
    for key, name, version in items:
        if isinstance(key, str) and isinstance(name, str) and name:
            out[key] = f"{name}@{version}" if isinstance(version, str) and version else name
    return out


def corrected_ntia_of(result: RunResult) -> NtiaReport | None:
    if result.quality is not None:
        return result.quality.after_ntia
    return ntia_check(result.fixed_doc, "cyclonedx") if result.ok and isinstance(result.fixed_doc, dict) else None


def check_original(raw: bytes, name: str) -> OriginalCheck:
    """Validate the input as it is, against its own schema (the issues the suggestions file lists)."""
    from .detect import detect
    from .errors import SbomFixerError
    from .schemas import VERSION_ORDER
    from .validate import validate

    out = OriginalCheck(name=name)
    try:
        det, doc = detect(raw)
    except SbomFixerError as exc:
        out.error = str(exc)
        return out
    out.spec, out.version, out.generator = det.spec, det.version, det.generator
    items = doc.get("packages" if det.spec == "spdx" else "components") if isinstance(doc, dict) else None
    out.components = len(items) if isinstance(items, list) else 0
    if isinstance(doc, dict):
        out.ntia = ntia_check(doc, det.spec)
        out.labels = _labels(doc, det.spec)
    if det.version in VERSION_ORDER[det.spec]:
        out.issues = validate(doc, det.spec, det.version)
    else:
        out.error = f"no schema for {det.spec} {det.version}"
    return out
