"""The two Markdown files of the corrected command: tech notes (what changed, with a summary) and suggestions (issues of the
original SBOM, to fix at the generator)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

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


def _code(text: str) -> str:
    """A path as inline code that cannot break a Markdown table (a pipe splits a cell even inside backticks)."""
    return "`" + text.replace("`", "'").replace("|", "\\|").replace("\r", " ").replace("\n", " ") + "`"


def _short(value: Any, limit: int = 90) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    text = text.replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("`", "'")
    return text if len(text) <= limit else text[: limit - 3] + "..."


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
        return f"{_code(c.path)} removed: {_short(c.before, 60)}"
    if c.before is None:
        return f"{_code(c.path)} = {_short(c.after, 60)}"
    return f"{_code(c.path)}: {_short(c.before, 45)} -> {_short(c.after, 45)}"


def _components(doc: Any) -> int:
    comps = doc.get("components") if isinstance(doc, dict) else None
    return len(comps) if isinstance(comps, list) else 0


def tech_notes(result: RunResult, conv: Conversion, original: OriginalCheck, sbom_name: str, tool_line: str) -> str:
    doc = result.fixed_doc if result.ok else None
    issues = [c for c in result.log.changes if is_issue(c)]
    reductions = [c for c in result.log.changes if not is_issue(c)]
    L: list[str] = [f"# Tech notes: {original.name}", ""]
    L += ["## Summary", ""]
    L.append(f"- **Input:** {conv.source_spec} {conv.source_version}"
             + (f", generator {original.generator}" if original.generator else "")
             + f", {original.components:,} component(s)")
    if doc is not None:
        deps = doc.get("dependencies")
        L.append(f"- **Output:** `{sbom_name}`, CycloneDX {result.final_version} "
                 f"(schema-valid), {_components(doc):,} component(s), "
                 f"{len(deps) if isinstance(deps, list) else 0:,} dependency entries")
    else:
        L.append(f"- **Output:** `{sbom_name}` was NOT written: {result.error or 'schema errors remain'}")
    L.append(f"- **Tool in metadata:** {tool_line}")
    L.append(f"- **Changes:** {len(result.log.changes):,} in total; {len(issues):,} fixed problems of the input, "
             f"{len(reductions):,} layout changes for Checkmarx")
    L.append(f"- **Original schema errors:** not validated as it is ({original.error})" if original.error
             else f"- **Original schema errors:** {len(original.issues):,} (details in the suggestions file)")
    L.append(f"- **Exit code:** {result.exit_code} ({_EXIT_TEXT.get(result.exit_code, 'see README')})")
    if result.quality is not None:
        q = result.quality
        L.append(f"- **NTIA minimum elements after the fix:** {'PASS' if q.after_ntia.passed else 'FAIL'}"
                 + (f", sbomqs {q.after_score:.1f}" if q.after_score is not None else ""))
    L.append("")

    L += ["## What was done", "",
          f"1. **Converted** ({conv.source_spec} {conv.source_version} -> CycloneDX "
          f"{conv.target_version})."]
    L += [f"   - {n}" for n in conv.notes]
    L.append(f"2. **Validated** the converted file against the CycloneDX {conv.target_version} schema: "
             f"{len(result.original_issues):,} error(s).")
    for kw, pth, n, msg in group(result.original_issues)[:10]:
        L.append(f"   - {n:,} x `{kw}` at {_code(pth)}: {_short(msg, 100)}")
    L.append("3. **Repaired and reduced to the Checkmarx layout** on the same CycloneDX version "
             "(specVersion is never changed). Output layout:")
    L += ["   - top level: `bomFormat`, `specVersion`, `serialNumber`, `version`, `metadata`, `components`, "
          "`dependencies` (`components` is always there, `[]` when the input has none)",
          "   - `metadata`: `timestamp`, `tools`, `component` (the root application)",
          "   - each component: `bom-ref`, `type`, `name`, `version`, `purl`, `licenses` (NOASSERTION when unknown)",
          "   - no `externalReferences`, `properties`, `evidence`, `description`; no purl or bom-ref with http(s)",
          "   - dependencies only between components in the file, no self-dependencies", ""]

    L += ["## Changes by rule", "", "| Rule | What | Kind | Count | Example |", "|---|---|---|---:|---|"]
    for kind, items_of_kind in (("fix", issues), ("layout", reductions)):
        for rid, items in _by_rule(items_of_kind):
            L.append(f"| {rid} | {_title(rid)} | {kind} | {len(items):,} | {_example(items[0])} |")
    if not result.log.changes:
        L.append("| - | no changes | - | 0 | - |")
    L.append("")
    L.append("*fix* = a problem of the input that was repaired; *layout* = reshaped for the Checkmarx layout; data Checkmarx does not read is dropped from "
             "this copy only (the original file keeps it).")
    L.append("")
    if result.log.findings:
        L += ["## Not changed (findings)", ""]
        for f in result.log.findings[:30]:
            L.append(f"- [{f.rule_id}] {_code(f.path or '/')}: {f.message}")
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
    L: list[str] = [f"# Suggestions: {original.name}", ""]
    if original.error:
        L += [f"Not checked against a schema: {original.error}", ""]
    if not rows and not original.issues and not original.error:
        return "\n".join(L + ["No issues found. Nothing to fix.", ""])
    L += ["| # | Missing / wrong | Count | Components | Fix |", "|---:|---|---:|---|---|"]
    n = 0
    for kw, pth, cnt, msg in group(original.issues):
        n += 1
        hint = _SCHEMA_HINTS.get(kw, "Check the field against the schema.")
        L.append(f"| {n} | Schema error at {_code(pth)}: {_short(msg, 70)} | {cnt:,} | - | {hint} |")
    for (issue, fix), names in sorted(rows.items(), key=lambda kv: -len(kv[1])):
        n += 1
        known = sorted({x for x in names if x})
        count = len(known) if known and None not in names else len(names)
        shown = ", ".join(_short(x, 40) for x in known[:5]) + (f" +{len(known) - 5} more" if len(known) > 5 else "")
        L.append(f"| {n} | {_short(issue, 90)} | {count:,} | {shown or '-'} | {_short(fix, 160)} |")
    fixes = {fix for _, fix in rows}
    for hint in (h for h in _generator_hints(result, original) if h not in fixes):
        n += 1
        L.append(f"| {n} | Pipeline | - | - | {hint} |")
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
    if result.quality is not None and not result.quality.after_ntia.document.get("Author of SBOM data"):
        out.append("Set metadata.authors (the team that produced the SBOM); NTIA requires an author.")
    return out


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
    if det.version in VERSION_ORDER[det.spec]:
        out.issues = validate(doc, det.spec, det.version)
    else:
        out.error = f"no schema for {det.spec} {det.version}"
    return out
