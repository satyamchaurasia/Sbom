"""Command line interface: fix | fill-all | verify."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from . import __version__
from .ecosystem import ECOSYSTEMS
from .errors import SbomFixerError
from .pipeline import EXIT_CANNOT_FIX, EXIT_OK, EXIT_VERIFY, run_fix
from .profile import load_profile
from .validate import group

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Fix any SBOM for Checkmarx (fix), fill every schema field (fill-all), upload and check "
                       "it in Checkmarx (verify).")


@app.command("fix")
def fix(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="SBOM file (CycloneDX or SPDX 2.x JSON, any generator)")],
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Output folder (default: next to the input)")] = None,
    name: Annotated[str | None, typer.Option("--name", help="File name of the corrected SBOM (default: <name>.corrected.cdx.json)")] = None,
    profile: Annotated[str, typer.Option("--profile", "-p", help="Profile name or YAML path")] = "checkmarx",
    ecosystem: Annotated[str | None, typer.Option(help="Force the ecosystem instead of detecting it: " + ", ".join(ECOSYSTEMS))] = None,
    spec_version: Annotated[str | None, typer.Option("--spec-version", help="CycloneDX version of the converted file "
                                                     "(default: CycloneDX input keeps its version, SPDX becomes 1.6)")] = None,
    no_audit: Annotated[bool, typer.Option("--no-audit", help="Skip the NTIA / sbomqs quality audit")] = False,
    keep_converted: Annotated[bool, typer.Option("--keep-converted", help="Also write the step-1 file <name>.converted.cdx.json")] = False,
) -> None:
    """Convert any SBOM to CycloneDX, validate it, then write the corrected Checkmarx form.

    Step 1 (convert): SPDX 2.2/2.3 becomes CycloneDX 1.6; CycloneDX keeps its version; purls written as a
    URL become the registry purl; bom-ref = purl when missing; one dependencies entry per component.
    Step 2 (schema validation): the converted file is validated against its CycloneDX schema; errors are listed.
    Step 3 (fix + canonical form): repair the schema errors on that version (specVersion never changes); top level
    bomFormat, specVersion, serialNumber, version, metadata, components (always, [] when empty), dependencies;
    every component {bom-ref, type, name, version, purl, licenses}; metadata {timestamp, tools, component};
    dependencies only to existing components. metadata.tools names the generator of the detected ecosystem
    (.NET -> cyclonedx-dotnet, Java -> cyclonedx-java, ...; --ecosystem overrides). No purl or bom-ref holds http(s).

    Writes three files: <name>.corrected.cdx.json (--name), <name>.tech-notes.txt (what changed, with a summary) and
    <name>.suggestions.txt (issues of the original SBOM and how to fix them at the generator). Exit codes as for fix.
    """
    import dataclasses
    import tempfile

    from .cdxgen import to_cdxgen
    from .cdxgen_report import check_original, ntia_summary, suggestions, tech_notes
    from .errors import DetectError
    from .pipeline import output_stem
    from .profile import CanonicalPolicy
    from .serialize import write_json, write_text

    try:
        prof = load_profile(profile)
        if "cyclonedx" not in prof.specs:
            raise SbomFixerError(f"Profile '{prof.name}' has no cyclonedx section.")
        canonical = dataclasses.replace(prof.canonical or CanonicalPolicy(), tool_per_ecosystem=True)
        if ecosystem:
            if ecosystem.lower() not in canonical.ecosystem_tools:
                raise SbomFixerError(f"--ecosystem must be one of {', '.join(sorted(canonical.ecosystem_tools))}.")
            canonical = dataclasses.replace(canonical, ecosystem=ecosystem.lower())
        prof = dataclasses.replace(prof, canonical=canonical)
        raw = file.read_bytes()
        conv = to_cdxgen(raw, spec_version)
    except (DetectError, SbomFixerError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_CANNOT_FIX) from None
    out_dir = out or file.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = output_stem(file)
    sbom_name = name or f"{stem}.corrected.cdx.json"
    original = check_original(raw, file.name)
    with tempfile.TemporaryDirectory(prefix="sbom-fixer-") as tmp:
        converted = (out_dir if keep_converted else Path(tmp)) / f"{stem}.converted.cdx.json"
        write_json(conv.doc, converted)
        r = run_fix(converted, prof, out_dir, audit=not no_audit, sbom_name=sbom_name, reports=False)

    tool_line = next((c.reason for c in r.log.changes if c.rule_id == "CXN-011" and c.path == "/metadata/tools"),
                     next((f.message for f in r.log.findings if f.rule_id == "CXN-011"), "tools unchanged"))
    notes_path = out_dir / f"{stem}.tech-notes.txt"
    advice_path = out_dir / f"{stem}.suggestions.txt"
    write_text(tech_notes(r, conv, original, sbom_name, tool_line), notes_path)
    write_text(suggestions(r, original), advice_path)

    final_ok = r.ok and r.outputs.get("sbom") is not None
    typer.echo(f"{file.name}: {conv.source_spec} {conv.source_version} -> converted to CycloneDX {conv.target_version}")
    for note in conv.notes:
        typer.echo(f"  convert    : {note}")
    if keep_converted:
        typer.echo(f"  converted  : {converted}")
    typer.echo(f"  original   : not validated as it is ({original.error})" if original.error
               else f"  original   : {len(original.issues)} schema error(s)")
    if original.ntia is not None:
        typer.echo(f"  ntia       : original {ntia_summary(original.ntia)}")
    typer.echo(f"  validate   : converted file vs CycloneDX {conv.target_version} schema: {len(r.original_issues)} error(s)"
               + (" -> repaired" if r.original_issues and final_ok else ""))
    for kw, pth, n, msg in group(r.original_issues)[:10]:
        typer.echo(f"    {n:>6}  {kw:20} {pth}  e.g. {msg[:70]}")
    typer.echo(f"  tool       : {tool_line}")
    typer.echo(f"  changes    : {len(r.log.changes)} ({r.log.count('WARN')} WARN, {r.log.count('DATA_LOSS')} DATA_LOSS)")
    typer.echo("  sbom       : " + (f"{out_dir / sbom_name} (schema-valid CycloneDX {r.final_version})" if final_ok
                                   else f"NOT written - {r.error or 'schema errors remain'}"))
    typer.echo(f"  tech notes : {notes_path}")
    typer.echo(f"  suggestions: {advice_path}")
    typer.echo(f"  exit code  : {r.exit_code}")
    raise typer.Exit(r.exit_code)


def _fill(file: Path, out: Path | None, mode: str, include_sensitive: bool, spec: str | None,
          version: str | None) -> None:
    import hashlib

    from .complete import fill, prepare_input, render_summary
    from .pipeline import output_stem
    from .progress import for_input, size_text
    from .serialize import write_json, write_text

    if spec is not None and spec not in ("cyclonedx", "spdx"):
        typer.echo("error: --spec must be cyclonedx or spdx", err=True)
        raise typer.Exit(EXIT_CANNOT_FIX)
    raw = file.read_bytes()
    progress = for_input(len(raw))
    progress(f"{file.name}: reading ({size_text(len(raw))})")
    try:
        doc, use_spec, use_version, notes = prepare_input(raw, spec, version)
    except SbomFixerError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_CANNOT_FIX) from None
    stem = output_stem(file)
    res = fill(doc, use_spec, use_version, mode, file_stem=stem, source_sha256=hashlib.sha256(raw).hexdigest(),
               include_sensitive=include_sensitive, prepared=notes, progress=progress)
    out_dir = out or file.parent
    ext = "cdx" if use_spec == "cyclonedx" else "spdx"
    sbom_path = out_dir / f"{stem}.fill-{mode}.{ext}.json"
    report_path = out_dir / f"{stem}.fill-{mode}.{ext}.report.json"
    progress(f"writing {sbom_path.name}")
    write_json(res.doc, sbom_path)
    progress(f"writing {report_path.name}")
    report = {"input": file.name, **res.to_dict()}
    write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n", report_path)
    progress("done")
    typer.echo(render_summary(file.name, res, {"sbom": str(sbom_path), "report": str(report_path)}))
    out_size = sbom_path.stat().st_size
    if mode == "all" and out_size > 10 * len(raw):
        typer.echo(f"  note          : output is {out_size / max(len(raw), 1):.0f}x the input ({size_text(out_size)}). "
                   "fill-all shows every schema field; for a Checkmarx upload use fix.")
    raise typer.Exit(EXIT_OK if res.errors_after == 0 else 1)


_SPEC_HELP = "Treat the input as cyclonedx or spdx (default: detected; plain JSON without markers is cyclonedx)"
_VERSION_HELP = ("Write this schema version, e.g. 1.6 or 2.3 (default: the declared one; missing/unknown -> 1.6 / 2.3, "
                 "CycloneDX 1.8+ -> 1.7)")


@app.command("fill-all")
def fill_all(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="SBOM or any JSON file")],
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Output folder (default: next to the input)")] = None,
    spec: Annotated[str | None, typer.Option("--spec", help=_SPEC_HELP)] = None,
    version: Annotated[str | None, typer.Option("--version", help=_VERSION_HELP)] = None,
    include_sensitive: Annotated[bool, typer.Option("--include-sensitive",
                                                    help="Also add placeholders for hashes, signatures, vulnerabilities, "
                                                         "attestations and crypto (off by default)")] = False,
) -> None:
    """Make any JSON schema-valid with EVERY field the schema defines: repair, derive, else placeholder.

    Steps: read any JSON (adds bomFormat/specVersion if missing), apply the repair rules at that version (never a
    downgrade), add every required and optional field (derived where possible, else a placeholder) and replace values
    the schema rejects. Writes <name>.fill-all.<cdx|spdx>.json and
    <name>.fill-all.<cdx|spdx>.report.json. Deprecated fields and recursive structures (components inside new
    components) are not expanded. Exit 0 = schema-valid output.
    """
    _fill(file, out, "all", include_sensitive, spec, version)


@app.command()
def verify(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    expected_packages: Annotated[int | None, typer.Option(help="Expected package count (5% tolerance)")] = None,
) -> None:
    """Upload a file to the Checkmarx verification project and check the import (exit 5 on failure)."""
    from .checkmarx import CxCliClient
    from .checkmarx import verify as cx_verify

    ok, res = cx_verify(CxCliClient(), file, expected_packages)
    typer.echo(json.dumps(res.to_dict(), indent=2))
    raise typer.Exit(EXIT_OK if ok else EXIT_VERIFY)


@app.callback(invoke_without_command=True)
def main(version: Annotated[bool, typer.Option("--version", help="Show the version")] = False) -> None:
    if version:
        typer.echo(f"sbom-fixer {__version__}")
        raise typer.Exit(0)


if __name__ == "__main__":
    sys.exit(app())
