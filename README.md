# sbom-fixer

Makes SBOMs from any generator import into Checkmarx, and explains every change it makes.

For each SBOM the tool:

1. Checks the file against the schema of the version it **declares**, and repairs what can be repaired without guessing.
2. If the corrected file is OK (schema-valid **and** accepted by the consumer), it stops. The version does not change.
3. Errors no repair rule can fix are resolved **on the same schema**: a value of the wrong JSON type is converted when the meaning is clear (COERCE-001), otherwise the rejected value is removed and reported as DATA_LOSS (COERCE-002).
4. **The version never changes.** A version the profile does not list is kept with a warning (VER-KEEP). The only exceptions: CycloneDX 1.8+ (no schema exists) is brought to 1.7, and `allow_downgrade: true` in a profile turns on the old behaviour of stepping down one version at a time (for example 1.7 to 1.6) with the hop rules.

For Checkmarx (profiles `checkmarx` and `checkmarx-cli`) it also:

- **writes the canonical form (rules CXN-\*)** as the last step: a schema-valid SBOM is not always ingested by
  Checkmarx (extra fields such as SHA3 hashes, evidence, properties, externalReferences, services, purl qualifiers or the
  1.5+ tools object make uploads fail or return 0 packages). The output keeps `bomFormat`, `specVersion` (unchanged),
  `serialNumber` and `version`; `metadata` becomes `{timestamp, tools: [AppThreat cyclonedx-dotnet 0.8.0], component}`;
  every component becomes `{bom-ref, type, name, version, purl, licenses}` with a purl of the form
  `pkg:type/[namespace/]name@version` (built from the ecosystem, else `pkg:generic/...`, never null) and a licence
  (`NOASSERTION` when there is none); `dependencies` point only at components that exist, without self-references.
  Configure it in the profile's `canonical:` section.

- keeps CycloneDX 1.6 and 1.7 at their own version in every profile (`checkmarx`, `checkmarx-cli`, `compliance`); nothing steps down unless the profile sets `allow_downgrade: true`;
- brings a newer CycloneDX version (1.8, 1.9, ...) down to 1.7 with a generic "future hop" (CDX-FWD-*);
- keeps every purl type Checkmarx supports as written, repairs the format Checkmarx cannot match (npm `@` scope, missing version or groupId, URL qualifiers), remaps unsupported types only on hard evidence (CXP-010..013) and lists every component Checkmarx will skip;
- converts a purl written as a web URL (`https://...`) into the real purl when it is a registry URL (SAN-009);
- adds sbom-fixer as the default tool when the SBOM names none (SAN-013).

Details and the Checkmarx sources: `docs/checkmarx-version-purl-fix.md`.

Every edit is recorded with a rule ID, so the diff, the notes file and the change log always match what happened.

Background: `SBOM_Fixer_Guide.md`, `SBOM_Fixer_Implementation_Plan.md` and `SBOM_Fixer_Jira_Stories/` (decisions ADR-01 to ADR-19).

## Install

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"     # Windows (Git Bash); on Linux use .venv/bin/pip
```

or use the image:

```bash
docker build -t sbom-fixer:1.0.0 .
docker run --rm -v "$PWD:/work" -w /work sbom-fixer:1.0.0 fix build/sbom.json --out build/sbom-fixed
```

Python 3.11 or newer. The tool never uses the network except for the optional Checkmarx commands.

The sbomqs quality score works offline out of the box: sbomqs 2.1.2 is vendored in `tools/sbomqs` (Windows x64 binary, Linux x64 archive, checksums, licence) and found automatically. Order: `SBOMQS_BIN`, then `tools/sbomqs`, then `PATH`. Details: `tools/sbomqs/README.md`.

## Use

The tool has three commands:

```bash
sbom-fixer fix sbom.json --out out/                # any SBOM -> out/sbom.corrected.cdx.json + tech-notes.md + suggestions.md
sbom-fixer fill-all any.json --out out/                  # schema-valid with every schema field (derive, else placeholder)
sbom-fixer verify out/sbom.corrected.cdx.json            # upload to the Checkmarx verification project and check the import
```

`check`, `audit`, `fill-required`, `schema-diff`, `bisect`, `rules` and `cdxgen-fix` were removed. `fix` is now
the former `cdxgen-fix` (convert, correct, tech notes, suggestions); its SBOM is `<name>.corrected.cdx.json`.

Options of `fix`:

| Option | Effect |
|---|---|
| `--out DIR` | Output folder (default: next to the input) |
| `--name FILE` | File name of the corrected SBOM (default `<name>.corrected.cdx.json`) |
| `--profile checkmarx-cli` | Profile (default `checkmarx`; `checkmarx-cli` for an upload with the cx CLI) |
| `--ecosystem java` | Force the ecosystem that names `metadata.tools` instead of detecting it |
| `--spec-version 1.6` | CycloneDX version of the converted file (default: CycloneDX keeps its version, SPDX becomes 1.6) |
| `--keep-converted` | Also write the step-1 file `<name>.converted.cdx.json` |
| `--no-audit` | Skip the NTIA / sbomqs audit |

On Windows PowerShell 5.1, never write SBOMs with `>`; it produces UTF-16. The tool always writes its files itself.

## Any SBOM to the Checkmarx form: `fix`

```bash
sbom-fixer fix sbom.json --out out/                     # writes out/sbom.corrected.cdx.json + 2 .md files
sbom-fixer fix sbom.spdx.json --out out/ --ecosystem dotnet --name app.cdx.json
```

Three steps:

1. **convert** (kept only with `--keep-converted`: `<name>.converted.cdx.json`). cdxgen builds SBOMs from source code and cannot read an existing SBOM,
   so this step gives any SBOM the shape cdxgen writes. SPDX 2.2/2.3 JSON becomes CycloneDX 1.6: packages become
   components (purl from `externalRefs`, licences from `licenseConcluded`/`licenseDeclared`, checksums become hashes),
   `DEPENDS_ON` and `*_DEPENDENCY_OF` become dependencies, and the single described package (else the document) becomes
   `metadata.component`. CycloneDX keeps its version (`--spec-version` overrides it). In both cases a missing bom-ref is
   set to the purl, and every component gets a dependencies entry.
   Purls written as a URL become the registry purl (registry downloads and package pages: npmjs.com, pypi.org,
   mvnrepository.com, nuget.org, crates.io, packagist.org, hex.pm, rubygems.org, pkg.go.dev, Maven Central).
2. **schema validation**: the original is validated against its own schema and the converted file against its
   CycloneDX schema; the errors are printed grouped by cause and listed in the two Markdown files.
3. **fix + canonical form** (the `#2` prompt). The repair fixes those errors on the same version, then the canonical
   rules CXN-* apply (see above), and the result is validated again before it is written. The top level is
   `bomFormat`, `specVersion` (never changed), `serialNumber`, `version`, `metadata`, `components`, `dependencies`;
   `components` is always written, `[]` when the input has none (the schema's top-level list is `components`; the
   singular `component` is the root application in `metadata.component`, also always written: when the input has
   none it is `{"type": "application", "name": ""}` (plus `"version": ""` on CycloneDX 1.2/1.3, where the schema
   requires it), and a root without a name or type gets them blank instead of being dropped). **No purl or bom-ref holds
   a web URL** (http/https, also percent-encoded): a URL that is not a known registry is moved out of the purl and the
   component gets `pkg:generic/<name>@<version>`. A component without a purl gets one, in this order: a DLL/JAR
   whose file path is in a NuGet or Maven/Gradle cache gets that package's purl and version
   (`.nuget/packages/newtonsoft.json/13.0.3/...` → `pkg:nuget/newtonsoft.json@13.0.3`); a registry URL in its
   externalReferences that names the same package; the SBOM's single ecosystem (Erlang → `pkg:hex`, never for a file
   name such as `Foo.dll`); else `pkg:generic`. `metadata.tools` is named after the **detected ecosystem**:

   | Ecosystem (purl types) | Tool name |
   |---|---|
   | .NET (`nuget`) | `cyclonedx-dotnet` |
   | Java (`maven`, `gradle`, `sbt`, `ivy`) | `cyclonedx-java` |
   | Node (`npm`, `yarn`, `bower`, `pnpm`) | `cyclonedx-node` |
   | Python (`pypi`, `pip`, `poetry`) | `cyclonedx-python` |
   | Go (`golang`) | `cyclonedx-go` |
   | Ruby (`gem`) / PHP (`composer`) / Rust (`cargo`) / Erlang (`hex`) | `cyclonedx-ruby` / `-php` / `-rust` / `-erlang` |
   | Dart (`pub`) / Swift (`swift`, `cocoapods`) / C++ (`conan`) / Perl (`cpan`) | `cyclonedx-dart` / `-swift` / `-cpp` / `-perl` |

   The vendor (`AppThreat`) and version (`0.8.0`) come from the profile's `canonical.tools`. Detection: the majority
   of the component purl types (OS packages and `generic` do not count); a tie goes to the root component's type; with
   no package purl, the root component, then the generator name (`cyclonedx-gradle-plugin` gives Java). With no
   evidence the profile's default tool (`cyclonedx-dotnet`) is kept. `--ecosystem java` skips the detection. The
   names can be changed in a profile: `canonical.ecosystem_tools: {java: cyclonedx-maven}`.

Outputs in `--out`, three files only:

| File | Content |
|---|---|
| `<name>.corrected.cdx.json` (`--name`) | the fixed SBOM to upload |
| `<name>.tech-notes.md` | summary (input, output, tool, change counts, exit code), the three steps, every change grouped by rule as *fix* (a problem of the input) or *layout* (reshaped for Checkmarx), findings |
| `<name>.suggestions.md` | one short table of what is missing or wrong in the original: problem, count, which components, how to fix it at the generator (schema errors first, each problem once) |

No change log, diff, notes or report JSON is written. Exit codes: see below.

## Fill every field: `fill-all`

Takes **any JSON** and returns a schema-valid SBOM with every schema field filled:

```bash
sbom-fixer fill-all      sbom.json --out out/   # EVERY field the schema defines (required and optional)
sbom-fixer fill-all      sbom.json --include-sensitive   # also hashes, signatures, vulnerabilities, crypto
sbom-fixer fill-all      components.json --spec cyclonedx --version 1.7   # plain JSON / pick the version
```

Steps, in this order:

1. **Read any JSON.** A JSON array becomes the components (SPDX: packages); an object without `bomFormat`/`spdxVersion` is
   CycloneDX (or `--spec`); a missing or unknown version becomes 1.6 / 2.3 (or `--version`); CycloneDX 1.8+ goes to 1.7
   with the future hop. Only invalid JSON syntax and SPDX 3.0 are refused (exit 2).
2. **Derive required fields first** (so nothing is dropped), then run the repair and sanitize rules at that version
   (wrong case, wrong types, bad dates, licence shapes, bad hashes, unknown fields). Never a downgrade.
3. **Fill** each missing field, in this order of preference: `derived` from the SBOM (purl → name/version/group, bom-ref →
   purl, publisher ↔ supplier, hash length → alg, evidence → licenses/copyright, purl qualifiers → externalReferences,
   file name → root component, one dependency entry per component), `standard` (SPDX `NOASSERTION`, `CC0-1.0`),
   the schema `default`, an allowed `enum` value (`unknown`/`other` first), else a `dummy` that is obviously a placeholder:
   `PLACEHOLDER-<field>`, `https://placeholder.invalid/`, `placeholder@example.invalid`, `0`, `false`.
4. **Coerce** values the schema still rejects: convert when the meaning is clear (`"no"` → `false`, `"42"` → `42`, a bare
   string where an object is expected → `{"name": ...}`), otherwise remove and fill again. Additions that would make the
   document invalid are rolled back.

Never invented (only derived): identity fields (`purl`, `cpe`, `swid`, `omniborId`, `swhid`, SPDX `externalRefs`) and
references to other elements (`ref`, `dependsOn`, `assemblies`, relationships). A dummy purl would be scanned as a real
package. `fill-all` does not expand deprecated fields or recursive structures (components inside new components); objects
created deeper than 4 levels get only their required fields.

Big files: `fill-all` adds every schema field to every component, so 5,000 components become about 1.7 million fields (~50x the input, about a minute). Above 5,000 entries the report groups fields by path pattern. For a Checkmarx upload use `fix`.

Outputs: `<name>.fill-all.<cdx|spdx>.json` and `<name>.fill-all.<cdx|spdx>.report.json` with
`prepared` (how the input was read), `repairs` (repair rules applied), `removed_invalid` (converted or removed values),
`fills` (every added field with its source), `skipped` and `unresolved_required`. Exit 0 = schema-valid output, 1 = some
errors could not be resolved (see the report), 2 = not JSON / unsupported format.

## Exit codes

Exit codes of `fix` (`fill-all`: 0 schema-valid, 1 errors left, 2 not JSON; `verify`: 0 imported, 5 failed):

| Code | Meaning |
|---|---|
| 0 | Already compatible; output identical to input |
| 1 | Corrected |
| 2 | Cannot fix: unsupported format, a version with no schema (CycloneDX 1.0/1.1, 2.x), or schema errors that even the same-version coercion could not resolve |
| 3 | DATA_LOSS changes happened and the profile sets `allow_data_loss: false` |
| 4 | Quality gate failed (profile `quality.audit: gate`) |
| 5 | Checkmarx verification failed |
| 7 | Fixed, but no component has a purl type the profile supports; Checkmarx would fail the scan ("no valid PURLs"), so do not upload |

## Profiles

Built in: `checkmarx` (web portal), `checkmarx-cli` (cx CLI / Jenkins, same versions) and `compliance` (`sbom_fixer/data/profiles/`). Pass a YAML path to use your own.

```yaml
name: checkmarx
cyclonedx:
  floor: "1.2"                              # lowest version when allow_downgrade is true ("declared" = never)
  accepted_versions: ["1.2", "1.3", "1.4", "1.5", "1.6", "1.7"]  # 1.7 PROVISIONAL until docs/checkmarx-matrix.md is filled in
  max_version: "1.7"                        # newer declared versions (1.8+) are brought down to this one
  future_versions: downgrade                # downgrade | reject (default reject)
spdx:
  floor: "2.2"
  accepted_versions: ["2.2", "2.3"]
acceptance: profile        # profile | checkmarx | schema-only
allow_downgrade: false     # true = step down one version when the file is not accepted (old behaviour)
tools_form: as-is          # legacy-array if Checkmarx only reads the 1.4 tools array
flatten_nested_components: true
require_purl: warn         # fail -> exit 2 when a component has no valid purl
ensure_tools: true         # add sbom-fixer to metadata.tools / SPDX creators when no tool is named
purl:                      # consumer purl types; enables CXP-* rules, coverage CSV and exit 7
  supported_types: {NPM: [npm, yarn, bower], Maven: [maven, sbt, ivy, gradle]}   # see checkmarx.yaml for the full list
  os_types: [rpm, apk, alpm]
  remap: true              # CXP-010..013
  unsupported_action: keep # keep | remove (remove = DATA_LOSS)
  os_package_action: keep  # keep | remove
  strip_url_qualifiers: true
  min_supported: 1         # fewer supported components -> exit 7
allow_data_loss: true
quality: {audit: report, fail_on_regression: true, min_score: 0, score_tolerance: 0.2}
```

The old keys `target`, `supported` and `convert` are rejected with a message.

## Checkmarx configuration

Only needed for `verify`, `bisect`, `--verify` and `--verify-each-step`. The `cx` CLI reads its own credentials from the environment; the tool never puts them on a command line or in a log.

| Variable | Purpose |
|---|---|
| `CX_BASE_URI`, `CX_TENANT` | Checkmarx One tenant |
| `CX_CLIENT_ID` + `CX_CLIENT_SECRET`, or `CX_APIKEY` | Service account (Jenkins credentials) |
| `CX_BIN` | Path to `cx` if not on PATH |
| `SBOM_FIXER_CX_PROJECT` | Verification project (default `sbom-fixer-verification`) |
| `SBOM_FIXER_CX_SCAN_ARGS`, `SBOM_FIXER_CX_RESULTS_ARGS` | Override the `cx` argument templates if your CLI version uses other flags (check `cx scan create --help`) |
| `SBOM_FIXER_CX_TIMEOUT_S` | Scan timeout (default 900) |
| `SBOMQS_BIN` | Path to a `sbomqs` executable; overrides the copy in `tools/sbomqs` and PATH |
| `SBOM_FIXER_PROGRESS=1` / `0` | Force progress lines on stderr on / off (default: on for inputs of 1 MB or more) |
| `SBOM_FIXER_FAST_VALIDATION=0` | Disable the fastjsonschema pre-check (use only for debugging) |

## Development

```bash
python tools/make_corpus.py          # regenerate corpus/ and corpus/expected.yaml
.venv/Scripts/pytest                 # the whole suite, about a minute
.venv/Scripts/ruff check sbom_fixer tests tools
.venv/Scripts/mypy sbom_fixer
python tools/vendor_schemas.py       # only when upgrading schemas; commit with schemas/SOURCES.md
python tools/vendor_sbomqs.py 2.1.2  # only when upgrading sbomqs; also set ARG SBOMQS_VERSION in the Dockerfile
python tools/make_rule_catalog.py    # docs/rule-catalog.md and the rule table of the Rule Book, from the code
python tools/make_rule_book_docx.py  # Rule Book .docx from docs/SBOM_Fixer_Rule_Book.md (needs: pip install python-docx)
```

The user manual is `docs/SBOM_Fixer_Rule_Book.md`; the Word copies (`docs/SBOM_Fixer_Rule_Book.docx`,
`SBOM_Fixer_Rule_Book_And_Installation_guide.docx`) are generated from it. Edit the Markdown, then run the two scripts
above.

Adding a rule follows the seven-step recipe in the Implementation Plan (evidence, classify, fixture, implement, describe, run everything, catalog).

## How the stories map to the code

| Phase | Stories | Where |
|---|---|---|
| 0 Discovery | SBOMFIX-101 to 106 | `corpus/minimal/`, `docs/checkmarx-matrix.md`, `tools/make_corpus.py` |
| 1 Core | SBOMFIX-201 to 207 | `schemas.py`, `detect.py`, `validate.py`, `changes.py`, `rules/base.py`, `cli.py check` |
| 2 Same-version repair | SBOMFIX-301 to 307 | `rules/repair.py`, `descent.process_level`, `serialize.py` |
| 3 Version conversion | SBOMFIX-401 to 407 | `schemadiff.py`, `descent.py`, `oracle.py`, `rules/cdx_*`, `prune.py` |
| 4 Sanitizers, reporting | SBOMFIX-501 to 510 | `rules/sanitize.py`, `diff.py`, `notes.py`, `profile.py`, `pipeline.py`, `Dockerfile` |
| 5 Quality | SBOMFIX-601 to 606 | `audit/ntia.py`, `audit/sbomqs.py`, `audit/gate.py`, `profiles/compliance.yaml` |
| 6 Checkmarx | SBOMFIX-701 to 704 | `checkmarx.py`, `bisect.py`, `tools/run_corpus_checkmarx.py`, `jenkins/nightly-corpus.groovy` |
| 7 SPDX, rollout | SBOMFIX-801 to 806 | `rules/spdx_23_to_22.py`, `audit/ntia.py` (SPDX), `jenkins/sbom-fix-stage.groovy`, `docs/rollout.md` |

## Known limitations

- Performance: a 25 MB SBOM with 50,000 components, every one needing two changes, takes about 38 seconds end to end including audit and reports (measured on a developer laptop). ADR-18 targets 30 seconds; files that need fewer changes are faster.
- Checkmarx `accepted_versions` are provisional (ADR-01) until the upload matrix is run in your tenant.
- The `cx` flags and results JSON fields used by `checkmarx.py` are defaults; confirm them for your CLI version. They have not been run against a real tenant.
- The `corpus/` files are synthetic, modelled on typical generator output. Add real SBOMs from your pipelines (SBOMFIX-103).
- Not supported yet: CycloneDX XML, SPDX tag-value / RDF / 3.0, upgrade hops, REP-013 and REP-014.
