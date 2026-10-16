# sbom-fixer

**sbom-fixer takes an SBOM from any generator and turns it into a file that Checkmarx One SCA imports, and it
explains every change it makes.**

You give it a CycloneDX or SPDX JSON file. It gives back three files:

| File | What it is |
|---|---|
| `<name>.corrected.cdx.json` | The corrected SBOM. Upload this to Checkmarx. |
| `<name>.tech-notes.txt` | What was changed, with a summary. |
| `<name>.suggestions.txt` | A short table of what is missing or wrong in the original and how to fix it at the generator. |

```text
sbom-fixer fix ratecard-sbom.json --out out

ratecard-sbom.json: cyclonedx 1.5 -> converted to CycloneDX 1.5
  original   : 0 schema error(s)
  ntia       : original FAIL - supplier 72/320, author missing
  validate   : converted file vs CycloneDX 1.5 schema: 0 error(s)
  tool       : Tool cyclonedx-java for the ecosystem java: 320 of 320 components
  changes    : 703 (323 WARN, 0 DATA_LOSS)
  sbom       : out\ratecard-sbom.corrected.cdx.json (schema-valid CycloneDX 1.5)
  tech notes : out\ratecard-sbom.tech-notes.txt
  suggestions: out\ratecard-sbom.suggestions.txt
  exit code  : 1
```

---

## Contents

1. [Why this tool exists](#1-why-this-tool-exists)
2. [Quick start](#2-quick-start)
3. [What `fix` does, step by step](#3-what-fix-does-step-by-step)
4. [Before and after](#4-before-and-after)
5. [The three output files](#5-the-three-output-files)
6. [How purls are made](#6-how-purls-are-made)
7. [The tool name in metadata.tools](#7-the-tool-name-in-metadatatools)
8. [Commands and options](#8-commands-and-options)
9. [Exit codes](#9-exit-codes)
10. [Install](#10-install)
11. [Jenkins](#11-jenkins)
12. [Profiles](#12-profiles)
13. [Checkmarx and environment settings](#13-checkmarx-and-environment-settings)
14. [What is in this repository](#14-what-is-in-this-repository)
15. [Development](#15-development)
16. [Known limitations](#16-known-limitations)

---

## 1. Why this tool exists

Checkmarx One SCA can scan a project from an SBOM instead of the source code. In practice many SBOMs fail:
the upload is rejected without a clear error, or it is accepted and Checkmarx finds **0 packages**.

There are two kinds of causes:

| Cause | Examples |
|---|---|
| **The file breaks its own schema** | `"type": "Library"` instead of `library`, `null` values, a date without timezone, a licence written as a plain string, a `serialNumber` that is not `urn:uuid:...`, hash algorithm `sha256` instead of `SHA-256`, fields the version does not define |
| **The file is valid but Checkmarx still cannot use it** | purls with qualifiers (`?type=jar`), purls written as web URLs (`https://www.npmjs.com/package/lodash`), components without a purl, DLLs with only a file name, the CycloneDX 1.5+ `tools` object, SHA3 hashes, evidence, properties, nested components, dependencies that point to nothing |

A schema-valid file is therefore not enough. sbom-fixer repairs the schema errors **and** reduces the file to the
small layout that Checkmarx ingests reliably (the layout written by cyclonedx-dotnet), while keeping the CycloneDX
version of the original.

It never guesses: when a value is not certain it uses a neutral value (`NOASSERTION`, `pkg:generic`, a blank
`""`) and tells you in the suggestions file.

---

## 2. Quick start

```cmd
git clone https://github.com/satyamchaurasia/Sbom.git sbom-fixer
cd sbom-fixer
python -m venv .venv
.venv\Scripts\activate.bat
pip install .

sbom-fixer fix build\sbom.json --out build\sbom-fixed
```

PowerShell: activate with `.\.venv\Scripts\Activate.ps1`; the `sbom-fixer` command is the same.
Linux/macOS: `source .venv/bin/activate`.

Then:

1. Read `build\sbom-fixed\sbom.suggestions.txt`. Those are the problems to fix in your generator or build.
2. Upload `build\sbom-fixed\sbom.corrected.cdx.json` to Checkmarx (never the original).
3. Optional: `sbom-fixer verify build\sbom-fixed\sbom.corrected.cdx.json` uploads it to a test project and checks the import.

> On Windows PowerShell 5.1 never write an SBOM with `>`; it creates a UTF-16 file. Use the generator's own output option.

---

## 3. What `fix` does, step by step

```text
 any SBOM (CycloneDX 1.2-1.7+, SPDX 2.2/2.3 JSON)
    │
    ▼
 1. Convert ─────────── SPDX -> CycloneDX 1.6, purl URLs -> real purls, bom-ref = purl, one dependency entry each
    │
    ▼
 2. Validate ────────── original vs its own schema, converted file vs its CycloneDX schema (errors grouped by cause)
    │
    ▼
 3. Repair ──────────── every schema error fixed ON THE SAME VERSION (the version is never changed)
    │
    ▼
 4. Canonical form ──── the layout Checkmarx ingests (top level, metadata, components, purls, licences, dependencies)
    │
    ▼
 5. Check and write ─── validated again; corrected.cdx.json + tech-notes.txt + suggestions.txt
```

### Step 1 – Convert

| Input | What happens |
|---|---|
| CycloneDX JSON | Keeps its version (`--spec-version` can choose another). |
| SPDX 2.2 / 2.3 JSON | Becomes CycloneDX 1.6. Packages become components; the purl comes from `externalRefs`, the licence from `licenseConcluded` / `licenseDeclared`, checksums become hashes; `DEPENDS_ON` and `*_DEPENDENCY_OF` become dependencies; the described package becomes the root component. |
| A bare JSON array, or an object without `bomFormat` | Read as CycloneDX components. |

In every case: a purl written as a web URL becomes the registry purl (npmjs.com, registry.npmjs.org, pypi.org,
files.pythonhosted.org, nuget.org, Maven Central, mvnrepository.com, crates.io, packagist.org, hex.pm,
repo.hex.pm, rubygems.org, pkg.go.dev, proxy.golang.org, pub.dev); a missing bom-ref is set to the purl; every
component gets a dependencies entry. This is the layout cdxgen writes.

### Step 2 – Validate

The **original** is checked against the schema of the version it declares. Those errors go into the suggestions
file. The **converted** file is checked against its CycloneDX schema. Those errors are printed and repaired in the
next step. Both use the official schemas stored in `sbom_fixer/data/schemas/` (no network).

### Step 3 – Repair (same version)

Every error is repaired by a rule with an ID, on the version the file declares. Examples:

| Problem | Repair | Rule |
|---|---|---|
| `"Library"`, `"sha256"` | `library`, `SHA-256` | REP-003 |
| `"version": 2.11` (number) | `"2.11"` | REP-004 |
| `null` / empty values | removed | REP-005, SAN-001 |
| `serialNumber: "ACME-0001"` | deterministic `urn:uuid:...` | REP-007 |
| `2026-10-02 10:00` | `2026-10-02T10:00:00Z` | REP-008 |
| Space in a URL | percent-encoded | REP-009 |
| Licence `"MIT"` as a string, `Apache 2.0` | `{"license": {"id": "MIT"}}`, `Apache-2.0` | REP-010, SAN-030 |
| Hash that does not fit its algorithm | removed | REP-011 |
| Duplicate bom-refs / duplicate packages | renamed / merged | SAN-020, SAN-022 |
| Dependencies to components that do not exist | removed | SAN-021 |
| Field the version does not allow | removed (DATA_LOSS) | PRUNE-001 |
| Anything left | converted to the expected type, else removed (DATA_LOSS) | COERCE-001, COERCE-002 |

**The version never changes.** A CycloneDX 1.5 file stays 1.5. The only exception is CycloneDX 1.8 or newer
(no schema exists yet), which is brought to 1.7.

### Step 4 – Canonical form (the Checkmarx layout)

| Part | Result |
|---|---|
| Top level | Only `bomFormat`, `specVersion` (unchanged), `serialNumber`, `version`, `metadata`, `components`, `dependencies`. `components` is always there, `[]` when the SBOM has none. |
| `metadata` | Only `timestamp`, `tools`, `component`. `tools` is `[{vendor: AppThreat, name: cyclonedx-<ecosystem>, version: 0.8.0}]` ([section 7](#7-the-tool-name-in-metadatatools)). |
| `metadata.component` (the application) | Always there. When the SBOM has none: `{"type": "application", "name": ""}` (CycloneDX 1.2/1.3 also `"version": ""`, the schema requires it). A root without a name or type gets them blank instead of being dropped. A root written as a string (`"app"`) becomes `{"type": "application", "name": "app"}`. |
| Every component | Only `bom-ref`, `type`, `name`, `version`, `purl`, `licenses`. Nested components are moved to the top level. |
| `purl` | `pkg:type/[namespace/]name@version`, no qualifiers or subpath, never a web URL ([section 6](#6-how-purls-are-made)). |
| `licenses` | SPDX id, name or one expression. No licence: `NOASSERTION`. |
| `dependencies` | One entry per component and the root; only references to components in the file; no self-dependencies; duplicates merged. |
| `bom-ref` | Never a web URL (renamed, also inside `dependencies`). |

Dropped: `externalReferences`, `properties`, `evidence`, `description`, `hashes`, `supplier`, `services`,
`compositions`, `vulnerabilities`, ... Checkmarx does not read them. **The original file keeps them**; keep it for
audits and customers.

### Step 5 – Check and write

The result is validated against its schema again and written only when it is valid. Running `fix` on its own output
changes nothing (exit 0).

---

## 4. Before and after

One component of a cyclonedx-gradle-plugin SBOM (`ratecard-sbom.json`):

**Before**

```json
{
  "type": "library",
  "bom-ref": "pkg:maven/com.fasterxml/classmate@1.7.3?type=jar",
  "publisher": "fasterxml.com",
  "group": "com.fasterxml",
  "name": "classmate",
  "version": "1.7.3",
  "description": "Library for introspecting types with full generic information ...",
  "hashes": [ { "alg": "MD5", "content": "..." }, { "alg": "SHA3-512", "content": "..." } ],
  "licenses": [ { "license": { "id": "Apache-2.0" } } ],
  "purl": "pkg:maven/com.fasterxml/classmate@1.7.3?type=jar",
  "externalReferences": [ { "type": "website", "url": "https://..." } ]
}
```

**After**

```json
{
  "bom-ref": "pkg:maven/com.fasterxml/classmate@1.7.3?type=jar",
  "type": "library",
  "name": "classmate",
  "version": "1.7.3",
  "purl": "pkg:maven/com.fasterxml/classmate@1.7.3",
  "licenses": [ { "license": { "id": "Apache-2.0" } } ]
}
```

The whole file went from 538 KB to 157 KB, all 320 components kept, `metadata.tools` became
`AppThreat cyclonedx-java 0.8.0`.

A DLL found by a binary scan:

| Before | After |
|---|---|
| `name: Newtonsoft.Json.dll`, `version: 13.0.0.0`, no purl, path `/root/.nuget/packages/newtonsoft.json/13.0.3/lib/net6.0/Newtonsoft.Json.dll` | `version: 13.0.3`, `purl: pkg:nuget/newtonsoft.json@13.0.3` |
| `name: Serilog.dll`, `purl: pkg:generic/Serilog.dll@2.0.0.0`, path `packages\Serilog.3.1.1\lib\net45\Serilog.dll` | `version: 3.1.1`, `purl: pkg:nuget/Serilog@3.1.1` |
| `name: MyCompany.Core.dll`, no purl, no cache path | `pkg:generic/MyCompany.Core.dll@1.0.0.0` (not guessed) |

---

## 5. The three output files

### `<name>.corrected.cdx.json`

The SBOM to upload: CycloneDX in the canonical form, UTF-8 without BOM, schema-valid, same CycloneDX version as the
input (SPDX input: 1.6).

### `<name>.tech-notes.txt` – what was changed

Plain text, short lines, numbered sections. Open it in Notepad.

| Section | Content |
|---|---|
| 1. SUMMARY | Input (format, version, generator, component count), output (version, components, dependency entries), the chosen tool name, number of changes, schema errors of the original, result, NTIA result of the original and of the corrected file, sbomqs score |
| 2. NTIA MINIMUM ELEMENTS | The seven NTIA elements (supplier, name, version, unique identifier, dependencies, author, timestamp) for the original and the corrected file; `(gap)` marks what is missing |
| 3. WHAT WAS DONE | Conversion notes, the schema errors of the converted file grouped by cause, the output layout |
| 4. CHANGES MADE | One entry per rule: rule ID, what it does, how many times, an example. **FIX** = a problem of the input that was repaired; **LAYOUT** = reshaped for Checkmarx |
| 5. NOTICED BUT NOT CHANGED | Things noticed but not changed |

### `<name>.suggestions.txt` – what to fix in the original

One short entry per problem: what is wrong, how many components, which ones, and how to fix it:

```text
WHAT TO FIX IN YOUR SBOM
========================
File: ratecard-sbom.json

4 problem(s) found in your original file. Fix them in the tool that creates
the SBOM (your generator or build), then run sbom-fixer again.

1. No licence
   How many      : 13 component(s)
   Which         : antlr-runtime@3.4, aos-common-models@SB3-0.0.1, ... and 8 more
   How to fix    : Add the licence (SPDX id, e.g. MIT, Apache-2.0) to the
                   package manifest (pom, csproj, package.json); for own
                   libraries set it in the build.

2. No SBOM author (NTIA)
   How to fix    : Set metadata.authors (CycloneDX) or a Person/Organization
                   creator (SPDX) to the team that produced the SBOM.
```

Schema errors of the original come first, then data problems, then the NTIA minimum elements the original
misses (supplier, name, version, unique identifier, dependencies, author, timestamp), then pipeline hints. Each problem appears once.
Layout changes (dropped hashes, qualifiers, the reshaped `tools`) are not listed: they are not mistakes of the
original. With nothing to fix the file says "No issues found. Nothing to fix."

A full example of all three files is in [`examples/`](examples/).

---

## 6. How purls are made

Checkmarx matches packages by purl. Every component of the output has one, and **no purl or bom-ref contains
`http` or `https`** (also percent-encoded).

| Situation | Result |
|---|---|
| Valid purl | Kept; type in lower case; qualifiers (`?type=jar`) and subpath removed; version filled from the component when missing |
| Purl written as a registry URL (`https://www.npmjs.com/package/lodash/v/4.17.21`) | `pkg:npm/lodash@4.17.21` |
| Purl is any other URL | Removed; the component gets `pkg:generic/<name>@<version>` |
| No purl, bom-ref is a purl | Purl taken from the bom-ref |
| No purl (or `pkg:generic`), DLL/JAR in a package cache | Purl and version of that package (see below) |
| No purl, registry URL of the same package in `externalReferences` | That registry's purl, with the component's version |
| No purl, the SBOM has one ecosystem | That ecosystem's purl: Erlang → `pkg:hex`, .NET → `pkg:nuget`, Node → `pkg:npm`, Python → `pkg:pypi`, Go → `pkg:golang`, Ruby → `pkg:gem`, Rust → `pkg:cargo`, Dart → `pkg:pub`, C++ → `pkg:conan`, Perl → `pkg:cpan` (Maven, Composer and Swift only when the component has a group). Never for a file name such as `Foo.dll`, never when the SBOM mixes ecosystems |
| Nothing of the above | `pkg:generic/<name>@<version>` (Checkmarx skips it; listed in the suggestions) |

Package-cache paths are read from the component's properties (`syft:location:0:path`,
`aquasecurity:trivy:FilePath`, ...), `evidence.occurrences`, the bom-ref and the name:

| Path | Purl |
|---|---|
| `.nuget/packages/<id>/<version>/...` | `pkg:nuget/<id>@<version>` |
| `packages/<Id>.<Version>/lib/...dll` (packages.config) | `pkg:nuget/<Id>@<Version>` |
| `.m2/repository/<group path>/<artifact>/<version>/<file>.jar` | `pkg:maven/<group>/<artifact>@<version>` |
| `.gradle/caches/modules-2/files-2.1/<group>/<artifact>/<version>/<sha1>/...` | `pkg:maven/<group>/<artifact>@<version>` |

Checkmarx does not scan every purl type. Supported: npm, pypi, nuget, maven, composer, swift/cocoapods, golang,
conan, gem, unity, cpan, pub. Not scanned: `generic`, `cargo`, `hex`, `docker`, `github`, OS packages
(`rpm`, `apk`, `alpm`, distro `deb`). When **no** component has a supported type, `fix` exits with 7: do not upload.

---

## 7. The tool name in metadata.tools

`metadata.tools` is always the array form `[{vendor, name, version}]`. The name follows the ecosystem of the SBOM:

| Ecosystem (purl types) | Tool name |
|---|---|
| .NET (`nuget`) | `cyclonedx-dotnet` |
| Java (`maven`, `gradle`, `sbt`, `ivy`) | `cyclonedx-java` |
| Node (`npm`, `yarn`, `bower`, `pnpm`) | `cyclonedx-node` |
| Python (`pypi`, `pip`, `poetry`) | `cyclonedx-python` |
| Go (`golang`) | `cyclonedx-go` |
| Ruby (`gem`) / PHP (`composer`) / Rust (`cargo`) / Erlang (`hex`) | `cyclonedx-ruby` / `-php` / `-rust` / `-erlang` |
| Dart (`pub`) / Swift (`swift`, `cocoapods`) / C++ (`conan`) / Perl (`cpan`) | `cyclonedx-dart` / `-swift` / `-cpp` / `-perl` |

Detection, strongest first: the majority of the component purl types (OS packages and `generic` do not count; a tie
goes to the root component, then the generator); the root component's purl; the generator name
(`cyclonedx-gradle-plugin` → Java, `rebar3_sbom` / `mix` → Erlang). Without evidence: `cyclonedx-dotnet`.
`--ecosystem java` skips the detection. Vendor `AppThreat` and version `0.8.0` come from the profile
(`canonical.tools`); names can be changed with `canonical.ecosystem_tools`.

---

## 8. Commands and options

The tool has three commands.

### `fix` – correct an SBOM for Checkmarx

```bash
sbom-fixer fix sbom.json --out out
sbom-fixer fix sbom.spdx.json --out out --ecosystem dotnet --name app.cdx.json
sbom-fixer fix sbom.json --profile checkmarx-cli --out out      # for an upload with the cx CLI
```

| Option | Effect |
|---|---|
| `--out DIR`, `-o` | Output folder (default: next to the input) |
| `--name FILE` | File name of the corrected SBOM (default `<name>.corrected.cdx.json`) |
| `--profile NAME\|PATH`, `-p` | `checkmarx` (default), `checkmarx-cli`, or your own YAML ([section 12](#12-profiles)) |
| `--ecosystem NAME` | Force the ecosystem (`dotnet`, `java`, `node`, `python`, `go`, `ruby`, `php`, `rust`, `erlang`, `dart`, `swift`, `cpp`, `perl`) for the tool name and for missing purls |
| `--spec-version 1.6` | CycloneDX version of the converted file (default: CycloneDX keeps its version, SPDX becomes 1.6) |
| `--keep-converted` | Also write the step-1 file `<name>.converted.cdx.json` |
| `--no-audit` | Skip the NTIA / sbomqs quality audit (faster) |

### `fill-all` – fill every field the schema defines

For review and tests, not for Checkmarx. Takes **any JSON** and returns a schema-valid SBOM where every schema field
has a value:

```bash
sbom-fixer fill-all sbom.json --out out
sbom-fixer fill-all sbom.json --include-sensitive                  # also hashes, signatures, vulnerabilities, crypto
sbom-fixer fill-all components.json --spec cyclonedx --version 1.7 # plain JSON / choose the version
```

Values are taken in this order: **derived** from the SBOM (purl → name/version/group, bom-ref → purl, publisher ↔
supplier, hash length → algorithm, ...), a **standard** value (SPDX `NOASSERTION`), the schema **default**, an allowed
**enum** value (`unknown`/`other` first), else an obvious **placeholder** (`PLACEHOLDER-<field>`,
`https://placeholder.invalid/`, `placeholder@example.invalid`). Identity fields (`purl`, `cpe`, `swid`, ...) and
references are only derived, never invented. Outputs: `<name>.fill-all.<cdx|spdx>.json` and a report JSON listing
every added value with its source. The output is about 50 times larger than the input.

### `verify` – upload to Checkmarx and check the import

```bash
sbom-fixer verify out/sbom.corrected.cdx.json --expected-packages 120
```

Uploads the file to the verification project (default `sbom-fixer-verification`), waits for the import and prints
the result as JSON. Needs the `cx` CLI and the settings in [section 13](#13-checkmarx-and-environment-settings).

---

## 9. Exit codes

| Code | `fix` | What to do |
|---|---|---|
| 0 | Nothing to change (already in the canonical form) | Upload the output |
| 1 | Corrected | Upload the output; read the suggestions |
| 2 | Cannot fix: not JSON, CycloneDX XML, SPDX 3.0 / tag-value, CycloneDX 1.0/1.1 or 2.x, or errors that could not be resolved | Read the error; regenerate the SBOM as CycloneDX or SPDX 2.3 JSON |
| 3 | Data loss and the profile forbids it (`allow_data_loss: false`) | Review the DATA_LOSS rows in the tech notes |
| 4 | Quality gate failed (`quality.audit: gate`) | Fix the NTIA gaps at the source |
| 7 | Written, but no component has a purl type Checkmarx scans | Do not upload; regenerate the SBOM with ecosystem purls |

`fill-all`: 0 schema-valid, 1 errors left, 2 not JSON. `verify`: 0 imported, 5 not imported.

Read the exit code with `echo %ERRORLEVEL%` (cmd), `$LASTEXITCODE` (PowerShell) or `echo $?` (bash).

---

## 10. Install

Python 3.11 or newer. The tool works offline; only `verify` uses the network.

**Virtual environment (Windows cmd):**

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install .
sbom-fixer --version
```

Developers: `pip install -e ".[dev]"` (adds pytest, ruff, mypy).

**Offline machine:** `wheelhouse/` contains the tool and every dependency (Python 3.14, Windows x64):

```cmd
pip install --no-index --find-links wheelhouse sbom-fixer
```

For another Python version build it once on a machine with internet: `python -m pip wheel . -w wheelhouse`.

**Docker** (no Python on the machine):

```bash
docker build -t sbom-fixer:1.0.0 .
docker run --rm -v "$PWD:/work" -w /work sbom-fixer:1.0.0 fix build/sbom.json --out build/sbom-fixed
```

Rebuild the image after every update.

**Quality score:** sbomqs 2.1.2 is in `tools/sbomqs` (Windows x64 binary, Linux x64 archive, checksums, licence) and is
found automatically, also offline and in Docker. Order: `SBOMQS_BIN`, `tools/sbomqs`, `PATH`. Details:
`tools/sbomqs/README.md`.

The full step-by-step manual (install on Windows/Linux/Docker, daily workflow, troubleshooting) is the
**Rule Book**: [`docs/SBOM_Fixer_Rule_Book.md`](docs/SBOM_Fixer_Rule_Book.md), also as Word
(`SBOM_Fixer_Rule_Book_And_Installation_guide.docx`).

---

## 11. Jenkins

`jenkins/sbom-fix-stage.groovy` is a stage to paste into a service Jenkinsfile right after the SBOM is generated:

```groovy
docker run --rm -v "$PWD:/work" -w /work sbom-fixer:1.0.0 \
  fix build/sbom.json --profile checkmarx-cli --out build/sbom-fixed
# fails the build only for exit code 2 or higher; archives the three outputs
cx scan create ... -s build/sbom-fixed/sbom.corrected.cdx.json --scan-types sca --sbom-only
```

`jenkins/nightly-corpus.groovy` uploads the sample corpus every night to the verification project, so a change on the
Checkmarx side is noticed.

---

## 12. Profiles

A profile says what the consumer accepts. Built in (`sbom_fixer/data/profiles/`):

| Profile | Use |
|---|---|
| `checkmarx` (default) | Upload through the Checkmarx portal |
| `checkmarx-cli` | Upload with the `cx` CLI (Jenkins); same settings |
| `compliance` | Library and tests only; `fix` always writes the canonical form |

Copy one and pass its path with `--profile my-profile.yaml`. The main keys:

```yaml
name: checkmarx
cyclonedx:
  accepted_versions: ["1.2", "1.3", "1.4", "1.5", "1.6", "1.7"]  # another version is kept with the warning VER-KEEP
  max_version: "1.7"            # 1.8+ is brought down to this version
  future_versions: downgrade    # downgrade | reject
spdx:
  accepted_versions: ["2.2", "2.3"]
allow_downgrade: false          # true = old behaviour, step down one version when not accepted
require_purl: warn              # fail -> exit 2 when a component has no valid purl
allow_data_loss: true           # false -> exit 3 on any DATA_LOSS change
purl:                           # Checkmarx-supported purl types; enables the CXP-* rules and exit 7
  supported_types: {NPM: [npm, yarn, bower], Maven: [maven, sbt, ivy, gradle], ...}
  min_supported: 1              # fewer supported components -> exit 7
canonical:                      # the Checkmarx layout (CXN-* rules)
  tools: [{vendor: AppThreat, name: cyclonedx-dotnet, version: "0.8.0"}]
  ecosystem_tools: {java: cyclonedx-java, ...}   # tool name per ecosystem
  component_fields: [bom-ref, type, name, version, purl, licenses]
  default_license: NOASSERTION
  keep_purl_qualifiers: false
  purl_fallback: generic        # generic | none
quality: {audit: report, min_score: 0, score_tolerance: 0.2}   # gate -> exit 4
```

> CycloneDX 1.7 in the checkmarx profiles is provisional: the Checkmarx "Scanning SBOMs" page lists 1.0-1.6. Upload
> the files in `corpus/minimal/` with `verify`, fill in `docs/checkmarx-matrix.md`, and remove 1.7 if your tenant
> rejects it.

---

## 13. Checkmarx and environment settings

Only `verify` talks to Checkmarx. The `cx` CLI reads its credentials from the environment; sbom-fixer never puts them
on a command line or in a log.

| Variable | Purpose |
|---|---|
| `CX_BASE_URI`, `CX_TENANT` | Checkmarx One tenant |
| `CX_CLIENT_ID` + `CX_CLIENT_SECRET`, or `CX_APIKEY` | Service account (Jenkins credentials) |
| `CX_BIN` | Path to `cx` if not on PATH |
| `SBOM_FIXER_CX_PROJECT` | Verification project (default `sbom-fixer-verification`) |
| `SBOM_FIXER_CX_SCAN_ARGS`, `SBOM_FIXER_CX_RESULTS_ARGS` | Override the `cx` argument templates if your CLI version uses other flags (`cx scan create --help`) |
| `SBOM_FIXER_CX_TIMEOUT_S` | Scan timeout (default 900) |
| `SBOMQS_BIN` | Path to a `sbomqs` executable |
| `SBOM_FIXER_PROGRESS=1` / `0` | Progress lines on stderr on / off (default: on from 1 MB) |
| `SBOM_FIXER_FAST_VALIDATION=0` | Disable the fast validation pre-check (debugging only) |

---

## 14. What is in this repository

| Path | Content |
|---|---|
| `sbom_fixer/cli.py` | The three commands |
| `sbom_fixer/cdxgen.py` | Step 1: any SBOM → CycloneDX (SPDX conversion, purl URLs, bom-refs, dependency entries) |
| `sbom_fixer/pipeline.py`, `descent.py` | Steps 2, 3 and 5: validate, repair on the same version, coerce, write |
| `sbom_fixer/rules/` | All rules: `repair.py` (REP), `sanitize.py` / `sanitize_purl.py` (SAN, CXP), `canonical.py` (CXN), version hops |
| `sbom_fixer/binpath.py` | Purls of DLL/JAR files from NuGet / Maven / Gradle cache paths |
| `sbom_fixer/ecosystem.py` | Ecosystem detection and tool names |
| `sbom_fixer/purlmap.py` | Registry URL → purl, Checkmarx purl coverage |
| `sbom_fixer/cdxgen_report.py` | `tech-notes.txt` and `suggestions.txt` |
| `sbom_fixer/complete.py` | `fill-all` |
| `sbom_fixer/checkmarx.py` | `cx` CLI client for `verify` |
| `sbom_fixer/audit/` | NTIA check, sbomqs wrapper, quality gate |
| `sbom_fixer/data/schemas/` | Official CycloneDX 1.2-1.7 and SPDX 2.2/2.3 JSON schemas (with sources) |
| `sbom_fixer/data/profiles/` | Built-in profiles |
| `examples/` | `demo-broken.cdx.json` and its three outputs |
| `corpus/` | Sample SBOMs (generators, versions, purl cases) used by the tests |
| `docs/SBOM_Fixer_Rule_Book.md` | User manual (also as .docx) |
| `docs/rule-catalog.md` | Every rule, generated from the code |
| `docs/checkmarx-version-purl-fix.md` | Checkmarx research: versions, purl types, sources |
| `jenkins/` | Jenkins stage and nightly job |
| `tools/` | sbomqs (vendored), schema/sbomqs update scripts, rule catalog and Word manual generators, corpus scripts |
| `wheelhouse/` | Offline install packages |
| `tests/` | pytest suite |

---

## 15. Development

```bash
pip install -e ".[dev]"
pytest                                # whole suite, about a minute
ruff check sbom_fixer tests tools
mypy sbom_fixer
python tools/make_corpus.py           # regenerate corpus/ and corpus/expected.yaml
python tools/vendor_schemas.py        # only when upgrading schemas; commit with schemas/SOURCES.md
python tools/vendor_sbomqs.py 2.1.2   # only when upgrading sbomqs; also set ARG SBOMQS_VERSION in the Dockerfile
python tools/make_rule_catalog.py     # docs/rule-catalog.md and the rule table of the Rule Book
python tools/make_rule_book_docx.py   # Word manual from the Rule Book Markdown (needs: pip install python-docx)
python -m pip wheel . --no-deps -w wheelhouse   # refresh the offline wheel
```

Adding a rule:

1. Add a file that shows the problem to `corpus/`.
2. Write a test with the file before and after.
3. Implement the rule in `sbom_fixer/rules/` with an ID, a title, a plain-language `description` (tech notes) and a
   `source_fix` (suggestions). Change the document only through the change log.
4. Run `pytest`, then `python tools/make_rule_catalog.py`, and add a line to `CHANGELOG.md`.

Every change is recorded with a rule ID, a path, the old and new value, a severity (INFO, WARN, DATA_LOSS) and a
reason; the tech notes and the suggestions are generated from that record.

---

## 16. Known limitations

- Not supported: CycloneDX XML, SPDX tag-value / RDF / 3.0. Regenerate as JSON.
- Checkmarx does not scan `hex` (Erlang), `cargo` (Rust), `generic` and OS packages; such SBOMs give exit 7.
- DLLs or JARs that are not in a package cache, and company-internal libraries, stay `pkg:generic`. Generate the SBOM
  from the project (`dotnet CycloneDX`, CycloneDX Maven/Gradle plugin, `cyclonedx-npm`) for exact purls.
- The canonical form drops supplier and author, so the NTIA check of the corrected file usually fails; keep the
  original for NTIA and audits. The NTIA gaps of the original are in the console output (`ntia :` line), the
  suggestions and the tech notes.
- CycloneDX 1.7 acceptance and the `cx` flags used by `verify` are provisional until checked against your tenant
  (`docs/checkmarx-matrix.md`).
- The files in `corpus/` are synthetic, modelled on typical generator output; add real SBOMs from your pipelines.
