# SBOM Fixer Rule Book

Installation, daily use and rule reference for `sbom-fixer` 1.0.0. Follow the steps in order on a new machine; after that, Step 08 is the everyday workflow.

| Item | Value |
|---|---|
| Tool | `sbom-fixer` 1.0.0 (Python command-line tool) |
| Commands | `fix` (correct any SBOM for Checkmarx), `fill-all` (fill every schema field), `verify` (upload to Checkmarx and check the import) |
| What `fix` does | Converts any CycloneDX or SPDX 2.x JSON to CycloneDX, repairs it on its own schema version, writes the layout Checkmarx ingests, and explains every change in two plain-text files |
| Works on | Windows 10/11, Linux, macOS, or any machine with Docker |
| Needs | Python 3.11 or newer (3.12 recommended); internet only for installing packages. sbomqs is in the repository (`tools\sbomqs`), nothing to download for the quality score |
| Source folder | `sbom-fixer` (README.md, CHANGELOG.md, docs/ inside it) |

---

## Contents

Step 01 What sbom-fixer does · Step 02 Prerequisites · Step 03 Get the code · Step 04 Install on Windows · Step 05 Install on Linux or macOS · Step 06 Install with Docker · Step 07 Verify the installation · Step 08 Daily workflow · Step 09 Output files · Step 10 Exit codes · Step 11 Profiles · Step 12 Checkmarx integration · Step 13 Quality audit · Step 14 Jenkins · Step 15 Rule reference · Step 16 Troubleshooting · Step 17 Updating · Step 18 Cheat sheet

---

## Step 01 – What sbom-fixer does

Checkmarx rejects many SBOMs without a clear error, or imports them with 0 packages. Two kinds of problem cause this:

| Problem | Example | What `fix` does |
|---|---|---|
| The file breaks its own schema | wrong case (`Library`), null values, bad dates, broken licences, a serialNumber that is not a urn:uuid | Repairs it on the same schema version |
| The file is valid but Checkmarx still fails or imports nothing | SHA3 hashes, evidence, properties, externalReferences, purl qualifiers, the 1.5+ tools object, purls written as web URLs, no purls | Reduces the file to the layout Checkmarx ingests reliably (the canonical form, rules CXN-*) |

`fix` runs these steps for every SBOM:

1. **Convert.** CycloneDX keeps its version. SPDX 2.2/2.3 JSON becomes CycloneDX 1.6: packages become components, `externalRefs` give the purls, `licenseConcluded`/`licenseDeclared` the licences, checksums the hashes, `DEPENDS_ON` and `*_DEPENDENCY_OF` the dependencies, and the described package the root component. Purls written as a web URL become the registry purl. A missing bom-ref is set to the purl.
2. **Validate.** The original is checked against its own schema and the converted file against its CycloneDX schema. The errors are printed grouped by cause.
3. **Repair.** Every error is repaired on the same version (the version never changes). A value of the wrong type is converted when the meaning is clear (COERCE-001); otherwise the rejected value is removed and reported as DATA_LOSS (COERCE-002).
4. **Canonical form** (the layout Checkmarx ingests):
   - top level only `bomFormat`, `specVersion` (unchanged), `serialNumber`, `version`, `metadata`, `components`, `dependencies`; `components` is always there, `[]` when the SBOM has none;
   - `metadata` = `timestamp`, `tools`, `component`. `tools` names the generator of the detected ecosystem (vendor AppThreat, version 0.8.0): .NET → `cyclonedx-dotnet`, Java → `cyclonedx-java`, Node → `cyclonedx-node`, Python → `cyclonedx-python`, Go, Ruby, PHP, Rust, Erlang, Dart, Swift, C++, Perl. `component` (the root application) is always there; when the SBOM has none it is `{"type": "application", "name": ""}` (CycloneDX 1.2/1.3 also `"version": ""`);
   - every component = `bom-ref`, `type`, `name`, `version`, `purl`, `licenses`. Nested components are moved to the top level. The purl is `pkg:type/[namespace/]name@version` without qualifiers. A DLL or JAR found in a NuGet or Maven cache gets that package's purl and version (`.nuget/packages/newtonsoft.json/13.0.3/...` → `pkg:nuget/newtonsoft.json@13.0.3`). Any other missing purl is built from the component's registry URL (when it names the same package), then from the SBOM's single ecosystem (Erlang → `pkg:hex`, .NET → `pkg:nuget`, ...; never for a file name such as `Foo.dll`), and only then `pkg:generic/<name>@<version>`. **No purl or bom-ref contains http or https.** A missing licence becomes `NOASSERTION`;
   - dependencies only between components in the file, without self-dependencies or duplicates; every component has an entry (`dependsOn: []` when unknown), so running `fix` on its own output changes nothing.
5. **Check again and write.** The result is validated against its schema before it is written. Three files are written (Step 09).

Every change is recorded with a rule ID; the tech notes list them all.

> **Golden rule:** The tool never guesses. When the correct value is not certain (for example the licence name "BSD", or a purl type in an SBOM that mixes ecosystems), it keeps a neutral value and reports it.

---

## Step 02 – Check the prerequisites on the new machine

Open a terminal and run the checks below.

| Need | Check command | Expected |
|---|---|---|
| Python 3.11 or newer | `python --version` (Windows may also have `py --version`) | `Python 3.11.x` or higher |
| pip | `python -m pip --version` | A pip version is printed |
| Internet or an internal package mirror | `python -m pip download --no-deps -d %TEMP% typer` | Download succeeds |
| Git (only to clone the repository) | `git --version` | A git version is printed |
| Docker (optional, Step 06) | `docker --version` | A docker version is printed |
| Checkmarx `cx` CLI (optional, Step 12) | `cx version` | A cx version is printed |
| sbomqs (bundled, Step 13) | `tools\sbomqs\windows-amd64\sbomqs.exe version` | `GitVersion: v2.1.2` |

If Python is missing on Windows:

1. Download Python 3.12 from python.org, or install it from the company software portal.
2. In the installer, tick **Add python.exe to PATH**.
3. Close and reopen the terminal, then run `python --version` again.

> **Corporate proxy:** If pip cannot reach the internet, set the proxy for the session (`set HTTPS_PROXY=http://proxy.company:8080` in cmd) or use the offline install in Step 04.6.

---

## Step 03 – Get the code onto the machine

Use one of these options.

**Option A – Git (recommended):**

```bash
git clone https://github.com/satyamchaurasia/Sbom.git sbom-fixer
cd sbom-fixer
```

**Option B – Copy the folder:**

1. On the machine that has the tool, zip the `sbom-fixer` folder **without** the `.venv` folder (and without `.mypy_cache`, `.ruff_cache`, `__pycache__`).
2. Copy the zip to the new machine and extract it, for example to `C:\Tools\sbom-fixer`.

> **Do not copy .venv:** A virtual environment contains absolute paths of the machine it was created on and does not work on another machine. Always create a new one (Step 04).

After this step the folder must contain at least: `pyproject.toml`, `README.md`, `sbom_fixer\`, `sbom_fixer\data\schemas\`, `sbom_fixer\data\profiles\`, and `tools\sbomqs\` for the offline quality score. When you copy the folder as a zip (Option B), keep the `tools` folder.

---

## Step 04 – Install on Windows

### 4.1 Open a terminal in the folder

Use **cmd** (Command Prompt) for the commands below. PowerShell and Git Bash variants are in 4.5.

```cmd
cd C:\Tools\sbom-fixer
```

### 4.2 Create a virtual environment

```cmd
python -m venv .venv
```

This creates a private Python environment in `.venv` so the tool's libraries do not change the system Python.

### 4.3 Activate it

```cmd
.venv\Scripts\activate.bat
```

The prompt now starts with `(.venv)`. Repeat this step in every new terminal window before using the tool.

### 4.4 Install the tool

```cmd
python -m pip install --upgrade pip
pip install .
```

Developers who will change the code use `pip install -e ".[dev]"` instead. That also installs the test and lint tools.

### 4.5 Activation in other terminals

| Terminal | Activate command |
|---|---|
| cmd | `.venv\Scripts\activate.bat` |
| PowerShell | `.\.venv\Scripts\Activate.ps1` |
| Git Bash | `source .venv/Scripts/activate` |
| Without activating | Call the full path: `C:\Tools\sbom-fixer\.venv\Scripts\sbom-fixer.exe` |

If PowerShell says "running scripts is disabled on this system", run this once and activate again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 4.6 Offline install (machine without internet)

The repository already contains `wheelhouse\` with the tool and every dependency for Python 3.14 on Windows x64. On another Python version, build it on a machine **with** internet and the same Python version:

```cmd
cd C:\Tools\sbom-fixer
python -m pip wheel . -w wheelhouse
```

Copy the `wheelhouse` folder to the offline machine together with the code, then on the offline machine:

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install --no-index --find-links wheelhouse sbom-fixer
```

The quality score needs no extra download on the offline machine: sbomqs is already in `tools\sbomqs\windows-amd64\sbomqs.exe` and sbom-fixer finds it automatically (Step 13).

### 4.7 Make the command available everywhere (optional)

To use `sbom-fixer` from any folder without activating, add `C:\Tools\sbom-fixer\.venv\Scripts` to the user PATH (Windows Settings, search "Edit environment variables for your account", edit `Path`, add the folder), then open a new terminal.

---

## Step 05 – Install on Linux or macOS

```bash
cd ~/tools/sbom-fixer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install .
sbom-fixer --version
```

Repeat `source .venv/bin/activate` in every new shell, or call `~/tools/sbom-fixer/.venv/bin/sbom-fixer` directly.

---

## Step 06 – Install with Docker (no Python needed)

Build the image once from the folder that contains the `Dockerfile`:

```bash
docker build -t sbom-fixer:1.0.0 .
```

Run it with the current folder mounted as `/work`:

```bash
docker run --rm -v "$PWD:/work" -w /work sbom-fixer:1.0.0 fix sbom.json --out out
```

In Windows cmd, use `%cd%` instead of `$PWD`:

```cmd
docker run --rm -v "%cd%:/work" -w /work sbom-fixer:1.0.0 fix sbom.json --out out
```

The image also contains sbomqs 2.1.2 for the quality score. The build does not download it: it copies the Linux archive from `tools\sbomqs\linux-amd64\`, checks it against `tools\sbomqs\SHA256SUMS` and extracts it to `/usr/local/bin/sbomqs`. Keep `ARG SBOMQS_VERSION` in the `Dockerfile` equal to `tools\sbomqs\VERSION` (a test checks this).

> **Rebuild after every update.** The image contains the tool itself. After `git pull`, run `docker build` again, otherwise Jenkins keeps the old commands.

---

## Step 07 – Verify the installation

Run these commands from the `sbom-fixer` folder with the environment activated.

**Check 1 – The version and the commands:**

```cmd
sbom-fixer --version
sbom-fixer --help
```

Expected: `sbom-fixer 1.0.0`, and the three commands `fix`, `fill-all` and `verify`.

**Check 2 – Fix the demo file:**

```cmd
sbom-fixer fix examples\demo-broken.cdx.json --out examples\out
```

Expected: `original : 13 schema error(s)`, `sbom : ... (schema-valid CycloneDX 1.6)`, `exit code : 1`, and three files in `examples\out`: `demo-broken.corrected.cdx.json`, `demo-broken.tech-notes.txt` and `demo-broken.suggestions.txt`. The same three files are in `examples\` for comparison.

**Check 3 – The quality score works offline:**

Open `examples\out\demo-broken.tech-notes.txt`. The summary line "NTIA minimum elements after the fix" shows an sbomqs score (for example `sbomqs 4.9`). If there is no score, see Step 13.6.

**Check 4 – (Developers only) Run the tests:**

```cmd
pytest
```

Expected: every test passes.

If all checks pass, the installation is complete.

---

## Step 08 – Daily workflow: fix an SBOM step by step

### 8.1 Generate the SBOM with your normal tool

Use the generator's own output option. Never write an SBOM with `>` in Windows PowerShell 5.1, because that creates a UTF-16 file.

```cmd
trivy fs --format cyclonedx --output build\sbom.json .
```

Best results come from generators that read the project (for .NET `dotnet CycloneDX MyApp.sln -o build`, for Java the CycloneDX Maven or Gradle plugin, for Node `cyclonedx-npm`): they write a purl for every package. Scans of binaries (DLL, JAR files) often give components without purls; `fix` recovers the purl when the file path is in a NuGet or Maven cache (Step 16, "DLL components").

### 8.2 Fix the file

```cmd
sbom-fixer fix build\sbom.json --out build\sbom-fixed
```

The terminal shows each step:

```text
sbom.json: cyclonedx 1.5 -> converted to CycloneDX 1.5
  original   : 0 schema error(s)
  ntia       : original FAIL - supplier 72/320, author missing
  validate   : converted file vs CycloneDX 1.5 schema: 0 error(s)
  tool       : Tool cyclonedx-java for the ecosystem java: 320 of 320 components
  changes    : 703 (323 WARN, 0 DATA_LOSS)
  sbom       : build\sbom-fixed\sbom.corrected.cdx.json (schema-valid CycloneDX 1.5)
  tech notes : build\sbom-fixed\sbom.tech-notes.txt
  suggestions: build\sbom-fixed\sbom.suggestions.txt
  exit code  : 1
```

Options:

| Option | Effect |
|---|---|
| `--out DIR` | Output folder (default: next to the input) |
| `--name FILE` | File name of the corrected SBOM (default `<name>.corrected.cdx.json`) |
| `--profile checkmarx-cli` | Profile (default `checkmarx`; `checkmarx-cli` for an upload with the cx CLI) |
| `--ecosystem java` | Force the ecosystem that names `metadata.tools` and missing purls, instead of detecting it (`dotnet`, `java`, `node`, `python`, `go`, `ruby`, `php`, `rust`, `erlang`, `dart`, `swift`, `cpp`, `perl`) |
| `--spec-version 1.6` | CycloneDX version of the converted file (default: CycloneDX keeps its version, SPDX becomes 1.6) |
| `--keep-converted` | Also write the step-1 file `<name>.converted.cdx.json` |
| `--no-audit` | Skip the NTIA / sbomqs audit (faster) |

PowerShell and cmd use the same command. In PowerShell a path with spaces needs quotes: `sbom-fixer fix "C:\My SBOMs\sbom.json" --out out`.

### 8.3 Read the exit code

| Terminal | Command |
|---|---|
| cmd | `echo %ERRORLEVEL%` |
| PowerShell | `$LASTEXITCODE` |
| Git Bash / Linux | `echo $?` |

0 and 1 mean the file is ready. 2 or higher means it is not (Step 10).

### 8.4 Read the two plain-text files

- `sbom.tech-notes.txt`: what was changed, with a summary (Step 09).
- `sbom.suggestions.txt`: what is wrong in the original and how to fix it at the generator. Fix these at the source so the next SBOM is correct on its own.

Open them in any editor; Notepad is enough.

### 8.5 Upload to Checkmarx

Upload `build\sbom-fixed\sbom.corrected.cdx.json`, never the original, through the portal or with the cx CLI (Step 12). To check a file on the verification project first:

```cmd
sbom-fixer verify build\sbom-fixed\sbom.corrected.cdx.json
```

Exit code 7 means the file is written but no component has a purl type Checkmarx scans (for example only `pkg:hex` or `pkg:generic`); Checkmarx would fail the scan, so do not upload it (Step 10).

### 8.6 Keep the original

The corrected file contains only what Checkmarx reads. Keep the original SBOM for audits and customers; it still has hashes, suppliers, descriptions and references.

### 8.7 Fill every schema field (any JSON)

`fill-all` takes **any JSON** and returns a schema-valid SBOM with every field the schema defines:

```bash
sbom-fixer fill-all sbom.json --out out/                                 # every schema field (required and optional)
sbom-fixer fill-all sbom.json --include-sensitive                        # also hashes, signatures, vulnerabilities, crypto
sbom-fixer fill-all components.json --spec cyclonedx --version 1.7       # plain JSON / pick the version
```

Steps, in this order:

1. **Read any JSON.** A JSON array becomes the components (SPDX: packages); an object without `bomFormat`/`spdxVersion` is CycloneDX (or `--spec`); a missing or unknown version becomes 1.6 / 2.3 (or `--version`); CycloneDX 1.8+ goes to 1.7 with the future hop. Only invalid JSON syntax and SPDX 3.0 are refused (exit 2).
2. **Derive required fields first** (so nothing is dropped), then run the repair and sanitize rules at that version (wrong case, wrong types, bad dates, licence shapes, bad hashes, unknown fields). Never a downgrade.
3. **Fill** each missing field, in this order of preference: `derived` from the SBOM (purl → name/version/group, bom-ref → purl, publisher ↔ supplier, hash length → alg, evidence → licenses/copyright, purl qualifiers → externalReferences, file name → root component, one dependency entry per component), `standard` (SPDX `NOASSERTION`, `CC0-1.0`), the schema `default`, an allowed `enum` value (`unknown`/`other` first), else a `dummy` that is obviously a placeholder: `PLACEHOLDER-<field>`, `https://placeholder.invalid/`, `placeholder@example.invalid`, `0`, `false`.
4. **Coerce** values the schema still rejects: convert when the meaning is clear (`"no"` → `false`, `"42"` → `42`, a bare string where an object is expected → `{"name": ...}`), otherwise remove and fill again. Additions that would make the document invalid are rolled back.

Never invented (only derived): identity fields (`purl`, `cpe`, `swid`, `omniborId`, `swhid`, SPDX `externalRefs`) and references to other elements (`ref`, `dependsOn`, `assemblies`, relationships). `fill-all` output is for review and tests, not for Checkmarx: it is about 50 times larger than the input. For a Checkmarx upload use `fix`.

Outputs: `<name>.fill-all.<cdx|spdx>.json` and `<name>.fill-all.<cdx|spdx>.report.json` with `prepared` (how the input was read), `repairs` (repair rules applied), `removed_invalid` (converted or removed values), `fills` (every added field with its source), `skipped` and `unresolved_required`. Exit 0 = schema-valid output, 1 = some errors could not be resolved (see the report), 2 = not JSON / unsupported format.

---

## Step 09 – Understand the output files

For an input `sbom.json`, `fix` writes exactly three files:

| File | What it is | Who uses it |
|---|---|---|
| `sbom.corrected.cdx.json` | The corrected SBOM: CycloneDX in the canonical form, UTF-8 without BOM, schema-valid | Upload to Checkmarx |
| `sbom.tech-notes.txt` | What was changed, with a summary | Reviewers, the platform team |
| `sbom.suggestions.txt` | Issues of the original and how to fix them at the generator | The team that owns the SBOM |

**Tech notes** sections:

| Section | What it tells you |
|---|---|
| Summary | Input (format, version, generator, component count), output (version, component and dependency counts), the tool name chosen and why, change counts, original schema errors, exit code, NTIA result of the original and of the corrected file, sbomqs score |
| NTIA minimum elements | The seven NTIA elements for the original and the corrected file, for example `Supplier name 72 / 320 ✗` |
| What was done | The three steps: conversion notes, the schema errors of the converted file grouped by cause, the output layout |
| Changes by rule | One row per rule: what it does, kind, count and an example. Kind **fix** = a problem of the input that was repaired; **layout** = reshaped for Checkmarx (data Checkmarx does not read is dropped from this copy only) |
| Not changed (findings) | Things the tool noticed but did not change |

**Suggestions** is one short table, one row per problem of the original:

| # | Missing / wrong | Count | Components | Fix |
|---:|---|---:|---|---|
| 1 | No licence | 13 | antlr-runtime@3.4, aos-common-models@SB3-0.0.1, api-commons@SB3-0.0.1, ... +8 more | Add the licence (SPDX id, e.g. MIT, Apache-2.0) to the package manifest (pom, csproj, package.json); for own libraries set it in the build. |
| 2 | Schema error at `/serialNumber`: 'ACME-0001' does not match '^urn:uuid:...' | 1 | - | Write the value in the expected pattern (for example urn:uuid:... for serialNumber). |
| 3 | No root component (metadata.component) | 1 | root component | Let the generator write the application itself as metadata.component (name, version). |
| 4 | No supplier (NTIA) | 248 of 320 | bean-matchers@0.13, lucene-sandbox@7.5.0, ... +243 more | Let the generator write the supplier of every package (from the package metadata: the organization element of the pom, authors in the nuspec or package.json); for own libraries set your company. |
| 5 | No SBOM author (NTIA) | - | - | Set metadata.authors (CycloneDX) or a Person/Organization creator (SPDX) to the team that produced the SBOM. |

Schema errors of the original come first (grouped by cause), then the data problems, then the NTIA minimum
elements the original misses, then pipeline hints. A problem
is listed once: the repair of a schema error is not listed again. With nothing to fix the file says
"No issues found. Nothing to fix."

Layout changes (dropped hashes, properties, qualifiers, the reshaped `metadata.tools`) are not listed in the suggestions: they are not mistakes of the original.

Change severities (in the tech notes):

| Severity | Meaning | Action |
|---|---|---|
| INFO | Fixed without changing meaning | None |
| WARN | Fixed, but an assumption was made, or data Checkmarx does not read was dropped | Review once |
| DATA_LOSS | A value the schema rejects was removed | Check it does not matter for scanning |

---

## Step 10 – Exit codes and what to do

| Code | Meaning | What to do |
|---|---|---|
| 0 | Already in the canonical form; output identical to input | Upload the output |
| 1 | Corrected | Upload the output; read the suggestions once |
| 2 | Cannot fix | Read the error: not JSON, unsupported format (XML, SPDX 3.0, tag-value), a version with no schema (CycloneDX 1.0/1.1, 2.x), or schema errors that could not be resolved |
| 3 | Data loss happened and the profile forbids it | Review the DATA_LOSS rows in the tech notes, or allow data loss in the profile |
| 4 | Quality gate failed | Fix NTIA gaps (supplier, author) at the source |
| 5 | `verify`: Checkmarx did not import the file | Check the JSON printed by `verify`; send the file to the platform team |
| 7 | Written, but no component has a purl type Checkmarx scans | Do not upload: Checkmarx would fail the scan ("no valid PURLs"). Regenerate the SBOM with ecosystem purls (Step 16) |

---

## Step 11 – Profiles and configuration

A profile says what the consumer accepts. Three are built in:

| Profile | Use | Behaviour |
|---|---|---|
| `checkmarx` (default) | File to upload to Checkmarx through the portal | Canonical form; keeps CycloneDX 1.2-1.7 at their own version; brings 1.8 and newer down to 1.7; Checkmarx purl rules and exit 7 |
| `checkmarx-cli` | File to upload with the cx CLI (Jenkins) | Same as checkmarx |
| `compliance` | Not for `fix` | Has no canonical section and is used only by the library and the tests; `fix` always writes the canonical form, also with this profile |

The built-in files are in `sbom_fixer\data\profiles\`. To change behaviour, copy one, edit it and pass its path:

```cmd
copy sbom_fixer\data\profiles\checkmarx.yaml my-profile.yaml
sbom-fixer fix build\sbom.json --profile my-profile.yaml --out build\sbom-fixed
```

Profile keys:

| Key | Values | Effect |
|---|---|---|
| `canonical.tools` | list of `{vendor, name, version}` | Default tool list (AppThreat cyclonedx-dotnet 0.8.0); `fix` replaces the name with the ecosystem's tool |
| `canonical.ecosystem_tools` | ecosystem: tool name | Tool names per ecosystem, for example `{java: cyclonedx-maven}` |
| `canonical.component_fields` | list | Fields kept on every component (default `bom-ref, type, name, version, purl, licenses`) |
| `canonical.default_license` | text | Licence for components without one (default `NOASSERTION`) |
| `canonical.keep_purl_qualifiers` | `true` / `false` | Keep `?type=jar` and other qualifiers (default `false`) |
| `canonical.purl_fallback` | `generic` / `none` | Missing purl that cannot be built: `pkg:generic/...` or no purl |
| `cyclonedx.accepted_versions` | list, for example `["1.4", "1.5"]` | Versions the consumer accepts; another version is kept with the warning VER-KEEP |
| `cyclonedx.max_version` | a version, for example `"1.7"` | Newer declared versions (1.8, 1.9, ...) are brought down to this one |
| `cyclonedx.future_versions` | `downgrade` / `reject` | `reject` gives exit 2 for a version newer than the tool knows |
| `purl.supported_types` | package manager: list of purl types | The purl types the consumer scans; enables the CXP rules |
| `purl.remap`, `purl.strip_url_qualifiers` | `true` / `false` | Remap unsupported types on evidence; remove URL qualifiers |
| `purl.unsupported_action`, `purl.os_package_action` | `keep` / `remove` | What to do with components Checkmarx skips |
| `purl.min_supported` | number (default 1) | Fewer supported components give exit 7 |
| `require_purl` | `warn` / `fail` | `fail` gives exit 2 when a component has no purl |
| `allow_data_loss` | `true` / `false` | `false` gives exit 3 on any DATA_LOSS change |
| `allow_downgrade` | `true` / `false` (default `false`) | `true` steps down one version when the file is not accepted |
| `quality.audit` | `report`, `gate`, `off` | `gate` turns quality failures into exit 4 |
| `quality.min_score`, `quality.score_tolerance` | numbers | sbomqs thresholds |

> **Provisional value:** CycloneDX 1.7 in the `checkmarx` profile is an assumption: the Checkmarx Scanning SBOMs page lists 1.0-1.6, another Checkmarx page says the portal reads 1.7. Upload the files in `corpus\minimal\` to your tenant once with `sbom-fixer verify`, fill in `docs\checkmarx-matrix.md`, and remove 1.7 from the profile if the portal rejects it.

Individual rules cannot be switched on or off by name. Profile keys control the rules that depend on them.

---

## Step 12 – Checkmarx integration

`verify` talks to a real Checkmarx tenant. Use a dedicated test project (default name `sbom-fixer-verification`), never a product project.

### 12.1 Set up once

**Setup 1.** Install the Checkmarx One CLI (`cx`) and check `cx version`.
**Setup 2.** Set the credentials as environment variables (in Jenkins, use the credential store):

| Variable | Value |
|---|---|
| `CX_BASE_URI` | Your Checkmarx One URL |
| `CX_TENANT` | Your tenant name |
| `CX_CLIENT_ID` and `CX_CLIENT_SECRET` | Service account (or `CX_APIKEY` instead) |
| `SBOM_FIXER_CX_PROJECT` | Optional; default `sbom-fixer-verification` |
| `CX_BIN` | Optional; path to `cx` if it is not on PATH |

**Setup 3.** Confirm the SBOM upload flags with `cx scan create --help`. If they differ from the tool's defaults, set `SBOM_FIXER_CX_SCAN_ARGS` (see README).

> **Untested defaults:** The `cx` flags and the results fields used by sbom-fixer are defaults that have not yet been run against a real tenant. Verify them on the first use and adjust the environment variables if needed.

### 12.2 Upload and check a file

```cmd
sbom-fixer verify build\sbom-fixed\sbom.corrected.cdx.json --expected-packages 120
```

`verify` uploads the file, waits for the import and prints the result as JSON (status, package count, errors). Exit 0 = imported (and the package count is within 5 % of `--expected-packages` when given), exit 5 = not imported.

---

## Step 13 – Quality audit (NTIA and sbomqs)

`fix` checks the NTIA minimum elements (supplier, component name, version, unique identifier, dependencies, SBOM author, timestamp) of the **original** and of the **corrected** file:

- console: `ntia : original FAIL - supplier 72/320, author missing` (or `PASS`);
- suggestions: one row per missing element, with the count, the components and the fix (for example "No supplier (NTIA) | 248 of 320 | bean-matchers@0.13, ...");
- tech notes: the summary lines and a table of the seven elements, original next to corrected.

The NTIA check is built in and always runs. The sbomqs score (0 to 10) of the corrected file is added to the tech notes; `--no-audit` skips sbomqs.

The canonical form keeps only what Checkmarx reads, so supplier and author are not in the corrected file and NTIA usually shows FAIL there. This does not matter for the Checkmarx import; keep the original for NTIA and audits. The suggestions file lists the gaps to fix at the source:

- **Author:** set `metadata.authors` to your team or organisation in the pipeline.
- **Supplier:** use a generator that reads package metadata.

### 13.1 sbomqs is bundled in the repository

The folder `tools\sbomqs\` holds sbomqs 2.1.2 by Interlynk (Apache-2.0 licence, `tools\sbomqs\LICENSE`):

| File | Content |
|---|---|
| `windows-amd64\sbomqs.exe` | Windows x64 binary, runs as is |
| `linux-amd64\sbomqs_2.1.2_Linux_x86_64.tar.gz` | Linux x64 release archive (extract once, see 13.4; Docker extracts it) |
| `VERSION` | Pinned version, 2.1.2 |
| `checksums.txt` | Checksums of the release archives, as published by Interlynk |
| `SHA256SUMS` | sha256 of every file in the folder (checked by the tests and the Docker build) |
| `README.md` | The same instructions in short |

sbomqs scores the file locally and does not need the network.

### 13.2 How sbom-fixer finds sbomqs

| Order | Source | When it is used |
|---|---|---|
| 1 | `SBOMQS_BIN` | The environment variable is set to the full path of a sbomqs executable |
| 2 | `tools\sbomqs\` in the repository | Windows x64: `windows-amd64\sbomqs.exe`. Linux x64: `linux-amd64/sbomqs` after extracting the archive |
| 3 | `sbomqs` on `PATH` | For example `/usr/local/bin/sbomqs` in the Docker image |

Without any of them `fix` still runs and the tech notes show no sbomqs score.

### 13.3 Use sbomqs directly

Windows (cmd or PowerShell, from the repository folder):

```cmd
tools\sbomqs\windows-amd64\sbomqs.exe version
tools\sbomqs\windows-amd64\sbomqs.exe score build\sbom.json
tools\sbomqs\windows-amd64\sbomqs.exe score build\sbom.json --json
```

The plain `score` output also shows the scores for industry profiles (Interlynk, NTIA, BSI TR-03183-2, OpenChain Telco) and a breakdown by category.

Linux x64 – extract once next to the archive; sbom-fixer then finds it automatically:

```bash
tar -xzf tools/sbomqs/linux-amd64/sbomqs_2.1.2_Linux_x86_64.tar.gz -C tools/sbomqs/linux-amd64 sbomqs
tools/sbomqs/linux-amd64/sbomqs score build/sbom.json
```

macOS and ARM machines: install sbomqs from github.com/interlynk-io/sbomqs/releases and set `SBOMQS_BIN`.

### 13.4 Check that the bundled copy is genuine

```cmd
cd tools\sbomqs
certutil -hashfile windows-amd64\sbomqs.exe SHA256
```

The hash must be the one on the `windows-amd64/sbomqs.exe` line of `SHA256SUMS`. In Git Bash or Linux: `cd tools/sbomqs && sha256sum -c SHA256SUMS`. The repository's `.gitattributes` stops Git from changing line endings in this folder, so the check also passes on Windows.

### 13.5 When there is no score

| Cause | Fix |
|---|---|
| sbomqs not found (not Windows x64, Linux archive not extracted, or the tools folder was not copied) | Run `tools\sbomqs\windows-amd64\sbomqs.exe version`; extract the Linux archive (13.3), copy `tools\sbomqs\`, or set `SBOMQS_BIN` |
| `--no-audit` was given | Run without it |
| Windows or the antivirus blocks `sbomqs.exe` | Unblock it once: `Unblock-File tools\sbomqs\windows-amd64\sbomqs.exe` in PowerShell; ask IT to allow the file, using its sha256 from `SHA256SUMS` |

---

## Step 14 – Use in Jenkins

Copy the stage from `jenkins\sbom-fix-stage.groovy` into the service Jenkinsfile, right after the SBOM is generated. It:

1. Runs `fix build/sbom.json --profile checkmarx-cli --out build/sbom-fixed` in the Docker image and uploads `build/sbom-fixed/sbom.corrected.cdx.json` with the cx CLI.
2. Fails the build only for exit code 2 or higher (7 = nothing Checkmarx can scan).
3. Archives the original and the three outputs, so the tech notes and suggestions are attached to every build.

Rebuild the Docker image after every update (Step 06). The nightly job in `jenkins\nightly-corpus.groovy` uploads the sample corpus to the verification project, so you notice when Checkmarx changes what it accepts. The full rollout guide is `docs\rollout.md`.

---

## Step 15 – Rule reference

### 15.1 How to read a rule ID

| Prefix | When it runs | Meaning |
|---|---|---|
| `REP-` | At the file's version | Repairs errors against the schema |
| `SAN-` | At the file's version (SAN-060 and SAN-090 once at the end) | Clean-ups for the importer (purl URLs, default tool, refs, licences, ...) |
| `CXP-` | At the file's version, in profiles with a purl section | Checkmarx purl rules: keep supported types, repair their format, remap unsupported types on evidence, report the rest |
| `CXN-` | Last, in profiles with a canonical section | The canonical form Checkmarx ingests (top level, metadata, components, purls, licences, dependencies) |
| `COERCE-001/002` | When errors remain after the rules | Convert a value of the wrong type, or remove a value the schema rejects |
| `PRUNE-001` | At the file's version | Removes a field the schema does not allow (DATA_LOSS) |
| `ENC-001/002/003` | At the start | File was UTF-8 with BOM, UTF-16, or not UTF-8 |
| `CDX-FWD-` | Once, for CycloneDX 1.8+ | Generic step down to max_version (1.7) |
| `CDX17-`, `CDX16-`, `CDX15-`, `CDX14-`, `SPDX23-` | Only with `allow_downgrade: true` | Converts fields that changed between two versions |

### 15.2 Rules every rule follows

1. **No guessing.** A value is changed only when the correct value is certain; otherwise a neutral value is used and the case is reported.
2. **Everything is logged.** Each change has a rule ID, a path, the old and new value, a severity and a reason.
3. **Same input, same output.** Running the tool twice gives the same result, and running it on its own output changes nothing.
4. **The version never changes** (except CycloneDX 1.8+ to 1.7, or with `allow_downgrade: true`).

### 15.3 Where the rules come from

The rule IDs are this tool's own naming. The rules are based on official sources, all stored in the tool folder:

| Source | Location |
|---|---|
| Official CycloneDX and SPDX JSON schemas (with GitHub commit IDs) | `sbom_fixer\data\schemas\`, `SOURCES.md` |
| Differences between schema versions, generated from those schemas | `docs\schema-diff-*.txt` |
| Full rule list generated from the code | `docs\rule-catalog.md` (`python tools\make_rule_catalog.py`) |
| Checkmarx purl and version research | `docs\checkmarx-version-purl-fix.md` |

Online references: CycloneDX specification (github.com/CycloneDX/specification), SPDX specification (spdx.github.io/spdx-spec), SPDX license list (spdx.org/licenses), package-url specification (github.com/package-url/purl-spec), and NTIA "Minimum Elements for a Software Bill of Materials" (ntia.gov).

### 15.4 All rules

<!-- RULES:START -->
| Rule | Case | Kind | Hop | Title | Description | Fix at the source |
|---|---|---|---|---|---|---|
| REP-001 | A | repair |  | $schema matches specVersion | $schema pointed to a different CycloneDX version than specVersion; $schema was corrected. | Make the generator write a $schema URL that matches specVersion, or omit $schema. |
| REP-002 | A | repair |  | specVersion is a string | specVersion was written as a number; it must be a string such as "1.5". |  |
| REP-003 | A | repair |  | Enum values in the exact form the schema expects | A value was written in the wrong case or spelling (for example 'Library' or 'sha256'); it was mapped to the one allowed value it matches. |  |
| REP-004 | A | repair |  | Scalars have the type the schema expects | A number or boolean was written where the schema expects a string (or the reverse); it was converted without changing its meaning. |  |
| REP-005 | A | repair |  | Remove null and empty values the schema rejects | A field was null or empty where the schema requires content; the field was removed. |  |
| REP-006 | A | repair |  | Fill or remove entries that miss required fields | An entry missed a required field. It was filled only when the value is unambiguous (for example a name taken from the purl); otherwise the entry was removed or reported. | Check why the generator writes components without name or type. |
| REP-007 | A | repair |  | serialNumber is a urn:uuid | serialNumber was not in urn:uuid form; a deterministic UUID was written and the old value kept in metadata.properties. |  |
| REP-008 | A | repair |  | Timestamps are ISO 8601 date-times | A timestamp was not a valid ISO 8601 date-time; it was rewritten in UTC (a missing timezone is assumed to be UTC and reported). |  |
| REP-009 | A | repair |  | URLs are valid IRI references | A URL contained characters that are not allowed (for example spaces); they were percent-encoded. External references whose URL could not be repaired were removed. |  |
| REP-010 | A | repair |  | License entries have a valid structure | A licenses array was malformed (plain strings, unwrapped objects, id and name together, non-SPDX IDs, or expressions mixed with license objects); it was restructured without dropping license text. | Use SPDX license IDs (https://spdx.org/licenses/) in the build metadata. |
| REP-011 | A | repair |  | Hash values match their algorithm | A hash value did not match its algorithm (wrong length or characters) or used an unknown algorithm; that hash was removed. |  |
| REP-012 | A | repair |  | Arrays where the schema expects arrays | A single value was written where the schema expects an array; it was wrapped in an array. |  |
| SAN-001 | C | sanitize |  | Remove null values | null values are invalid in every SBOM schema; they were removed. |  |
| SAN-002 | C | sanitize |  | Remove empty arrays and objects | Empty arrays and objects in optional fields were removed (dependsOn is kept, because an empty dependsOn means 'no dependencies'). |  |
| SAN-003 | C | sanitize |  | Add a serialNumber | The BOM had no serialNumber; a deterministic urn:uuid derived from the input was added. |  |
| SAN-004 | C | sanitize |  | Timestamp in UTC | metadata.timestamp had a timezone offset; it was normalized to UTC 'Z' form. A missing timestamp is reported, never invented. |  |
| SAN-009 | C | sanitize |  | purl written as a URL | The purl field held a web URL (https://...), which is not a purl. A registry URL was converted to the exact purl; any other URL was moved to externalReferences and the component reported as not scannable. | Write a package URL (pkg:type/namespace/name@version) in the purl field; put web links in externalReferences. |
| SAN-010 | C | sanitize |  | purls parse | A purl did not parse; characters were percent-encoded where that made it valid, otherwise the purl was removed and the component reported as not scannable. | Report the generator bug; purls must follow the package-url specification. |
| SAN-011 | C | sanitize |  | Build missing purls when the ecosystem is certain | A component had no purl. One was built when the ecosystem was certain (bom-ref is a purl, or a generator property names the package type); otherwise the component is reported as not scannable. | Use a generator that writes purls for every package component. |
| SAN-012 | C | sanitize |  | Report purl types scanners usually ignore | Components with purl types such as generic or github are kept but counted separately, because SCA scanners usually do not match them. |  |
| SAN-013 | C | sanitize |  | Add a default tool when none is named | The SBOM named no generating tool (CycloneDX metadata.tools, SPDX creationInfo creators 'Tool:'); sbom-fixer was added as the default tool, because some importers expect at least one. | Let the generator record itself in metadata.tools (CycloneDX) or creationInfo.creators (SPDX). |
| SAN-020 | C | sanitize |  | Unique bom-refs | Several components shared one bom-ref; duplicates were renamed with a #2, #3 suffix (dependencies keep pointing to the first). |  |
| SAN-021 | C | sanitize |  | Remove dependency edges that point to nothing | Dependency entries referred to bom-refs that do not exist in the document; those edges were removed. | The generator writes dependency refs for components it does not list; report it upstream. |
| SAN-022 | C | sanitize |  | Merge components with the same purl | Top-level components with an identical purl were merged into the first one; dependency references were rewritten to it. |  |
| SAN-030 | C | sanitize |  | License names that are really SPDX IDs | A license name was an SPDX ID or an unambiguous alias of one (for example 'Apache 2.0'); it was written as the SPDX id. | Use SPDX license IDs in package metadata. |
| SAN-031 | C | sanitize |  | License expressions parse | A license expression did not parse as SPDX; it was normalized when every license in it is known, otherwise kept as a license name. |  |
| SAN-050 | C | sanitize |  | Flatten nested components | Nested components were moved to the top-level components list, which the profile requires. |  |
| SAN-060 | C | final |  | Remove an invalidated signature | The document carried a signature; any change invalidates it, so it was removed. Re-sign the output if signatures are required. |  |
| SAN-090 | C | final |  | Record sbom-fixer provenance | sbom-fixer was added to metadata.tools and metadata.properties record the source version and hash, so the output can be traced to its original. |  |
| CXP-001 | C | sanitize |  | purl type in lower case | The purl type (or the 'pkg:' prefix) was not lower case; it was lower-cased as the purl specification requires. |  |
| CXP-002 | C | sanitize |  | npm scope percent-encoded | An npm scope was written as '@scope'; Checkmarx only matches the encoded form '%40scope', so '@' was percent-encoded. | Use a generator that writes scoped npm purls as pkg:npm/%40scope/name@version. |
| CXP-010 | C | sanitize |  | github purl of a Go module remapped to golang | A Go module was identified as pkg:github (not scanned by Checkmarx); the generator marks it as a Go module, so it was rewritten to pkg:golang/github.com/... The original purl is kept in sbom-fixer:original-purl. | Configure the generator to write pkg:golang purls for Go modules. |
| CXP-011 | C | sanitize |  | generic purl remapped from the generator's package type | A pkg:generic purl (not scanned by Checkmarx) belonged to a component whose generator property names the ecosystem; it was rebuilt as that ecosystem's purl from the component's name, group and version. | Configure the generator to write ecosystem purls instead of pkg:generic. |
| CXP-012 | C | sanitize |  | generic purl remapped from its registry URL | A pkg:generic purl carried a download_url / repository_url / vcs_url on a known package registry (Maven Central, npm, PyPI, NuGet, RubyGems, Go proxy, pub.dev); it was rewritten to that registry's purl. | Configure the generator to write ecosystem purls instead of pkg:generic. |
| CXP-013 | C | sanitize |  | Non-standard purl type with one meaning | The purl used a type that is not in the purl specification but has exactly one meaning (nodejs/node -> npm, dotnet/nupkg -> nuget, jar -> maven when a groupId is present); the type was replaced. | Use the purl specification's type names (npm, nuget, maven). |
| CXP-003 | C | sanitize |  | purl version taken from the component | A supported purl had no version, which makes Checkmarx check the latest version instead; the component's own version was added. Without any version the component is reported (results may not match the version in use). | Make the generator write the resolved version into every purl. |
| CXP-004 | C | sanitize |  | Maven purl groupId | A Maven-family purl (maven, gradle, sbt, ivy) had no namespace (groupId), so Checkmarx cannot look it up; the component's group was used. Without a group the component is reported. | Maven purls need the groupId as namespace: pkg:maven/<groupId>/<artifactId>@<version>. |
| CXP-005 | C | sanitize |  | URL qualifiers removed from the purl | A supported purl carried URL-valued qualifiers or subpath (for example repository_url=https://...). Checkmarx documents purls as pkg:type/[namespace/]name@version and matches by name and version, so they were removed; the original purl is kept in sbom-fixer:original-purl. |  |
| CXP-020 | C | sanitize |  | purl types Checkmarx does not scan | The component's purl type is not in the Checkmarx supported list (for example cargo, hex, generic, docker, github); Checkmarx skips it silently. It is kept and listed (or removed when unsupported_action: remove). | Scan ecosystems Checkmarx does not support (for example Rust crates) with another tool. |
| CXP-021 | C | sanitize |  | OS packages | The component is an operating-system package (rpm, apk, alpm, or deb from a Linux distribution). Checkmarx does not scan OS packages and reads deb as a C++ (Conan) package, so results for it may be wrong. It is kept and listed (or removed when os_package_action: remove). | Scan container and OS packages with a container scanner (Checkmarx Container Security). |
| CXP-030 | C | sanitize |  | Components identified only by CPE or hash | The component has no purl, only a CPE, SWID or hash; Checkmarx skips such components silently. A purl is never derived from a CPE, because the mapping is not reliable. | Use a generator that writes purls for every package component. |
| CXP-051 | C | sanitize |  | SPDX direct dependencies | The SPDX document has no DESCRIBES or DEPENDS_ON relationship; Checkmarx then treats every package as a direct dependency. Relationships are never invented. | Declare DESCRIBES / DEPENDS_ON from the main package to each direct dependency. |
| CXN-001 | C | canonical |  | All components at the top level | Components nested inside other components (or inside metadata.component) were moved to the top-level components list; Checkmarx reads only the top level. |  |
| CXN-020 | C | canonical |  | purl in the form Checkmarx matches | Every component got a purl of the form pkg:type/[namespace/]name@version: the type in lower case, qualifiers and subpath removed (Checkmarx does not use them), the version filled from the component. A missing (or generic) purl of a DLL/JAR in a NuGet or Maven cache path became that package's purl. A missing purl was built from the bom-ref, the component's registry URL, or the SBOM's one ecosystem (Erlang -> pkg:hex, .NET -> pkg:nuget, ...; not when the SBOM mixes ecosystems, and never for a file name such as Foo.dll), otherwise as pkg:generic/<name>@<version> (Checkmarx skips generic components but no purl is ever null). A purl never holds a web URL (http/https): URLs are converted to the registry purl or dropped. | Let the generator write a plain purl (pkg:type/namespace/name@version) for every component. |
| CXN-030 | C | canonical |  | Every component has a licence | Licences were reduced to the SPDX id or name (or one expression); licence text, URLs and other details were dropped. A component without a licence got NOASSERTION, because Checkmarx rejects empty licence arrays. | Make the generator record the licence of every package (SPDX id such as MIT or Apache-2.0); packages without licence metadata need it added in the package manifest. |
| CXN-040 | C | canonical |  | Components reduced to the fields Checkmarx reads | Each component was reduced to bom-ref, type, name, version, purl and licenses (profile key canonical.component_fields). Hashes, evidence, properties, externalReferences, descriptions and the other fields Checkmarx does not read were dropped; the original SBOM still has them. A missing bom-ref (or one holding a web URL, renamed in dependencies too) was set to the purl (or the name), a missing type to library. | Give every component a bom-ref (cdxgen uses the purl) and a type; never a web URL as bom-ref. |
| CXN-011 | C | canonical |  | metadata is timestamp, tools and component | metadata was reduced to timestamp (kept; added when missing), tools (the tool list of the profile, by default cyclonedx-dotnet in the 1.4 array form, which Checkmarx reads in every version; with tool_per_ecosystem the name follows the detected ecosystem: cyclonedx-java, cyclonedx-node, ...) and the root component (kept as it was; when missing it is added with the fields the schema requires left blank: type application, name "", and version "" for CycloneDX 1.2/1.3). Other metadata (authors, lifecycles, properties, ...) was dropped. | Let the generator write metadata.component: the application the SBOM describes, with name and version. |
| CXN-050 | C | canonical |  | Dependencies point only at existing components | dependencies entries were reduced to ref and dependsOn. An entry whose ref is not a component (or the root component) was removed; dependsOn values that are not a component bom-ref, self-references and duplicates were removed; entries with the same ref were merged. | List dependencies only between components that are in the SBOM, without self-dependencies and with one entry per ref. |
| CXN-010 | C | canonical |  | Top level is bomFormat, specVersion, serialNumber, version, metadata, components, dependencies | Top-level sections Checkmarx does not read (services, compositions, vulnerabilities, annotations, externalReferences, properties, formulation, declarations, definitions, signature, $schema) were dropped. bomFormat and specVersion are kept as they were; serialNumber and version were added when missing; components is always present (an empty list when there are none). | Let the generator write serialNumber (urn:uuid:...), version 1 and a components list. |
| CDX14-001 | B | hop | 1.4 -> 1.3 | component.version is required in 1.3 | CycloneDX 1.3 requires a component version; it was taken from the purl, or set to 'unknown' and reported. |  |
| CDX14-002 | B | hop | 1.4 -> 1.3 | Remove vulnerabilities | CycloneDX 1.3 has no vulnerabilities section; it was removed (the scanner computes its own findings). |  |
| CDX14-003 | B | hop | 1.4 -> 1.3 | Remove signatures and release notes | signature and releaseNotes (1.4) do not exist in 1.3 and were removed. |  |
| CDX14-004 | B | hop | 1.4 -> 1.3 | 1.4-only values | Values added in 1.4 were mapped: the external reference type release-notes became other; tool externalReferences were removed. |  |
| CDX15-001 | B | hop | 1.5 -> 1.4 | metadata.tools object to legacy array | metadata.tools (and vulnerabilities[].tools) in the 1.5 object form {components, services} were converted to the 1.4 array of {vendor, name, version}. |  |
| CDX15-001P | C | sanitize |  | metadata.tools as legacy array for importers that need it | The profile sets tools_form: legacy-array, so metadata.tools was written in the legacy array form even though this version also accepts the object form. |  |
| CDX15-002 | B | hop | 1.5 -> 1.4 | metadata.lifecycles to property | metadata.lifecycles (1.5) was kept as the property sbom-fixer:lifecycles. |  |
| CDX15-003 | B | hop | 1.5 -> 1.4 | Remove formulation and annotations | Top-level formulation and annotations (1.5) have no 1.4 equivalent and were removed. |  |
| CDX15-004 | B | hop | 1.5 -> 1.4 | 1.5-only component types | Component types added in 1.5 were mapped to their nearest 1.4 type (device-driver to device, data to file, platform and machine-learning-model to application); the original type is kept in a property. |  |
| CDX15-005 | B | hop | 1.5 -> 1.4 | Remove modelCard and component data | component.modelCard and component.data (1.5) were removed. |  |
| CDX15-006 | B | hop | 1.5 -> 1.4 | Remove evidence identity, occurrences and callstack | evidence.identity, occurrences and callstack (1.5) were removed; evidence.licenses and copyright were kept. |  |
| CDX15-007 | B | hop | 1.5 -> 1.4 | Remove 1.5-only vulnerability fields | Vulnerability fields rejected, proofOfConcept and workaround (1.5) were removed. |  |
| CDX15-008 | B | hop | 1.5 -> 1.4 | 1.5-only external reference types to other | External reference types added in 1.5 became 'other'; the original type is kept in comment. |  |
| CDX15-009 | B | hop | 1.5 -> 1.4 | Root properties to metadata.properties | CycloneDX 1.4 has no root-level properties; they were moved to metadata.properties. |  |
| CDX15-010 | B | hop | 1.5 -> 1.4 | BOM version is required | CycloneDX 1.4 and older require the root field version (the BOM revision); it was set to 1. |  |
| CDX15-011 | B | hop | 1.5 -> 1.4 | 1.5-only enum values | Enum values added in 1.5 were mapped: composition aggregate incomplete_* became incomplete, rating methods CVSSv4 and SSVC became other. |  |
| CDX16-001 | B | hop | 1.6 -> 1.5 | metadata.manufacturer to metadata.manufacture | metadata.manufacturer (1.6) was renamed to metadata.manufacture, its 1.5 equivalent. |  |
| CDX16-002 | B | hop | 1.6 -> 1.5 | component.manufacturer to supplier | component.manufacturer (1.6) was moved to supplier when supplier was empty, otherwise dropped. |  |
| CDX16-003 | B | hop | 1.6 -> 1.5 | component.authors to author | component.authors (1.6, a list of contacts) was joined into the 1.5 string field author. |  |
| CDX16-004 | B | hop | 1.6 -> 1.5 | evidence.identity array to single object | evidence.identity was an array (1.6 form); the entry with the highest confidence was kept as the single 1.5 object. |  |
| CDX16-005 | B | hop | 1.6 -> 1.5 | Remove license acknowledgement | license acknowledgement (declared/concluded, 1.6) does not exist in 1.5 and was removed. |  |
| CDX16-006 | B | hop | 1.6 -> 1.5 | omniborId and swhid to properties | component.omniborId and swhid (1.6) were kept as properties sbom-fixer:omniborId / sbom-fixer:swhid. |  |
| CDX16-007 | B | hop | 1.6 -> 1.5 | tags to property | tags (1.6) on components and services were kept as one property sbom-fixer:tags. |  |
| CDX16-008 | B | hop | 1.6 -> 1.5 | Remove declarations and definitions | Top-level declarations and definitions (1.6 attestations and standards) have no 1.5 equivalent and were removed. |  |
| CDX16-009 | B | hop | 1.6 -> 1.5 | Remove dependencies[].provides | dependencies[].provides (1.6) does not exist in 1.5 and was removed. |  |
| CDX16-010 | B | hop | 1.6 -> 1.5 | Remove cryptographic-asset components | Components of type cryptographic-asset (1.6) are not packages a scanner can match and were removed with their dependency edges. |  |
| CDX16-011 | B | hop | 1.6 -> 1.5 | 1.6-only external reference types to other | External reference types added in 1.6 (source-distribution, digital-signature, electronic-signature, rfc-9116) became 'other'; the original type is kept in comment. |  |
| CDX17-001 | B | hop | 1.7 -> 1.6 | component.versionRange and isExternal to properties | CycloneDX 1.7 component fields versionRange and isExternal do not exist in 1.6; they were kept as properties. |  |
| CDX17-002 | B | hop | 1.7 -> 1.6 | Remove patent assertions, citations and distribution constraints | CycloneDX 1.7 patent assertions, citations and metadata.distributionConstraints have no 1.6 equivalent and were removed. |  |
| CDX17-ENUM | B | hop | 1.7 -> 1.6 | 1.7-only enum values | Enum values that exist only in CycloneDX 1.7 were mapped: new external reference types became 'other' (original kept in comment); Streebog hashes were removed. |  |
| CDX-FWD-001 | B | hop |  | Newer CycloneDX version brought down to max_version | The SBOM declared a CycloneDX version newer than this tool knows (for example 1.8); specVersion was set to the profile's max_version and the document was checked against that schema (generic future hop). | If the generator has a spec-version option, set it to a version Checkmarx accepts (1.6 or 1.7). |
| CDX-FWD-002 | B | hop |  | Fields unknown to the target version kept as properties | A field that the target CycloneDX version does not define was moved into a property sbom-fixer:cdxNN:<field> where the object allows properties; otherwise it was removed (DATA_LOSS). |  |
| CDX-FWD-003 | B | hop |  | Enum values unknown to the target version | A value that the target CycloneDX version does not allow (a new enum value) became 'other' where the schema allows it, with the original value kept; otherwise the value was removed (DATA_LOSS). |  |
| SPDX23-001 | B | hop | 2.3 -> 2.2 | 2.3-only package fields to comment | Package fields added in SPDX 2.3 (primaryPackagePurpose, releaseDate, builtDate, validUntilDate) were moved into the package comment. |  |
| SPDX23-002 | B | hop | 2.3 -> 2.2 | 2.3-only relationship types to OTHER | Relationship types added in SPDX 2.3 (REQUIREMENT_DESCRIPTION_FOR, SPECIFICATION_FOR) became OTHER with the original type in the comment. |  |
<!-- RULES:END -->

---

## Step 16 – Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `'sbom-fixer' is not recognized` in cmd | The virtual environment is not activated | Run `.venv\Scripts\activate.bat`, or use the full path to `.venv\Scripts\sbom-fixer.exe` (Step 4.5) |
| `No such command 'check'` (or `audit`, `rules`, `bisect`, `fill-required`, `cdxgen-fix`) | These commands were removed | Use `fix` (it validates, repairs and audits in one run); `fix` is the former `cdxgen-fix` |
| PowerShell: "running scripts is disabled" | Execution policy | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `python` opens the Microsoft Store | Windows app alias | Install Python from python.org with "Add to PATH", or use `py -3.12 -m venv .venv` |
| pip: SSL or proxy errors | Corporate network | Set `HTTPS_PROXY`, use the internal mirror (`pip install --index-url ...`), or use the offline install (Step 4.6) |
| `.venv` copied from another machine does not work | Absolute paths inside `.venv` | Delete `.venv` and create it again (Step 4.2) |
| Exit 2 with "not valid JSON" | A syntax error, often a comma left after deleting a field by hand (`],` before `}`) | Fix the JSON at the line and column printed, or regenerate the SBOM |
| Exit 2 with "XML ... not supported" | CycloneDX XML input | Regenerate the SBOM as JSON |
| Exit 2 with "SPDX 3.0" or "tag-value" | Unsupported SPDX format | Regenerate as CycloneDX JSON or SPDX 2.3 JSON |
| Exit 2 with "has no vendored schema" | CycloneDX 1.0 / 1.1 (XML-only versions) or 2.x | Regenerate as CycloneDX JSON 1.2 or newer |
| `metadata.component` has `"name": ""` | The original has no root component | Let the generator write the application as metadata.component (see the suggestions file) |
| Components get `pkg:generic/...` | No purl, no registry URL, and the SBOM mixes ecosystems (or has none) | Use a generator that writes purls; or force the ecosystem with `--ecosystem` when the SBOM has only one |
| DLL components (`Foo.dll`, version `1.0.0.0`) stay `pkg:generic` | The SBOM was made from binaries and the file path is not in a package cache; the assembly version is not the NuGet package version | `fix` uses the path when it is in `.nuget/packages/<id>/<version>/`, `packages/<Id>.<Version>/lib/`, `.m2/repository/` or the Gradle cache (properties such as `syft:location:0:path` or `evidence.occurrences`). Otherwise generate from the project (`dotnet CycloneDX MyApp.sln`), or scan the publish folder with Syft, which reads `*.deps.json`. Company DLLs stay generic: they are in no public registry |
| Exit 7 for an Erlang or Rust SBOM | Checkmarx does not scan `pkg:hex` or `pkg:cargo` | Scan these ecosystems with another tool |
| Quality score missing | sbomqs not found, or `--no-audit` | See Step 13.5 |
| `sha256sum -c SHA256SUMS` fails in `tools\sbomqs` | A file was changed, or line endings were converted by a copy without .gitattributes | `git checkout -- tools/sbomqs`, or `python tools\vendor_sbomqs.py 2.1.2` |
| Checkmarx still rejects the corrected file | The importer needs something the schema does not require | Run `sbom-fixer verify` on the file and send the output and the file to the platform team so a rule can be added |
| A large SBOM is slow | Very large files | Progress lines appear from 1 MB; `--no-audit` saves the sbomqs run |

---

## Step 17 – Updating the tool

### 17.1 Install a newer version

```cmd
cd C:\Tools\sbom-fixer
git pull
.venv\Scripts\activate.bat
pip install .
sbom-fixer --version
```

Check `CHANGELOG.md`; any release that adds or changes rules can change outputs. Rebuild the Docker image for Jenkins (Step 06).

### 17.2 When CycloneDX releases a new version

1. `python tools\vendor_schemas.py` downloads the latest official schemas.
2. Compare the new schema with the previous one (`docs\schema-diff-*.txt` shows the format).
3. Add sample files to `corpus\`.
4. Until then, the checkmarx profiles already bring the new version down to 1.7 with the generic future hop (rules CDX-FWD-001 to 003) and report every field they move or remove.

### 17.3 When Checkmarx supports a newer version

Add the version to `accepted_versions` in the `checkmarx` profile so files at that version no longer get the VER-KEEP warning. No code change is needed (fix never changes the version anyway).

### 17.4 When a new sbomqs is released

1. `python tools\vendor_sbomqs.py 2.2.0` (example version) downloads the release, checks it against the published checksums and replaces the files in `tools\sbomqs\`.
2. Set `ARG SBOMQS_VERSION` in the `Dockerfile` to the same version.
3. Run `pytest`. The score JSON can change between sbomqs releases; `sbom_fixer\audit\sbomqs.py` reads `sbom_quality_score` (2.x) and `avg_score` (1.x).
4. Add a line to `CHANGELOG.md`. Scores can differ between sbomqs versions, so compare scores only from the same version.

### 17.5 Adding a new rule (developers)

1. Add a file that shows the problem to `corpus\`.
2. Decide the prefix and the next free rule ID.
3. Write a test with the file before and after the fix.
4. Implement the rule; edit the document only through the change log. Give it a `source_fix` so the suggestions file can say how to fix it at the source.
5. Write the plain-language description that appears in the tech notes.
6. Run `pytest` and the whole corpus.
7. Regenerate `docs\rule-catalog.md` with `python tools\make_rule_catalog.py`.

---

## Step 18 – Command cheat sheet

| Task | Command |
|---|---|
| Activate (cmd) | `.venv\Scripts\activate.bat` |
| Version | `sbom-fixer --version` |
| Help | `sbom-fixer --help`, `sbom-fixer fix --help` |
| Correct an SBOM | `sbom-fixer fix sbom.json --out out` |
| Correct, own file name | `sbom-fixer fix sbom.json --out out --name app.cdx.json` |
| Correct for the cx CLI | `sbom-fixer fix sbom.json --profile checkmarx-cli --out out` |
| Correct, force the ecosystem | `sbom-fixer fix sbom.json --ecosystem java --out out` |
| SPDX to CycloneDX 1.5 | `sbom-fixer fix sbom.spdx.json --spec-version 1.5 --out out` |
| Keep the converted file too | `sbom-fixer fix sbom.json --keep-converted --out out` |
| Faster, without the audit | `sbom-fixer fix sbom.json --no-audit --out out` |
| Every schema field, any JSON | `sbom-fixer fill-all any.json --out out` |
| Upload and verify | `sbom-fixer verify out\sbom.corrected.cdx.json` |
| sbomqs score directly | `tools\sbomqs\windows-amd64\sbomqs.exe score sbom.json` |
| Check the bundled sbomqs | `certutil -hashfile tools\sbomqs\windows-amd64\sbomqs.exe SHA256` |
| Rule catalog | `python tools\make_rule_catalog.py` |
| Exit code (cmd / PowerShell) | `echo %ERRORLEVEL%` / `$LASTEXITCODE` |
