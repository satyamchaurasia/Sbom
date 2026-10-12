# Suggestions: fix these in demo-broken.cdx.json

sbom-fixer worked around the issues below in the output. Fix them in the generator or the build so the original SBOM is correct on its own.

**13 schema error(s) in the original and 22 value(s) sbom-fixer had to repair (17 kind(s)).**

## 1. Schema errors in the original (cyclonedx 1.6)

| Count | Keyword | Where | Example | How to fix |
|---:|---|---|---|---|
| 2 | enum | `/components/*/hashes/*/alg` | 'sha256' is not one of ['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA... | Use one of the values the schema allows. |
| 2 | type | `/components/*/version` | 2.11 is not of type 'string' | Write the value with the JSON type the schema expects (string, number, array, object). |
| 1 | additionalProperties | `/components/*` | Additional properties are not allowed ('x-scanner-internal' was unexpected) | Remove fields that are not part of this CycloneDX / SPDX version. |
| 1 | type | `/components/*/description` | None is not of type 'string' | Write the value with the JSON type the schema expects (string, number, array, object). |
| 1 | format | `/components/*/externalReferences/*/url` | 'https://registry.npmjs.org/lodash/-/lodash 4.17.20.tgz' is not a 'iri-refere... | Write the value in the expected format (for example date-time, iri-reference, email). |
| 1 | pattern | `/components/*/hashes/*/content` | 'not-a-real-hash' does not match '^([a-fA-F0-9]{32}\|[a-fA-F0-9]{40}\|[a-fA-F... | Write the value in the expected pattern (for example urn:uuid:... for serialNumber). |
| 1 | additionalProperties | `/components/*/licenses/*` | Additional properties are not allowed ('license' was unexpected) | Remove fields that are not part of this CycloneDX / SPDX version. |
| 1 | enum | `/components/*/type` | 'Library' is not one of ['application', 'framework', 'library', 'container', ... | Use one of the values the schema allows. |
| 1 | type | `/components/*/licenses/*` | 'MIT' is not of type 'object' | Write the value with the JSON type the schema expects (string, number, array, object). |
| 1 | format | `/metadata/timestamp` | '2026-10-02 10:00' is not a 'date-time' | Write the value in the expected format (for example date-time, iri-reference, email). |
| 1 | pattern | `/serialNumber` | 'DEMO-0001' does not match '^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-... | Write the value in the expected pattern (for example urn:uuid:... for serialNumber). |

## 2. Data problems sbom-fixer had to repair

### REP-003: Enum values in the exact form the schema expects (3)

- 1 x 'sha256' is not an allowed value; the schema expects 'SHA-256'
- 1 x 'sha-1' is not an allowed value; the schema expects 'SHA-1'
- 1 x 'Library' is not an allowed value; the schema expects 'library'
- Examples: `/components/0/hashes/0/alg`: sha256 -> SHA-256; `/components/0/hashes/1/alg`: sha-1 -> SHA-1; `/components/0/type`: Library -> library

### REP-005: Remove null and empty values the schema rejects (2)

- 1 x Empty version taken from the purl
- 1 x Value was null or empty
- Examples: `/components/3/version` = 1.3.0; `/components/0/description` removed: null
- **Fix at the source:** Leave a field out instead of writing null or an empty value.

### REP-010: License entries have a valid structure (2)

- 1 x 'Apache 2.0' is not an SPDX license ID; it matches 'Apache-2.0'
- 1 x A license was written as a plain string
- Examples: `/components/0/licenses/0/license/id`: Apache 2.0 -> Apache-2.0; `/components/2/licenses/0`: MIT -> {"license": {"id": "MIT"}}
- **Fix at the source:** Use SPDX license IDs (https://spdx.org/licenses/) in the build metadata.

### SAN-021: Remove dependency edges that point to nothing (2)

- 1 x 'pkg:npm/does-not-exist@9.9.9' does not exist
- 1 x ref 'ghost-component' does not exist
- Examples: `/dependencies/0/dependsOn/1` removed: pkg:npm/does-not-exist@9.9.9; `/dependencies/1` removed: {"ref": "ghost-component", "dependsOn": []}
- **Fix at the source:** The generator writes dependency refs for components it does not list; report it upstream.

### CXN-011: metadata is timestamp, tools and component (1)

- 1 x No metadata.component; added with the required fields blank
- Examples: `/metadata/component` = {"type": "application", "name": ""}
- **Fix at the source:** Let the generator write metadata.component: the application the SBOM describes, with name and version.

### CXN-030: Every component has a licence (1)

- 1 x No licence; NOASSERTION added
- Examples: `/components/2/licenses` = [{"license": {"name": "NOASSERTION"}}]
- **Fix at the source:** Make the generator record the licence of every package (SPDX id such as MIT or Apache-2.0); packages without licence metadata need it added in the package manifest.

### PRUNE-001: Fields the schema of this version does not allow (1)

- 1 x Field is not allowed by the schema of the current version
- Examples: `/components/0/x-scanner-internal` removed: {"scanId": 991}
- **Fix at the source:** Write only fields of this CycloneDX / SPDX version; custom data belongs in properties.

### REP-001: $schema matches specVersion (1)

- 1 x $schema must be http://cyclonedx.org/schema/bom-1.6.schema.json for specVersion 1.6
- Examples: `/$schema`: http://cyclonedx.org/schema/bom-1.4.schema... -> http://cyclonedx.org/schema/bom-1.6.schema...
- **Fix at the source:** Make the generator write a $schema URL that matches specVersion, or omit $schema.

### REP-004: Scalars have the type the schema expects (1)

- 1 x Schema expects string
- Examples: `/components/2/version`: 2.11 -> 2.11

### REP-007: serialNumber is a urn:uuid (1)

- 1 x serialNumber must match urn:uuid:<uuid>
- Examples: `/serialNumber`: DEMO-0001 -> urn:uuid:e6a2b683-542f-5212-8766-80162174bc8e
- **Fix at the source:** Write serialNumber as urn:uuid:<uuid>.

### REP-008: Timestamps are ISO 8601 date-times (1)

- 1 x No timezone given; UTC assumed
- Examples: `/metadata/timestamp`: 2026-10-02 10:00 -> 2026-10-02T10:00:00Z

### REP-009: URLs are valid IRI references (1)

- 1 x Characters not allowed in a URL were percent-encoded
- Examples: `/components/0/externalReferences/0/url`: https://registry.npmjs.org/lodash/-/lodash... -> https://registry.npmjs.org/lodash/-/lodash...

### REP-011: Hash values match their algorithm (1)

- 1 x Hash content does not match its algorithm
- Examples: `/components/0/hashes/0` removed: {"alg": "SHA-256", "content": "not-a-real-hash"}

### SAN-011: Build missing purls when the ecosystem is certain (1)

- 1 x purl built from verified component data
- Examples: `/components/2/purl` = pkg:maven/commons-io/commons-io@2.11
- **Fix at the source:** Use a generator that writes purls for every package component.

### SAN-013: Add a default tool when none is named (1)

- 1 x No tool named; sbom-fixer added as the default tool (object form)
- Examples: `/metadata/tools` = {"components": [{"type": "application", "name": "sbom-fix...
- **Fix at the source:** Let the generator record itself in metadata.tools (CycloneDX) or creationInfo.creators (SPDX).

### SAN-020: Unique bom-refs (1)

- 1 x bom-ref must be unique
- Examples: `/components/1/bom-ref`: pkg:npm/lodash@4.17.20 -> pkg:npm/lodash@4.17.20#2
- **Fix at the source:** Give every component a unique bom-ref (cdxgen uses the purl).

### SAN-022: Merge components with the same purl (1)

- 1 x Duplicate component with the same purl
- Examples: `/components/1` removed: {"bom-ref": "pkg:npm/lodash@4.17.20#2", "type": "library"...
- **Fix at the source:** List each package once; merge duplicates in the build before generating the SBOM.

## 3. Generator and pipeline

- Let the generator record itself in metadata.tools (CycloneDX) or creationInfo.creators (SPDX).
- Set metadata.authors (the team that produced the SBOM); NTIA requires an author.
