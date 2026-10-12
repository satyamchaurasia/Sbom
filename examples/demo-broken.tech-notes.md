# Tech notes: demo-broken.cdx.json

## Summary

- **Input:** cyclonedx 1.6, 4 component(s)
- **Output:** `demo-broken.corrected.cdx.json`, CycloneDX 1.6 (schema-valid), 3 component(s), 3 dependency entries
- **Tool in metadata:** Tool cyclonedx-node for the ecosystem node: 2 of 3 components (also java 1)
- **Changes:** 29 in total; 22 fixed problems of the input, 7 layout changes for Checkmarx
- **Original schema errors:** 13 (details in the suggestions file)
- **Exit code:** 1 (fixed)
- **NTIA minimum elements (original):** FAIL - supplier 0/4, component 3/4, unique 3/4
- **NTIA minimum elements (corrected):** FAIL - supplier 0/3, author missing, sbomqs 3.9

## NTIA minimum elements

| NTIA element | Original | Corrected |
|---|---|---|
| Supplier name | 0 / 4 ✗ | 0 / 3 ✗ |
| Component name | 4 / 4 | 3 / 3 |
| Component version | 3 / 4 ✗ | 3 / 3 |
| Unique identifier | 3 / 4 ✗ | 3 / 3 |
| Dependency relationships | yes | yes |
| Author of SBOM data | yes | no ✗ |
| Timestamp | yes | yes |
| **Result** | **FAIL** | **FAIL** |

The corrected file keeps only what Checkmarx reads (no supplier, no author), so its NTIA result is usually FAIL. Use the original for NTIA; fix the gaps of the original at the source (suggestions file).

## What was done

1. **Converted** (cyclonedx 1.6 -> CycloneDX 1.6).
   - 2 dependencies entries added (dependsOn unknown)
2. **Validated** the converted file against the CycloneDX 1.6 schema: 13 error(s).
   - 2 x `enum` at `/components/*/hashes/*/alg`: 'sha256' is not one of ['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384', ...
   - 2 x `type` at `/components/*/version`: 2.11 is not of type 'string'
   - 1 x `additionalProperties` at `/components/*`: Additional properties are not allowed ('x-scanner-internal' was unexpected)
   - 1 x `type` at `/components/*/description`: None is not of type 'string'
   - 1 x `format` at `/components/*/externalReferences/*/url`: 'https://registry.npmjs.org/lodash/-/lodash 4.17.20.tgz' is not a 'iri-reference'
   - 1 x `pattern` at `/components/*/hashes/*/content`: 'not-a-real-hash' does not match '^([a-fA-F0-9]{32}\|[a-fA-F0-9]{40}\|[a-fA-F0-9]{64}\|[a-fA-F0-9...
   - 1 x `additionalProperties` at `/components/*/licenses/*`: Additional properties are not allowed ('license' was unexpected)
   - 1 x `enum` at `/components/*/type`: 'Library' is not one of ['application', 'framework', 'library', 'container', 'platform', 'operati...
   - 1 x `type` at `/components/*/licenses/*`: 'MIT' is not of type 'object'
   - 1 x `format` at `/metadata/timestamp`: '2026-10-02 10:00' is not a 'date-time'
3. **Repaired and reduced to the Checkmarx layout** on the same CycloneDX version (specVersion is never changed). Output layout:
   - top level: `bomFormat`, `specVersion`, `serialNumber`, `version`, `metadata`, `components`, `dependencies` (`components` is always there, `[]` when the input has none)
   - `metadata`: `timestamp`, `tools`, `component` (the root application)
   - each component: `bom-ref`, `type`, `name`, `version`, `purl`, `licenses` (NOASSERTION when unknown)
   - no `externalReferences`, `properties`, `evidence`, `description`; no purl or bom-ref with http(s)
   - dependencies only between components in the file, no self-dependencies

## Changes by rule

| Rule | What | Kind | Count | Example |
|---|---|---|---:|---|
| REP-003 | Enum values in the exact form the schema expects | fix | 3 | `/components/0/hashes/0/alg`: sha256 -> SHA-256 |
| REP-005 | Remove null and empty values the schema rejects | fix | 2 | `/components/3/version` = 1.3.0 |
| REP-010 | License entries have a valid structure | fix | 2 | `/components/0/licenses/0/license/id`: Apache 2.0 -> Apache-2.0 |
| SAN-021 | Remove dependency edges that point to nothing | fix | 2 | `/dependencies/0/dependsOn/1` removed: pkg:npm/does-not-exist@9.9.9 |
| CXN-011 | metadata is timestamp, tools and component | fix | 1 | `/metadata/component` = {"type": "application", "name": ""} |
| CXN-030 | Every component has a licence | fix | 1 | `/components/2/licenses` = [{"license": {"name": "NOASSERTION"}}] |
| PRUNE-001 | Fields the schema of this version does not allow | fix | 1 | `/components/0/x-scanner-internal` removed: {"scanId": 991} |
| REP-001 | $schema matches specVersion | fix | 1 | `/$schema`: http://cyclonedx.org/schema/bom-1.4.schema... -> http://cyclonedx.org/schema/bom-1.6.schema... |
| REP-004 | Scalars have the type the schema expects | fix | 1 | `/components/2/version`: 2.11 -> 2.11 |
| REP-007 | serialNumber is a urn:uuid | fix | 1 | `/serialNumber`: DEMO-0001 -> urn:uuid:e6a2b683-542f-5212-8766-80162174bc8e |
| REP-008 | Timestamps are ISO 8601 date-times | fix | 1 | `/metadata/timestamp`: 2026-10-02 10:00 -> 2026-10-02T10:00:00Z |
| REP-009 | URLs are valid IRI references | fix | 1 | `/components/0/externalReferences/0/url`: https://registry.npmjs.org/lodash/-/lodash... -> https://registry.npmjs.org/lodash/-/lodash... |
| REP-011 | Hash values match their algorithm | fix | 1 | `/components/0/hashes/0` removed: {"alg": "SHA-256", "content": "not-a-real-hash"} |
| SAN-011 | Build missing purls when the ecosystem is certain | fix | 1 | `/components/2/purl` = pkg:maven/commons-io/commons-io@2.11 |
| SAN-013 | Add a default tool when none is named | fix | 1 | `/metadata/tools` = {"components": [{"type": "application", "name": "sbom-fix... |
| SAN-020 | Unique bom-refs | fix | 1 | `/components/1/bom-ref`: pkg:npm/lodash@4.17.20 -> pkg:npm/lodash@4.17.20#2 |
| SAN-022 | Merge components with the same purl | fix | 1 | `/components/1` removed: {"bom-ref": "pkg:npm/lodash@4.17.20#2", "type": "library"... |
| CXN-011 | metadata is timestamp, tools and component | layout | 2 | `/metadata/tools`: {"components": [{"type": "application", "n... -> [{"vendor": "AppThreat", "name": "cycloned... |
| CXN-040 | Components reduced to the fields Checkmarx reads | layout | 2 | `/components/0` removed: {"evidence": {"identity": [{"field": "purl", "confidence"... |
| CXN-010 | Top level is bomFormat, specVersion, serialNumber, version, metadata, components, dependencies | layout | 1 | `/$schema` removed: http://cyclonedx.org/schema/bom-1.6.schema.json |
| CXN-030 | Every component has a licence | layout | 1 | `/components/0/licenses`: [{"license": {"id": "Apache-2.0", "acknowl... -> [{"license": {"id": "Apache-2.0"}}] |
| SAN-090 | Record sbom-fixer provenance | layout | 1 | `/metadata` = sbom-fixer provenance |

*fix* = a problem of the input that was repaired; *layout* = reshaped for the Checkmarx layout; data Checkmarx does not read is dropped from this copy only (the original file keeps it).

