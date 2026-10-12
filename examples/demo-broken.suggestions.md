# Suggestions: demo-broken.cdx.json

| # | Missing / wrong | Count | Components | Fix |
|---:|---|---:|---|---|
| 1 | Schema error at `/components/*/hashes/*/alg`: 'sha256' is not one of ['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-... | 2 | - | Use one of the values the schema allows. |
| 2 | Schema error at `/components/*/version`: 2.11 is not of type 'string' | 2 | - | Write the value with the JSON type the schema expects (string, number, array, object). |
| 3 | Schema error at `/components/*`: Additional properties are not allowed ('x-scanner-internal' was une... | 1 | - | Remove fields that are not part of this CycloneDX / SPDX version. |
| 4 | Schema error at `/components/*/description`: None is not of type 'string' | 1 | - | Write the value with the JSON type the schema expects (string, number, array, object). |
| 5 | Schema error at `/components/*/externalReferences/*/url`: 'https://registry.npmjs.org/lodash/-/lodash 4.17.20.tgz' is not a '... | 1 | - | Write the value in the expected format (for example date-time, iri-reference, email). |
| 6 | Schema error at `/components/*/hashes/*/content`: 'not-a-real-hash' does not match '^([a-fA-F0-9]{32}\|[a-fA-F0-9]{40... | 1 | - | Write the value in the expected pattern (for example urn:uuid:... for serialNumber). |
| 7 | Schema error at `/components/*/licenses/*`: Additional properties are not allowed ('license' was unexpected) | 1 | - | Remove fields that are not part of this CycloneDX / SPDX version. |
| 8 | Schema error at `/components/*/type`: 'Library' is not one of ['application', 'framework', 'library', 'co... | 1 | - | Use one of the values the schema allows. |
| 9 | Schema error at `/components/*/licenses/*`: 'MIT' is not of type 'object' | 1 | - | Write the value with the JSON type the schema expects (string, number, array, object). |
| 10 | Schema error at `/metadata/timestamp`: '2026-10-02 10:00' is not a 'date-time' | 1 | - | Write the value in the expected format (for example date-time, iri-reference, email). |
| 11 | Schema error at `/serialNumber`: 'DEMO-0001' does not match '^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a... | 1 | - | Write the value in the expected pattern (for example urn:uuid:... for serialNumber). |
| 12 | Dependency on a component that is not in the SBOM | 2 | - | List dependencies only between components that are in the SBOM. |
| 13 | No purl | 1 | left-pad@1.3.0 | Use a generator that writes a purl for every package. |
| 14 | No tool in metadata.tools | 1 | - | Let the generator record itself in metadata.tools (CycloneDX) or creationInfo.creators (SPDX). |
| 15 | Same bom-ref used twice | 1 | commons-io@2.11 | Give every component a unique bom-ref. |
| 16 | Same package listed twice | 1 | commons-io@2.11 | List each package once. |
| 17 | No licence | 1 | left-pad@1.3.0 | Add the licence (SPDX id, e.g. MIT, Apache-2.0) to the package manifest (pom, csproj, package.json); for own libraries set it in the build. |
| 18 | No root component (metadata.component) | 1 | root component | Let the generator write the application itself as metadata.component (name, version). |
| 19 | No supplier (NTIA) | 4 of 4 | lodash@4.17.20, lodash@4.17.20, commons-io, left-pad | Let the generator write the supplier of every package (from the package metadata: the organization element of the pom, authors in the nuspec or package.json); for own libraries set your company. |
| 20 | No component version (NTIA) | 1 of 4 | left-pad | Write the resolved version of every package. |
| 21 | No unique identifier: purl, CPE or SWID (NTIA) | 1 of 4 | commons-io | Use a generator that writes a purl for every package. |
