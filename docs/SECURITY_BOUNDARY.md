# Security boundary

## In scope

- deterministic processing of caller-supplied JSON-compatible metadata;
- strict identifiers, timestamps, enumerations and SHA-256 syntax;
- evidence-reference linkage and future-time/currentness checks;
- time-bounded acceptance and independent-verification checks;
- local schema validation and dossier generation.
- strict local mapping of selected SARIF and CycloneDX JSON documents;
- raw-artifact, canonical-document and per-record digest binding.

## Out of scope

- scanner, endpoint, cloud, repository, CMDB, ticketing or patch-platform access;
- storage or processing of credentials, secrets, exploit payloads or raw production telemetry;
- CVSS calculation, exploitability prediction or vulnerability discovery;
- general SARIF/CycloneDX conformance validation or vendor-specific extension interpretation;
- patch deployment, containment, ticket mutation or autonomous risk acceptance;
- production identity, authorization, database isolation, encryption or retention enforcement.

## Evidence handling

The v0.2 contract stores normalized metadata, source locators and artifact/record digests only.
`artifact_ref` is an opaque locator. Intake reads a source artifact locally but does not copy its
raw body into the output batch.
Callers are responsible for access control, retention, encryption, authenticity and availability
of the referenced artifact.

Repository examples are synthetic. Contributors must not commit real hostnames, IP addresses,
credentials, customer identifiers, proprietary scanner exports or exploit material.
