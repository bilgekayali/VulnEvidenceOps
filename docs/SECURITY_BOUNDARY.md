# Security boundary

## In scope

- deterministic processing of caller-supplied JSON-compatible metadata;
- strict identifiers, timestamps, enumerations and SHA-256 syntax;
- evidence-reference linkage and future-time/currentness checks;
- time-bounded acceptance and independent-verification checks;
- local schema validation and dossier generation;
- strict local mapping of selected SARIF and CycloneDX JSON documents;
- raw-artifact, canonical-document and per-record digest binding.
- evidence-linked currentness and conflict assessment for caller-supplied exploit and business
  context assertions.
- deterministic composition of supplied cases into raw SLA, exception and accountability views.
- canonical JSON digesting and Ed25519 signing with caller-managed private-key input;
- local signature, payload-digest and public-key lifecycle verification;
- local binding and time-state checks for caller-supplied opaque anchor receipts;
- exact caller-supplied build subject, Git object, invocation and material identities.

## Out of scope

- scanner, endpoint, cloud, repository, CMDB, ticketing or patch-platform access;
- storage or processing of credentials, secrets, exploit payloads or raw production telemetry;
- CVSS calculation, exploitability prediction or vulnerability discovery;
- intelligence-feed access, assertion truth verification, business-impact calculation, scoring,
  prioritization or remediation-SLA assignment;
- automatic deduplication, compliance calculation, severity weighting, executive approval or
  cross-system identity resolution;
- general SARIF/CycloneDX conformance validation or vendor-specific extension interpretation;
- patch deployment, containment, ticket mutation or autonomous risk acceptance;
- production identity, authorization, database isolation, encryption or retention enforcement.
- private-key generation, custody, storage, rotation, recovery or revocation publication;
- certificate-chain, signer-identity, delegated-authority or non-repudiation decisions;
- network access to RFC 3161 services, transparency logs, ledgers or other anchor providers;
- external receipt authenticity, trusted-time, build reproducibility, source trust or artifact-
  safety verification.

## Evidence handling

The v0.5 contract stores normalized metadata, source locators, artifact/record digests, public keys,
signatures and opaque anchor receipt metadata. It never serializes private-key material.
`artifact_ref` is an opaque locator. Intake reads a source artifact locally but does not copy its
raw body into the output batch.
Callers are responsible for private-key security, verification-key distribution, access control,
retention, encryption, authenticity and availability of referenced artifacts and receipts.

Repository examples are synthetic. Contributors must not commit real hostnames, IP addresses,
credentials, customer identifiers, proprietary scanner exports or exploit material.
