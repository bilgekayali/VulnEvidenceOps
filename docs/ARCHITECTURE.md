# Architecture

## Purpose

VulnEvidenceOps is a local, deterministic evidence-contract library. It turns normalized finding
metadata and governance records into an assurance dossier at an explicit point in time. A bounded
intake layer maps selected open JSON formats into normalized finding and provenance records.

## One-data-model boundary

The core relationship is:

```text
asset reference -> finding -> evidence catalog
                         -> triage decision
                         -> remediation record -> verification record
                         -> risk acceptance -> expiry/revalidation
                         -> assurance dossier
```

The v0.2 intake path precedes that relationship:

```text
source artifact -> versioned adapter -> intake batch
                -> normalized findings + per-record mapping ledger
```

The v0.3 context path remains separate from lifecycle decisions:

```text
finding + exploit assertions + business-service classifications + evidence catalog
        -> currentness/conflict assessment -> exposure-context assessment
```

The assessment reports only supplied context and gaps. It does not feed an implicit score,
priority, SLA or remediation decision into the governance lifecycle.

The v0.4 portfolio path composes existing case assessments:

```text
case bundles + policy + portfolio scope -> per-case dossiers
                                        -> cohorts + exceptions + accountability view
```

It retains explicit human duplicate decisions and raw counts. It does not infer similarity,
calculate compliance percentages or rank findings.

The v0.5 signed-evidence path is orthogonal to domain assessment:

```text
canonical JSON payload + Ed25519 private-key operation -> signed envelope
signed envelope + public key + optional anchor receipts -> local verification result
```

Only the signing operation receives an externally managed private-key object or file. The package
does not generate, retain, publish or rotate private keys. Verification separates payload digest,
signature, key lifecycle, claimed time and anchor binding instead of collapsing them into trust.

The v0.6 integration path binds a payload to one frozen peer-contract profile:

```text
canonical payload + profile -> integration handoff
handoff + payload + exact peer-contract bytes + verification time -> local verification
```

The profile selects direction, relationship, media type and exact peer Git identity. Verification
does not call a peer repository or system and does not infer delivery, authority, identity,
semantic compatibility or acceptance.

All links use immutable identifiers or SHA-256 digests. Mutable labels, ticket state and scanner
dashboards are not treated as evidence by themselves.

## Components

- `models.py` defines immutable governance records and their local invariants.
- `assurance.py` computes currentness, overdue state, evidence gaps and control representation.
- `canonical.py` provides deterministic JSON serialization and SHA-256 identity.
- `intake.py` provides strict SARIF and CycloneDX adapters plus source-mapping records.
- `exposure.py` binds time-bounded external assertions to evidence and assesses currentness.
- `portfolio.py` composes case dossiers into raw cohorts, exception ages and accountable views.
- `signed_evidence.py` binds canonical payloads to Ed25519 signatures, public keys, anchor metadata
  and exact build provenance while preserving explicit trust non-claims.
- `integration.py` binds canonical payloads to frozen peer-contract identities and verifies local
  digest, profile, Git-blob and temporal facts.
- `schema.py` validates documents against explicit Draft 2020-12 contracts.
- `cli.py` exposes local digest, schema, intake, lifecycle, context, portfolio, signed-evidence and
  integration operations.

## Integration posture

External scanners, CMDBs, ticketing systems, patch platforms, code hosts and evidence stores remain
outside the trust boundary. v0.2 adapters accept caller-supplied local JSON documents only. They
have no network clients, credentials, webhooks, scanner execution or patch orchestration.

The v0.6 profiles reference exact public contract snapshots from DataGovOps, DORAOps,
ModelRiskOps and ai-threat-detection-framework. Snapshots are verification fixtures, not imported
runtime implementations. No integration profile makes either repository responsible for the
other repository's domain.

## Determinism

The caller supplies `assessed_at`. Canonical input bytes are sorted and compact JSON. Identical
case, policy and assessment time inputs therefore produce identical dossier content and digest.
Identical intake document bytes, canonical content and mapping context produce identical intake
identities, findings and mapping records. Identical exposure bundles and assessment times produce
identical context positions, gaps, inventories and input digests. Identical portfolio bundles and
assessment times produce identical case summaries, cohorts, exception records and accountability
views.
Identical payload, key, claimed signing time and Ed25519 private key produce identical envelopes.
Identical envelope, verification key, receipts and verification time produce identical local
verification results.
Identical payload, frozen profile and handoff metadata produce identical handoffs. Identical
handoff, payload bytes, peer-contract bytes and verification time produce identical integration
verification results.
