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

All links use immutable identifiers or SHA-256 digests. Mutable labels, ticket state and scanner
dashboards are not treated as evidence by themselves.

## Components

- `models.py` defines immutable governance records and their local invariants.
- `assurance.py` computes currentness, overdue state, evidence gaps and control representation.
- `canonical.py` provides deterministic JSON serialization and SHA-256 identity.
- `intake.py` provides strict SARIF and CycloneDX adapters plus source-mapping records.
- `exposure.py` binds time-bounded external assertions to evidence and assesses currentness.
- `schema.py` validates documents against explicit Draft 2020-12 contracts.
- `cli.py` exposes local digest, schema, intake, lifecycle and exposure-context operations.

## Integration posture

External scanners, CMDBs, ticketing systems, patch platforms, code hosts and evidence stores remain
outside the trust boundary. v0.2 adapters accept caller-supplied local JSON documents only. They
have no network clients, credentials, webhooks, scanner execution or patch orchestration.

The result can be referenced by DORAOps or another control plane through its dossier digest. The
integration does not make either repository responsible for the other repository's domain.

## Determinism

The caller supplies `assessed_at`. Canonical input bytes are sorted and compact JSON. Identical
case, policy and assessment time inputs therefore produce identical dossier content and digest.
Identical intake document bytes, canonical content and mapping context produce identical intake
identities, findings and mapping records. Identical exposure bundles and assessment times produce
identical context positions, gaps, inventories and input digests.
