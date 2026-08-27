# Architecture

## Purpose

VulnEvidenceOps is a local, deterministic evidence-contract library. It turns normalized finding
metadata and governance records into an assurance dossier at an explicit point in time.

## One-data-model boundary

The core relationship is:

```text
asset reference -> finding -> evidence catalog
                         -> triage decision
                         -> remediation record -> verification record
                         -> risk acceptance -> expiry/revalidation
                         -> assurance dossier
```

All links use immutable identifiers or SHA-256 digests. Mutable labels, ticket state and scanner
dashboards are not treated as evidence by themselves.

## Components

- `models.py` defines immutable governance records and their local invariants.
- `assurance.py` computes currentness, overdue state, evidence gaps and control representation.
- `canonical.py` provides deterministic JSON serialization and SHA-256 identity.
- `schema.py` validates documents against explicit Draft 2020-12 contracts.
- `cli.py` exposes local digest, schema and assessment operations.

## Integration posture

External scanners, CMDBs, ticketing systems, patch platforms, code hosts and evidence stores remain
outside the trust boundary. Adapters may normalize their outputs later, but v0.1 deliberately has
no network clients, credentials, webhooks, scanner execution or patch orchestration.

The result can be referenced by DORAOps or another control plane through its dossier digest. The
integration does not make either repository responsible for the other repository's domain.

## Determinism

The caller supplies `assessed_at`. Canonical input bytes are sorted and compact JSON. Identical
case, policy and assessment time inputs therefore produce identical dossier content and digest.
