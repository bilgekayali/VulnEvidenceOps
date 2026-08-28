# Integration contracts

VulnEvidenceOps v0.6 represents a handoff as a canonical payload digest plus one frozen peer
contract identity. The implementation is deliberately local: it has no HTTP client, webhook,
credential, queue, repository lookup or mutation capability.

## Frozen profiles

| Profile | Direction | Relationship | Exact peer contract |
|---|---|---|---|
| `datagovops-control-evidence` | VulnEvidenceOps → DataGovOps | `control_evidence` | `DataGovOps@8bfd1b9…/schemas/control-evidence-reference.schema.json` |
| `doraops-operational-control-evidence` | VulnEvidenceOps → DORAOps | `operational_control_evidence` | `DORAOps@c4a565f…/schemas/operational-control-evidence.schema.json` |
| `modelriskops-assurance-evidence` | VulnEvidenceOps → ModelRiskOps | `model_security_assurance_evidence` | `ModelRiskOps@a4c35ff…/schemas/assurance-evidence-reference.schema.json` |
| `ai-threat-evaluation` | AI Threat Detection → VulnEvidenceOps | `alert_evaluation_evidence` | `ai-threat-detection-framework@3c268eb…/schemas/evaluation-report.schema.json` |

Each peer identity records the full repository URL, exact 40-character commit, tree and blob IDs,
and repository-relative path. Git SHA-1 is reproduced only as the peer repository's blob identity;
payload integrity uses SHA-256. Neither digest is treated as proof of repository authenticity.

## Handoff record

`integration-handoff.v1` contains:

- a stable handoff and subject reference;
- profile-selected producer, consumer, relationship and payload media type;
- SHA-256 of strict canonical JSON payload bytes;
- the exact peer contract identity and whether it is the producer or consumer contract;
- caller-supplied creation and optional expiry timestamps;
- an explicit synthetic marker and complete false non-claim set.

`build_integration_handoff` does not accept caller overrides for profile bindings. Updating an
external peer contract therefore requires a deliberate new VulnEvidenceOps contract version or
profile update with new fingerprints.

## Verification result

`verify_integration_handoff` receives the handoff, payload document, peer-contract bytes and an
explicit verification time. It independently reports:

- `profile_binding_valid`;
- `payload_digest_valid`;
- `peer_contract_blob_valid`;
- `temporal_state` as `current`, `future` or `expired`;
- `integration_position` as `verified`, `with_gaps` or `invalid`;
- an exact, non-duplicated gap set.

Payload, profile or peer-blob mismatch is `invalid`. A locally intact but future or expired
handoff is `with_gaps`. `verified` means only that all four local checks passed.

## CLI

```bash
vulnevidenceops integration-handoff examples/synthetic-assurance-dossier.json \
  --profile datagovops-control-evidence \
  --handoff-id HANDOFF-LOCAL-001 \
  --subject-ref synthetic-case:CASE-SYNTH-001 \
  --created-at 2026-01-20T00:10:00Z \
  --valid-until 2027-01-20T00:10:00Z \
  --synthetic \
  --output /tmp/handoff.json

vulnevidenceops verify-integration /tmp/handoff.json \
  examples/synthetic-assurance-dossier.json \
  --peer-contract examples/peer-contracts/datagovops-control-evidence-reference.schema.json \
  --as-of 2026-01-20T00:15:00Z \
  --output /tmp/integration-verification.json
```

## Non-claims

A `verified` result does not establish peer-repository authenticity, payload truth or schema
conformance, producer identity or authority, cross-system identity, semantic compatibility,
delivery, consumer acceptance, artifact safety, regulatory compliance or production
interoperability. Those require system-specific transport, identity, approval and operational
evidence outside this repository.
