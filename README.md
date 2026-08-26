# VulnEvidenceOps

**Open vulnerability-evidence control plane for normalized findings, accountable risk
decisions, remediation verification and audit-ready evidence.**

VulnEvidenceOps is an open-source reference architecture for representing the governance
lifecycle around vulnerability findings without operating scanners, patch systems, ticketing
platforms or production infrastructure.

Current package boundary: **VulnEvidenceOps v0.1.0 — Alpha Governance Foundation**.

> [!IMPORTANT]
> A valid VulnEvidenceOps dossier proves only that the supplied metadata satisfies this
> reference contract. It does not prove vulnerability absence, scanner completeness,
> production remediation, acceptable residual risk, regulatory compliance or production
> readiness.

## v0.1 scope

The initial boundary provides:

- scanner-neutral, asset-reference-based vulnerability findings;
- SHA-256-bound evidence metadata without embedding scanner payloads or secrets;
- accountable triage dispositions;
- remediation ownership, due dates and change references;
- explicit, time-bounded risk acceptance with compensating-control references;
- independent remediation verification and evidence-backed closure;
- deterministic currentness, overdue and revalidation decisions at an explicit assessment time;
- internal control-to-evidence results of `represented`, `gap` or `not_applicable`;
- a deterministic assurance dossier with explicit non-claims;
- Draft 2020-12 JSON Schemas, a CLI, synthetic examples and release-integrity gates.

## Portfolio boundary

| Repository | Primary ownership |
|---|---|
| DataGovOps | Data ownership, classification, lineage, quality, retention and privacy evidence |
| DORAOps | ICT operational resilience, incidents, testing, continuity and third-party evidence |
| ModelRiskOps | Model/AI inventory, validation, monitoring, change and deployment-governance evidence |
| ai-threat-detection-framework | Synthetic AI-assisted alert scoring and evaluation evidence |
| **VulnEvidenceOps** | Vulnerability finding, triage, acceptance, remediation, verification and closure evidence |

VulnEvidenceOps links to external assets, controls, changes and tickets through opaque references.
It does not duplicate enterprise inventory, incident management, BCM, TPRM, model governance or
scanner execution.

## Lifecycle

```text
detected -> triaged -> verification_pending -> closed_verified
                   \-> risk_accepted -> revalidation_required
                   \-> closed_dispositioned
```

State is computed from append-only records at an explicit `assessed_at` time. Future-dated,
missing, expired or unlinked evidence fails closed as a gap.

## CLI

```bash
vulnevidenceops --version
vulnevidenceops digest-json examples/synthetic-case.json
vulnevidenceops schema schemas/case-bundle.schema.json examples/synthetic-case.json
vulnevidenceops assess examples/synthetic-case.json \
  --policy examples/synthetic-policy.json \
  --as-of 2026-01-20T00:00:00Z
```

## Standards posture

The design is informed by vulnerability-management and evidence concepts in ISO/IEC 27001:2022,
NIST Cybersecurity Framework 2.0, NIST SP 800-40 Rev. 4 and DORA ICT-risk governance. Framework
references are mapping aids only; applicability and control effectiveness remain human-owned.

## Explicit non-claims

VulnEvidenceOps does **not** by itself establish:

- complete asset or vulnerability discovery;
- CVE, CWE, CVSS, vendor-advisory or scanner accuracy;
- successful patching, mitigation or production verification;
- acceptable residual risk or valid accountable authority;
- ISO, NIST, DORA or other legal/regulatory compliance;
- production IAM, ticketing, CMDB, scanner, patching or evidence-store effectiveness;
- live repository-governance enforcement merely because a policy is committed;
- certification, supervisory acceptance or production fitness.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Control/evidence matrix](docs/CONTROL_EVIDENCE_MATRIX.md)
- [Security boundary](docs/SECURITY_BOUNDARY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Release process](docs/RELEASE_PROCESS.md)
- [Compatibility](COMPATIBILITY.md)
- [Roadmap](docs/ROADMAP.md)

## License

Apache License 2.0.
