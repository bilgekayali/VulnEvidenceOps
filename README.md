# VulnEvidenceOps

**Open vulnerability-evidence control plane for normalized findings, accountable risk
decisions, remediation verification and audit-ready evidence.**

VulnEvidenceOps is an open-source reference architecture for representing the governance
lifecycle around vulnerability findings without operating scanners, patch systems, ticketing
platforms or production infrastructure.

Current package boundary: **VulnEvidenceOps v0.5.0 — Alpha Signed Evidence Reference**.

> [!IMPORTANT]
> A valid VulnEvidenceOps dossier proves only that the supplied metadata satisfies this
> reference contract. It does not prove vulnerability absence, scanner completeness,
> production remediation, acceptable residual risk, regulatory compliance or production
> readiness.

## v0.5 scope

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

The v0.2 intake boundary additionally provides:

- strict adapters for SARIF 2.1.0 and CycloneDX 1.5/1.6 JSON;
- one explicit mapping record for every normalized source result or vulnerability-affect pair;
- raw-artifact, canonical-document and per-record SHA-256 identities;
- JSON Pointer traceability without embedding raw scanner payloads in governance records;
- explicit, caller-supplied asset/source references and observation time;
- fail-closed handling of unsupported versions and incomplete candidate records.

The v0.3 exposure-context boundary adds:

- time-bounded exploit-intelligence assertions tied to finding technical identifiers;
- accountable business-criticality assertions tied to finding asset references;
- explicit source identities, source references and evidence references for every assertion;
- deterministic currentness states for missing, unlinked, mismatched, future or expired evidence;
- distinct `current`, `partial`, `stale`, `unavailable` and `with_gaps` context positions;
- visible conflict gaps without selecting a preferred source or computing a risk score.

The v0.4 portfolio-assurance boundary adds:

- cross-case representation of explicit human deduplication decisions without similarity inference;
- raw SLA cohorts derived from the committed policy and an explicit assessment time;
- time, policy and evidence states for risk-acceptance exceptions plus transparent age bands;
- accountable role views spanning triage, remediation, approval, ownership and verification;
- digest-bound case summaries and raw counts without percentages, weighted scores or rankings;
- explicit portfolio gaps for future, unlinked, out-of-scope or chained decisions.

The v0.5 signed-evidence boundary adds:

- strict canonical JSON envelopes with context-bound Ed25519 signatures;
- digest-bound public verification keys with explicit validity and revocation metadata;
- local separation of signature, payload-digest and key-lifecycle results;
- opaque external anchor receipts with visible binding and temporal states;
- exact build subject, Git object, builder, invocation and material provenance;
- explicit non-claims for identity, authority, trusted time, external anchor authenticity,
  reproducibility, non-repudiation and artifact safety.

## Portfolio boundary

| Repository | Primary ownership |
|---|---|
| DataGovOps | Data ownership, classification, lineage, quality, retention and privacy evidence |
| DORAOps | ICT operational resilience, incidents, testing, continuity and third-party evidence |
| ModelRiskOps | Model/AI inventory, validation, monitoring, change and deployment-governance evidence |
| ai-threat-detection-framework | Synthetic AI-assisted alert scoring and evaluation evidence |
| **VulnEvidenceOps** | Vulnerability finding, exposure context, decisions, remediation and closure evidence |

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

vulnevidenceops intake sarif examples/synthetic-sarif.json \
  --artifact-ref synthetic://intake/sarif.json \
  --collected-at 2026-01-05T00:00:00Z \
  --observed-at 2026-01-04T00:00:00Z \
  --source-identity synthetic-source:reference-v1 \
  --source-ref synthetic-source:export-001 \
  --asset-ref synthetic-asset:repository-001 \
  --synthetic

vulnevidenceops exposure examples/synthetic-exposure-context.json \
  --as-of 2026-01-20T00:00:00Z

vulnevidenceops portfolio examples/synthetic-portfolio.json \
  --as-of 2026-01-20T00:00:00Z

vulnevidenceops verify-evidence examples/synthetic-signed-evidence-envelope.json \
  --key examples/synthetic-verification-key.json \
  --receipt examples/synthetic-anchor-receipt.json \
  --as-of 2026-01-20T00:05:00Z
```

## Standards posture

The design is informed by vulnerability-management and evidence concepts in ISO/IEC 27001:2022,
NIST Cybersecurity Framework 2.0, NIST SP 800-40 Rev. 4 and DORA ICT-risk governance. Framework
references are mapping aids only; applicability and control effectiveness remain human-owned.

## Explicit non-claims

VulnEvidenceOps does **not** by itself establish:

- complete asset or vulnerability discovery;
- CVE, CWE, CVSS, vendor-advisory or scanner accuracy;
- source-artifact authenticity or full upstream-format conformance;
- source severity, asset identity or finding validity merely because an adapter mapped it;
- exploitability, business impact, source truth, remediation priority or an SLA merely because
  an exposure-context assertion is current;
- automatic deduplication, SLA compliance, executive approval, portfolio risk rank or a
  compliance percentage merely because a portfolio view is valid;
- signer identity, signing authority, trusted signing time, external-anchor authenticity,
  verification-key authenticity, payload-schema conformance, non-repudiation, build
  reproducibility or artifact safety merely because a signature verifies;
- successful patching, mitigation or production verification;
- acceptable residual risk or valid accountable authority;
- ISO, NIST, DORA or other legal/regulatory compliance;
- production IAM, ticketing, CMDB, scanner, patching or evidence-store effectiveness;
- live repository-governance enforcement merely because a policy is committed;
- certification, supervisory acceptance or production fitness.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Control/evidence matrix](docs/CONTROL_EVIDENCE_MATRIX.md)
- [Intake adapters](docs/INTAKE_ADAPTERS.md)
- [Exposure context](docs/EXPOSURE_CONTEXT.md)
- [Portfolio assurance](docs/PORTFOLIO_ASSURANCE.md)
- [Signed evidence](docs/SIGNED_EVIDENCE.md)
- [Security boundary](docs/SECURITY_BOUNDARY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Release process](docs/RELEASE_PROCESS.md)
- [Compatibility](COMPATIBILITY.md)
- [Roadmap](docs/ROADMAP.md)

## License

Apache License 2.0.
