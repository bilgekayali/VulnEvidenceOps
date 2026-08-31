# VulnEvidenceOps

**Open vulnerability-evidence control plane for normalized findings, accountable risk
decisions, remediation verification and audit-ready evidence.**

VulnEvidenceOps is an open-source reference architecture for representing the governance
lifecycle around vulnerability findings without operating scanners, patch systems, ticketing
platforms or production infrastructure.

Current package boundary: **VulnEvidenceOps v1.0.0 — Stable Reference**.

> [!IMPORTANT]
> A valid VulnEvidenceOps dossier proves only that the supplied metadata satisfies this
> reference contract. It does not prove vulnerability absence, scanner completeness,
> production remediation, acceptable residual risk, regulatory compliance or production
> readiness.

## v1 stable-reference scope

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

The v0.6 integration-contract boundary adds:

- four frozen handoff profiles for DataGovOps, DORAOps, ModelRiskOps and
  ai-threat-detection-framework;
- canonical producer-payload SHA-256 identity and exact peer repository, commit, tree, path and
  Git-blob identity;
- deterministic local checks for profile binding, payload digest, peer-contract bytes and the
  handoff validity window;
- public peer-contract, handoff and verification schemas plus exact public contract snapshots;
- explicit non-claims for cross-system identity, authority, delivery, consumer acceptance,
  semantic compatibility, payload truth and production interoperability.

The v1 stable reference freezes the Python API, CLI, runtime-dependency and byte-exact
public-schema surfaces. Independent human review was not performed; the repository owner explicitly
waived that prerequisite. “Stable” describes the package and compatibility contract, not a
production-safety, compliance or effectiveness attestation.

## Run the real DataGovOps consumer demo

From this repository's current `main` checkout, with Python 3.11+ and Git available:

```bash
python tools/demo_datagovops.py --test
```

The command installs both projects as wheels in a temporary isolated environment, then
runs an offline synthetic case → dossier → **actual DataGovOps registry** pipeline.
Five missing evidence records become five represented records; at expiry they require
revalidation. Corrupted content and a re-hashed incompatible schema are rejected before
any accepted consumer receipt is written. The full integration test suite also runs.
The consumer independently verifies Ed25519 over the whole packet under an explicit
public-test-key policy; wrong, untrusted and revoked keys plus rehashed tampering are
rejected. Public RFC test keys demonstrate policy enforcement, not real sender identity.
Successful CI runs provide SHA-bound downloadable evidence and a readable report.

See [the end-to-end walkthrough](docs/DATAGOVOPS_E2E_DEMO.md) for exact mapping, outputs,
pins and boundaries. Results are written under `artifacts/datagovops-demo/`; existing
output is never overwritten. The demo is an additive repository example after the
immutable v1.0.0 tag, not a new stable package API or a production integration claim.

## Extend the same evidence into real DORAOps governance

```bash
python tools/demo_doraops.py --test
```

This runs the signed DataGovOps demo, then reconsumes the source through a separately
defined **DORAOps ICT risk and resilience-testing** adapter. Actual DORAOps APIs compute
the risk decision and `open → remediation_submitted → closed` finding lifecycle.
Completion evidence is separate from the plan; missing/failed retests remain blocked.
An independently verified DORAOps-scoped signature binds the handoff, source packet,
DataGovOps receipt and additional completion; upstream signing cannot substitute for it.
No vulnerability is turned into an incident, no deployment controls are fabricated,
and finding closure does not automatically lower risk or approve risk acceptance.

See [the three-project walkthrough](docs/DORAOPS_RISK_REMEDIATION_DEMO.md) for the exact
contract, native outputs, fourteen rejection scenarios, attention cases and downloadable
CI evidence. All data, keys and reviewer roles remain synthetic; existing stable APIs/tags
and both peer repositories are unchanged.

The [durable demo/replay guide](docs/PORTFOLIO_DEMO_RELEASE.md) describes the separately
versioned demo release, complete dependency lock, SHA-256-verified wheelhouse and
byte-identical offline replay gate. This publication never moves the core `v1.0.0` tag.

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

vulnevidenceops integration-handoff examples/synthetic-assurance-dossier.json \
  --profile datagovops-control-evidence \
  --handoff-id HANDOFF-LOCAL-001 \
  --subject-ref synthetic-case:CASE-SYNTH-001 \
  --created-at 2026-01-20T00:10:00Z \
  --valid-until 2027-01-20T00:10:00Z \
  --synthetic \
  --output /tmp/datagovops-handoff.json

vulnevidenceops verify-integration /tmp/datagovops-handoff.json \
  examples/synthetic-assurance-dossier.json \
  --peer-contract examples/peer-contracts/datagovops-control-evidence-reference.schema.json \
  --as-of 2026-01-20T00:15:00Z
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
- peer-repository authenticity, cross-system identity, producer authority, payload truth,
  payload-schema conformance, semantic compatibility, delivery, consumer acceptance or production
  interoperability merely because an integration handoff verifies;
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
- [Integration contracts](docs/INTEGRATION_CONTRACTS.md)
- [Security boundary](docs/SECURITY_BOUNDARY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Release process](docs/RELEASE_PROCESS.md)
- [v1 stable reference](docs/V1_STABLE_REFERENCE.md)
- [Compatibility](COMPATIBILITY.md)
- [Roadmap](docs/ROADMAP.md)

## License

Apache License 2.0.
