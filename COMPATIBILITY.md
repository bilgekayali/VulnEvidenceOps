# Compatibility policy

VulnEvidenceOps `1.0.0rc1` is the stable-reference candidate. Its intended v1 Python API, CLI,
runtime dependencies and JSON Schemas are frozen byte-for-byte in
`compatibility/v1-stable-baseline.json` and checked by `tools/stable_candidate.py`.

The following are intentional v1 candidate public surfaces:

- symbols listed in `vulnevidenceops.__all__`;
- the `vulnevidenceops` CLI commands `digest-json`, `schema`, `intake`, `assess`, `exposure`,
  `portfolio`, `sign-evidence`, `verify-evidence`, `integration-handoff` and
  `verify-integration`;
- files matching `schemas/*.schema.json`;
- the internal control identities in `configs/control-evidence-matrix.json`;
- the adapter contract `vulnevidenceops.intake.v1` for SARIF 2.1.0 and CycloneDX 1.5/1.6.
- the exposure contract `vulnevidenceops.exposure-context.v1` and its four public record schemas.
- the portfolio contract `vulnevidenceops.portfolio-assurance.v1` and its two public schemas.
- the signed-evidence contract `vulnevidenceops.signed-evidence.v1`, Ed25519 profile and its five
  public schemas.
- the integration contract `vulnevidenceops.integration-contract.v1`, its four frozen peer
  profiles and three public schemas.

Final v1.0 patch releases must remain backward compatible with this baseline. Additive changes
require an explicit compatibility review; removals or incompatible schema changes require a new
major version. The candidate is not a final stable release while independent review is pending.

No package version implies a Git tag, GitHub Release, package publication, deployment, security
assessment, compliance decision or production-readiness attestation.
