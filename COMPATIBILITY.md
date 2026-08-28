# Compatibility policy

VulnEvidenceOps `0.x` releases are alpha references. Minor releases may deliberately change the
Python API, CLI or JSON Schemas when accompanied by a changelog entry and a release-contract
update.

The following are intentional v0.5 public surfaces:

- symbols listed in `vulnevidenceops.__all__`;
- the `vulnevidenceops` CLI commands `digest-json`, `schema`, `intake`, `assess`, `exposure`,
  `portfolio`, `sign-evidence` and `verify-evidence`;
- files matching `schemas/*.schema.json`;
- the internal control identities in `configs/control-evidence-matrix.json`;
- the adapter contract `vulnevidenceops.intake.v1` for SARIF 2.1.0 and CycloneDX 1.5/1.6.
- the exposure contract `vulnevidenceops.exposure-context.v1` and its four public record schemas.
- the portfolio contract `vulnevidenceops.portfolio-assurance.v1` and its two public schemas.
- the signed-evidence contract `vulnevidenceops.signed-evidence.v1`, Ed25519 profile and its five
  public schemas.

Patch releases must remain backward compatible with the v0.5 contract. A future v1.0 release will
freeze exact API and schema fingerprints and adopt Semantic Versioning compatibility guarantees.

No package version implies a Git tag, GitHub Release, package publication, deployment, security
assessment, compliance decision or production-readiness attestation.
