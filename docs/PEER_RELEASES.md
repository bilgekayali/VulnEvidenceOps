# Verified DataGovOps and DORAOps releases

This ledger records the peer repositories' independently published stable GitHub Releases
as verified on 2026-09-01 UTC. These identities supplement the portfolio evidence trail.
They do not rewrite the exact commits, dependency lock, manifests or retained wheel bytes
already bound into VulnEvidenceOps `demo-v1.0.0`.

## Release ledger

| Peer | Published release | Exact tag and release target | Demo runtime pin |
|---|---|---|---|
| DataGovOps | [`v1.0.0`](https://github.com/bilgekayali/DataGovOps/releases/tag/v1.0.0) | [`065a14e77487f97adf5c6228f93c3737f2dd409a`](https://github.com/bilgekayali/DataGovOps/commit/065a14e77487f97adf5c6228f93c3737f2dd409a) | [`8bfd1b9558ae996e15f4c3d21158e8688d657f16`](https://github.com/bilgekayali/DataGovOps/commit/8bfd1b9558ae996e15f4c3d21158e8688d657f16) |
| DORAOps | [`v1.0.0`](https://github.com/bilgekayali/DORAOps/releases/tag/v1.0.0) | [`6b1fd28ad8a83f0c8ac83b33709d34f7d964f539`](https://github.com/bilgekayali/DORAOps/commit/6b1fd28ad8a83f0c8ac83b33709d34f7d964f539) | [`c4a565f425084f64018ec91e5aec91ba9084f4fa`](https://github.com/bilgekayali/DORAOps/commit/c4a565f425084f64018ec91e5aec91ba9084f4fa) |

For both peers, the `v1.0.0` Git ref resolved directly to the listed commit, the release
target matched that same commit, and the published release was neither a draft nor a
prerelease. Each peer's release publisher first required the current `main` commit to pass
its complete configured workflow gate set.

## Why the demo pins remain unchanged

Each release target is exactly one commit ahead of its corresponding demo pin, with no
divergence. Those commits add or adjust only release workflows, release policy and notes,
operator documentation, and publisher tests/tools. Neither comparison changes package
source, public schemas or package metadata.

The retained `demo-v1.0.0` evidence and wheel assets were produced and replay-verified at
the demo runtime pins in the table. Replacing those pins would create a different evidence
candidate and require a newly versioned demo publication. A later repository-level release
therefore does not retroactively re-identify the bytes or receipts already published.

## Boundaries

- This ledger records GitHub repository tag/release identity; it is not a package-registry,
  container, deployment or archival claim.
- It does not add peer authority, production interoperability, compliance, control
  effectiveness, independent review or real-world evidence claims.
- VulnEvidenceOps `v1.0.0`, `demo-v1.0.0`, all existing release assets and their hashes remain
  unchanged.
