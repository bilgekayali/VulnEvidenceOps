# Release process

The committed `1.0.0` version is the stable-reference source boundary. Source promotion does not
by itself imply a Git tag, GitHub Release, package publication or deployment.

A release candidate must pass on the exact candidate SHA:

1. Python 3.11, 3.12 and 3.13 CI;
2. CodeQL;
3. `python tools/release_contract.py --emit --verify`;
4. deterministic direct-dependency CycloneDX generation;
5. wheel build and clean-environment CLI assessment;
6. clean-wheel SARIF, CycloneDX, exposure-context, portfolio, signed-evidence and integration
   smoke tests;
7. verification of the committed synthetic Ed25519 envelope, public key, build provenance and
   anchor binding without private-key material;
8. exact Git-blob verification of every committed peer-contract snapshot and all four reference
   handoffs;
9. human review of the explicit non-claims and synthetic-data boundary.
10. `python tools/stable_candidate.py --emit --verify` against the frozen v1 baseline.

Final stable promotion must additionally pass
`python tools/stable_candidate.py --require-final-review`. This is satisfied either by an identified
independent reviewer with linked evidence or by an explicit, accountable repository-owner waiver.
The waiver does not constitute or imply independent review.

Tagging and GitHub Release creation require a separate human decision after the exact merged
`main` SHA has passed the same gates. Package publication and deployment are separate decisions.

## Publication gate

`release/publish-policy.json` records the authorized version, notes and exact workflow paths/names.
`Publish release` reacts only to completed main-branch push workflows from this repository. It
requires every configured workflow's latest run/attempt on the same exact SHA to succeed, and
requires that SHA to still be `main`. A PR check, fork run, older success, missing check, failed
check or different SHA cannot authorize publication. The gate job has read-only permissions;
only the publish job has contents-write permission and it rechecks the gate before writing.

Existing published versions are no-ops: the tag is never moved and the Release is never edited.
A tag without a Release may only be completed if it already points to the exact tested candidate.
The original `v1.0.0` tag therefore remains unchanged by later maintenance commits. Future versions
require an explicit publication-policy update; a version bump alone cannot publish them.
