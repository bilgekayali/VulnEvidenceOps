# Release process

The committed `1.0.0rc1` version is a stable-reference candidate source boundary. It does not
imply final `1.0.0`, a Git tag, GitHub Release, package publication or deployment.

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
`python tools/stable_candidate.py --require-final-review`. The candidate intentionally fails that
command until an identified independent reviewer and linked review evidence are recorded.

Tagging and GitHub Release creation require a separate human decision after the exact merged
`main` SHA has passed the same gates. Package publication and deployment are separate decisions.
