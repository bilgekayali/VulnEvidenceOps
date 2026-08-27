# Release process

The committed `0.1.0` version is an alpha source boundary. It does not imply a Git tag, GitHub
Release, package publication or deployment.

A release candidate must pass on the exact candidate SHA:

1. Python 3.11, 3.12 and 3.13 CI;
2. CodeQL;
3. `python tools/release_contract.py --emit --verify`;
4. deterministic direct-dependency CycloneDX generation;
5. wheel build and clean-environment CLI assessment;
6. human review of the explicit non-claims and synthetic-data boundary.

Tagging and GitHub Release creation require a separate human decision after the exact merged
`main` SHA has passed the same gates. Package publication and deployment are not part of v0.1.
