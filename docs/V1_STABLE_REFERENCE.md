# v1 stable reference

`1.0.0` freezes the v1 Python API, CLI, dependency and JSON Schema surfaces in
`compatibility/v1-stable-baseline.json`. `tools/stable_candidate.py --verify` fails on byte-level
schema drift or any change to the other declared compatibility surfaces.

Independent human review was not performed. The repository owner explicitly waived that
prerequisite on 2026-08-28; the accountable waiver is recorded separately from
`review_completed`, which remains false. The waiver must never be represented as independent
review.

Stable Reference establishes repository consistency, compatibility policy and clean-wheel
execution for the synthetic reference boundary only. It does not establish production safety,
regulatory compliance, scanner completeness, vulnerability absence, remediation effectiveness or
the truth of supplied evidence.

The `v1.0.0` Git tag and GitHub Release bind the published release to one exact green `main` SHA.
Package-index publication and deployment are not part of this release unless separately recorded.
