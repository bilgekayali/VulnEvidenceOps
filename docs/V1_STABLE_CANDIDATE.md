# v1 stable candidate

`1.0.0rc1` freezes the intended v1 Python API, CLI, dependency and JSON Schema surfaces in
`compatibility/v1-stable-baseline.json`. `tools/stable_candidate.py --verify` fails on byte-level
schema drift or any change to the other declared compatibility surfaces.

This is a candidate, not a stable release. Independent human review was not performed. The
repository owner explicitly waived that prerequisite on 2026-08-28; the accountable waiver is
recorded separately from `review_completed`, which remains false. A green candidate establishes
repository consistency and clean-wheel execution only; it does not establish production safety,
regulatory compliance, scanner completeness or the truth of supplied evidence.

After the candidate is merged, its exact `main` commit may be bound into post-merge release
evidence. Final `1.0.0`, tagging, GitHub Release creation and package publication each remain
separate human decisions; the waiver must never be represented as an independent review.
