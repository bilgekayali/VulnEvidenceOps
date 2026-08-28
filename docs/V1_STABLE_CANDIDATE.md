# v1 stable candidate

`1.0.0rc1` freezes the intended v1 Python API, CLI, dependency and JSON Schema surfaces in
`compatibility/v1-stable-baseline.json`. `tools/stable_candidate.py --verify` fails on byte-level
schema drift or any change to the other declared compatibility surfaces.

This is a candidate, not a stable release. The committed independent-review record deliberately
states that human review is pending. The final promotion command remains fail-closed until that
record identifies a reviewer and links review evidence. A green candidate therefore establishes
repository consistency and clean-wheel execution only; it does not establish production safety,
regulatory compliance, scanner completeness or the truth of supplied evidence.

After the candidate is merged, its exact `main` commit may be bound into post-merge release
evidence. Final `1.0.0`, tagging, GitHub Release creation and package publication each remain
separate human decisions.
