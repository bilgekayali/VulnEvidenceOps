# Contributing

Contributions must preserve the repository's evidence-only, non-operating boundary.

1. Create a focused branch and keep commits reviewable.
2. Add or update tests for every behavioral change.
3. Update the relevant JSON Schema and compatibility notes when a public contract changes.
4. Run `ruff check .`, `pytest` and `python tools/release_contract.py --emit --verify`.
5. Keep all examples synthetic and pass `synthetic=true` for generated evidence records.
6. Adapter changes must preserve one mapping per candidate record or fail the whole batch.
7. Exposure assertions must retain source identity, evidence linkage and explicit expiry; they
   must not introduce autonomous scores, priorities or SLA decisions.
8. Portfolio changes must retain raw counts and accountable records; do not introduce compliance
   percentages, severity-weighted rankings or inferred deduplication.

Do not commit real hostnames, IP addresses, credentials, customer identifiers, proprietary scanner
exports, exploit payloads or confidential vulnerability evidence. Framework mappings must remain
non-certifying and must not produce compliance percentages.
