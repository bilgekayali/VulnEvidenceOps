# Intake adapters

## Boundary

VulnEvidenceOps v0.2 accepts local JSON documents for these exact source versions:

- SARIF 2.1.0;
- CycloneDX 1.5 and 1.6.

The adapters normalize source assertions. They do not run scanners, validate every optional field
in the upstream standards, resolve assets, calculate CVSS, verify advisories or prove that a
vulnerability exists.

## Traceability contract

An `intake-batch.v1` contains:

- the SHA-256 of the exact input artifact bytes;
- the SHA-256 of its canonical JSON content;
- the SHA-256 of caller-supplied mapping context;
- one normalized `vulnerability-finding.v1` per mapped source candidate;
- one `intake-mapping.v1` record per finding;
- JSON Pointer source locators and a source-record digest;
- explicit false-valued non-claims.

The output does not embed the raw scanner document. The caller remains responsible for secure
artifact custody and for retaining the exact artifact named by `artifact_ref`.

## SARIF mapping

Every item in `runs[].results[]` maps to one finding. The caller supplies one opaque `asset_ref`
for the batch. `ruleId`, message and level are mapped through fixed rules. A rule-level default may
be used when the result omits its level; an absent or unknown level becomes `informational` with an
explicit notice. A result missing a rule identity or message fails the entire batch.

## CycloneDX mapping

Every `vulnerabilities[]` and `affects[]` pair maps to one finding. The affected component `ref` is
appended to a caller-supplied opaque asset-reference prefix. The highest recognized rating is used;
missing or unknown severity becomes `informational` with an explicit notice. A vulnerability
without an affected component fails the entire batch.

## Determinism and cardinality

Finding, mapping and batch identifiers derive from canonical source content, explicit mapping
context and source locators. Repeated source records are retained as separate mappings rather than
silently deduplicated. Identical inputs and context produce byte-equivalent output JSON.
