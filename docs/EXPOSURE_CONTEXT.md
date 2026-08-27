# Exposure context

## Boundary

VulnEvidenceOps v0.3 binds caller-supplied exploit-intelligence and business-criticality
assertions to one normalized finding. It evaluates whether the assertions and their referenced
evidence are current at an explicit assessment time. It has no network client and does not query,
endorse or verify an intelligence feed, service catalogue or CMDB.

## Input contract

An `exposure-context-bundle.v1` contains:

- one complete `vulnerability-finding.v1`;
- zero or more `exploit-intelligence.v1` assertions whose finding ID and technical identifier
  match that finding;
- zero or more `business-criticality.v1` assertions whose asset reference matches that finding;
- evidence references used by those assertions.

Every assertion identifies its source, an opaque source record, its effective time, an explicit
`valid_until` time and zero or more evidence references. Missing evidence is accepted as input but
reported as a gap; invalid cross-record links fail construction.

## Currentness

Each assertion receives one deterministic state:

| State | Meaning |
|---|---|
| `current` | Effective, unexpired and linked to evidence from the same source collected by the assessment time |
| `future` | Assertion is not yet effective |
| `expired` | Assertion validity ended at or before the assessment time |
| `evidence_missing` | Assertion names no evidence |
| `evidence_unlinked` | At least one named evidence ID is absent from the bundle |
| `evidence_source_mismatch` | Assertion and referenced evidence source identities differ |
| `evidence_future` | Referenced evidence was collected after the assessment time |

The aggregate position is `current` when both domains have a current, non-conflicting record;
`partial` when only one does; `stale` when supplied records are all non-current; `unavailable`
when neither domain has records; and `with_gaps` when current assertions conflict.

## Conflict handling

The assessor exposes, but does not resolve:

- a current positive exploit signal alongside a current `no_exploitation_signal_reported` signal
  for the same technical identifier;
- multiple current criticality labels for the same business service.

Source precedence, confidence weighting and adjudication remain human or downstream concerns.

## Explicit non-claims

A valid and current context assessment does not establish exploitability, business impact,
assertion truth, autonomous priority, a risk score or a remediation SLA. The output preserves each
of those boundaries as an explicit false-valued non-claim.
