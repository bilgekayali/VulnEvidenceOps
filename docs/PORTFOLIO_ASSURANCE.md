# Portfolio assurance

## Boundary

VulnEvidenceOps v0.4 composes caller-supplied case bundles under one explicit vulnerability policy
and assessment time. It produces digest-bound case summaries, raw SLA cohorts, exception-ageing
records and role-based accountability views. It does not query an inventory, infer duplicates,
calculate compliance or decide remediation priority.

## Input contract

A `portfolio-bundle.v1` contains:

- an opaque portfolio and scope reference;
- one accountable portfolio role;
- zero or more complete `case-bundle.v1` records;
- one explicit `vulnerability-policy.v1` used for every case.

Case and finding identifiers must be unique inside the bundle. An empty bundle remains valid input
but produces an `unavailable` view and a `portfolio_cases_missing` gap; it does not establish that
the real scope contains no vulnerabilities.

## Deduplication decisions

The portfolio view reads only triage records whose disposition is explicitly `duplicate`. It does
not compare titles, CVEs, assets or scanner output. Each decision reports:

- whether the decision is current at `assessed_at`;
- whether its target is linked, out of scope or itself marked duplicate;
- whether the named evidence is linked, missing, unlinked or future-dated;
- the accountable role, rationale and exact evidence references.

Future decisions, chained targets and evidence defects become stable portfolio gaps. The assessor
does not select or repair a canonical target.

## SLA cohorts

Every supplied case appears exactly once in a severity-specific raw cohort:

| Cohort | Meaning |
|---|---|
| `closed` | Evidence-closed verification or disposition path |
| `accepted_exception` | Current, policy-bounded risk-acceptance path |
| `revalidation_required` | Acceptance expired and requires review |
| `overdue` | Open case is past its policy-derived due timestamp |
| `due_today` | Due on the UTC assessment date |
| `due_within_7_days` | Due in one to seven UTC calendar days |
| `due_within_30_days` | Due in eight to thirty UTC calendar days |
| `due_later` | Due more than thirty UTC calendar days later |

The output contains case IDs, finding IDs and integer counts only. It has no denominator,
percentage, severity weighting, trend claim or pass/fail compliance state.

## Exception ageing

Every supplied risk acceptance is reported as `future`, `current` or `expired`, with signed days
until expiry and a transparent age band. Policy duration and evidence linkage are separate fields;
neither makes the acceptance valid in law, proves authority or establishes acceptable residual
risk.

## Accountability view

Roles are collected from portfolio oversight, triage, remediation, risk ownership, approval and
verification records. Each row lists only raw responsibilities and the linked case/finding IDs.
Missing case-level governance roles become explicit gaps. The view does not prove identity,
delegated authority, executive approval or action completion.

## Explicit non-claims

A valid portfolio view does not establish inventory completeness, automatic deduplication,
cross-system identity, SLA compliance, compliance percentages, executive approval, risk ranking,
remediation priority or risk-acceptance validity.
