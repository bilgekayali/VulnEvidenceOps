# Threat model

## Protected properties

- finding and decision identity;
- evidence-to-record linkage;
- lifecycle ordering and currentness;
- closure and risk-acceptance integrity;
- deterministic dossier reproduction.

## Primary threats

| Threat | v0.4 response | Residual boundary |
|---|---|---|
| Evidence substitution | Exact SHA-256 artifact digest and opaque evidence ID | External artifact authenticity and custody |
| Finding relabelling | Immutable finding, asset and source references | External inventory correctness |
| Unsupported closure | Evidence-backed disposition or effective verification required | Live remediation effectiveness |
| Self-verification | Verifier role must differ from remediation owner when policy requires | Real identity and authority verification |
| Permanent risk acceptance | Explicit expiry and maximum duration | Human risk appetite and legal validity |
| Future-dated evidence | Records after `assessed_at` cannot satisfy controls | Trusted external time |
| Missing scanner coverage | Explicit non-claim and inventory/evidence gap | Discovery and scanner completeness |
| Malicious input | JSON Schema and local invariant checks | Host resource limits and sandboxing |
| Silent adapter omission | Every candidate result or vulnerability-affect pair maps or the batch fails | Upstream export completeness |
| Severity translation drift | Fixed, versioned mapping rules and explicit fallback notices | Source severity correctness |
| Source-record substitution | Artifact, canonical document and source-record digests plus JSON Pointers | External custody and authenticity |
| Stale context treated as current | Explicit assertion expiry and evidence collection-time checks | Trusted external time and refresh cadence |
| Context-source substitution | Assertion and evidence source identities must match | Real source identity and authenticity |
| Conflicting context hidden | Concurrent contradictory exploit or criticality assertions become explicit gaps | Human source adjudication |
| Context converted into an implicit decision | No score, priority, SLA or business-impact output; explicit false non-claims | Downstream use and human governance |
| Silent duplicate inference | Only explicit accountable `duplicate` triage decisions enter the portfolio view | Human decision quality and source completeness |
| Chained or external duplicate target hidden | Target state and stable portfolio gaps remain visible | Human canonical-record adjudication |
| Exception age presented as approval | Age, expiry, evidence and policy states are separate; approval remains a non-claim | Real authority and risk appetite |
| Raw counts presented as compliance | No percentage, weighted score or rank is produced; explicit false non-claims | Downstream presentation and interpretation |
| Incomplete portfolio scope | Opaque scope reference and explicit asset-inventory completeness non-claim | External inventory and query completeness |

## Trust assumptions

The caller controls input authenticity, actor identity, artifact custody and system-of-record
integrity. SHA-256 syntax and deterministic processing do not prove those external facts.
