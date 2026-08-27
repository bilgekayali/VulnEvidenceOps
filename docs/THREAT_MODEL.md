# Threat model

## Protected properties

- finding and decision identity;
- evidence-to-record linkage;
- lifecycle ordering and currentness;
- closure and risk-acceptance integrity;
- deterministic dossier reproduction.

## Primary threats

| Threat | v0.1 response | Residual boundary |
|---|---|---|
| Evidence substitution | Exact SHA-256 artifact digest and opaque evidence ID | External artifact authenticity and custody |
| Finding relabelling | Immutable finding, asset and source references | External inventory correctness |
| Unsupported closure | Evidence-backed disposition or effective verification required | Live remediation effectiveness |
| Self-verification | Verifier role must differ from remediation owner when policy requires | Real identity and authority verification |
| Permanent risk acceptance | Explicit expiry and maximum duration | Human risk appetite and legal validity |
| Future-dated evidence | Records after `assessed_at` cannot satisfy controls | Trusted external time |
| Missing scanner coverage | Explicit non-claim and inventory/evidence gap | Discovery and scanner completeness |
| Malicious input | JSON Schema and local invariant checks | Host resource limits and sandboxing |

## Trust assumptions

The caller controls input authenticity, actor identity, artifact custody and system-of-record
integrity. SHA-256 syntax and deterministic processing do not prove those external facts.
