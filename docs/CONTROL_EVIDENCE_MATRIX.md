# Control/evidence matrix

`configs/control-evidence-matrix.json` defines six internal controls. The assessor reports each as:

- `represented`: required, linked evidence is present for the represented state;
- `gap`: the control applies but required records or evidence are missing, stale or invalid;
- `not_applicable`: the control does not apply to the selected governance path.

The matrix never calculates a compliance or maturity percentage. A framework reference is a
design cross-reference, not a claim that the framework applies or that its requirement is met.

| Control | Evidence intent |
|---|---|
| VEO-INV-001 | Finding identity, external asset/source references and observed evidence |
| VEO-TRI-001 | Accountable, evidence-linked triage |
| VEO-REM-001 | Owned remediation plan and change reference |
| VEO-ACC-001 | Time-bounded acceptance, compensating controls and decision evidence |
| VEO-VER-001 | Effective, evidence-linked and independent verification |
| VEO-CLS-001 | Closure supported by disposition or verified remediation |

Institution-owned control owners must confirm applicability, authority, evidence sufficiency and
real-world effectiveness.
