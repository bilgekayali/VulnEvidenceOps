# VulnEvidenceOps → DataGovOps → DORAOps

This repository-only example exercises **real installed consumer APIs**, not a local
hash/profile check relabeled as interoperability. It first runs the signed DataGovOps
example, then reconsumes that source and indexes the synthetic finding into DORAOps'
ICT risk and resilience-testing lifecycle. Both consumer processes avoid importing the
VulnEvidenceOps runtime.

No peer source, frozen API/schema, runtime dependency declaration or existing v1.0.0 tag
is changed. The adapter and its example contracts live in this repository, not in the
stable DORAOps package. This is not a deployment or a production integration.

## One command

In a current VulnEvidenceOps `main` checkout with Python 3.11+ and Git:

```bash
python tools/demo_doraops.py --test
```

This installs VulnEvidenceOps, DataGovOps and DORAOps as non-editable wheels in a
temporary isolated environment, runs the DORAOps integration suite and runs the full
three-project scenario. GitHub and the configured package index are needed only during
installation. No global environment is modified. All scenario execution is offline:
no scanner, ticketing system, evidence URL, remote schema or live institution is accessed.

Outputs are retained under `artifacts/doraops-demo/`. Existing output is rejected:

```bash
python tools/demo_doraops.py --test --output-dir artifacts/doraops-second
```

Offline developer mode with the exact source-compatible packages already available:

```bash
python tools/demo_doraops.py --prepared-environment --test
```

Prepared mode is recorded honestly. The default wheel path runs in the required `CI`
workflow on Python 3.11/3.12/3.13. The separate DataGovOps job still runs its entire
integration/signature/bundle suite. Each successful job uploads a SHA-bound artifact
and readable report, retained for 30 days; failed/partial demos are not published as
successful bundles. No package-index publication is performed.

## The correct consumer boundary

The frozen `doraops-operational-control-evidence` profile identifies deployment/runtime
controls such as immutable deployments, secret injection and backup/restore evidence.
A vulnerability dossier is not evidence that those seven controls were performed.
That existing public profile remains unchanged and is **not used** for this demo.

Instead, the repository example defines:

- `doraops-risk-remediation-input.v1`: exact input members and syntactic constraints;
- `doraops-risk-remediation-handoff.v1`: identity, exact peer/context/input digests and time window;
- `doraops-risk-remediation-demo-contract.v1`: exact runtime and ten official DORAOps schema snapshots;
- `doraops-demo-governance-context.v1`: consumer-owned, explicitly fictional inventory/risk/test decisions;
- `doraops-demo-change-completion.v1`: additional synthetic completion evidence, distinct from a plan.

The new profile is `doraops-risk-remediation-demo`, with boundary
`ict-risk-and-resilience-testing`. These are repository-example interfaces, not additions
to either package's stable public API. Their schema files are under `examples/doraops-demo/`,
not the frozen public `schemas/` directory.

A finding is **never automatically classified as a DORA incident**. No reporting deadline,
regulatory applicability decision, incident notification or deployment control is fabricated.
The fictional entity uses country code `ZZ`, not a claim about a regulated institution.

## Actual consumption, in order

1. VulnEvidenceOps creates the synthetic dossier and signs the DataGovOps transcript.
   The original real DataGovOps consumer runs, with all six signature/integrity negative cases.
2. The DORAOps adapter validates its new input schema, exact peer/context identities,
   input hashes, asset mapping and exclusive validity window.
3. It repeats **actual DataGovOps consumption** and compares the complete receipt.
   A supplied `accepted:true` flag or a rehashed forged receipt is not an acceptance signal.
   DataGovOps currentness/signature policy is also checked at the later DORAOps consumption time.
4. The adapter registers a fictional function → service → asset graph in an actual
   DORAOps `InventoryRegistry`, assesses ICT risk and checks the decision's current snapshot.
5. The actual resilience APIs create a vulnerability-assessment plan/execution/finding,
   separately register completion, apply the configured synthetic reviewer rule, and
   calculate finding resolution at each phase. All official output schemas are checked.

The DataGovOps receipt is at `2026-01-20T00:05:00Z`; the DORAOps handoff is created no
earlier than that and consumed at `00:10:00Z`. Its exclusive expiry is
`2026-01-21T00:00:00Z`. These are fixed **fixture times**, not claims of current evidence
on the wall-clock CI date. The underlying synthetic finding/test event is January 1,
the remediation plan January 3, additional completion January 15, and retest January 16.

## Mapping and deliberately separate judgments

| Input | Actual DORAOps representation | Limit |
|---|---|---|
| Consumer-owned source-asset mapping | Entity-scoped `NodeRef`, graph and inventory snapshot | No guessed tenant/entity mapping |
| Finding identity/title/severity | `ICTRiskScenario` and `ResilienceFinding` | No incident classification |
| Explicit fictional likelihood 3 and impact 3 | `assess_ict_risk`: inherent/residual score 9, high | Not inferred from CVSS or VEO priority |
| No verified effectiveness observations | Empty control set and zero control credit | Represented DataGovOps rows do not reduce risk |
| VEO remediation owner/due date | `RiskTreatmentPlan(MITIGATE)` | No risk-acceptance approval |
| Consumer-owned fictional test event | `build_resilience_test_plan` and `record_test_execution` | The demo does not perform a scanner test |
| Additional bound completion document | `create_remediation`, with its own `completed_at` and digest | Plan date is never used as completion |
| Linked `effective` verification and configured reviewer | `create_retest(PASSED)` | Reviewer is a fictional role, not a real review |
| Linked `ineffective` verification | `create_retest(FAILED)` | No closure |
| Missing or `partial` verification | No passed/failed retest manufactured | Finding remains remediation-submitted/blocked |

Native evidence identities bind the inventory, risk decision, plan, execution, finding,
completion and retest. The receipt also binds the full source packet, reconsumed DataGovOps
receipt and each emitted native artifact. Completion must name the same finding, plan,
change and owner; event/collection times must be ordered. Stage materials must match their
observation/change/retest kinds, subject, verifier and represented outcome. A bare
`effective` label with unrelated or future evidence cannot close the finding.

| Phase | Actual finding status | Actual test resolution |
|---|---|---|
| No remediation evidence | `open` | `blocked` |
| Completion without retest | `remediation_submitted` | `blocked` |
| Configured synthetic independent retest passes | `closed` | `successful_with_findings` |
| Retest missing/partial | `remediation_submitted` | `blocked` |
| Retest fails | `retest_failed` | `blocked` |

The ICT risk remains **high with score 9 and zero control credit even after finding
closure**. Its `remediation_required` flag is not silently cleared. A separate risk
reassessment/human decision would be needed to change that conclusion. In this bounded
demo, a risk-acceptance disposition is unsupported rather than auto-approved.

## Negative and attention evidence

Seven scenarios always run in separate consumer processes. Each must exit 2 with its
expected reason and leave no consumer output directory or accepted receipt:

| Scenario | Rejection |
|---|---|
| Modified source packet | `input_digest_mismatch` |
| Incompatible handoff version | `schema_incompatible` |
| Old operational-control profile substituted | `boundary_mismatch` |
| Forged DataGovOps receipt, digest recalculated | `upstream_receipt_mismatch` |
| Plan supplied without a completion timestamp | `schema_incompatible` |
| Validly signed source with an unconfigured reviewer | Native `doraops_rejected` |
| Retest before completion | Native `doraops_rejected` |

The last two are actual DORAOps validation failures, not schema-only substitutes.
Two additional attention cases preserve metadata successfully but remain **blocked**:
missing retest and failed retest. Acceptance of a record is not successful remediation.

The integration suite additionally verifies partial outcomes, evidence-role/type/time
mismatches, source revalidation, future/expired handoffs, peer/schema/runtime/context drift,
exact native digest chains, native entity-scope checks, stale inventory/risk/test plans,
conflicting latest retest evidence, deterministic bundles and overwrite protection.

## Evidence to inspect

- `REPORT.md`, `summary.json`, `source-provenance.json`, `execution-environment.json`.
- `datagovops/`: the complete signed DataGovOps evidence bundle, with its own report/manifest.
- `doraops/input.json`: the new handoff, original signed source, actual receipt and additional completion.
- `doraops/consumer/inventory.json`, `governance-context.json`, `risk-*.json`.
- `doraops/consumer/test-plan.json`, `test-execution.json`, `finding.json`, `remediation.json`, `retest.json`.
- `doraops/consumer/resolution-*.json` and `receipt.json`.
- `negative/`: exact rejected inputs/reasons; `attention/`: accepted metadata with blocked findings.
- `manifest.json`: complete sorted file inventory, sizes and raw-file SHA-256 hashes.

Download `doraops-evidence-<SHA>-py<version>-<run>-<attempt>` from a successful
[CI run](https://github.com/bilgekayali/VulnEvidenceOps/actions/workflows/ci.yml).
After safely extracting the artifact, the verifier needs only Python stdlib:

```bash
python tools/demo_evidence.py path/to/evidence \
  --expected-source-sha FULL_COMMIT_SHA \
  --expected-manifest-sha256 DIGEST_FROM_TRUSTED_JOB_SUMMARY --report
```

The source SHA and manifest digest should come from the trusted job, not a potentially
modified bundle. Native/input digests use canonical JSON; schema/context file fingerprints
and the emitted-file manifest use exact bytes. Repeated runs in the same source/worktree,
environment and CI identity produce byte-identical evidence. Cross-runtime dependency
wheel reproducibility is not claimed.

## Exact pins and non-claims

DORAOps v1.0.0 is installed from
[`c4a565f425084f64018ec91e5aec91ba9084f4fa`](https://github.com/bilgekayali/DORAOps/commit/c4a565f425084f64018ec91e5aec91ba9084f4fa).
All **27** installed Python source files and **10** byte-exact official schema snapshots
(including Git blob identities) are checked. Snapshots are embedded as raw text in the
demo contract to preserve even final-newline differences. All `$ref` values are local.
The [DataGovOps pin and signed-consumer boundary](DATAGOVOPS_E2E_DEMO.md) remain in force.

The existing Ed25519 signature covers the DataGovOps transcript, **not the separate
DORAOps handoff or additional completion**. DORAOps reconsumes and validates the source,
but does not inherit production signing authority from a different audience/purpose.
The DORAOps receipt explicitly keeps `doraops_handoff_signature_verified=false`. Its new
mapping/completion integrity checks are not independent origin authentication. The RFC
demo keys are public and forgeable; no real private keys are used.

All identities, evidence bodies, risk judgments, classifications and dates are synthetic.
No real review, scanner execution, change execution, remediation effectiveness, key custody,
incident determination, legal/regulatory compliance or production interoperability is
established. The configured synthetic independent-reviewer check is distinct from the
repository owner's PR-review waiver: neither represents a real governance approval.
