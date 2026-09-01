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
initial wheel acquisition/building. Build/runtime versions are locked and the execution
environment uses only hash-verified wheel bytes. No global environment is modified.
All scenario execution is offline:
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

The Python 3.12 job also replays the exact wheelhouse in a second new environment
with no index access and requires every evidence byte to match before creating a
durable demo candidate. See [durable release and replay](PORTFOLIO_DEMO_RELEASE.md)
for the separate publication gate, assets and platform-specific replay instructions.

## The correct consumer boundary

The frozen `doraops-operational-control-evidence` profile identifies deployment/runtime
controls such as immutable deployments, secret injection and backup/restore evidence.
A vulnerability dossier is not evidence that those seven controls were performed.
That existing public profile remains unchanged and is **not used** for this demo.

Instead, the repository example defines:

- `doraops-risk-remediation-input.v2`: exact input members and a required separate signature;
- `doraops-risk-remediation-handoff.v1`: identity, exact peer/context/input digests and time window;
- `doraops-risk-remediation-demo-contract.v2`: runtime/schema pins and the DORAOps key-policy hash;
- `doraops-demo-governance-context.v1`: consumer-owned, explicitly fictional inventory/risk/test decisions;
- `doraops-demo-change-completion.v1`: additional synthetic completion evidence, distinct from a plan.
- `doraops-demo-transcript.v1`: four signed input hashes, audience, purpose, schema and context;
- `doraops-demo-signing-policy.v1`: pinned public test keys and consumption-time revocation policy.

Input/contract v2 deliberately rejects the earlier unsigned repository-demo input. This
is a demo-only compatibility change; no frozen public package schema is changed.

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
4. It independently verifies the separate DORAOps Ed25519 transcript under its own
   pinned audience/purpose/key policy. All four inputs, including completion, are signed.
   This does not reuse DataGovOps' verifier result or accept packet-supplied trust keys.
5. The adapter registers a fictional function → service → asset graph in an actual
   DORAOps `InventoryRegistry`, assesses ICT risk and checks the decision's current snapshot.
6. The actual resilience APIs create a vulnerability-assessment plan/execution/finding,
   separately register completion, apply the configured synthetic reviewer rule, and
   calculate finding resolution at each phase. All official output schemas are checked.

The DataGovOps receipt is at `2026-01-20T00:05:00Z`; the DORAOps handoff is created no
earlier than that, signed at `00:06:00Z` and consumed at `00:10:00Z`. The negative
revoked-key fixture is revoked at `00:08:00Z`: a signature valid before revocation is
still rejected at consumption. The handoff's exclusive expiry is
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

Fourteen scenarios always run in separate consumer processes. Each must exit 2 with its
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
| Missing separate DORAOps signature | `doraops_signature_required` |
| Valid demo signature for another audience | `doraops_signature_context_mismatch` |
| Wrong private key under the allowed key ID | `doraops_signature_invalid` |
| Untrusted signing key ID | `doraops_key_not_trusted` |
| Key revoked after signing but before consumption | `doraops_key_revoked` |
| Completion, binding hashes and transcript replaced; old signature retained | `doraops_signature_invalid` |
| DataGovOps signature replayed as DORAOps authority | `doraops_signature_context_mismatch` |

The reviewer and retest-chronology cases are actual DORAOps validation failures,
with otherwise valid demo signatures, not schema-only substitutes.
Two additional attention cases preserve metadata successfully but remain **blocked**:
missing retest and failed retest. Acceptance of a record is not successful remediation.

The integration suite additionally verifies partial outcomes, evidence-role/type/time
mismatches, source revalidation, future/expired handoffs, peer/schema/runtime/context drift,
exact native digest chains, native entity-scope checks, stale inventory/risk/test plans,
conflicting latest retest evidence, deterministic bundles and overwrite protection.
The separate signature suite checks wrong purpose, every signed member, claimed-time
ordering, expiry, malformed encodings, canonical transcripts, key-policy drift and
no-output-on-rejection. The consumer never imports the producer runtime or verifier.

## Evidence to inspect

- `index.html`: responsive five-minute walkthrough generated only from the retained JSON.
- `presentation.json`: strict display model with source identity and SHA-256/size-bound links.
- `REPORT.md`, `summary.json`, `source-provenance.json`, `execution-environment.json`.
- `datagovops/`: the complete signed DataGovOps evidence bundle, with its own report/manifest.
- `doraops/input.json`: handoff, signed source, actual receipt, completion and separate signed envelope.
- `doraops/consumer/signature-verification.json`: independent DORAOps signature/key-policy result.
- `doraops/consumer/inventory.json`, `governance-context.json`, `risk-*.json`.
- `doraops/consumer/test-plan.json`, `test-execution.json`, `finding.json`, `remediation.json`, `retest.json`.
- `doraops/consumer/resolution-*.json` and `receipt.json`.
- `negative/`: exact rejected inputs/reasons; `attention/`: accepted metadata with blocked findings.
- `manifest.json`: complete sorted file inventory, sizes and raw-file SHA-256 hashes.

The HTML is self-contained: no CDN, remote font, image, analytics or network request is
permitted. Its restrictive content-security policy hashes the exact embedded CSS and
script. Native buttons filter the four comparison outcomes and the fourteen rejection
boundaries remain available in an expandable audit table. The verifier re-derives the
complete model from actual receipts, signature reports, risk/resolution records,
attention receipts and rejection files, then requires byte-exact model and HTML matches.
It therefore cannot turn a changed risk score, failed signature, blocked case or altered
rejection into a stale success page.

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
environment and CI identity produce byte-identical evidence. Retained-wheel offline
replay is now explicitly checked; cross-runtime portability and independent
bit-reproducible wheel rebuilding are not claimed.

## Exact pins and non-claims

DORAOps v1.0.0 is installed from
[`c4a565f425084f64018ec91e5aec91ba9084f4fa`](https://github.com/bilgekayali/DORAOps/commit/c4a565f425084f64018ec91e5aec91ba9084f4fa).
All **27** installed Python source files and **10** byte-exact official schema snapshots
(including Git blob identities) are checked. Snapshots are embedded as raw text in the
demo contract to preserve even final-newline differences. All `$ref` values are local.
The [DataGovOps pin and signed-consumer boundary](DATAGOVOPS_E2E_DEMO.md) remain in force.

Two independent Ed25519 verifications now have distinct audience/purpose scopes. The
DataGovOps signature still covers its original transcript. A **second DORAOps signature**
covers the entire new handoff, source packet, actual DataGovOps receipt and additional
completion, together with exact demo-contract, input-version, context and key-policy
identities. The DORAOps receipt records `doraops_handoff_signature_verified=true` and
binds the verification report and envelope digests. Neither signature substitutes for
schema, semantic, chronology or real native-consumer checks. Unsigned fallback is disabled.

The RFC 8032 test-vector keys are **public and forgeable by anyone**. Separate identifiers
and audience/purpose binding demonstrate replay rejection, not production key custody or
sender authentication. No real private keys are used, and no signature establishes that
a real change was performed. All production-authority non-claims remain false.

All identities, evidence bodies, risk judgments, classifications and dates are synthetic.
No real review, scanner execution, change execution, remediation effectiveness, key custody,
incident determination, legal/regulatory compliance or production interoperability is
established. The configured synthetic independent-reviewer check is distinct from the
repository owner's PR-review waiver: neither represents a real governance approval.
