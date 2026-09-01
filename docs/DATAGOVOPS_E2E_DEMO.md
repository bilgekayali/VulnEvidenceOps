# VulnEvidenceOps → DataGovOps: real consumer, synthetic evidence

This example closes the gap between an intended handoff and actual local consumption.
It calls the real DataGovOps v1 `ControlEvidenceRegistry`, registers evidence and
builds DataGovOps control assessments and matrices. It does not copy/reimplement the
registry or treat a successful producer-side hash check as consumer acceptance.

For the complete three-project continuation, see
[DORAOps risk/remediation consumption](DORAOPS_RISK_REMEDIATION_DEMO.md). It revalidates
this signed source and actual DataGovOps receipt before invoking DORAOps' separate
risk/resilience APIs; it does not reuse the operational-deployment-control profile.

## One command

In a checkout of VulnEvidenceOps `main`, with Python 3.11+ (including venv/pip) and Git:

```bash
python tools/demo_datagovops.py --test
```

The command creates a temporary isolated environment, installs both projects as
non-editable wheels, runs the full integration suite, and runs the positive and two
negative integrity scenarios plus four signature/key-policy rejection scenarios.
GitHub and the configured Python package index are needed for
installation only. The scenario and consumer perform no network operations, retrieve
no evidence URLs and resolve no remote schemas. No global Python environment is changed.
The temporary environment is removed afterward; generated evidence is retained.

`--test` is optional: the positive case and all six negative scenarios always run.
To preserve an earlier result, choose another directory:

```bash
python tools/demo_datagovops.py --output-dir artifacts/datagovops-demo-second
```

Existing output is rejected, never silently overwritten. For an already prepared
offline developer environment containing both exact source-compatible packages:

```bash
python tools/demo_datagovops.py --prepared-environment --test
```

Prepared mode is recorded honestly; only the default path claims isolated wheel
installation. CI runs the default command on Python 3.11, 3.12 and 3.13 inside the
existing required `CI` workflow, so the publication gate also waits for this demo.

## Download a CI evidence bundle

Open a successful [CI run](https://github.com/bilgekayali/VulnEvidenceOps/actions/workflows/ci.yml)
and choose its `datagovops-evidence-<exact-SHA>-py<version>-<run>-<attempt>` artifact.
Each Python matrix job uploads its own complete bundle, retained for 30 days. The job
summary also contains the readable report and the raw manifest SHA-256. Failed or
partial demos are not uploaded as successful evidence.

The demo job explicitly checks out the PR head (or push commit), compares the actual
Git HEAD with the expected full SHA, requires a clean CI checkout, and records its
tree, run URL, attempt, event, Python/dependencies and installation mode. It does not
mislabel a synthetic PR merge ref as the PR head. The upload action is exact-SHA pinned
and the job has read-only repository permissions; checkout credentials are not retained.

After downloading and safely extracting the GitHub artifact, verify it using Python
stdlib only; no project dependencies or installation are needed:

```bash
python tools/demo_evidence.py path/to/extracted-evidence \
  --expected-source-sha FULL_40_CHARACTER_SHA \
  --expected-manifest-sha256 SHA256_FROM_TRUSTED_JOB_SUMMARY --report
```

The verifier rejects missing/extra/modified files, duplicate or unsafe paths, symlinks,
oversized bundles and inconsistent source identities. It does not extract archives.
The external expected SHA/digest must come from the trusted run, not from a possibly
modified bundle. Internal consistency alone is **not** origin authentication; an
attacker could replace both data and an unsigned manifest. Local dirty checkouts are
explicitly labeled and do not claim exact committed-source evidence.

## What actually happens

1. The existing synthetic case/policy are loaded without changing the frozen fixtures.
   Four local synthetic observation/triage/change/retest materials are hashed, replacing
   placeholder hashes in the in-memory case. No scanner or patch system is operated.
2. The installed VulnEvidenceOps package assesses the case at
   `2026-01-20T00:00:00Z` and creates a dossier plus the frozen DataGovOps handoff profile.
3. A separate consumer process, which does not import the VulnEvidenceOps runtime,
   independently checks strict JSON, pinned producer schemas, exact peer identity,
   payload/case/policy/material digests, subject/evidence links and the validity window.
   It also independently verifies Ed25519 over all five packet members and the exact
   consumer context, using only its pinned, explicitly public demo-key policy.
4. The adapter creates real DataGovOps `ControlDefinition` and
   `ControlEvidenceReference` objects. DataGovOps enforces institution, exact control
   version, evidence type, source boundary, duplicate identity and schema constraints.
5. Real registry assessments/matrices are serialized with DataGovOps' canonical JSON,
   validated against its pinned public schemas, and bound into a consumer receipt.

The default synthetic finding is `FIND-SYNTH-001`, with dossier case `CASE-SYNTH-001`.
The consumer's institution and roles are explicitly synthetic identifiers.

| Observation | Actual DataGovOps matrix state | Counts |
|---|---|---|
| Before registration | `with_gaps` | 5 gaps |
| After registration, at 2026-01-20T00:05:00Z | `represented` | 5 represented controls |
| At 2026-01-21T00:00:00Z expiry | `revalidation_required` | 5 stale controls |

`VEO-ACC-001` is explicitly excluded because this fixture did not choose risk acceptance.
It is not silently treated as evidence or compliance. An upstream `gap` remains a gap
in DataGovOps; it is not promoted to represented merely because the dossier validates.

## Exact adapter mapping

| Producer information | DataGovOps representation |
|---|---|
| Each applicable VEO control row | One version-1 institution-owned `ControlDefinition` |
| Explicit demo-contract evidence type for that control | `evidence_type` and its requirement |
| Dossier handoff ID + control ID | Unique `evidence_id` |
| SHA-256 of canonical dossier | `source_artifact_digest` |
| SHA-256 of canonical case snapshot | `source_snapshot_digest` |
| SHA-256 of independent consumer validation report | `verification_evidence_digest` |
| Dossier assessment timestamp | `observed_at` (UTC integer seconds) |
| Exclusive handoff expiry minus one second | Inclusive `revalidate_after` |
| Dossier metadata boundary | `source_boundary=governance_dossier` |
| Producer row `gap` | Control registered, no evidence reference registered |
| Producer row `not_applicable` | Explicit exclusion in the receipt |

The six control/evidence-type mappings are explicit in `examples/datagovops-demo/demo-contract.json`.
No framework applicability or control effectiveness is inferred from a represented row.

## Negative evidence, not just happy-path output

| Scenario | Producer hash/profile-only check | Independent consumer result |
|---|---|---|
| Dossier content changed without rehashing | Digest mismatch | `payload_digest_mismatch`, exit 2 |
| Dossier schema changed to v999, digest recalculated | `verified` | `schema_incompatible`, exit 2 |
| Wrong private key, same allowed key ID | Hashes unchanged | `signature_invalid`, exit 2 |
| Valid signature under an unknown key ID | Hashes unchanged | `key_not_trusted`, exit 2 |
| Signature predating key revocation | Library reports valid at claimed signing time | `key_revoked` at consumption, exit 2 |
| Modified dossier; all exposed hashes/transcript recalculated | Hashes match | Old signature fails: `signature_invalid`, exit 2 |

The second row is intentional: a valid digest does not prove a compatible payload.
All failed cases leave **no consumer output directory or accepted receipt**. Their
packets, rejection records and the misleading-but-correctly-bounded old local check
are preserved under `negative/`. The overall demo exits 0 only when the positive
case succeeds and all six negative cases fail at their expected boundary. The incompatible
schema case is re-signed with a valid demo key: signatures do not bypass schema validation.

## Signed consumption and deliberately limited trust

`examples/datagovops-demo/signing-policy.json` is consumer-owned configuration whose exact
SHA-256 is pinned in the demo contract. It requires a signature and lists exact Ed25519
public keys/fingerprints, validity windows and revocation dates. A packet cannot provide
its own trusted verification key or disable signature checking. There is no unsigned
fallback in the consumer CLI or function.

The producer uses the existing public `sign_evidence` API. The consumer does **not** call
the producer's verifier: it reconstructs the public `signature-input.v1` format and uses
`cryptography`'s Ed25519 verifier directly. The signed transcript binds the case, policy,
materials, dossier and handoff hashes; exact demo-contract/key-policy hashes; target
audience; and registration purpose. The envelope additionally binds key ID, algorithm,
payload type, claimed signing time and transcript digest. DataGovOps' reference hashes
bind the resulting signature verification through the independent validation report.

Key validity is required both at claimed signing time and at consumption time. A key
revoked before the synthetic verification time is rejected even when its claimed
signature predates revocation. Handoff creation/signing/verification times must be ordered.
These are **fixture dates in January 2026**, not a claim that the evidence/key is current
on the CI run date. There is no trusted clock, external timestamp or revocation service.

The two seeds are **public RFC 8032 §7.1 test vectors**, not real credentials. They are
used in memory by the producer-only demo signer; private seed bytes are not serialized
into the evidence bundle. Anyone can forge these demo signatures because the test keys
are public. Never use the policy, seeds or receipt as production sender authentication,
key-custody evidence, authorization or non-repudiation. No real key material is required.
The receipt proves only that this specific independent consumer enforced this demo policy.

The integration suite additionally covers rehashed malformed payloads, inflated claims,
wrong subjects/peer commits, case/policy changes, missing/tampered/non-synthetic materials,
duplicate/unlinked controls, future/expired evidence, exact expiry translation, runtime
and schema fingerprint drift, strict JSON, deterministic output and overwrite protection.
It calls real DataGovOps to prove that schema-valid cross-institution/wrong-source records,
unknown reference versions and conflicting evidence identities are still rejected.

## Evidence to inspect

- `summary.json`: compact outcome and both expected rejections.
- `producer/`: case, policy, four material bodies, dossier, handoff and original local check.
- `consumer/receipt.json`: actual registration identities, runtime pin and matrix digests.
- `consumer/validation-report.json`: independent boundary checks with explicit non-claims.
- `producer/signed-envelope.json`: context-bound signature over the full packet transcript.
- `consumer/signature-verification.json`: independent Ed25519/key-policy result, digest-bound into the receipt.
- `consumer/key-policy.json`: exact public demo key policy used by the consumer.
- `consumer/control-definitions.json`, `evidence-references.json`, `control-assessments.json`.
- `consumer/matrix-before.json`, `matrix-after.json`, `matrix-at-expiry.json`.
- `negative/`: corrupted and incompatible packets, exact rejection codes, local-check contrast.
- `execution-environment.json`: Python/dependency versions and installation mode.
- `source-provenance.json`: actual checkout commit/tree, cleanliness and optional CI run identity.
- `REPORT.md`: readable outcome, source identity, matrix transitions and non-claims.
- `manifest.json`: sorted raw-file SHA-256 and byte size for every generated file except itself.

Canonical payload hashes intentionally ignore JSON whitespace/key order; the manifest
also hashes exact emitted file bytes. Repeat runs in the same environment produce
byte-identical artifacts for the same source/worktree and CI run identity. Environment
records can differ across Python/dependency versions and CI runs.
No reproducible dependency-wheel build is claimed.

## Pins and honest limits

DataGovOps is installed from commit
[`8bfd1b9558ae996e15f4c3d21158e8688d657f16`](https://github.com/bilgekayali/DataGovOps/commit/8bfd1b9558ae996e15f4c3d21158e8688d657f16),
matching the frozen handoff contract. All 26 installed DataGovOps Python source files,
all 14 producer Python files, the 26-schema producer set, and four consumer schemas
are checked against committed fingerprints. Consumer schema snapshots also have exact
Git blob identities. The demo does not require a DataGovOps runtime/API change.

DataGovOps later published its independent
[`v1.0.0` stable GitHub Release](https://github.com/bilgekayali/DataGovOps/releases/tag/v1.0.0)
at `065a14e77487f97adf5c6228f93c3737f2dd409a`. That release-publication commit is
one commit after the tested demo pin and does not modify package source or schemas. It is
recorded as supplemental repository-release identity, not substituted for the install pin;
see the [peer-release ledger](PEER_RELEASES.md).

This is an additive repository example after VulnEvidenceOps v1.0.0. It does not change
the frozen package API, CLI, dependency bounds, public schemas or existing tag. Demo
scripts/receipt formats are not newly promised stable public interfaces.

Consumer acceptance means **local schema/integrity acceptance and registry indexing
for these synthetic inputs**. It does not establish sender authority, observation truth,
correct producer assurance reasoning, production sender authenticity, remote delivery, production
interoperability, effective remediation, legal/regulatory compliance or certification.
The prior handoff's broad `consumer_acceptance_established=false` stays unchanged;
the separate receipt records only this demonstrated local acceptance.

DataGovOps remains an evidence-index/currentness boundary. Human review remains required;
the repository owner's PR-review waiver is not a governance/control-effectiveness review.
No secrets, customer data, scanner execution, deployment or package-index publication occurs.
