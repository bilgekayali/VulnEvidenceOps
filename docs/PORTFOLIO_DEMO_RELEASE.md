# Durable portfolio demo and exact-wheel replay

The repository demo has its own `demo-v1.0.0` release boundary. It does not bump any
of the three stable packages, move `v1.0.0`, publish to a package index, change peer
repositories or deploy a service. Publication policy is in `demo/publish-policy.json`;
it remains disabled during preparation and requires the visual presentation when enabled.

## Two ways to run

From a clean exact Git checkout, Python 3.11/3.12/3.13 and Git:

```bash
python tools/demo_doraops.py --test
```

The bootstrap installs exact build-tool versions in a temporary builder. All nine
runtime dependencies are fixed in `demo/dependency-lock.json`, including transitive
dependencies. DataGovOps and DORAOps retain their exact Git pins. It builds/downloads
twelve runtime wheels in total, verifies the complete name/version closure and
records each filename, byte size and SHA-256. The execution environment installs
only those wheels using `--no-index --no-deps --require-hashes`, then runs `pip check`.

To retain the wheel bytes for replay:

```bash
python tools/demo_doraops.py --test --export-wheelhouse /path/to/new-wheelhouse
python tools/demo_doraops.py --wheelhouse /path/to/new-wheelhouse \
  --output-dir artifacts/doraops-replay --test
```

Export/output directories must be new; prior evidence is never overwritten. Keep
exports outside the Git checkout and evidence under ignored `artifacts/` or outside
the checkout. Replay requires a clean checkout with the exact source commit/tree,
dependency-lock hash, peer pins, OS, architecture and Python minor version. Pip also
checks actual wheel compatibility. A changed wheel, requirements file or manifest
identity fails before installation. No global environment is modified.

The released wheelhouse is specifically **Linux x86-64 / CPython 3.12**. It is not
a universal Windows/macOS or cross-Python wheel bundle. Other supported Python
versions exercise the same source-based demo in CI and emit their own wheel evidence.

`--prepared-environment` remains an explicitly labeled developer path; it makes no
hash-verified wheel replay claim and cannot export or select a wheelhouse.

## Five release assets

| Asset | Contents |
|---|---|
| `portfolio-evidence.zip` | Complete reports, source/run identity, both signatures, native JSON results, rejection/attention evidence and file manifest |
| `portfolio-wheels.zip` | Twelve runtime wheels, exact wheel manifest and hash-enforced installation requirements |
| `REPLAY.md` | Exact source checkout, platform, download verification and offline replay instructions |
| `demo-release-manifest.json` | Source/tree/CI attempt, dependency lock, peer pins, evidence/replay hashes and asset inventory |
| `SHA256SUMS` | Raw SHA-256 of the other four assets, including the release manifest |

Before extracting, compare the downloaded bytes with GitHub's release asset digests
and run `sha256sum -c SHA256SUMS` or an equivalent verifier. A checksum delivered with
an untrusted archive is not an independent authenticity proof. Use the authenticated
GitHub release and its exact source commit as the external distribution reference.

After safely extracting evidence, `tools/demo_evidence.py` needs only Python stdlib.
It verifies every file and can require an external source SHA and manifest SHA-256.
All archives are generated with fixed timestamps, sorted safe names and regular-file
modes. Publication independently rejects traversal, symlinks, duplicate names,
oversized expansion and unlisted or modified assets before uploading anything.

## CI and publication ordering

The Python 3.12 CI job runs the full signed three-project demo, then installs the
retained wheels in **another new environment without an index** and reruns all
fourteen rejection and both blocked-attention scenarios. Every output byte and the
complete evidence manifest must be identical. A mismatch prevents the candidate
artifact from being created. The other matrix jobs and release/security gates remain required.

The read-only publication gate requires the latest successful CI, CodeQL, Reference
Gate and Stable Release **main push runs on the same exact SHA**, which must still
be `main`. PR/fork runs, old successes, missing runs and failed newer attempts cannot
authorize publication. Only the exact Python 3.12 candidate artifact from that CI
run/attempt is eligible. Its immutable artifact ID, origin and GitHub ZIP SHA-256 are
checked; downloaded ZIP bytes must match that external digest before extraction.

Only the separate publish job receives `contents: write`. It rechecks the source,
gate, protected `v1.0.0` tag, dependency/wheel inventories and every release asset.
It creates a distinct demo tag and draft prerelease, uploads missing assets without
clobbering, compares their GitHub digests with the verified candidate, rechecks gates,
then publishes the draft with `make_latest=false`.

An interrupted same-SHA draft may resume only when existing bytes match. A conflicting
tag or draft asset blocks publication. An already published demo is a no-op: its tag,
notes and assets are never edited by this workflow. There is no automatic version
increment or retargeting to later `main` commits. Another demo version requires a new
explicit publication-policy change.

Release assets outlive the 30-day Actions artifacts, subject to owner/GitHub availability.
This workflow's no-overwrite policy is not an immutable archival or transparency service.

## Honest reproducibility and trust boundary

Exact retained-wheel replay is checked, not independent bit-for-bit wheel rebuilding.
Source/build tools and runtime versions are pinned, but different operating systems,
installer versions, compiler environments or future source rebuilds need not produce
identical wheels. Frozen dependencies also need future security maintenance.

All data, roles, dates and signing seeds are public synthetic fixtures. Signature
verification does not establish private-key custody, production sender identity,
actual remediation, independent human review, risk acceptance or compliance. No
SustainGRC internal schema, workflow, customer data or private implementation is used.
