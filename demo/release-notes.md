# Portfolio evidence demo 1.0.0

VulnEvidenceOps → DataGovOps → DORAOps, using actual installed consumers and
synthetic evidence. This is a separately versioned repository demo, not a new
stable package version. The original `v1.0.0` tag/release remains unchanged.

The evidence demonstrates two independently verified signature scopes, a real
risk/remediation lifecycle, blocked closure without a passing retest, and rejection
of altered or misbound inputs. Finding closure does not automatically lower risk.

Download `portfolio-evidence.zip` for reports and underlying JSON evidence.
`portfolio-wheels.zip` contains the exact Linux x86-64 / CPython 3.12 runtime wheel
bytes used in CI; `REPLAY.md` explains hash verification and offline replay from
this exact Git checkout. `demo-release-manifest.json` links source, dependency lock,
peer commits and asset hashes. `SHA256SUMS` also covers that release manifest.

These release assets are retained independently of the 30-day Actions artifact
window. Existing published demo tags, releases and assets are never moved or
overwritten by the publication workflow. Assets remain subject to repository-owner
and GitHub retention/availability; this is not an immutable archival service.

All data, roles, dates and RFC 8032 signing keys are public synthetic fixtures.
Anyone can reproduce the demo signatures. No production sender identity, real
change execution, independent human approval, risk acceptance or compliance is
asserted. Hash-verified replay of retained wheel bytes is demonstrated; independent
bit-for-bit rebuilding, cross-platform portability and current security of frozen
dependencies are not claimed.
