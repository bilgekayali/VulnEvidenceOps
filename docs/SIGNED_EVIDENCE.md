# Signed evidence

## Boundary

VulnEvidenceOps v0.5 signs strict canonical JSON with Ed25519 and verifies local cryptographic,
digest, key-lifecycle and receipt-binding facts. It does not operate a key-management service,
contact a timestamp authority or transparency log, resolve human identity, or decide whether a
signer had authority.

## Cryptographic profile

The `signed-evidence-envelope.v1` contract contains one canonical JSON payload and one Ed25519
signature. The signature covers a deterministic statement containing:

- the payload type and SHA-256 digest;
- the key identifier and `ed25519` algorithm identifier;
- the caller-supplied signing timestamp;
- the versioned signature-input contract.

The payload bytes must be compact, key-sorted UTF-8 JSON. This removes formatting ambiguity while
preserving a byte-exact payload digest. Payload bytes remain inside the envelope; private-key
material never does.

## Verification keys

A `verification-key.v1` record contains a raw Ed25519 public key, its SHA-256 fingerprint, an
opaque issuer identity, an explicit validity interval, optional revocation time and a synthetic
marker. The verifier evaluates lifecycle state at the claimed signing time and reports `current`,
`future`, `expired` or `revoked`.

Issuer identity and lifecycle metadata are caller-supplied assertions. A valid key record does not
prove the real signer, delegated authority, key custody or revocation-source authenticity.

## Anchor receipts

An `anchor-receipt.v1` record represents opaque receipt metadata from an RFC 3161 service,
transparency log, ledger or other provider. Local verification reports separately:

- whether the receipt names the exact envelope SHA-256 digest;
- whether its timestamp is before signing, current at verification time or future-dated;
- the receipt artifact reference and digest.

The library does not fetch or cryptographically validate the external receipt. Every generated
verification result therefore keeps `external_validation_performed=false` and the external-anchor
authenticity non-claim false.

## Exact build provenance

The `build-provenance.v1` payload records an exact subject digest, Git commit and tree object IDs,
source ref, builder identity, build type, invocation ID, UTC interval and digest-bound materials.
It is evidence about supplied build metadata, not proof that the builder was secure, the source was
trusted, the build was reproducible or the artifact is safe.

## Verification positions

| Position | Meaning |
|---|---|
| `cryptographically_valid` | Signature, payload digest and key state are locally valid with no represented time/binding gaps |
| `with_gaps` | Core cryptographic checks pass, but a claimed time or supplied anchor has a visible gap |
| `invalid` | Signature, payload digest or key lifecycle state fails |

These positions are not trust, approval, compliance or non-repudiation decisions.

## CLI

Signing uses an externally generated, unencrypted Ed25519 PKCS#8 PEM file. The CLI reads the key
for the operation but never serializes it into output:

```bash
vulnevidenceops sign-evidence examples/synthetic-build-provenance.json \
  --payload-type application/vnd.vulnevidenceops.build-provenance.v1+json \
  --key-id KEY-EXAMPLE \
  --private-key /secure/path/ed25519-private.pem \
  --signed-at 2026-01-20T00:03:00Z \
  --output /tmp/signed-envelope.json
```

Verification can include zero or more caller-supplied anchor receipts:

```bash
vulnevidenceops verify-evidence examples/synthetic-signed-evidence-envelope.json \
  --key examples/synthetic-verification-key.json \
  --receipt examples/synthetic-anchor-receipt.json \
  --as-of 2026-01-20T00:05:00Z \
  --output /tmp/signature-verification.json
```

## Explicit non-claims

A valid result does not establish artifact safety, build reproducibility, external-anchor
authenticity, non-repudiation, payload-schema conformance, signer identity, signing authority,
source-material trust, a trusted signing time or verification-key authenticity.
