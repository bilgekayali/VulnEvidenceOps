from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vulnevidenceops import (
    AnchorReceipt,
    BuildProvenance,
    SignatureVerification,
    SignedEvidenceEnvelope,
    VerificationKey,
    canonical_json_bytes,
    sha256_digest,
    sign_evidence,
    verify_signed_evidence,
)
from vulnevidenceops.cli import main

from .helpers import ROOT

SIGNED_AT = "2026-01-20T00:03:00Z"
VERIFIED_AT = "2026-01-20T00:05:00Z"
PAYLOAD_TYPE = "application/vnd.vulnevidenceops.build-provenance.v1+json"


def _document(name: str) -> dict:
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


def _private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _verification_key(
    private_key: Ed25519PrivateKey,
    *,
    key_id: str = "KEY-TEST-001",
) -> VerificationKey:
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return VerificationKey(
        key_id=key_id,
        algorithm="ed25519",
        public_key_base64=base64.b64encode(public_key).decode("ascii"),
        public_key_sha256=hashlib.sha256(public_key).hexdigest(),
        issuer_identity="synthetic-issuer:test-only",
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T00:00:00Z",
        revoked_at=None,
        synthetic=True,
    )


def _signed_pair() -> tuple[SignedEvidenceEnvelope, VerificationKey]:
    private_key = _private_key()
    key = _verification_key(private_key)
    envelope = sign_evidence(
        _document("synthetic-build-provenance.json"),
        payload_type=PAYLOAD_TYPE,
        key_id=key.key_id,
        private_key=private_key,
        signed_at=SIGNED_AT,
    )
    return envelope, key


def _anchor(
    envelope: SignedEvidenceEnvelope,
    *,
    receipt_id: str = "ANCHOR-TEST-001",
    anchored_at: str = "2026-01-20T00:04:00Z",
) -> AnchorReceipt:
    return AnchorReceipt(
        receipt_id=receipt_id,
        envelope_sha256=sha256_digest(envelope.to_dict()),
        provider_identity="synthetic-anchor:test-only",
        anchor_type="transparency_log",
        anchored_at=anchored_at,
        artifact_ref=f"synthetic://anchors/{receipt_id}.json",
        artifact_sha256="d" * 64,
        synthetic=True,
    )


def test_reference_signature_chain_is_round_trippable_and_cryptographically_valid():
    provenance_document = _document("synthetic-build-provenance.json")
    key_document = _document("synthetic-verification-key.json")
    envelope_document = _document("synthetic-signed-evidence-envelope.json")
    receipt_document = _document("synthetic-anchor-receipt.json")

    provenance = BuildProvenance.from_dict(provenance_document)
    key = VerificationKey.from_dict(key_document)
    envelope = SignedEvidenceEnvelope.from_dict(envelope_document)
    receipt = AnchorReceipt.from_dict(receipt_document)
    verification = verify_signed_evidence(
        envelope,
        key,
        verified_at=VERIFIED_AT,
        anchor_receipts=(receipt,),
    )

    assert provenance.to_dict() == provenance_document
    assert key.to_dict() == key_document
    assert envelope.to_dict() == envelope_document
    assert receipt.to_dict() == receipt_document
    assert envelope.payload_document() == provenance_document
    assert verification.verification_position == "cryptographically_valid"
    assert verification.signature_valid is True
    assert verification.payload_digest_valid is True
    assert verification.key_state == "current"
    assert verification.envelope_key_id == key.key_id
    assert verification.verification_key_id == key.key_id
    assert verification.verification_key_sha256 == key.public_key_sha256
    assert verification.algorithm == "ed25519"
    assert verification.signed_at == SIGNED_AT
    assert verification.gaps == ()
    assert verification.anchor_receipts[0]["binding_state"] == "bound"
    assert verification.anchor_receipts[0]["temporal_state"] == "current"
    assert verification.anchor_receipts[0]["external_validation_performed"] is False
    assert all(value is False for value in verification.non_claims.values())


def test_signing_is_deterministic_and_normalizes_the_claimed_time():
    private_key = _private_key()
    payload = {"schema_version": "synthetic.payload.v1", "value": "same"}
    first = sign_evidence(
        payload,
        payload_type="application/vnd.synthetic+json",
        key_id="KEY-TEST-001",
        private_key=private_key,
        signed_at="2026-01-20T01:03:00+01:00",
    )
    second = sign_evidence(
        payload,
        payload_type="application/vnd.synthetic+json",
        key_id="KEY-TEST-001",
        private_key=private_key,
        signed_at=SIGNED_AT,
    )

    assert first.to_dict() == second.to_dict()
    assert first.signed_at == SIGNED_AT
    assert first.payload_bytes() == canonical_json_bytes(payload)


def test_payload_tampering_is_reported_separately_from_signature_validity():
    envelope, key = _signed_pair()
    tampered_payload = envelope.payload_document()
    tampered_payload["subject_name"] = "tampered.whl"
    tampered = replace(
        envelope,
        payload_base64=base64.b64encode(canonical_json_bytes(tampered_payload)).decode("ascii"),
    )

    result = verify_signed_evidence(tampered, key, verified_at=VERIFIED_AT)

    assert result.signature_valid is True
    assert result.payload_digest_valid is False
    assert result.verification_position == "invalid"
    assert "payload_digest_mismatch" in result.gaps


def test_signature_tampering_fails_closed():
    envelope, key = _signed_pair()
    signature = bytearray(base64.b64decode(envelope.signature_base64))
    signature[0] ^= 1
    tampered = replace(
        envelope,
        signature_base64=base64.b64encode(signature).decode("ascii"),
    )

    result = verify_signed_evidence(tampered, key, verified_at=VERIFIED_AT)

    assert result.signature_valid is False
    assert result.payload_digest_valid is True
    assert result.verification_position == "invalid"
    assert "signature_invalid" in result.gaps


def test_wrong_key_identity_and_wrong_key_material_fail_closed():
    envelope, key = _signed_pair()
    mismatch = replace(key, key_id="KEY-OTHER")
    mismatch_result = verify_signed_evidence(envelope, mismatch, verified_at=VERIFIED_AT)
    assert mismatch_result.signature_valid is False
    assert "verification_key_id_mismatch" in mismatch_result.gaps

    other_private = _private_key()
    wrong_material = _verification_key(other_private, key_id=envelope.key_id)
    wrong_result = verify_signed_evidence(envelope, wrong_material, verified_at=VERIFIED_AT)
    assert wrong_result.signature_valid is False
    assert "signature_invalid" in wrong_result.gaps


@pytest.mark.parametrize(
    ("changes", "expected_state"),
    [
        ({"valid_from": "2026-02-01T00:00:00Z", "valid_until": None}, "future"),
        ({"valid_until": "2026-01-10T00:00:00Z"}, "expired"),
        ({"revoked_at": "2026-01-15T00:00:00Z"}, "revoked"),
    ],
)
def test_key_lifecycle_is_evaluated_at_the_claimed_signing_time(changes, expected_state):
    envelope, key = _signed_pair()
    changed = replace(key, **changes)

    result = verify_signed_evidence(envelope, changed, verified_at=VERIFIED_AT)

    assert result.signature_valid is True
    assert result.key_state == expected_state
    assert result.verification_position == "invalid"
    assert f"verification_key_{expected_state}_at_claimed_signing_time" in result.gaps


def test_future_claimed_signing_time_is_a_gap_not_a_trusted_timestamp():
    private_key = _private_key()
    key = _verification_key(private_key)
    envelope = sign_evidence(
        {"schema_version": "synthetic.payload.v1"},
        payload_type="application/vnd.synthetic+json",
        key_id=key.key_id,
        private_key=private_key,
        signed_at="2026-02-01T00:00:00Z",
    )

    result = verify_signed_evidence(envelope, key, verified_at=VERIFIED_AT)

    assert result.signature_valid is True
    assert result.verification_position == "with_gaps"
    assert result.gaps == ("claimed_signing_time_future",)
    assert result.non_claims["trusted_signing_time_established"] is False


@pytest.mark.parametrize(
    ("mutation", "expected_binding", "expected_temporal", "gap"),
    [
        (
            lambda receipt: replace(receipt, envelope_sha256="0" * 64),
            "unbound",
            "current",
            "anchor_receipt_unbound:ANCHOR-TEST-001",
        ),
        (
            lambda receipt: replace(receipt, anchored_at="2026-01-19T00:00:00Z"),
            "bound",
            "before_signing",
            "anchor_receipt_before_signing:ANCHOR-TEST-001",
        ),
        (
            lambda receipt: replace(receipt, anchored_at="2026-02-01T00:00:00Z"),
            "bound",
            "future",
            "anchor_receipt_future:ANCHOR-TEST-001",
        ),
    ],
)
def test_anchor_receipts_preserve_binding_and_time_gaps(
    mutation, expected_binding, expected_temporal, gap
):
    envelope, key = _signed_pair()
    receipt = mutation(_anchor(envelope))

    result = verify_signed_evidence(
        envelope,
        key,
        verified_at=VERIFIED_AT,
        anchor_receipts=(receipt,),
    )

    assert result.verification_position == "with_gaps"
    assert result.anchor_receipts[0]["binding_state"] == expected_binding
    assert result.anchor_receipts[0]["temporal_state"] == expected_temporal
    assert gap in result.gaps
    assert result.non_claims["external_anchor_authenticity_established"] is False


def test_duplicate_anchor_receipt_identity_is_rejected():
    envelope, key = _signed_pair()
    receipt = _anchor(envelope)
    with pytest.raises(ValueError, match="duplicate"):
        verify_signed_evidence(
            envelope,
            key,
            verified_at=VERIFIED_AT,
            anchor_receipts=(receipt, receipt),
        )


def test_anchor_receipt_requires_an_explicit_boolean_synthetic_marker():
    envelope, _ = _signed_pair()
    with pytest.raises(ValueError, match="boolean"):
        replace(_anchor(envelope), synthetic="yes")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(source_commit="bad"), "Git object ID"),
        (lambda value: value.update(finished_at="2025-01-01T00:00:00Z"), "precede"),
        (lambda value: value.update(materials=[]), "at least one"),
        (
            lambda value: value["materials"].append(copy.deepcopy(value["materials"][0])),
            "duplicate",
        ),
        (lambda value: value.update(synthetic="yes"), "boolean"),
    ],
)
def test_build_provenance_rejects_ambiguous_or_incomplete_identity(mutation, message):
    document = _document("synthetic-build-provenance.json")
    mutation(document)
    with pytest.raises(ValueError, match=message):
        BuildProvenance.from_dict(document)


def test_build_provenance_materials_preserve_the_exact_field_set():
    document = _document("synthetic-build-provenance.json")
    document["materials"][0]["trusted"] = True
    with pytest.raises(ValueError, match="exactly"):
        BuildProvenance.from_dict(document)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"algorithm": "rsa"}, "algorithm"),
        ({"public_key_base64": "bad"}, "base64"),
        ({"public_key_base64": base64.b64encode(b"short").decode()}, "32 bytes"),
        ({"public_key_sha256": "0" * 64}, "must match"),
        ({"valid_until": "2025-01-01T00:00:00Z"}, "later"),
        ({"synthetic": "yes"}, "boolean"),
    ],
)
def test_verification_key_rejects_invalid_crypto_and_lifecycle_fields(changes, message):
    _, key = _signed_pair()
    with pytest.raises(ValueError, match=message):
        replace(key, **changes)


def test_verification_key_rejects_noncanonical_base64():
    _, key = _signed_pair()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    canonical_character = key.public_key_base64[-2]
    index = alphabet.index(canonical_character)
    noncanonical_character = alphabet[index + 1]
    noncanonical = key.public_key_base64[:-2] + noncanonical_character + "="
    assert base64.b64decode(noncanonical) == base64.b64decode(key.public_key_base64)
    with pytest.raises(ValueError, match="canonical padded base64"):
        replace(key, public_key_base64=noncanonical)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"payload_base64": "bad"}, "base64"),
        ({"payload_base64": base64.b64encode(b"not json").decode()}, "JSON"),
        ({"payload_base64": base64.b64encode(b"[]").decode()}, "JSON object"),
        (
            {"payload_base64": base64.b64encode(b'{"b": 1, "a": 2}').decode()},
            "canonical",
        ),
        ({"signature_base64": base64.b64encode(b"short").decode()}, "64 bytes"),
        ({"algorithm": "rsa"}, "algorithm"),
        ({"signed_at": "not-a-time"}, "ISO 8601"),
    ],
)
def test_envelope_rejects_noncanonical_or_malformed_crypto_fields(changes, message):
    envelope, _ = _signed_pair()
    with pytest.raises(ValueError, match=message):
        replace(envelope, **changes)


def test_signature_verification_rejects_weakened_invariants():
    envelope = SignedEvidenceEnvelope.from_dict(
        _document("synthetic-signed-evidence-envelope.json")
    )
    key = VerificationKey.from_dict(_document("synthetic-verification-key.json"))
    receipt = AnchorReceipt.from_dict(_document("synthetic-anchor-receipt.json"))
    result = verify_signed_evidence(
        envelope,
        key,
        verified_at=VERIFIED_AT,
        anchor_receipts=(receipt,),
    )
    assert isinstance(result, SignatureVerification)

    with pytest.raises(ValueError, match="boolean"):
        replace(result, signature_valid=1)
    with pytest.raises(ValueError, match="represented verification state"):
        replace(result, verification_position="with_gaps")
    with pytest.raises(ValueError, match="non_claims"):
        replace(
            result,
            non_claims={**result.non_claims, "signer_identity_established": True},
        )
    with pytest.raises(ValueError, match="duplicate"):
        replace(result, anchor_receipts=result.anchor_receipts * 2)
    with pytest.raises(ValueError, match="gaps must exactly match"):
        replace(result, gaps=("unrepresented",), verification_position="with_gaps")

    record = result.anchor_receipts[0]
    with pytest.raises(ValueError, match="exact field set"):
        replace(result, anchor_receipts=({**record, "trusted": True},))
    with pytest.raises(ValueError, match="explicit false"):
        replace(
            result,
            anchor_receipts=({**record, "external_validation_performed": True},),
        )
    with pytest.raises(ValueError, match="anchor synthetic"):
        replace(result, anchor_receipts=({**record, "synthetic": "yes"},))
    with pytest.raises(ValueError, match="gaps must exactly match"):
        replace(result, anchor_receipts=({**record, "binding_state": "unbound"},))


def test_public_operations_require_typed_inputs():
    private_key = _private_key()
    with pytest.raises(ValueError, match="JSON object"):
        sign_evidence(
            ["not", "an", "object"],
            payload_type="application/json",
            key_id="KEY-TEST",
            private_key=private_key,
            signed_at=SIGNED_AT,
        )
    with pytest.raises(ValueError, match="Ed25519PrivateKey"):
        sign_evidence(
            {"value": "test"},
            payload_type="application/json",
            key_id="KEY-TEST",
            private_key="private",
            signed_at=SIGNED_AT,
        )
    envelope, key = _signed_pair()
    with pytest.raises(ValueError, match="SignedEvidenceEnvelope"):
        verify_signed_evidence("envelope", key, verified_at=VERIFIED_AT)
    with pytest.raises(ValueError, match="VerificationKey"):
        verify_signed_evidence(envelope, "key", verified_at=VERIFIED_AT)
    with pytest.raises(ValueError, match="AnchorReceipt"):
        verify_signed_evidence(
            envelope,
            key,
            verified_at=VERIFIED_AT,
            anchor_receipts=("receipt",),
        )


def test_cli_signs_and_verifies_without_serializing_private_key(tmp_path):
    private_key = _private_key()
    key = _verification_key(private_key)
    private_path = tmp_path / "private.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path = tmp_path / "key.json"
    key_path.write_text(json.dumps(key.to_dict()), encoding="utf-8")
    envelope_path = tmp_path / "envelope.json"
    receipt_path = tmp_path / "receipt.json"
    verification_path = tmp_path / "verification.json"

    assert (
        main(
            [
                "sign-evidence",
                str(ROOT / "examples" / "synthetic-build-provenance.json"),
                "--payload-type",
                PAYLOAD_TYPE,
                "--key-id",
                key.key_id,
                "--private-key",
                str(private_path),
                "--signed-at",
                SIGNED_AT,
                "--output",
                str(envelope_path),
            ]
        )
        == 0
    )
    generated_envelope = SignedEvidenceEnvelope.from_dict(
        json.loads(envelope_path.read_text(encoding="utf-8"))
    )
    receipt_path.write_text(
        json.dumps(_anchor(generated_envelope).to_dict()),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "verify-evidence",
                str(envelope_path),
                "--key",
                str(key_path),
                "--receipt",
                str(receipt_path),
                "--as-of",
                VERIFIED_AT,
                "--output",
                str(verification_path),
            ]
        )
        == 0
    )
    verification = json.loads(verification_path.read_text(encoding="utf-8"))
    assert verification["verification_position"] == "cryptographically_valid"
    assert verification["anchor_receipts"][0]["binding_state"] == "bound"
    assert "private" not in json.dumps(json.loads(envelope_path.read_text()))


def test_cli_rejects_a_non_ed25519_private_key(tmp_path):
    private_path = tmp_path / "x25519.pem"
    private_path.write_bytes(
        X25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(SystemExit, match="Ed25519"):
        main(
            [
                "sign-evidence",
                str(ROOT / "examples" / "synthetic-build-provenance.json"),
                "--payload-type",
                PAYLOAD_TYPE,
                "--key-id",
                "KEY-TEST",
                "--private-key",
                str(private_path),
                "--signed-at",
                SIGNED_AT,
            ]
        )
