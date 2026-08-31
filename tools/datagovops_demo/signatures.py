"""Independent Ed25519 verification under an explicitly PUBLIC, demo-only key policy.

No producer runtime, producer verifier, network lookup or caller-supplied trust keys.
"""

from __future__ import annotations

import base64
import binascii
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .common import ROOT, DemoRejected, Schemas, canonical_bytes, digest, read_json, timestamp

BODY_PARTS = ("case", "policy", "materials", "dossier", "handoff")
POLICY_PATH = ROOT / "examples/datagovops-demo/signing-policy.json"


def _decode(value: str, *, length: int | None = None) -> bytes:
    try:
        if len(value) > 65_536:
            raise ValueError("bounded base64 required")
        raw = base64.b64decode(value, validate=True)
        if (length is not None and len(raw) != length) or base64.b64encode(raw).decode() != value:
            raise ValueError("canonical padded base64 required")
        return raw
    except (binascii.Error, ValueError, TypeError) as exc:
        raise DemoRejected("signature_encoding_invalid", "invalid signature encoding") from exc


def load_signing_policy(contract: dict, schemas: Schemas) -> dict:
    policy = read_json(POLICY_PATH)
    if (
        hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest() != contract["signing_policy_sha256"]
        or policy.get("schema_version") != "vulnevidenceops.datagovops-demo-signing-policy.v1"
        or policy.get("scope") != "local-synthetic-demo"
        or policy.get("signature_required") is not True
        or policy.get("public_test_keys_only") is not True
        or policy.get("audience") != "datagovops.local-synthetic-evidence-consumer"
        or policy.get("purpose") != "register-dossier-evidence"
        or policy.get("payload_type")
        != "application/vnd.vulnevidenceops.datagovops-demo-transcript.v1+json"
        or not isinstance(policy.get("keys"), list)
        or not policy["keys"]
    ):
        raise DemoRejected("signing_policy_mismatch", "pinned consumer demo key policy differs")
    identifiers, fingerprints = set(), set()
    for key in policy["keys"]:
        schemas.validate("producer", "verification-key", key)
        raw = _decode(key["public_key_base64"], length=32)
        if (
            key["key_id"] in identifiers
            or key["public_key_sha256"] in fingerprints
            or hashlib.sha256(raw).hexdigest() != key["public_key_sha256"]
            or key["synthetic"] is not True
            or key["valid_until"] is None
            or timestamp(key["valid_from"]) >= timestamp(key["valid_until"])
        ):
            raise DemoRejected("signing_policy_mismatch", "ambiguous or invalid demo key policy")
        identifiers.add(key["key_id"])
        fingerprints.add(key["public_key_sha256"])
    return policy


def transcript(packet: dict, contract: dict, policy: dict) -> dict:
    """Bind all five packet members plus this exact contract, audience and purpose."""
    return {
        "schema_version": "vulnevidenceops.datagovops-demo-transcript.v1",
        "scope": "local-synthetic-demo",
        "audience": policy["audience"],
        "purpose": policy["purpose"],
        "demo_contract_sha256": digest(contract),
        "key_policy_sha256": contract["signing_policy_sha256"],
        "members_sha256": {name: digest(packet[name]) for name in BODY_PARTS},
    }


def verify_packet_signature(
    packet: dict, contract: dict, schemas: Schemas, verified_at: str
) -> dict:
    policy = load_signing_policy(contract, schemas)
    if "signed-envelope" not in packet:
        raise DemoRejected("signature_required", "unsigned consumption is disabled")
    envelope = packet["signed-envelope"]
    schemas.validate("producer", "signed-evidence-envelope", envelope)
    if envelope["payload_type"] != policy["payload_type"]:
        raise DemoRejected("signature_context_mismatch", "signature has the wrong payload purpose")
    key = next((item for item in policy["keys"] if item["key_id"] == envelope["key_id"]), None)
    if key is None:
        raise DemoRejected("key_not_trusted", "key is not in the consumer's pinned demo policy")
    signed, verified = timestamp(envelope["signed_at"]), timestamp(verified_at)
    if key["revoked_at"] is not None and verified >= timestamp(key["revoked_at"]):
        raise DemoRejected("key_revoked", "key is revoked at consumer verification time")
    if not timestamp(key["valid_from"]) <= signed <= verified < timestamp(key["valid_until"]):
        raise DemoRejected("key_not_current", "key or claimed signing time is not current")
    if not timestamp(packet["handoff"]["created_at"]) <= signed:
        raise DemoRejected("signature_time_mismatch", "signature predates the handoff")
    payload = _decode(envelope["payload_base64"])
    if hashlib.sha256(payload).hexdigest() != envelope["payload_sha256"]:
        raise DemoRejected("signed_payload_digest_mismatch", "signed payload hash differs")
    if payload != canonical_bytes(transcript(packet, contract, policy)):
        raise DemoRejected("signed_packet_mismatch", "signature is not bound to this exact packet")
    # Public v1 signature-input format; independently reconstructed, no producer verifier.
    signature_input = canonical_bytes(
        {
            "schema_version": "vulnevidenceops.signature-input.v1",
            **{
                name: envelope[name]
                for name in ("payload_type", "payload_sha256", "key_id", "algorithm", "signed_at")
            },
        }
    )
    try:
        Ed25519PublicKey.from_public_bytes(_decode(key["public_key_base64"], length=32)).verify(
            _decode(envelope["signature_base64"], length=64), signature_input
        )
    except InvalidSignature as exc:
        raise DemoRejected("signature_invalid", "Ed25519 signature verification failed") from exc
    return {
        "schema_version": "vulnevidenceops.datagovops-demo-signature-verification.v1",
        "scope": "local-synthetic-demo",
        "signature_valid": True,
        "packet_binding_valid": True,
        "consumer_key_policy_satisfied": True,
        "public_test_key": True,
        "key_id": key["key_id"],
        "key_sha256": key["public_key_sha256"],
        "key_policy_sha256": contract["signing_policy_sha256"],
        "envelope_sha256": digest(envelope),
        "transcript_sha256": envelope["payload_sha256"],
        "signed_at": envelope["signed_at"],
        "verified_at": verified_at,
        "key_current_at_signing_and_verification": True,
        "non_claims": {
            "production_sender_identity_established": False,
            "production_signing_authority_established": False,
            "private_key_custody_established": False,
            "trusted_signing_time_established": False,
            "source_observation_truth_established": False,
            "non_repudiation_established": False,
        },
    }
