"""Independent DORAOps-scoped verification, with pinned PUBLIC demonstration keys.

The upstream DataGovOps signature never substitutes for this second signature.
No producer runtime/verifier or packet-supplied trust policy is imported or trusted.
"""

from __future__ import annotations

import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tools.datagovops_demo.common import (
    ROOT,
    DemoRejected,
    canonical_bytes,
    digest,
    read_json,
    timestamp,
)
from tools.datagovops_demo.common import Schemas as EnvelopeSchemas
from tools.datagovops_demo.common import load_contract as load_upstream_contract
from tools.datagovops_demo.signatures import _decode

POLICY_PATH = ROOT / "examples/doraops-demo/signing-policy.json"
BODY_PARTS = ("handoff", "source_packet", "datagovops_receipt", "change_completion")
AUDIENCE = "doraops.local-synthetic-risk-remediation-consumer"
PURPOSE = "consume-risk-remediation-evidence"
PAYLOAD_TYPE = "application/vnd.vulnevidenceops.doraops-demo-transcript.v1+json"


def load_signing_policy(contract: dict) -> dict:
    policy = read_json(POLICY_PATH)
    if (
        hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest() != contract["signing_policy_sha256"]
        or policy.get("schema_version") != "vulnevidenceops.doraops-demo-signing-policy.v1"
        or policy.get("scope") != "local-synthetic-demo"
        or policy.get("signature_required") is not True
        or policy.get("public_test_keys_only") is not True
        or policy.get("audience") != AUDIENCE
        or policy.get("purpose") != PURPOSE
        or policy.get("payload_type") != PAYLOAD_TYPE
        or not isinstance(policy.get("keys"), list)
        or not policy["keys"]
    ):
        raise DemoRejected("doraops_signing_policy_mismatch", "pinned DORAOps key policy differs")
    schemas = EnvelopeSchemas(load_upstream_contract())
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
            raise DemoRejected("doraops_signing_policy_mismatch", "invalid DORAOps demo key")
        identifiers.add(key["key_id"])
        fingerprints.add(key["public_key_sha256"])
    return policy


def transcript(packet: dict, contract: dict, policy: dict) -> dict:
    return {
        "schema_version": "vulnevidenceops.doraops-demo-transcript.v1",
        "scope": "local-synthetic-demo",
        "audience": policy["audience"],
        "purpose": policy["purpose"],
        "demo_contract_sha256": digest(contract),
        "key_policy_sha256": contract["signing_policy_sha256"],
        "governance_context_sha256": contract["governance_context_sha256"],
        "input_schema_version": packet["schema_version"],
        "members_sha256": {name: digest(packet[name]) for name in BODY_PARTS},
    }


def verify_packet_signature(packet: dict, contract: dict, verified_at: str) -> dict:
    policy = load_signing_policy(contract)
    if "signed_envelope" not in packet:
        raise DemoRejected("doraops_signature_required", "unsigned DORAOps input is disabled")
    envelope = packet["signed_envelope"]
    EnvelopeSchemas(load_upstream_contract()).validate(
        "producer", "signed-evidence-envelope", envelope
    )
    if envelope["payload_type"] != PAYLOAD_TYPE:
        raise DemoRejected("doraops_signature_context_mismatch", "wrong signature payload purpose")
    key = next((item for item in policy["keys"] if item["key_id"] == envelope["key_id"]), None)
    if key is None:
        raise DemoRejected("doraops_key_not_trusted", "key is absent from the pinned demo policy")
    signed, verified = timestamp(envelope["signed_at"]), timestamp(verified_at)
    if key["revoked_at"] is not None and verified >= timestamp(key["revoked_at"]):
        raise DemoRejected("doraops_key_revoked", "key is revoked at DORAOps consumption time")
    if not timestamp(key["valid_from"]) <= signed <= verified < timestamp(key["valid_until"]):
        raise DemoRejected("doraops_key_not_current", "key or claimed signing time is not current")
    if signed < timestamp(packet["handoff"]["created_at"]):
        raise DemoRejected("doraops_signature_time_mismatch", "signature predates DORAOps handoff")
    raw = _decode(envelope["payload_base64"])
    if hashlib.sha256(raw).hexdigest() != envelope["payload_sha256"]:
        raise DemoRejected("doraops_signed_payload_digest_mismatch", "signed payload hash differs")
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise DemoRejected("doraops_signed_packet_mismatch", "invalid signed transcript") from exc
    expected = transcript(packet, contract, policy)
    if not isinstance(payload, dict) or any(
        payload.get(name) != expected[name]
        for name in ("schema_version", "scope", "audience", "purpose")
    ):
        raise DemoRejected(
            "doraops_signature_context_mismatch", "wrong DORAOps audience or purpose"
        )
    if raw != canonical_bytes(expected):
        raise DemoRejected("doraops_signed_packet_mismatch", "signature does not bind all inputs")
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
        raise DemoRejected("doraops_signature_invalid", "DORAOps Ed25519 signature failed") from exc
    return {
        "schema_version": "vulnevidenceops.doraops-demo-signature-verification.v1",
        "scope": "local-synthetic-demo",
        "signature_valid": True,
        "packet_binding_valid": True,
        "consumer_key_policy_satisfied": True,
        "public_test_key": True,
        "audience": AUDIENCE,
        "purpose": PURPOSE,
        "key_id": key["key_id"],
        "key_sha256": key["public_key_sha256"],
        "key_policy_sha256": contract["signing_policy_sha256"],
        "envelope_sha256": digest(envelope),
        "transcript_sha256": envelope["payload_sha256"],
        "members_sha256": expected["members_sha256"],
        "signed_at": envelope["signed_at"],
        "verified_at": verified_at,
        "key_current_at_signing_and_verification": True,
        "non_claims": {
            "production_sender_identity_established": False,
            "production_signing_authority_established": False,
            "private_key_custody_established": False,
            "trusted_signing_time_established": False,
            "real_change_execution_verified": False,
            "non_repudiation_established": False,
        },
    }
