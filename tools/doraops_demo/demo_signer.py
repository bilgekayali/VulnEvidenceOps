"""Producer-only DORAOps demo signing and deliberately invalid public-key fixtures.

All seeds are PUBLIC RFC 8032 section 7.1 vectors (or the public all-zero vector).
The separate key identifiers and signed audience/purpose prevent cross-demo replay,
not forgery by someone who possesses these intentionally public demonstration seeds.
"""

from __future__ import annotations

import base64
import copy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.datagovops_demo.common import canonical_bytes, digest
from tools.datagovops_demo.demo_signer import PUBLIC_TEST_SEEDS
from vulnevidenceops import sign_evidence

from .common import load_contract
from .signatures import load_signing_policy, transcript

ACTIVE = "synthetic-dora-rfc8032-active"
REVOKED = "synthetic-dora-rfc8032-revoked"
UNTRUSTED = "synthetic-dora-untrusted"


def sign_packet(
    packet: dict,
    *,
    key_id: str = ACTIVE,
    wrong_key: bool = False,
    audience: str | None = None,
    purpose: str | None = None,
    signed_at: str | None = None,
) -> dict:
    """Overrides exist solely to exercise negative demo cases, never as trust inputs."""
    contract = load_contract()
    policy = load_signing_policy(contract)
    document = transcript(packet, contract, policy)
    document["audience"] = audience if audience is not None else policy["audience"]
    document["purpose"] = purpose if purpose is not None else policy["purpose"]
    vector = {
        ACTIVE: "synthetic-rfc8032-active",
        REVOKED: "synthetic-rfc8032-revoked",
        UNTRUSTED: "synthetic-untrusted",
    }[UNTRUSTED if wrong_key else key_id]
    return sign_evidence(
        document,
        payload_type=policy["payload_type"],
        key_id=key_id,
        private_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(PUBLIC_TEST_SEEDS[vector])),
        signed_at=signed_at or policy["claimed_signed_at"],
    ).to_dict()


def signature_scenarios(packet: dict):
    unsigned = copy.deepcopy(packet)
    unsigned.pop("signed_envelope")
    wrong_audience = copy.deepcopy(packet)
    wrong_audience["signed_envelope"] = sign_packet(packet, audience="synthetic.other-consumer")
    wrong_key = copy.deepcopy(packet)
    wrong_key["signed_envelope"] = sign_packet(packet, wrong_key=True)
    untrusted = copy.deepcopy(packet)
    untrusted["signed_envelope"] = sign_packet(packet, key_id=UNTRUSTED)
    revoked = copy.deepcopy(packet)
    revoked["signed_envelope"] = sign_packet(packet, key_id=REVOKED)
    rehashed = copy.deepcopy(packet)
    rehashed["change_completion"]["statement"] = "Replaced synthetic completion statement."
    rehashed["handoff"]["change_completion_sha256"] = digest(rehashed["change_completion"])
    contract = load_contract()
    payload = transcript(rehashed, contract, load_signing_policy(contract))
    rehashed["signed_envelope"]["payload_base64"] = base64.b64encode(
        canonical_bytes(payload)
    ).decode("ascii")
    rehashed["signed_envelope"]["payload_sha256"] = digest(payload)
    replay = copy.deepcopy(packet)
    replay["signed_envelope"] = copy.deepcopy(packet["source_packet"]["signed-envelope"])
    return (
        ("unsigned-doraops-input", unsigned, "doraops_signature_required"),
        ("wrong-signature-audience", wrong_audience, "doraops_signature_context_mismatch"),
        ("wrong-signing-key", wrong_key, "doraops_signature_invalid"),
        ("untrusted-signing-key", untrusted, "doraops_key_not_trusted"),
        ("revoked-signing-key", revoked, "doraops_key_revoked"),
        ("rehashed-completion", rehashed, "doraops_signature_invalid"),
        ("upstream-signature-replay", replay, "doraops_signature_context_mismatch"),
    )
