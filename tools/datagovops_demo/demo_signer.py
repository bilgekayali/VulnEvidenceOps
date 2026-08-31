"""Sign synthetic demo transcripts with PUBLIC RFC 8032 vectors, never real keys.

These seeds are published in RFC 8032 section 7.1 and intentionally NOT secrets.
Anybody can reproduce/forge these demo signatures. This module is producer-only.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vulnevidenceops import sign_evidence

from .common import Schemas, load_contract
from .signatures import load_signing_policy, transcript

PUBLIC_TEST_SEEDS = {
    "synthetic-rfc8032-active": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "synthetic-rfc8032-revoked": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "synthetic-untrusted": "00" * 32,
}


def sign_packet(
    packet: dict, *, key_id: str = "synthetic-rfc8032-active", wrong_key: bool = False
) -> dict:
    contract = load_contract()
    policy = load_signing_policy(contract, Schemas(contract))
    seed = PUBLIC_TEST_SEEDS["synthetic-untrusted" if wrong_key else key_id]
    return sign_evidence(
        transcript(packet, contract, policy),
        payload_type=policy["payload_type"],
        key_id=key_id,
        private_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)),
        signed_at=policy["claimed_signed_at"],
    ).to_dict()
