"""Producer signs; an independent consumer checks signature and its own demo policy."""

from __future__ import annotations

import base64
import copy
import unittest

from tools.datagovops_demo.__main__ import produce
from tools.datagovops_demo.common import (
    DemoRejected,
    Schemas,
    canonical_bytes,
    digest,
    load_contract,
)
from tools.datagovops_demo.consumer import consume
from tools.datagovops_demo.demo_signer import PUBLIC_TEST_SEEDS, sign_packet
from tools.datagovops_demo.signatures import (
    BODY_PARTS,
    load_signing_policy,
    transcript,
    verify_packet_signature,
)
from vulnevidenceops import SignedEvidenceEnvelope, VerificationKey, verify_signed_evidence


class SignedConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = load_contract()
        cls.schemas = Schemas(cls.contract)
        cls.policy = load_signing_policy(cls.contract, cls.schemas)
        cls.packet, _ = produce()

    def reject_signature(self, packet, expected, *, contract=None, verified_at=None):
        with self.assertRaises(DemoRejected) as caught:
            verify_packet_signature(
                packet,
                contract or self.contract,
                self.schemas,
                verified_at or self.contract["verified_at"],
            )
        self.assertEqual(caught.exception.code, expected)

    def test_existing_public_producer_api_and_independent_consumer_agree(self):
        envelope = SignedEvidenceEnvelope.from_dict(self.packet["signed-envelope"])
        key = VerificationKey.from_dict(self.policy["keys"][0])
        producer = verify_signed_evidence(envelope, key, verified_at=self.contract["verified_at"])
        self.assertEqual(producer.verification_position, "cryptographically_valid")
        result = consume(self.packet)
        signature = result["signature-verification.json"]
        self.assertTrue(signature["signature_valid"])
        self.assertTrue(signature["consumer_key_policy_satisfied"])
        self.assertTrue(signature["public_test_key"])
        self.assertTrue(all(value is False for value in signature["non_claims"].values()))
        self.assertEqual(result["receipt.json"]["signature_verification_sha256"], digest(signature))
        self.assertEqual(result["validation-report.json"]["signature_verification"], signature)

    def test_unsigned_packets_cannot_downgrade(self):
        packet = copy.deepcopy(self.packet)
        packet.pop("signed-envelope")
        with self.assertRaises(DemoRejected) as caught:
            consume(packet)
        self.assertEqual(caught.exception.code, "signature_required")

    def test_wrong_key_same_id_and_unknown_key_id(self):
        for kwargs, expected in (
            ({"wrong_key": True}, "signature_invalid"),
            ({"key_id": "synthetic-untrusted"}, "key_not_trusted"),
        ):
            packet = copy.deepcopy(self.packet)
            packet["signed-envelope"] = sign_packet(packet, **kwargs)
            with self.subTest(kwargs=kwargs):
                self.reject_signature(packet, expected)

    def test_revoked_at_consumption_cannot_be_bypassed_with_backdated_signature(self):
        packet = copy.deepcopy(self.packet)
        packet["signed-envelope"] = sign_packet(packet, key_id="synthetic-rfc8032-revoked")
        # Frozen library reports validity at claimed signing time, before revocation.
        producer = verify_signed_evidence(
            SignedEvidenceEnvelope.from_dict(packet["signed-envelope"]),
            VerificationKey.from_dict(self.policy["keys"][1]),
            verified_at=self.contract["verified_at"],
        )
        self.assertEqual(producer.verification_position, "cryptographically_valid")
        # The independently defined consumer policy additionally checks consumption time.
        self.reject_signature(packet, "key_revoked")

    def test_every_packet_member_is_bound(self):
        for name in BODY_PARTS:
            packet = copy.deepcopy(self.packet)
            packet[name]["synthetic_modified_field"] = True
            with self.subTest(name=name):
                self.reject_signature(packet, "signed_packet_mismatch")

    def test_recomputed_hashes_and_payload_do_not_repair_old_signature(self):
        packet = copy.deepcopy(self.packet)
        packet["dossier"]["overdue"] = not packet["dossier"]["overdue"]
        packet["handoff"]["payload_sha256"] = digest(packet["dossier"])
        changed = transcript(packet, self.contract, self.policy)
        packet["signed-envelope"]["payload_base64"] = base64.b64encode(
            canonical_bytes(changed)
        ).decode()
        packet["signed-envelope"]["payload_sha256"] = digest(changed)
        with self.assertRaises(DemoRejected) as caught:
            consume(packet)
        self.assertEqual(caught.exception.code, "signature_invalid")

    def test_rehashed_and_resigned_schema_incompatibility_still_fails(self):
        packet = copy.deepcopy(self.packet)
        packet["dossier"]["schema_version"] = "vulnevidenceops.assurance-dossier.v999"
        packet["handoff"]["payload_sha256"] = digest(packet["dossier"])
        packet["signed-envelope"] = sign_packet(packet)
        # Signature alone is valid; full consumer acceptance still rejects the schema.
        self.assertTrue(
            verify_packet_signature(
                packet, self.contract, self.schemas, self.contract["verified_at"]
            )["signature_valid"]
        )
        with self.assertRaises(DemoRejected) as caught:
            consume(packet)
        self.assertEqual(caught.exception.code, "schema_incompatible")

    def test_consumer_contract_and_audience_are_bound(self):
        changed = copy.deepcopy(self.contract)
        changed["institution_id"] = "synthetic-institution:other"
        self.reject_signature(self.packet, "signed_packet_mismatch", contract=changed)
        packet = copy.deepcopy(self.packet)
        packet["signed-envelope"]["payload_type"] = "application/vnd.other-consumer+json"
        self.reject_signature(packet, "signature_context_mismatch")
        changed_policy = copy.deepcopy(self.policy)
        changed_policy["audience"] = "other-consumer"
        forged = transcript(packet, self.contract, changed_policy)
        packet["signed-envelope"] = copy.deepcopy(self.packet["signed-envelope"])
        packet["signed-envelope"]["payload_base64"] = base64.b64encode(
            canonical_bytes(forged)
        ).decode()
        packet["signed-envelope"]["payload_sha256"] = digest(forged)
        self.reject_signature(packet, "signed_packet_mismatch")

    def test_policy_fingerprint_mismatch_fails_closed(self):
        changed = copy.deepcopy(self.contract)
        changed["signing_policy_sha256"] = "f" * 64
        self.reject_signature(self.packet, "signing_policy_mismatch", contract=changed)

    def test_signing_and_verification_key_validity_and_handoff_order(self):
        for signed_at, verified_at, expected in (
            ("2025-12-31T23:59:59Z", self.contract["verified_at"], "key_not_current"),
            ("2026-01-21T00:00:00Z", self.contract["verified_at"], "key_not_current"),
            ("2026-01-20T00:03:00Z", "2026-01-22T00:00:00Z", "key_not_current"),
            ("2026-01-19T23:59:59Z", self.contract["verified_at"], "signature_time_mismatch"),
        ):
            packet = copy.deepcopy(self.packet)
            packet["signed-envelope"]["signed_at"] = signed_at
            with self.subTest(signed_at=signed_at, verified_at=verified_at):
                self.reject_signature(packet, expected, verified_at=verified_at)

    def test_noncanonical_base64_and_invalid_signature_bytes_are_rejected(self):
        packet = copy.deepcopy(self.packet)
        packet["signed-envelope"]["payload_base64"] = (
            "Zh=="  # Nonzero padding bits; canonical is Zg==.
        )
        self.reject_signature(packet, "signature_encoding_invalid")
        packet = copy.deepcopy(self.packet)
        packet["signed-envelope"]["signature_base64"] = base64.b64encode(bytes(64)).decode()
        self.reject_signature(packet, "signature_invalid")

    def test_public_seeds_are_never_serialized_into_evidence(self):
        encoded = canonical_bytes({"packet": self.packet, "consumer": consume(self.packet)})
        for key in ("synthetic-rfc8032-active", "synthetic-rfc8032-revoked"):
            self.assertNotIn(PUBLIC_TEST_SEEDS[key].encode(), encoded)


if __name__ == "__main__":
    unittest.main()
