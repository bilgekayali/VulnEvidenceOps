"""Two independent signature boundaries, not a reused upstream trust assertion."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.datagovops_demo.common import ROOT, DemoRejected, canonical_bytes, digest
from tools.doraops_demo.__main__ import make_packet
from tools.doraops_demo.common import load_contract
from tools.doraops_demo.consumer import consume
from tools.doraops_demo.demo_signer import REVOKED, sign_packet, signature_scenarios
from tools.doraops_demo.signatures import (
    AUDIENCE,
    BODY_PARTS,
    PURPOSE,
    load_signing_policy,
    transcript,
    verify_packet_signature,
)


class DORAOpsSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = load_contract()
        cls.policy = load_signing_policy(cls.contract)
        cls.base = make_packet()

    def setUp(self):
        self.packet = copy.deepcopy(self.base)

    def verify(self, **kwargs):
        return verify_packet_signature(
            self.packet, self.contract, kwargs.get("verified_at", self.contract["verified_at"])
        )

    def reject(self, code, **kwargs):
        with self.assertRaises(DemoRejected) as caught:
            self.verify(**kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_separate_signature_binds_every_member_and_consumer_context(self):
        result = self.verify()
        self.assertTrue(result["signature_valid"])
        self.assertTrue(result["public_test_key"])
        self.assertEqual(result["audience"], AUDIENCE)
        self.assertEqual(result["purpose"], PURPOSE)
        self.assertEqual(
            result["members_sha256"], {name: digest(self.packet[name]) for name in BODY_PARTS}
        )
        self.assertTrue(all(value is False for value in result["non_claims"].values()))

    def test_all_four_members_are_signed_not_just_locally_hash_linked(self):
        for name in BODY_PARTS:
            self.packet = copy.deepcopy(self.base)
            self.packet[name]["tampered"] = True
            with self.subTest(name=name):
                self.reject("doraops_signed_packet_mismatch")

    def test_recomputed_hashes_and_transcript_cannot_preserve_old_signature(self):
        self.packet = dict(signature_scenarios(self.base)[5][1])
        self.assertEqual(
            self.packet["handoff"]["change_completion_sha256"],
            digest(self.packet["change_completion"]),
        )
        self.assertEqual(
            self.packet["signed_envelope"]["payload_sha256"],
            digest(transcript(self.packet, self.contract, self.policy)),
        )
        self.reject("doraops_signature_invalid")

    def test_rehashed_completion_without_rebuilt_transcript_is_rejected(self):
        self.packet["change_completion"]["statement"] = "Changed synthetic statement"
        self.packet["handoff"]["change_completion_sha256"] = digest(
            self.packet["change_completion"]
        )
        self.reject("doraops_signed_packet_mismatch")

    def test_valid_signature_for_wrong_audience_is_rejected(self):
        self.packet["signed_envelope"] = sign_packet(self.packet, audience="synthetic.other")
        self.reject("doraops_signature_context_mismatch")

    def test_valid_signature_for_wrong_purpose_is_rejected(self):
        self.packet["signed_envelope"] = sign_packet(self.packet, purpose="approve-risk-acceptance")
        self.reject("doraops_signature_context_mismatch")

    def test_upstream_signature_cannot_authorize_doraops_completion(self):
        self.packet["signed_envelope"] = self.packet["source_packet"]["signed-envelope"]
        self.reject("doraops_signature_context_mismatch")

    def test_unsigned_packets_are_rejected_without_downgrade(self):
        self.packet.pop("signed_envelope")
        self.reject("doraops_signature_required")
        with self.assertRaises(DemoRejected) as caught:
            consume(self.packet)
        self.assertEqual(caught.exception.code, "doraops_signature_required")

    def test_all_signature_negative_cases_fail_in_the_real_consumer(self):
        for name, candidate, expected in signature_scenarios(self.base):
            with self.subTest(name=name), self.assertRaises(DemoRejected) as caught:
                consume(candidate)
            self.assertEqual(caught.exception.code, expected)

    def test_revocation_is_checked_at_consumption_not_only_signing(self):
        self.packet["signed_envelope"] = sign_packet(self.packet, key_id=REVOKED)
        before = self.verify(verified_at="2026-01-20T00:07:59Z")
        self.assertTrue(before["signature_valid"])
        self.reject("doraops_key_revoked", verified_at="2026-01-20T00:08:00Z")
        self.reject("doraops_key_revoked")

    def test_future_signature_is_not_current(self):
        self.packet["signed_envelope"] = sign_packet(self.packet, signed_at="2026-01-20T00:11:00Z")
        self.reject("doraops_key_not_current")

    def test_signature_cannot_predate_handoff(self):
        self.packet["signed_envelope"] = sign_packet(self.packet, signed_at="2026-01-20T00:04:59Z")
        self.reject("doraops_signature_time_mismatch")

    def test_expired_key_and_signing_before_key_validity_are_rejected(self):
        self.reject("doraops_key_not_current", verified_at="2026-01-22T00:00:00Z")
        self.packet["signed_envelope"] = sign_packet(self.packet, signed_at="2025-12-31T23:59:59Z")
        self.reject("doraops_key_not_current")

    def test_malformed_and_noncanonical_base64_are_rejected(self):
        for field, value in (("payload_base64", "!"), ("signature_base64", "YQ==")):
            self.packet = copy.deepcopy(self.base)
            self.packet["signed_envelope"][field] = value
            with self.subTest(field=field), self.assertRaises(DemoRejected):
                self.verify()

    def test_payload_hash_mismatch_is_rejected(self):
        self.packet["signed_envelope"]["payload_sha256"] = "f" * 64
        self.reject("doraops_signed_payload_digest_mismatch")

    def test_non_json_and_noncanonical_transcripts_are_rejected(self):
        for raw, expected in (
            (b"not JSON", "doraops_signed_packet_mismatch"),
            (b"[]", "doraops_signature_context_mismatch"),
            (
                canonical_bytes(transcript(self.packet, self.contract, self.policy)) + b"\n",
                "doraops_signed_packet_mismatch",
            ),
        ):
            self.packet["signed_envelope"]["payload_base64"] = base64.b64encode(raw).decode()
            self.packet["signed_envelope"]["payload_sha256"] = hashlib.sha256(raw).hexdigest()
            with self.subTest(raw=raw[:10]):
                self.reject(expected)

    def test_key_policy_cannot_be_replaced_by_packet_metadata(self):
        self.packet["signing_policy"] = self.policy
        with self.assertRaises(DemoRejected) as caught:
            consume(self.packet)
        self.assertEqual(caught.exception.code, "schema_incompatible")

    def test_policy_hash_and_safety_invariants_are_checked(self):
        contract = {**self.contract, "signing_policy_sha256": "f" * 64}
        with self.assertRaises(DemoRejected):
            load_signing_policy(contract)
        for mutation in ("signature_required", "public_test_keys_only", "duplicate_key"):
            policy = copy.deepcopy(self.policy)
            if mutation == "duplicate_key":
                policy["keys"].append(copy.deepcopy(policy["keys"][0]))
            else:
                policy[mutation] = False
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "policy.json"
                path.write_text(json.dumps(policy))
                contract = {
                    **self.contract,
                    "signing_policy_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
                with (
                    patch("tools.doraops_demo.signatures.POLICY_PATH", path),
                    self.assertRaises(DemoRejected) as caught,
                ):
                    load_signing_policy(contract)
                self.assertEqual(caught.exception.code, "doraops_signing_policy_mismatch")

    def test_signature_result_and_envelope_are_bound_into_real_receipt(self):
        outputs = consume(self.packet)
        receipt, result = outputs["receipt.json"], outputs["signature-verification.json"]
        self.assertTrue(receipt["doraops_handoff_signature_verified"])
        self.assertEqual(receipt["signature_verification_sha256"], digest(result))
        self.assertEqual(
            receipt["native_artifact_sha256"]["signature-verification.json"], digest(result)
        )
        self.assertEqual(receipt["signed_envelope_sha256"], digest(self.packet["signed_envelope"]))

    def test_signature_rejection_has_no_consumer_files_or_receipt(self):
        self.packet["signed_envelope"] = sign_packet(self.packet, wrong_key=True)
        with tempfile.TemporaryDirectory() as directory:
            path, output = Path(directory) / "input.json", Path(directory) / "consumer"
            path.write_text(json.dumps(self.packet))
            result = subprocess.run(
                [sys.executable, "-m", "tools.doraops_demo.consumer", "--input", str(path),
                 "--output-dir", str(output)],
                cwd=ROOT, capture_output=True, text=True, check=False, timeout=30,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stderr)["error_code"], "doraops_signature_invalid")
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
