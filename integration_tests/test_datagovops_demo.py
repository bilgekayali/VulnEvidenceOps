"""Real peer-runtime tests; run with tools/demo_datagovops.py --test."""

from __future__ import annotations

import ast
import copy
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from dataclasses import replace
from pathlib import Path

from datagovops import (
    ControlDefinition,
    ControlDomain,
    ControlEvidenceReference,
    ControlEvidenceRegistry,
    EvidenceRequirement,
    EvidenceSourceBoundary,
    GovernanceError,
    digest_artifact,
)

from tools.datagovops_demo import consumer
from tools.datagovops_demo.__main__ import _packet_files, produce, run_demo
from tools.datagovops_demo.common import (
    ROOT,
    DemoRejected,
    Schemas,
    canonical_bytes,
    check_runtime,
    digest,
    load_contract,
    read_json,
    timestamp,
)
from tools.datagovops_demo.demo_signer import sign_packet
from vulnevidenceops import IntegrationHandoff, verify_integration_handoff


class DataGovOpsConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_packet, cls.verification = produce()
        cls.contract = load_contract()
        cls.baseline = consumer.consume(cls.base_packet)
        cls.schemas = Schemas(cls.contract)

    def setUp(self):
        self.packet = copy.deepcopy(self.base_packet)

    def rehash(self):
        self.packet["handoff"]["payload_sha256"] = digest(self.packet["dossier"])
        self.packet["signed-envelope"] = sign_packet(self.packet)

    def reject(self, code, **kwargs):
        with self.assertRaises(DemoRejected) as caught:
            consumer.consume(self.packet, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def registry_fixture(self):
        item = copy.deepcopy(self.baseline["control-definitions.json"][0])
        item["domain"] = ControlDomain(item["domain"])
        item["evidence_requirements"] = tuple(
            EvidenceRequirement(
                row["evidence_type"],
                tuple(EvidenceSourceBoundary(s) for s in row["accepted_sources"]),
            )
            for row in item["evidence_requirements"]
        )
        item["framework_references"] = ()
        definition = ControlDefinition(**item)
        item = copy.deepcopy(self.baseline["evidence-references.json"][0])
        item["source_boundary"] = EvidenceSourceBoundary(item["source_boundary"])
        reference = ControlEvidenceReference(**item)
        registry = ControlEvidenceRegistry()
        registry.register_control(definition)
        return registry, definition, reference

    def test_real_datagovops_matrix_state_transition(self):
        before, after, stale = (
            self.baseline[name]
            for name in ("matrix-before.json", "matrix-after.json", "matrix-at-expiry.json")
        )
        self.assertEqual(before["state"], "with_gaps")
        self.assertEqual(before["gap_control_count"], 5)
        self.assertEqual(after["state"], "represented")
        self.assertEqual(after["represented_control_count"], 5)
        self.assertEqual(stale["state"], "revalidation_required")
        self.assertEqual(stale["revalidation_required_control_count"], 5)
        self.assertEqual(
            self.baseline["receipt.json"]["consumer_backend"], "datagovops.ControlEvidenceRegistry"
        )

    def test_all_consumer_records_match_actual_datagovops_schemas_and_digests(self):
        for filename, schema in (
            ("control-definitions.json", "control-definition"),
            ("evidence-references.json", "control-evidence-reference"),
            ("control-assessments.json", "control-assessment"),
        ):
            for document in self.baseline[filename]:
                self.schemas.validate("consumer", schema, document)
        receipt = self.baseline["receipt.json"]
        self.assertEqual(
            receipt["registered_evidence_digests"],
            [digest_artifact(item) for item in self.baseline["evidence-references.json"]],
        )
        self.assertEqual(
            receipt["matrix_after_digest"], digest_artifact(self.baseline["matrix-after.json"])
        )

    def test_every_reference_binds_exact_dossier_snapshot_and_consumer_validation(self):
        for reference in self.baseline["evidence-references.json"]:
            self.assertEqual(reference["source_artifact_digest"], digest(self.packet["dossier"]))
            self.assertEqual(reference["source_snapshot_digest"], digest(self.packet["case"]))
            self.assertEqual(
                reference["verification_evidence_digest"],
                digest(self.baseline["validation-report.json"]),
            )

    def test_four_actual_synthetic_materials_replace_placeholder_hashes(self):
        catalog = self.packet["case"]["evidence_catalog"]
        self.assertEqual(len(catalog), 4)
        for item in catalog:
            self.assertEqual(
                item["artifact_sha256"], digest(self.packet["materials"][item["evidence_id"]])
            )
            self.assertGreater(len(set(item["artifact_sha256"])), 1)
        self.assertEqual(self.packet["dossier"]["input_sha256"], digest(self.packet["case"]))

    def test_nonclaims_and_not_applicable_control_remain_explicit(self):
        self.assertTrue(all(value is False for value in self.verification["non_claims"].values()))
        self.assertTrue(
            all(value is False for value in self.baseline["receipt.json"]["non_claims"].values())
        )
        self.assertTrue(self.baseline["matrix-after.json"]["requires_human_review"])
        self.assertFalse(self.baseline["matrix-after.json"]["automated_compliance_scoring_enabled"])
        self.assertEqual(
            [row["control_id"] for row in self.baseline["receipt.json"]["excluded_controls"]],
            ["VEO-ACC-001"],
        )

    def test_consumer_does_not_import_the_producer_runtime(self):
        module = ast.parse((ROOT / "tools/datagovops_demo/consumer.py").read_text())
        imports = [node.module for node in ast.walk(module) if isinstance(node, ast.ImportFrom)]
        self.assertFalse(any(name and name.startswith("vulnevidenceops") for name in imports))
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from tools.datagovops_demo import consumer; "
                "assert not any(n == 'vulnevidenceops' or n.startswith('vulnevidenceops.') "
                "for n in sys.modules)",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_corrupted_content_fails_before_datagovops_registration(self):
        self.packet["dossier"]["finding_id"] = "CORRUPTED"
        self.reject("payload_digest_mismatch")

    def test_rehashed_unknown_schema_passes_old_local_check_but_fails_consumer(self):
        self.packet["dossier"]["schema_version"] = "vulnevidenceops.assurance-dossier.v999"
        self.rehash()
        peer = self.contract["consumer"]["schemas"]["control-evidence-reference"]
        local = verify_integration_handoff(
            IntegrationHandoff.from_dict(self.packet["handoff"]),
            self.packet["dossier"],
            (ROOT / peer["path"]).read_bytes(),
            verified_at=self.contract["verified_at"],
        )
        self.assertEqual(local.integration_position, "verified")
        self.reject("schema_incompatible")

    def test_rehashed_structurally_invalid_dossier_is_rejected(self):
        variants = [
            lambda item: item.pop("control_evidence"),
            lambda item: item.update(unknown_field="unsupported"),
            lambda item: item.update(overdue="false"),
            lambda item: item["non_claims"].update(regulatory_compliance_established=True),
        ]
        for change in variants:
            with self.subTest(change=change):
                self.packet = copy.deepcopy(self.base_packet)
                change(self.packet["dossier"])
                self.rehash()
                self.reject("schema_incompatible")

    def test_handoff_schema_version_is_checked(self):
        self.packet["handoff"]["schema_version"] = "vulnevidenceops.integration-handoff.v999"
        self.reject("schema_incompatible")

    def test_peer_identity_cannot_be_switched(self):
        for key, value in (
            ("commit", "a" * 40),
            ("blob", "b" * 40),
            ("repository", "https://github.com/other/repository"),
        ):
            with self.subTest(key=key):
                self.packet = copy.deepcopy(self.base_packet)
                self.packet["handoff"]["peer_contract"][key] = value
                self.reject("profile_mismatch")

    def test_valid_hash_does_not_allow_wrong_subject(self):
        self.packet["handoff"]["subject_ref"] = "CASE-SYNTH-OTHER"
        self.reject("subject_mismatch")

    def test_case_and_policy_snapshots_are_bound(self):
        for part in ("case", "policy"):
            with self.subTest(part=part):
                self.packet = copy.deepcopy(self.base_packet)
                if part == "case":
                    self.packet[part]["finding"]["title"] = "Changed synthetic title"
                else:
                    self.packet[part]["max_risk_acceptance_days"] = 30
                self.reject("snapshot_digest_mismatch")

    def test_material_tampering_is_rejected_even_with_unchanged_valid_dossier(self):
        self.packet["materials"]["EVD-SYNTH-VER-001"]["result"] = "changed-result"
        self.reject("material_digest_mismatch")

    def test_missing_material_is_rejected(self):
        del self.packet["materials"]["EVD-SYNTH-VER-001"]
        self.reject("evidence_link_mismatch")

    def test_non_synthetic_content_is_out_of_scope(self):
        self.packet["materials"]["EVD-SYNTH-VER-001"]["synthetic"] = False
        self.reject("non_synthetic_input")

    def test_duplicate_control_or_missing_control_is_rejected(self):
        for duplicate in (True, False):
            with self.subTest(duplicate=duplicate):
                self.packet = copy.deepcopy(self.base_packet)
                rows = self.packet["dossier"]["control_evidence"]
                rows.append(copy.deepcopy(rows[0])) if duplicate else rows.pop()
                self.rehash()
                self.reject("control_mapping_mismatch")

    def test_unlinked_control_evidence_is_rejected(self):
        self.packet["dossier"]["control_evidence"][1]["evidence_refs"] = ["MISSING"]
        self.rehash()
        self.reject("evidence_link_mismatch")

    def test_upstream_gap_is_not_silently_promoted_to_represented(self):
        row = self.packet["dossier"]["control_evidence"][1]
        row["status"], row["evidence_refs"] = "gap", []
        self.rehash()
        after = consumer.consume(self.packet)["matrix-after.json"]
        self.assertEqual(after["state"], "with_gaps")
        self.assertEqual(after["gap_control_count"], 1)
        self.assertEqual(after["represented_control_count"], 4)

    def test_future_and_expired_handoffs_are_rejected(self):
        for as_of in ("2026-01-19T23:59:59Z", self.contract["valid_until"]):
            with self.subTest(as_of=as_of):
                self.reject("handoff_not_current", verified_at=as_of)

    def test_expiry_boundary_is_translated_without_an_off_by_one_error(self):
        accepted = consumer.consume(self.packet, verified_at="2026-01-20T23:59:59Z")
        self.assertEqual(accepted["matrix-after.json"]["state"], "represented")
        for reference in accepted["evidence-references.json"]:
            self.assertEqual(
                reference["revalidate_after"], timestamp(self.contract["valid_until"]) - 1
            )
        self.assertEqual(accepted["matrix-at-expiry.json"]["state"], "revalidation_required")

    def test_actual_datagovops_rejects_cross_institution_even_when_schema_valid(self):
        registry, _, reference = self.registry_fixture()
        bad = replace(reference, institution_id="synthetic-institution:other")
        self.schemas.validate("consumer", "control-evidence-reference", consumer._document(bad))
        with self.assertRaises(GovernanceError):
            registry.register_evidence(bad)

    def test_actual_datagovops_rejects_unaccepted_source_even_when_schema_valid(self):
        registry, _, reference = self.registry_fixture()
        bad = replace(reference, source_boundary=EvidenceSourceBoundary.EXTERNAL)
        self.schemas.validate("consumer", "control-evidence-reference", consumer._document(bad))
        with self.assertRaises(GovernanceError):
            registry.register_evidence(bad)

    def test_actual_datagovops_rejects_unsupported_reference_schema(self):
        _, _, reference = self.registry_fixture()
        with self.assertRaises(GovernanceError):
            replace(reference, schema_version="datagovops.control-evidence-reference.v999")

    def test_actual_registry_is_idempotent_and_rejects_conflicting_evidence_identity(self):
        registry, _, reference = self.registry_fixture()
        first = registry.register_evidence(reference)
        self.assertEqual(registry.register_evidence(reference), first)
        with self.assertRaises(GovernanceError):
            registry.register_evidence(replace(reference, source_artifact_digest="a" * 64))

    def test_runtime_hash_and_version_mismatches_are_rejected(self):
        for field in ("version", "python_files_sha256"):
            with self.subTest(field=field):
                peer = copy.deepcopy(self.contract["consumer"])
                peer[field] = "0.0.0" if field == "version" else {}
                with self.assertRaises(DemoRejected) as caught:
                    check_runtime(peer)
                self.assertEqual(caught.exception.code, "runtime_mismatch")

    def test_schema_snapshot_mismatch_fails_closed(self):
        for side in ("producer", "consumer"):
            with self.subTest(side=side):
                contract = copy.deepcopy(self.contract)
                if side == "producer":
                    contract[side]["schema_set_sha256"] = "a" * 64
                else:
                    contract[side]["schemas"]["control-evidence-reference"]["sha256"] = "a" * 64
                with self.assertRaises(DemoRejected) as caught:
                    Schemas(contract)
                self.assertEqual(caught.exception.code, "contract_mismatch")

    def test_cli_rejects_before_writing_any_accepted_receipt(self):
        self.packet["dossier"]["finding_id"] = "CORRUPTED"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _packet_files(directory / "packet", self.packet)
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = consumer.main(
                    [
                        "--packet-dir",
                        str(directory / "packet"),
                        "--output-dir",
                        str(directory / "consumer"),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(stderr.getvalue())["error_code"], "payload_digest_mismatch")
            self.assertFalse((directory / "consumer").exists())

    def test_strict_json_rejects_duplicate_keys_nonfinite_values_and_invalid_utf8(self):
        for content in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b"\xff"):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "input.json"
                path.write_bytes(content)
                with self.assertRaises(DemoRejected) as caught:
                    read_json(path)
                self.assertEqual(caught.exception.code, "invalid_json")

    def test_overflowing_json_number_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            path.write_text('{"value":1e9999}')
            with self.assertRaises(DemoRejected) as caught:
                read_json(path)
            self.assertEqual(caught.exception.code, "invalid_json")

    def test_oversized_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            path.write_bytes(b" " * 2_000_001)
            with self.assertRaises(DemoRejected):
                read_json(path)

    def test_timestamp_requires_utc_whole_seconds(self):
        for value in (
            True,
            "2026-01-20",
            "2026-01-20Z",
            "2026-01-20 00:00:00Z",
            "2026-01-20T00:00:00.001Z",
            "1960-01-01T00:00:00Z",
        ):
            with self.subTest(value=value), self.assertRaises(DemoRejected):
                timestamp(value)

    def test_nonfinite_canonical_json_is_not_hashable(self):
        with self.assertRaises(ValueError):
            canonical_bytes({"value": float("nan")})

    def test_process_pipeline_has_reproducible_artifacts_and_negative_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, second = Path(temporary) / "first", Path(temporary) / "second"
            summary = run_demo(first)
            self.assertEqual(run_demo(second), summary)
            self.assertTrue(summary["positive_case_accepted"])
            self.assertTrue(summary["incompatible_schema_passes_digest_only_check"])
            self.assertEqual(len(summary["negative_cases"]), 6)
            manifest = read_json(first / "manifest.json")
            for item in manifest["artifacts"]:
                content = (first / item["path"]).read_bytes()
                self.assertEqual(content, (second / item["path"]).read_bytes())
                self.assertEqual(hashlib.sha256(content).hexdigest(), item["sha256"])
            self.assertEqual(
                (first / "manifest.json").read_bytes(), (second / "manifest.json").read_bytes()
            )

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            marker = path / "prior-evidence.txt"
            marker.write_text("keep")
            with self.assertRaises(DemoRejected) as caught:
                run_demo(path)
            self.assertEqual(caught.exception.code, "output_exists")
            self.assertEqual(marker.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
