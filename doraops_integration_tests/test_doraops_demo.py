"""Real DataGovOps and DORAOps consumers; no mocked successful consumption."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from doraops import (
    GovernanceError,
    ICTAsset,
    RetestOutcome,
    assert_risk_decision_current,
    assess_ict_risk,
    create_retest,
    record_test_execution,
    resolve_test,
)

from tools.datagovops_demo.__main__ import produce
from tools.datagovops_demo.common import (
    ROOT,
    DemoRejected,
    check_runtime,
    digest,
    read_json,
    timestamp,
)
from tools.demo_evidence import verify_bundle
from tools.doraops_demo import consumer
from tools.doraops_demo.__main__ import make_packet, run_demo, scenarios, variant_packet
from tools.doraops_demo.common import Schemas, load_context, load_contract


class DORAOpsConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = load_contract()
        cls.context = load_context(cls.contract)
        cls.schemas = Schemas(cls.contract)
        cls.base = make_packet()
        cls.accepted = consumer.consume(cls.base)

    def setUp(self):
        self.packet = copy.deepcopy(self.base)

    def rehash(self, part):
        self.packet["handoff"][part + "_sha256"] = digest(self.packet[part])

    def reject(self, expected, **kwargs):
        with self.assertRaises(DemoRejected) as caught:
            consumer.consume(self.packet, **kwargs)
        self.assertEqual(caught.exception.code, expected)

    def native(self):
        return consumer.build_native_records(self.packet, self.context)

    def test_actual_native_finding_lifecycle(self):
        for phase, status, state in (
            ("before", "open", "blocked"),
            ("remediation", "remediation_submitted", "blocked"),
            ("final", "closed", "successful_with_findings"),
        ):
            value = self.accepted[f"resolution-{phase}.json"]
            self.assertEqual(value["finding_resolutions"][0]["status"], status)
            self.assertEqual(value["state"], state)

    def test_risk_is_consumer_judgment_not_cvss_or_closed_dossier_credit(self):
        risk = self.accepted["risk-decision.json"]
        self.assertEqual(risk["inherent_score"], 9)
        self.assertEqual(risk["residual_score"], 9)
        self.assertEqual(risk["control_credit"], 0)
        self.assertEqual(risk["control_digests"], [])
        self.assertEqual(risk["residual_level"], "high")
        self.assertEqual(risk["treatment"]["treatment"], "mitigate")
        self.assertTrue(risk["remediation_required"])
        self.assertFalse(risk["risk_acceptance_required"])

    def test_complete_native_outputs_are_schema_valid_and_receipt_bound(self):
        receipt = self.accepted["receipt.json"]
        self.assertEqual(
            set(receipt["native_artifact_sha256"]), set(self.accepted) - {"receipt.json"}
        )
        for name, expected in receipt["native_artifact_sha256"].items():
            self.assertEqual(digest(self.accepted[name]), expected)
        self.assertEqual(receipt["consumer_source_commit"], self.contract["consumer"]["commit"])
        self.assertEqual(receipt["runtime"]["file_count"], 27)
        self.schemas.validate("ict-risk", self.accepted["risk-decision.json"])
        self.schemas.validate("resilience-test-resolution", self.accepted["resolution-final.json"])

    def test_inventory_and_all_native_chain_digests_bind(self):
        inventory, risk = self.accepted["inventory.json"], self.accepted["risk-decision.json"]
        self.assertEqual(inventory["snapshot_digest"], digest(inventory["snapshot_manifest"]))
        self.assertEqual(risk["inventory_snapshot_digest"], inventory["snapshot_digest"])
        plan, execution = self.accepted["test-plan.json"], self.accepted["test-execution.json"]
        finding, remediation = self.accepted["finding.json"], self.accepted["remediation.json"]
        retest = self.accepted["retest.json"]
        self.assertEqual(plan["risk_decision_digests"], [digest(risk)])
        self.assertEqual(execution["plan_digest"], digest(plan))
        self.assertEqual(finding["execution_digest"], digest(execution))
        self.assertEqual(remediation["finding_digest"], digest(finding))
        self.assertEqual(retest["remediation_digest"], digest(remediation))

    def test_plan_timestamp_is_not_used_as_completion(self):
        source = self.packet["source_packet"]["case"]["remediation"]
        completed = self.accepted["remediation.json"]["completed_at"]
        self.assertNotEqual(completed, timestamp(source["planned_at"]))
        self.assertEqual(completed, timestamp(self.packet["change_completion"]["completed_at"]))
        self.assertEqual(
            self.accepted["remediation.json"]["evidence_digest"],
            digest(self.packet["change_completion"]),
        )

    def test_separate_demo_signature_without_incident_or_real_review_claims(self):
        receipt = self.accepted["receipt.json"]
        self.assertTrue(receipt["requires_human_review"])
        self.assertTrue(receipt["upstream_datagovops_reconsumed"])
        self.assertTrue(receipt["doraops_handoff_signature_verified"])
        self.assertTrue(all(value is False for value in receipt["non_claims"].values()))
        self.assertFalse(self.packet["handoff"]["incident_created"])
        self.assertNotEqual(
            self.packet["handoff"]["profile"], "doraops-operational-control-evidence"
        )

    def test_all_negative_scenarios_fail_at_the_expected_boundary(self):
        for name, packet, expected in scenarios(self.base):
            with self.subTest(name=name):
                self.packet = packet
                self.reject(expected)

    def test_every_input_member_is_hash_bound(self):
        for part in ("source_packet", "datagovops_receipt", "change_completion"):
            self.packet = copy.deepcopy(self.base)
            if part == "change_completion":
                self.packet[part]["statement"] = "Modified synthetic completion statement"
            else:
                self.packet[part]["modified"] = True
            with self.subTest(part=part):
                self.reject("input_digest_mismatch")

    def test_rehashed_source_is_still_revalidated_by_datagovops(self):
        self.packet["source_packet"]["dossier"]["finding_id"] = "SYNTH-CORRUPTED"
        self.rehash("source_packet")
        self.reject("payload_digest_mismatch")

    def test_forged_upstream_receipt_is_not_an_acceptance_signal(self):
        self.packet["datagovops_receipt"]["registered_evidence_digests"] = []
        self.rehash("datagovops_receipt")
        self.reject("upstream_receipt_mismatch")

    def test_handoff_subject_and_exact_asset_mapping(self):
        self.packet["handoff"]["case_id"] = "SYNTH-OTHER"
        self.reject("subject_mismatch")
        self.packet = copy.deepcopy(self.base)
        self.packet["handoff"]["target_node"]["node_id"] = "synthetic-asset:other"
        self.reject("asset_mapping_mismatch")
        self.packet = copy.deepcopy(self.base)
        self.packet["handoff"]["target_node"]["entity_id"] = "synthetic-entity:other"
        self.reject("asset_mapping_mismatch")

    def test_peer_schema_boundary_and_contract_identity_cannot_be_swapped(self):
        for name, value in (
            ("consumer_commit", "f" * 40),
            ("consumer_tree", "f" * 40),
            ("boundary", "operational-deployment-controls"),
            ("demo_contract_sha256", "f" * 64),
            ("governance_context_sha256", "f" * 64),
        ):
            self.packet = copy.deepcopy(self.base)
            self.packet["handoff"][name] = value
            with self.subTest(name=name):
                self.reject("boundary_mismatch")

    def test_future_expired_and_retimed_handoffs(self):
        for as_of in ("2026-01-19T00:00:00Z", self.contract["valid_until"]):
            with self.subTest(as_of=as_of):
                self.reject("handoff_not_current", verified_at=as_of)
        self.packet["handoff"]["created_at"] = "2026-01-20T00:00:00Z"
        self.reject("handoff_not_current")

    def test_currentness_is_rechecked_at_later_consumer_time(self):
        result = consumer.consume(self.packet, verified_at="2026-01-20T23:59:59Z")
        self.assertEqual(result["receipt.json"]["verified_at"], "2026-01-20T23:59:59Z")

    def test_completion_subject_owner_and_change_ref_must_match_the_plan(self):
        for name, value in (
            ("finding_id", "SYNTH-OTHER"),
            ("remediation_id", "SYNTH-OTHER"),
            ("change_ref", "synthetic-change:other"),
            ("owner_role", "synthetic-other-owner"),
            ("evidence_id", "EVD-SYNTH-REM-001"),
        ):
            self.packet = copy.deepcopy(self.base)
            self.packet["change_completion"][name] = value
            self.rehash("change_completion")
            with self.subTest(name=name):
                self.reject("completion_binding_mismatch")

    def test_completion_is_not_future_or_before_the_plan(self):
        for completed, collected in (
            ("2026-01-02T00:00:00Z", "2026-01-02T00:00:00Z"),
            ("2026-01-21T00:00:00Z", "2026-01-21T00:00:00Z"),
            ("2026-01-15T00:00:00Z", "2026-01-14T00:00:00Z"),
        ):
            self.packet = copy.deepcopy(self.base)
            self.packet["change_completion"].update(completed_at=completed, collected_at=collected)
            self.rehash("change_completion")
            with self.subTest(completed=completed, collected=collected):
                self.reject("completion_not_current")

    def test_missing_failed_and_partial_retests_never_close(self):
        for outcome, expected in (
            (None, "remediation_submitted"),
            ("partial", "remediation_submitted"),
            ("ineffective", "retest_failed"),
        ):
            result = consumer.consume(variant_packet(verification_outcome=outcome))
            self.assertEqual(result["receipt.json"]["finding_status"], expected)
            self.assertEqual(result["receipt.json"]["resolution_state"], "blocked")
            if outcome in (None, "partial"):
                self.assertNotIn("retest.json", result)

    def test_effective_label_with_wrong_material_does_not_close(self):
        case = read_json(ROOT / "examples/synthetic-case.json")
        case["verification"]["evidence_refs"] = ["EVD-SYNTH-OBS-001"]
        self.packet = make_packet(produce(case_document=case)[0])
        self.reject("stage_evidence_mismatch")

    def test_future_verification_cannot_close_a_current_dossier(self):
        case = read_json(ROOT / "examples/synthetic-case.json")
        case["verification"]["performed_at"] = "2026-01-20T00:04:00Z"
        self.packet = make_packet(produce(case_document=case)[0])
        self.reject("stage_evidence_not_current")

    def test_retest_material_must_name_the_verifier_and_outcome(self):
        materials = read_json(ROOT / "examples/datagovops-demo/evidence-materials.json")
        materials["EVD-SYNTH-VER-001"]["verifier_role"] = "synthetic-other"
        self.packet = make_packet(produce(materials_document=materials)[0])
        self.reject("stage_evidence_mismatch")

    def test_actual_doraops_enforces_risk_policy_entity_scope(self):
        registry, native, _ = self.native()
        with self.assertRaises(GovernanceError):
            assess_ict_risk(
                registry,
                native["risk-scenario"],
                (),
                replace(native["risk-policy"], entity_id="synthetic-entity:other"),
                native["risk-treatment"],
            )

    def test_actual_doraops_detects_inventory_drift_for_risk_and_execution(self):
        registry, native, _ = self.native()
        registry.register_node(
            ICTAsset(
                self.context["entity_id"],
                "synthetic-asset:added",
                "Synthetic added node",
                "synthetic-owner",
                "synthetic",
            )
        )
        with self.assertRaises(GovernanceError):
            assert_risk_decision_current(
                native["risk-decision"],
                registry,
                native["risk-scenario"],
                (),
                native["risk-policy"],
            )
        old = native["test-execution"]
        with self.assertRaises(GovernanceError):
            record_test_execution(
                native["test-plan"],
                registry,
                (native["risk-decision"],),
                execution_id="synthetic-next",
                executed_at=old.executed_at,
                executor_id=old.executor_id,
                outcome=old.outcome,
                evidence_digests=old.evidence_digests,
                notes="Synthetic stale plan.",
            )

    def test_actual_doraops_rejects_wrong_reviewer_and_cross_finding_retest(self):
        _, native, _ = self.native()
        retest = native["retest"]
        for remediation, reviewer in (
            (native["remediation"], "synthetic-unconfigured-reviewer"),
            (replace(native["remediation"], finding_digest="a" * 64), retest.reviewer_id),
        ):
            with self.assertRaises(GovernanceError):
                create_retest(
                    native["test-plan"],
                    native["finding"],
                    remediation,
                    retest_id=retest.retest_id,
                    reviewer_id=reviewer,
                    tested_at=retest.tested_at,
                    outcome=RetestOutcome.PASSED,
                    notes=retest.notes,
                    evidence_digest=retest.evidence_digest,
                )

    def test_actual_doraops_rejects_conflicting_latest_retest(self):
        _, native, _ = self.native()
        conflict = replace(native["retest"], outcome=RetestOutcome.FAILED)
        with self.assertRaises(GovernanceError):
            resolve_test(
                native["test-plan"],
                native["test-execution"],
                (native["finding"],),
                (native["remediation"],),
                (native["retest"], conflict),
            )

    def test_pinned_runtime_context_and_schemas_fail_on_drift(self):
        changed = copy.deepcopy(self.contract)
        changed["consumer"]["python_files_sha256"] = {}
        with self.assertRaises(DemoRejected):
            check_runtime(changed["consumer"])
        changed = copy.deepcopy(self.contract)
        changed["governance_context_sha256"] = "a" * 64
        with self.assertRaises(DemoRejected):
            load_context(changed)
        changed = copy.deepcopy(self.contract)
        changed["consumer"]["schemas"]["ict-risk"]["content"] += " "
        with self.assertRaises(DemoRejected):
            Schemas(changed)
        changed = copy.deepcopy(self.contract)
        changed["input_schema_sha256"] = "a" * 64
        with self.assertRaises(DemoRejected):
            Schemas(changed)

    def test_schema_snapshots_are_exact_and_have_no_remote_references(self):
        def refs(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "$ref":
                        yield item
                    else:
                        yield from refs(item)
            elif isinstance(value, list):
                for item in value:
                    yield from refs(item)

        for entry in self.contract["consumer"]["schemas"].values():
            self.assertEqual(hashlib.sha256(entry["content"].encode()).hexdigest(), entry["sha256"])
            self.assertTrue(all(ref.startswith("#/") for ref in refs(json.loads(entry["content"]))))

    def test_consumer_imports_no_producer_runtime(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from tools.doraops_demo import consumer; "
                "assert not any(n == 'vulnevidenceops' or n.startswith('vulnevidenceops.') "
                "for n in sys.modules)",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_rejects_before_writing_and_retains_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, output = Path(temporary) / "packet.json", Path(temporary) / "consumer"
            self.packet["handoff"]["incident_created"] = True
            path.write_text(json.dumps(self.packet))
            command = [
                sys.executable,
                "-m",
                "tools.doraops_demo.consumer",
                "--input",
                str(path),
                "--output-dir",
                str(output),
            ]
            result = subprocess.run(
                command, cwd=ROOT, capture_output=True, text=True, check=False, timeout=20
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stderr)["error_code"], "schema_incompatible")
            self.assertFalse(output.exists())
            output.mkdir()
            (output / "prior.json").write_text("{}")
            result = subprocess.run(
                command, cwd=ROOT, capture_output=True, text=True, check=False, timeout=20
            )
            self.assertEqual(json.loads(result.stderr)["error_code"], "output_exists")
            self.assertEqual((output / "prior.json").read_text(), "{}")

    def test_single_command_pipeline_is_repeatable_and_preserves_attention_states(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, second = Path(temporary) / "first", Path(temporary) / "second"
            summary = run_demo(first)
            self.assertEqual(run_demo(second), summary)
            self.assertTrue(summary["upstream_signature_verified"])
            self.assertTrue(summary["doraops_signature_verified"])
            self.assertEqual(len(summary["negative_cases"]), 14)
            self.assertEqual(len(summary["attention_cases"]), 2)
            for directory in (first, second):
                self.assertTrue(verify_bundle(directory)["verified"])
                self.assertTrue(verify_bundle(directory / "datagovops")["verified"])
            for path in first.rglob("*"):
                if path.is_file():
                    self.assertEqual(
                        path.read_bytes(), (second / path.relative_to(first)).read_bytes()
                    )
            for name in summary["negative_cases"]:
                self.assertFalse((first / "negative" / name / "consumer").exists())

    def test_existing_demo_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            marker = path / "prior.json"
            marker.write_text("{}")
            with self.assertRaises(DemoRejected) as caught:
                run_demo(path)
            self.assertEqual(caught.exception.code, "output_exists")
            self.assertEqual(marker.read_text(), "{}")


if __name__ == "__main__":
    unittest.main()
