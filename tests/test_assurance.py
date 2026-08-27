from __future__ import annotations

import pytest

from vulnevidenceops import VulnerabilityCase, assess_case

from .helpers import case, case_document, policy

AS_OF = "2026-01-20T00:00:00Z"


def _assessment(document: dict, as_of: str = AS_OF):
    return assess_case(
        VulnerabilityCase.from_dict(document),
        policy=policy(),
        assessed_at=as_of,
    )


def test_reference_case_closes_with_deterministic_no_gap_evidence():
    first = assess_case(case(), policy=policy(), assessed_at=AS_OF)
    second = assess_case(case(), policy=policy(), assessed_at=AS_OF)

    assert first.to_dict() == second.to_dict()
    assert first.lifecycle_state == "closed_verified"
    assert first.assurance_position == "current"
    assert first.gaps == ()
    assert not first.overdue
    assert all(
        item["status"] in {"represented", "not_applicable"}
        for item in first.control_evidence
    )
    assert not any(first.non_claims.values())


def test_missing_triage_is_detected_and_eventually_overdue():
    document = case_document()
    document.pop("triage")
    document.pop("remediation")
    document.pop("verification")

    dossier = _assessment(document, "2026-03-01T00:00:00Z")

    assert dossier.lifecycle_state == "detected"
    assert dossier.assurance_position == "overdue"
    assert dossier.overdue
    assert "triage_decision_missing" in dossier.gaps


def test_supported_false_positive_closes_without_remediation_controls():
    document = case_document()
    document["triage"]["disposition"] = "false_positive"
    document.pop("remediation")
    document.pop("verification")

    dossier = _assessment(document)
    controls = {item["control_id"]: item for item in dossier.control_evidence}

    assert dossier.lifecycle_state == "closed_dispositioned"
    assert dossier.assurance_position == "current"
    assert controls["VEO-REM-001"]["status"] == "not_applicable"
    assert controls["VEO-CLS-001"]["status"] == "represented"


def test_current_time_bounded_risk_acceptance_is_represented():
    document = case_document()
    document.pop("remediation")
    document.pop("verification")
    document["evidence_catalog"].append(
        {
            "schema_version": "vulnevidenceops.evidence-reference.v1",
            "evidence_id": "EVD-SYNTH-ACC-001",
            "artifact_ref": "synthetic://approval/risk-001.json",
            "artifact_sha256": "e" * 64,
            "media_type": "application/json",
            "collected_at": "2026-01-03T00:00:00Z",
            "source_identity": "synthetic-approval:reference-v1",
            "synthetic": True,
        }
    )
    document["risk_acceptance"] = {
        "schema_version": "vulnevidenceops.risk-acceptance.v1",
        "decision_id": "ACC-SYNTH-001",
        "finding_id": "FIND-SYNTH-001",
        "accepted_at": "2026-01-03T00:00:00Z",
        "expires_at": "2026-02-01T00:00:00Z",
        "risk_owner_role": "synthetic-risk-owner",
        "approver_role": "synthetic-approver",
        "rationale": "Synthetic time-bounded exception.",
        "compensating_control_refs": ["synthetic-control:WAF-001"],
        "evidence_refs": ["EVD-SYNTH-ACC-001"],
    }

    dossier = _assessment(document)
    controls = {item["control_id"]: item for item in dossier.control_evidence}

    assert dossier.lifecycle_state == "risk_accepted"
    assert dossier.assurance_position == "current"
    assert dossier.gaps == ()
    assert controls["VEO-ACC-001"]["status"] == "represented"
    assert controls["VEO-VER-001"]["status"] == "not_applicable"


def test_expired_risk_acceptance_requires_revalidation():
    document = case_document()
    document.pop("remediation")
    document.pop("verification")
    document["evidence_catalog"].append(
        {
            "schema_version": "vulnevidenceops.evidence-reference.v1",
            "evidence_id": "E-ACC",
            "artifact_ref": "synthetic://approval/risk.json",
            "artifact_sha256": "e" * 64,
            "media_type": "application/json",
            "collected_at": "2026-01-03T00:00:00Z",
            "source_identity": "synthetic-approval",
            "synthetic": True,
        }
    )
    document["risk_acceptance"] = {
        "schema_version": "vulnevidenceops.risk-acceptance.v1",
        "decision_id": "ACC-1",
        "finding_id": "FIND-SYNTH-001",
        "accepted_at": "2026-01-03T00:00:00Z",
        "expires_at": "2026-02-01T00:00:00Z",
        "risk_owner_role": "risk-owner",
        "approver_role": "approver",
        "rationale": "Synthetic",
        "compensating_control_refs": ["CONTROL-1"],
        "evidence_refs": ["E-ACC"],
    }

    dossier = _assessment(document, "2026-03-01T00:00:00Z")

    assert dossier.lifecycle_state == "revalidation_required"
    assert dossier.assurance_position == "revalidation_required"
    assert "risk_acceptance_expired" in dossier.gaps


def test_self_verification_and_partial_outcome_fail_closed():
    document = case_document()
    document["verification"]["verifier_role"] = document["remediation"]["owner_role"]
    document["verification"]["outcome"] = "partial"

    dossier = _assessment(document)

    assert dossier.lifecycle_state == "verification_pending"
    assert dossier.assurance_position == "with_gaps"
    assert "verification_not_effective" in dossier.gaps
    assert "verification_not_independent" in dossier.gaps


def test_future_records_do_not_satisfy_current_assurance():
    document = case_document()
    dossier = _assessment(document, "2026-01-10T00:00:00Z")

    assert dossier.lifecycle_state == "verification_pending"
    assert "verification_record_future" in dossier.gaps


def test_assessment_cannot_predate_the_finding():
    try:
        assess_case(case(), policy=policy(), assessed_at="2025-12-31T00:00:00Z")
    except ValueError as exc:
        assert "must not precede" in str(exc)
    else:
        raise AssertionError("expected a fail-closed time validation")


@pytest.mark.parametrize(
    ("record", "field", "value", "expected_gap"),
    [
        ("finding", "evidence_refs", [], "finding_evidence_missing"),
        ("finding", "evidence_refs", ["UNKNOWN"], "finding_evidence_unlinked"),
        ("triage", "evidence_refs", [], "triage_evidence_missing"),
        ("triage", "evidence_refs", ["UNKNOWN"], "triage_evidence_unlinked"),
        ("triage", "decided_at", "2027-01-01T00:00:00Z", "triage_decision_future"),
        ("remediation", "evidence_refs", [], "remediation_evidence_missing"),
        ("remediation", "evidence_refs", ["UNKNOWN"], "remediation_evidence_unlinked"),
        ("verification", "evidence_refs", [], "verification_evidence_missing"),
        ("verification", "evidence_refs", ["UNKNOWN"], "verification_evidence_unlinked"),
    ],
)
def test_record_evidence_gaps_are_explicit(record, field, value, expected_gap):
    document = case_document()
    document[record][field] = value

    assert expected_gap in _assessment(document).gaps


def _acceptance_document() -> dict:
    document = case_document()
    document.pop("remediation")
    document.pop("verification")
    document["evidence_catalog"].append(
        {
            "schema_version": "vulnevidenceops.evidence-reference.v1",
            "evidence_id": "E-ACC",
            "artifact_ref": "synthetic://approval/risk.json",
            "artifact_sha256": "e" * 64,
            "media_type": "application/json",
            "collected_at": "2026-01-03T00:00:00Z",
            "source_identity": "synthetic-approval",
            "synthetic": True,
        }
    )
    document["risk_acceptance"] = {
        "schema_version": "vulnevidenceops.risk-acceptance.v1",
        "decision_id": "ACC-1",
        "finding_id": "FIND-SYNTH-001",
        "accepted_at": "2026-01-03T00:00:00Z",
        "expires_at": "2026-02-01T00:00:00Z",
        "risk_owner_role": "risk-owner",
        "approver_role": "approver",
        "rationale": "Synthetic",
        "compensating_control_refs": ["CONTROL-1"],
        "evidence_refs": ["E-ACC"],
    }
    return document


@pytest.mark.parametrize(
    ("field", "value", "expected_gap"),
    [
        ("expires_at", "2026-06-01T00:00:00Z", "risk_acceptance_exceeds_policy"),
        ("compensating_control_refs", [], "compensating_controls_missing"),
        ("evidence_refs", [], "risk_acceptance_evidence_missing"),
        ("evidence_refs", ["UNKNOWN"], "risk_acceptance_evidence_unlinked"),
    ],
)
def test_invalid_risk_acceptance_inputs_remain_visible_as_gaps(
    field, value, expected_gap
):
    document = _acceptance_document()
    document["risk_acceptance"][field] = value

    assert expected_gap in _assessment(document).gaps


def test_future_risk_acceptance_and_remediation_do_not_satisfy_the_case():
    document = _acceptance_document()
    document["risk_acceptance"]["accepted_at"] = "2027-01-01T00:00:00Z"
    document["risk_acceptance"]["expires_at"] = "2027-02-01T00:00:00Z"
    assert "risk_acceptance_future" in _assessment(document).gaps

    document = case_document()
    document["remediation"]["planned_at"] = "2027-01-01T00:00:00Z"
    document["remediation"]["due_at"] = "2027-02-01T00:00:00Z"
    dossier = _assessment(document)
    assert "remediation_record_future" in dossier.gaps
    assert "verified_remediation_record_missing" in dossier.gaps
