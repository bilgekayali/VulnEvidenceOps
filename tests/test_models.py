from __future__ import annotations

import copy

import pytest

from vulnevidenceops import (
    EvidenceReference,
    RemediationRecord,
    RiskAcceptance,
    TriageDecision,
    VulnerabilityCase,
    VulnerabilityFinding,
    VulnerabilityPolicy,
)

from .helpers import case_document, policy_document


def test_case_round_trip_preserves_the_public_document():
    document = case_document()
    assert VulnerabilityCase.from_dict(document).to_dict() == document


def test_record_parsing_rejects_unknown_fields_and_schema_drift():
    document = case_document()
    document["unexpected"] = True
    with pytest.raises(ValueError, match="unexpected fields"):
        VulnerabilityCase.from_dict(document)

    document = case_document()
    document["schema_version"] = "vulnevidenceops.case-bundle.v2"
    with pytest.raises(ValueError, match="schema_version must equal"):
        VulnerabilityCase.from_dict(document)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("artifact_sha256", "ABC", "SHA-256"),
        ("collected_at", "2026-01-01", "timezone"),
        ("collected_at", "not-a-time", "ISO 8601"),
        ("evidence_id", "", "non-empty"),
        ("synthetic", "yes", "boolean"),
    ],
)
def test_evidence_reference_rejects_invalid_invariants(field, value, message):
    kwargs = {
        "evidence_id": "E-1",
        "artifact_ref": "synthetic://evidence",
        "artifact_sha256": "a" * 64,
        "media_type": "application/json",
        "collected_at": "2026-01-01T00:00:00Z",
        "source_identity": "synthetic-source",
        "synthetic": True,
    }
    kwargs[field] = value
    with pytest.raises(ValueError, match=message):
        EvidenceReference(**kwargs)


def test_finding_rejects_unknown_severity_and_duplicates():
    with pytest.raises(ValueError, match="severity"):
        VulnerabilityFinding(
            finding_id="F-1",
            asset_ref="A-1",
            source_ref="S-1",
            title="Synthetic",
            severity="urgent",
            first_observed_at="2026-01-01T00:00:00Z",
        )
    with pytest.raises(ValueError, match="duplicate"):
        VulnerabilityFinding(
            finding_id="F-1",
            asset_ref="A-1",
            source_ref="S-1",
            title="Synthetic",
            severity="high",
            first_observed_at="2026-01-01T00:00:00Z",
            evidence_refs=("E-1", "E-1"),
        )


def test_duplicate_triage_requires_a_different_finding_reference():
    base = {
        "decision_id": "D-1",
        "finding_id": "F-1",
        "decided_at": "2026-01-01T00:00:00Z",
        "accountable_role": "owner",
        "disposition": "duplicate",
        "rationale": "Synthetic duplicate",
    }
    with pytest.raises(ValueError, match="required"):
        TriageDecision(**base)
    with pytest.raises(ValueError, match="different"):
        TriageDecision(**base, duplicate_of="F-1")
    with pytest.raises(ValueError, match="only valid"):
        TriageDecision(**{**base, "disposition": "confirmed"}, duplicate_of="F-2")

    duplicate = TriageDecision(**base, duplicate_of="F-2")
    assert duplicate.to_dict()["duplicate_of"] == "F-2"


def test_remediation_due_time_cannot_precede_the_plan():
    with pytest.raises(ValueError, match="must not precede"):
        RemediationRecord(
            remediation_id="R-1",
            finding_id="F-1",
            owner_role="owner",
            planned_at="2026-01-02T00:00:00Z",
            due_at="2026-01-01T00:00:00Z",
            action="Synthetic action",
            change_ref="synthetic-change:1",
        )


def test_case_rejects_duplicate_evidence_and_cross_finding_records():
    document = case_document()
    document["evidence_catalog"].append(copy.deepcopy(document["evidence_catalog"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        VulnerabilityCase.from_dict(document)

    document = case_document()
    document["triage"]["finding_id"] = "FIND-OTHER"
    with pytest.raises(ValueError, match="all case records"):
        VulnerabilityCase.from_dict(document)


def test_risk_acceptance_requires_forward_time_and_unique_references():
    base = {
        "decision_id": "RA-1",
        "finding_id": "F-1",
        "accepted_at": "2026-01-02T00:00:00Z",
        "expires_at": "2026-01-01T00:00:00Z",
        "risk_owner_role": "owner",
        "approver_role": "approver",
        "rationale": "Synthetic",
    }
    with pytest.raises(ValueError, match="later"):
        RiskAcceptance(**base)
    with pytest.raises(ValueError, match="duplicate"):
        RiskAcceptance(
            **{**base, "expires_at": "2026-02-01T00:00:00Z"},
            compensating_control_refs=("C-1", "C-1"),
        )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value["severity_sla_days"].pop("low"),
        lambda value: value["severity_sla_days"].__setitem__("high", 0),
        lambda value: value.__setitem__("max_risk_acceptance_days", 0),
        lambda value: value.__setitem__("independent_verification_required", "yes"),
    ],
)
def test_policy_rejects_incomplete_or_invalid_values(mutator):
    document = policy_document()
    mutator(document)
    with pytest.raises(ValueError):
        VulnerabilityPolicy.from_dict(document)
