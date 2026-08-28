from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from vulnevidenceops import (
    PortfolioAssuranceView,
    PortfolioBundle,
    assess_portfolio,
    sha256_digest,
)

from .helpers import portfolio_bundle, portfolio_document

ASSESSMENT_TIME = "2026-01-20T00:00:00Z"


def test_reference_portfolio_is_deterministic_current_and_round_trippable():
    document = portfolio_document()
    bundle = PortfolioBundle.from_dict(document)
    first = assess_portfolio(
        bundle,
        assessed_at="2026-01-20T01:00:00+01:00",
    )
    second = assess_portfolio(bundle, assessed_at=ASSESSMENT_TIME)

    assert bundle.to_dict() == document
    assert first.to_dict() == second.to_dict()
    assert first.assessed_at == ASSESSMENT_TIME
    assert first.input_sha256 == sha256_digest(document)
    assert first.policy_sha256 == sha256_digest(bundle.policy.to_dict())
    assert first.portfolio_position == "current"
    assert first.gaps == ()
    assert first.totals == {
        "case_count": 3,
        "closed_case_count": 2,
        "deduplication_decision_count": 1,
        "exception_count": 1,
        "finding_count": 3,
        "open_case_count": 1,
        "portfolio_gap_count": 0,
    }
    assert [item["case_id"] for item in first.case_summaries] == [
        "CASE-SYNTH-001",
        "CASE-SYNTH-ACC-003",
        "CASE-SYNTH-DUP-002",
    ]
    assert {item["cohort"] for item in first.sla_cohorts} == {
        "accepted_exception",
        "closed",
    }
    decision = first.deduplication_decisions[0]
    assert decision["target_finding_id"] == "FIND-SYNTH-001"
    assert decision["decision_currentness"] == "current"
    assert decision["target_state"] == "linked"
    assert decision["evidence_state"] == "linked"
    exception = first.exception_ageing[0]
    assert exception["exception_state"] == "current"
    assert exception["age_band"] == "0_30_days"
    assert exception["age_days"] == 8
    assert exception["days_until_expiry"] == 51
    assert exception["policy_state"] == "within_policy"
    assert exception["evidence_state"] == "linked"
    assert {item["accountable_role"] for item in first.accountability_view} == {
        "synthetic-cyber-risk-lead",
        "synthetic-independent-assurance",
        "synthetic-risk-approver",
        "synthetic-service-owner",
        "synthetic-vulnerability-owner",
    }
    assert all(value is False for value in first.non_claims.values())


def test_empty_portfolio_is_explicitly_unavailable():
    document = portfolio_document()
    document["cases"] = []

    view = assess_portfolio(
        PortfolioBundle.from_dict(document),
        assessed_at=ASSESSMENT_TIME,
    )

    assert view.portfolio_position == "unavailable"
    assert view.gaps == ("portfolio_cases_missing",)
    assert view.case_summaries == ()
    assert view.sla_cohorts == ()
    assert view.accountability_view == ()
    assert view.totals["case_count"] == 0
    assert view.totals["portfolio_gap_count"] == 1


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda document: document["cases"].append(
                copy.deepcopy(document["cases"][0])
            ),
            "case_id",
        ),
        (
            lambda document: (
                document["cases"][1]["finding"].update(
                    finding_id="FIND-SYNTH-001"
                ),
                document["cases"][1]["triage"].update(
                    finding_id="FIND-SYNTH-001",
                    duplicate_of="FIND-SYNTH-003",
                ),
            ),
            "portfolio finding_id",
        ),
        (
            lambda document: document.update(portfolio_id=""),
            "non-empty",
        ),
    ],
)
def test_portfolio_bundle_rejects_ambiguous_identity(mutation, message):
    document = portfolio_document()
    mutation(document)
    with pytest.raises(ValueError, match=message):
        PortfolioBundle.from_dict(document)


def test_portfolio_bundle_requires_typed_cases_and_policy():
    bundle = portfolio_bundle()
    with pytest.raises(ValueError, match="VulnerabilityPolicy"):
        replace(bundle, policy="default")
    with pytest.raises(ValueError, match="VulnerabilityCase"):
        replace(bundle, cases=("case",))


def test_portfolio_parser_rejects_schema_drift():
    document = portfolio_document()
    document["schema_version"] = "vulnevidenceops.portfolio-bundle.v2"
    with pytest.raises(ValueError, match="schema_version must equal"):
        PortfolioBundle.from_dict(document)


def _canonical_target_becomes_duplicate(document: dict) -> None:
    triage = document["cases"][0]["triage"]
    triage.update(
        disposition="duplicate",
        duplicate_of="FIND-SYNTH-003",
        rationale="Synthetic chained deduplication decision.",
    )


@pytest.mark.parametrize(
    ("mutation", "field", "expected", "gap"),
    [
        (
            lambda document: document["cases"][1]["triage"].update(
                decided_at="2026-02-01T00:00:00Z"
            ),
            "decision_currentness",
            "future",
            "deduplication_decision_future:FIND-SYNTH-002",
        ),
        (
            lambda document: document["cases"][1]["triage"].update(
                duplicate_of="FIND-OUTSIDE"
            ),
            "target_state",
            "target_out_of_scope",
            "deduplication_target_out_of_scope:FIND-SYNTH-002",
        ),
        (
            _canonical_target_becomes_duplicate,
            "target_state",
            "target_is_duplicate",
            "deduplication_target_is_duplicate:FIND-SYNTH-002",
        ),
        (
            lambda document: document["cases"][1]["triage"].update(
                evidence_refs=[]
            ),
            "evidence_state",
            "missing",
            "deduplication_evidence_missing:FIND-SYNTH-002",
        ),
        (
            lambda document: document["cases"][1]["triage"].update(
                evidence_refs=["EVD-UNKNOWN"]
            ),
            "evidence_state",
            "unlinked",
            "deduplication_evidence_unlinked:FIND-SYNTH-002",
        ),
        (
            lambda document: document["cases"][1]["evidence_catalog"][1].update(
                collected_at="2026-02-01T00:00:00Z"
            ),
            "evidence_state",
            "future",
            "deduplication_evidence_future:FIND-SYNTH-002",
        ),
    ],
)
def test_deduplication_decisions_preserve_link_and_evidence_gaps(
    mutation, field, expected, gap
):
    document = portfolio_document()
    mutation(document)

    view = assess_portfolio(
        PortfolioBundle.from_dict(document),
        assessed_at=ASSESSMENT_TIME,
    )
    decision = next(
        item
        for item in view.deduplication_decisions
        if item["duplicate_finding_id"] == "FIND-SYNTH-002"
    )

    assert decision[field] == expected
    assert gap in view.gaps
    assert view.totals["portfolio_gap_count"] == len(view.gaps)
    assert view.portfolio_position == "with_gaps"


@pytest.mark.parametrize(
    ("mutation", "field", "expected", "gap"),
    [
        (
            lambda document: document["cases"][2]["risk_acceptance"].update(
                accepted_at="2026-02-01T00:00:00Z",
                expires_at="2026-03-01T00:00:00Z",
            ),
            "exception_state",
            "future",
            "exception_future:FIND-SYNTH-003",
        ),
        (
            lambda document: document["cases"][2]["risk_acceptance"].update(
                expires_at="2026-01-15T00:00:00Z"
            ),
            "exception_state",
            "expired",
            "exception_expired:FIND-SYNTH-003",
        ),
        (
            lambda document: document["cases"][2]["risk_acceptance"].update(
                expires_at="2026-06-12T00:00:00Z"
            ),
            "policy_state",
            "exceeds_policy",
            "exception_exceeds_policy:FIND-SYNTH-003",
        ),
        (
            lambda document: document["cases"][2]["risk_acceptance"].update(
                evidence_refs=[]
            ),
            "evidence_state",
            "missing",
            "exception_evidence_missing:FIND-SYNTH-003",
        ),
        (
            lambda document: document["cases"][2]["risk_acceptance"].update(
                evidence_refs=["EVD-UNKNOWN"]
            ),
            "evidence_state",
            "unlinked",
            "exception_evidence_unlinked:FIND-SYNTH-003",
        ),
        (
            lambda document: document["cases"][2]["evidence_catalog"][2].update(
                collected_at="2026-02-01T00:00:00Z"
            ),
            "evidence_state",
            "future",
            "exception_evidence_future:FIND-SYNTH-003",
        ),
    ],
)
def test_exception_ageing_preserves_time_policy_and_evidence_gaps(
    mutation, field, expected, gap
):
    document = portfolio_document()
    mutation(document)

    view = assess_portfolio(
        PortfolioBundle.from_dict(document),
        assessed_at=ASSESSMENT_TIME,
    )
    exception = view.exception_ageing[0]

    assert exception[field] == expected
    assert gap in view.gaps
    if expected == "future" and field == "exception_state":
        assert exception["age_band"] == "future"
        assert exception["age_days"] is None


@pytest.mark.parametrize(
    ("assessed_at", "expected_band", "expected_age"),
    [
        ("2026-02-12T00:00:00Z", "31_60_days", 31),
        ("2026-03-14T00:00:00Z", "61_90_days", 61),
        ("2026-04-13T00:00:00Z", "91_plus_days", 91),
    ],
)
def test_exception_age_bands_use_explicit_utc_calendar_days(
    assessed_at, expected_band, expected_age
):
    document = portfolio_document()
    document["cases"] = [document["cases"][2]]
    document["cases"][0]["risk_acceptance"]["expires_at"] = "2027-01-12T00:00:00Z"
    document["policy"]["max_risk_acceptance_days"] = 500

    view = assess_portfolio(
        PortfolioBundle.from_dict(document),
        assessed_at=assessed_at,
    )

    assert view.exception_ageing[0]["age_band"] == expected_band
    assert view.exception_ageing[0]["age_days"] == expected_age


@pytest.mark.parametrize(
    ("severity", "assessed_at", "keep_acceptance", "expiry", "expected"),
    [
        ("critical", "2026-01-17T00:00:00Z", False, None, "due_today"),
        ("critical", "2026-01-12T00:00:00Z", False, None, "due_within_7_days"),
        ("medium", "2026-03-20T00:00:00Z", False, None, "due_within_30_days"),
        ("medium", "2026-01-20T00:00:00Z", False, None, "due_later"),
        ("critical", "2026-01-20T00:00:00Z", False, None, "overdue"),
        (
            "critical",
            "2026-01-20T00:00:00Z",
            True,
            "2026-01-15T00:00:00Z",
            "revalidation_required",
        ),
    ],
)
def test_sla_cohorts_are_raw_time_buckets(
    severity, assessed_at, keep_acceptance, expiry, expected
):
    document = portfolio_document()
    case = document["cases"][2]
    document["cases"] = [case]
    case["finding"]["severity"] = severity
    if keep_acceptance:
        case["risk_acceptance"]["expires_at"] = expiry
    else:
        case.pop("risk_acceptance")

    view = assess_portfolio(
        PortfolioBundle.from_dict(document),
        assessed_at=assessed_at,
    )

    assert len(view.sla_cohorts) == 1
    assert view.sla_cohorts[0]["cohort"] == expected
    assert view.sla_cohorts[0]["case_count"] == 1
    if expected in {"overdue", "revalidation_required"}:
        assert view.portfolio_position == "attention_required"


def test_case_without_governance_records_exposes_accountability_gap():
    document = portfolio_document()
    case = document["cases"][2]
    document["cases"] = [case]
    case.pop("triage")
    case.pop("risk_acceptance")

    view = assess_portfolio(
        PortfolioBundle.from_dict(document),
        assessed_at=ASSESSMENT_TIME,
    )

    assert "case_accountability_missing:CASE-SYNTH-ACC-003" in view.gaps
    assert len(view.accountability_view) == 1
    assert view.accountability_view[0]["accountable_role"] == document["accountable_role"]
    assert view.accountability_view[0]["responsibilities"] == ["portfolio_oversight"]


def test_portfolio_assessment_rejects_time_before_any_finding():
    with pytest.raises(ValueError, match="must not precede"):
        assess_portfolio(portfolio_bundle(), assessed_at="2025-12-31T00:00:00Z")


def test_portfolio_view_rejects_weakened_top_level_invariants():
    view = assess_portfolio(portfolio_bundle(), assessed_at=ASSESSMENT_TIME)
    with pytest.raises(ValueError, match="portfolio_position"):
        replace(view, portfolio_position="compliant")
    with pytest.raises(ValueError, match="exact public counter"):
        replace(view, totals={"case_count": 3})
    with pytest.raises(ValueError, match="non-negative"):
        replace(view, totals={**view.totals, "case_count": -1})
    with pytest.raises(ValueError, match="represented records"):
        replace(view, totals={**view.totals, "portfolio_gap_count": 1})
    with pytest.raises(ValueError, match="non_claims"):
        replace(
            view,
            non_claims={
                **view.non_claims,
                "compliance_percentage_established": True,
            },
        )


@pytest.mark.parametrize(
    ("collection", "field", "invalid", "message"),
    [
        ("deduplication_decisions", "decision_currentness", "trusted", "currentness"),
        ("deduplication_decisions", "target_state", "canonical", "target_state"),
        ("deduplication_decisions", "evidence_state", "verified", "evidence_state"),
        ("sla_cohorts", "cohort", "compliant", "cohort"),
        ("exception_ageing", "exception_state", "approved", "exception_state"),
        ("exception_ageing", "age_band", "old", "age_band"),
        ("exception_ageing", "policy_state", "approved", "policy_state"),
        ("exception_ageing", "evidence_state", "verified", "evidence_state"),
    ],
)
def test_portfolio_view_rejects_weakened_nested_enums(
    collection, field, invalid, message
):
    view = assess_portfolio(portfolio_bundle(), assessed_at=ASSESSMENT_TIME)
    records = list(getattr(view, collection))
    records[0] = {**records[0], field: invalid}
    with pytest.raises(ValueError, match=message):
        replace(view, **{collection: tuple(records)})


def test_portfolio_view_requires_valid_identity_time_and_digests():
    view = assess_portfolio(portfolio_bundle(), assessed_at=ASSESSMENT_TIME)
    with pytest.raises(ValueError, match="non-empty"):
        replace(view, scope_ref="")
    with pytest.raises(ValueError, match="timezone"):
        replace(view, assessed_at="2026-01-20")
    with pytest.raises(ValueError, match="SHA-256"):
        replace(view, input_sha256="bad")
    with pytest.raises(ValueError, match="duplicate"):
        replace(view, gaps=("same", "same"))


def test_portfolio_view_rejects_inconsistent_cohort_and_accountability_counts():
    view = assess_portfolio(portfolio_bundle(), assessed_at=ASSESSMENT_TIME)
    cohorts = list(view.sla_cohorts)
    cohorts[0] = {**cohorts[0], "case_count": 2}
    with pytest.raises(ValueError, match="SLA cohort case_count"):
        replace(view, sla_cohorts=tuple(cohorts))

    cohorts = list(view.sla_cohorts)
    cohorts[0] = {**cohorts[0], "finding_ids": []}
    with pytest.raises(ValueError, match="SLA cohort case_count must match finding_ids"):
        replace(view, sla_cohorts=tuple(cohorts))

    with pytest.raises(ValueError, match="cover every represented case"):
        replace(view, sla_cohorts=view.sla_cohorts[:-1])

    accountability = list(view.accountability_view)
    accountability[0] = {**accountability[0], "case_count": 4}
    with pytest.raises(ValueError, match="accountability case_count"):
        replace(view, accountability_view=tuple(accountability))

    accountability = list(view.accountability_view)
    accountability[0] = {**accountability[0], "finding_ids": []}
    with pytest.raises(
        ValueError, match="accountability case_count must match finding_ids"
    ):
        replace(view, accountability_view=tuple(accountability))

    summaries = list(view.case_summaries)
    summaries[1] = {**summaries[1], "case_id": summaries[0]["case_id"]}
    with pytest.raises(ValueError, match="duplicate"):
        replace(view, case_summaries=tuple(summaries))


def test_direct_portfolio_view_type_is_public():
    view = assess_portfolio(portfolio_bundle(), assessed_at=ASSESSMENT_TIME)
    assert isinstance(view, PortfolioAssuranceView)
