from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from vulnevidenceops import (
    BusinessCriticality,
    ExploitIntelligence,
    ExposureContextBundle,
    assess_exposure_context,
    sha256_digest,
)

from .helpers import exposure_bundle, exposure_document

ASSESSMENT_TIME = "2026-01-20T00:00:00Z"


def test_reference_context_is_deterministic_current_and_round_trippable():
    document = exposure_document()
    bundle = ExposureContextBundle.from_dict(document)
    first = assess_exposure_context(
        bundle,
        assessed_at="2026-01-20T01:00:00+01:00",
    )
    second = assess_exposure_context(bundle, assessed_at=ASSESSMENT_TIME)

    assert bundle.to_dict() == document
    assert first.to_dict() == second.to_dict()
    assert first.assessed_at == ASSESSMENT_TIME
    assert first.input_sha256 == sha256_digest(document)
    assert first.context_position == "current"
    assert first.gaps == ()
    assert first.exploit_intelligence[0]["currentness"] == "current"
    assert "known exploited" in first.exploit_intelligence[0]["statement"]
    assert first.business_criticality[0]["currentness"] == "current"
    assert "contract testing" in first.business_criticality[0]["rationale"]
    assert len(first.evidence_inventory) == 2
    assert all(value is False for value in first.non_claims.values())


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda document: document["exploit_intelligence"][0].update(
                asserted_at="2026-02-01T00:00:00Z",
                valid_until="2026-03-01T00:00:00Z",
            ),
            "future",
        ),
        (
            lambda document: document["exploit_intelligence"][0].update(
                valid_until="2026-01-10T00:00:00Z"
            ),
            "expired",
        ),
        (
            lambda document: document["exploit_intelligence"][0].update(
                evidence_refs=[]
            ),
            "evidence_missing",
        ),
        (
            lambda document: document["exploit_intelligence"][0].update(
                evidence_refs=["EVD-UNKNOWN"]
            ),
            "evidence_unlinked",
        ),
        (
            lambda document: document["evidence_catalog"][0].update(
                source_identity="synthetic-intelligence:other"
            ),
            "evidence_source_mismatch",
        ),
        (
            lambda document: document["evidence_catalog"][0].update(
                collected_at="2026-02-01T00:00:00Z"
            ),
            "evidence_future",
        ),
    ],
)
def test_exploit_context_currentness_is_explicit_and_gap_preserving(mutate, expected):
    document = exposure_document()
    mutate(document)

    assessment = assess_exposure_context(
        ExposureContextBundle.from_dict(document),
        assessed_at=ASSESSMENT_TIME,
    )

    assert assessment.exploit_intelligence[0]["currentness"] == expected
    assert assessment.context_position == "partial"
    assert "exploit_intelligence_no_current_record" in assessment.gaps
    assert f"exploit_intelligence_{expected}" in assessment.gaps


def test_empty_partial_and_stale_context_positions_are_distinct():
    empty = exposure_document()
    empty["exploit_intelligence"] = []
    empty["business_criticality"] = []
    unavailable = assess_exposure_context(
        ExposureContextBundle.from_dict(empty), assessed_at=ASSESSMENT_TIME
    )
    assert unavailable.context_position == "unavailable"
    assert unavailable.gaps == (
        "business_criticality_missing",
        "exploit_intelligence_missing",
    )

    one_domain = exposure_document()
    one_domain["business_criticality"] = []
    partial = assess_exposure_context(
        ExposureContextBundle.from_dict(one_domain), assessed_at=ASSESSMENT_TIME
    )
    assert partial.context_position == "partial"

    expired = exposure_document()
    expired["exploit_intelligence"][0]["valid_until"] = "2026-01-10T00:00:00Z"
    expired["business_criticality"][0]["valid_until"] = "2026-01-10T00:00:00Z"
    stale = assess_exposure_context(
        ExposureContextBundle.from_dict(expired), assessed_at=ASSESSMENT_TIME
    )
    assert stale.context_position == "stale"
    assert all(record["currentness"] == "expired" for record in (
        *stale.exploit_intelligence,
        *stale.business_criticality,
    ))


def test_conflicting_current_assertions_are_exposed_without_resolution():
    document = exposure_document()
    exploit = copy.deepcopy(document["exploit_intelligence"][0])
    exploit.update(
        intelligence_id="EXP-SYNTH-002",
        signal="no_exploitation_signal_reported",
        statement="Synthetic source reports no exploitation signal.",
    )
    document["exploit_intelligence"].append(exploit)
    criticality = copy.deepcopy(document["business_criticality"][0])
    criticality.update(
        classification_id="BIZ-SYNTH-002",
        criticality="non_critical",
        rationale="Conflicting synthetic classification for contract testing.",
    )
    document["business_criticality"].append(criticality)

    assessment = assess_exposure_context(
        ExposureContextBundle.from_dict(document), assessed_at=ASSESSMENT_TIME
    )

    assert assessment.context_position == "with_gaps"
    assert "exploit_intelligence_conflict" in assessment.gaps
    assert "business_criticality_conflict" in assessment.gaps


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda document: document["exploit_intelligence"][0].update(
                finding_id="FIND-OTHER"
            ),
            "bundle finding_id",
        ),
        (
            lambda document: document["exploit_intelligence"][0].update(
                technical_identifier="CVE-OTHER"
            ),
            "must exist on the finding",
        ),
        (
            lambda document: document["business_criticality"][0].update(
                asset_ref="synthetic-asset:other"
            ),
            "finding asset_ref",
        ),
        (
            lambda document: document["evidence_catalog"].append(
                copy.deepcopy(document["evidence_catalog"][0])
            ),
            "duplicate",
        ),
        (
            lambda document: document["exploit_intelligence"].append(
                copy.deepcopy(document["exploit_intelligence"][0])
            ),
            "duplicate",
        ),
        (
            lambda document: document["business_criticality"].append(
                copy.deepcopy(document["business_criticality"][0])
            ),
            "duplicate",
        ),
    ],
)
def test_context_bundle_rejects_ambiguous_or_cross_linked_records(mutate, message):
    document = exposure_document()
    mutate(document)
    with pytest.raises(ValueError, match=message):
        ExposureContextBundle.from_dict(document)


def test_context_bundle_requires_a_finding_record():
    bundle = exposure_bundle()
    with pytest.raises(ValueError, match="VulnerabilityFinding"):
        replace(bundle, finding="not-a-finding")


@pytest.mark.parametrize(
    ("record", "changes", "message"),
    [
        (
            "exploit",
            {"signal": "certainly_exploited"},
            "signal",
        ),
        (
            "exploit",
            {"valid_until": "2026-01-05T00:00:00Z"},
            "later than asserted_at",
        ),
        (
            "exploit",
            {"evidence_refs": ("E-1", "E-1")},
            "duplicate",
        ),
        (
            "business",
            {"criticality": "extreme"},
            "criticality",
        ),
        (
            "business",
            {"valid_until": "2026-01-03T00:00:00Z"},
            "later than classified_at",
        ),
        (
            "business",
            {"rationale": ""},
            "non-empty",
        ),
    ],
)
def test_context_records_reject_invalid_invariants(record, changes, message):
    bundle = exposure_bundle()
    original = (
        bundle.exploit_intelligence[0]
        if record == "exploit"
        else bundle.business_criticality[0]
    )
    with pytest.raises(ValueError, match=message):
        replace(original, **changes)


def test_public_record_parsers_reject_schema_drift():
    document = exposure_document()
    exploit = document["exploit_intelligence"][0]
    exploit["schema_version"] = "vulnevidenceops.exploit-intelligence.v2"
    with pytest.raises(ValueError, match="schema_version must equal"):
        ExploitIntelligence.from_dict(exploit)

    business = document["business_criticality"][0]
    business["unexpected"] = True
    with pytest.raises(ValueError, match="unexpected fields"):
        BusinessCriticality.from_dict(business)


def test_assessment_rejects_time_travel_and_weakened_output_invariants():
    bundle = exposure_bundle()
    with pytest.raises(ValueError, match="must not precede"):
        assess_exposure_context(bundle, assessed_at="2025-12-31T23:59:59Z")

    assessment = assess_exposure_context(bundle, assessed_at=ASSESSMENT_TIME)
    with pytest.raises(ValueError, match="context_position"):
        replace(assessment, context_position="ranked")
    with pytest.raises(ValueError, match="currentness"):
        replace(
            assessment,
            exploit_intelligence=(
                {**assessment.exploit_intelligence[0], "currentness": "trusted"},
            ),
        )
    with pytest.raises(ValueError, match="non_claims"):
        replace(
            assessment,
            non_claims={**assessment.non_claims, "risk_score_established": True},
        )
