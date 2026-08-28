from __future__ import annotations

import json

import pytest

from tools import stable_candidate


def test_frozen_v1_baseline_matches_repository():
    assert stable_candidate.verify() == stable_candidate.compute_baseline()


def test_final_stable_promotion_accepts_explicit_owner_waiver():
    assert stable_candidate.verify(require_final_review=True)


def test_baseline_detects_schema_drift(monkeypatch):
    baseline = stable_candidate.compute_baseline()
    baseline["schemas"][0]["sha256"] = "0" * 64
    monkeypatch.setattr(stable_candidate, "_json", lambda path: baseline)
    with pytest.raises(SystemExit, match="baseline drifted"):
        stable_candidate.verify()


def test_completed_review_requires_identity_and_evidence(monkeypatch):
    baseline = stable_candidate.compute_baseline()
    review = {
        "schema_version": "vulnevidenceops.independent-review.v1",
        "review_completed": True,
        "reviewer": None,
        "evidence_refs": [],
        "requirement_status": "required",
        "waiver": None,
    }
    evidence = json.loads(stable_candidate.EVIDENCE.read_text(encoding="utf-8"))

    def fake_json(path):
        if path == stable_candidate.BASELINE:
            return baseline
        if path == stable_candidate.REVIEW:
            return review
        return evidence

    monkeypatch.setattr(stable_candidate, "_json", fake_json)
    with pytest.raises(SystemExit, match="identified reviewer"):
        stable_candidate.verify()


def test_unwaived_pending_review_blocks_final_promotion(monkeypatch):
    baseline = stable_candidate.compute_baseline()
    review = {
        "schema_version": "vulnevidenceops.independent-review.v1",
        "review_completed": False,
        "reviewer": None,
        "evidence_refs": [],
        "requirement_status": "required",
        "waiver": None,
    }
    evidence = json.loads(stable_candidate.EVIDENCE.read_text(encoding="utf-8"))
    evidence["independent_review_requirement"] = "required"

    def fake_json(path):
        if path == stable_candidate.BASELINE:
            return baseline
        if path == stable_candidate.REVIEW:
            return review
        return evidence

    monkeypatch.setattr(stable_candidate, "_json", fake_json)
    with pytest.raises(SystemExit, match="independent human review pending"):
        stable_candidate.verify(require_final_review=True)
