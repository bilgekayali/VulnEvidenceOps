from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace

import pytest

from vulnevidenceops import (
    IntakeBatch,
    adapt_cyclonedx,
    adapt_sarif,
    sha256_digest,
)

from .helpers import ROOT


def _artifact(name: str) -> tuple[dict, str]:
    raw = (ROOT / "examples" / name).read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def _common(name: str) -> dict:
    _, artifact_sha256 = _artifact(name)
    return {
        "artifact_ref": f"synthetic://intake/{name}",
        "artifact_sha256": artifact_sha256,
        "collected_at": "2026-01-05T01:00:00+01:00",
        "observed_at": "2026-01-04T03:00:00+03:00",
        "source_identity": "synthetic-source:reference-v1",
        "source_ref": "synthetic-source:export-001",
        "synthetic": True,
    }


def _sarif_batch(document: dict | None = None) -> IntakeBatch:
    source, _ = _artifact("synthetic-sarif.json")
    return adapt_sarif(
        document if document is not None else source,
        asset_ref="synthetic-asset:repository-001",
        **_common("synthetic-sarif.json"),
    )


def _cyclonedx_batch(document: dict | None = None) -> IntakeBatch:
    source, _ = _artifact("synthetic-cyclonedx.json")
    return adapt_cyclonedx(
        document if document is not None else source,
        asset_ref_prefix="synthetic-component:",
        **_common("synthetic-cyclonedx.json"),
    )


def test_sarif_adapter_is_deterministic_traceable_and_round_trippable():
    source, artifact_sha256 = _artifact("synthetic-sarif.json")
    first = _sarif_batch(source)
    second = _sarif_batch(copy.deepcopy(source))

    assert first.to_dict() == second.to_dict()
    assert IntakeBatch.from_dict(first.to_dict()).to_dict() == first.to_dict()
    assert first.adapter_id == "sarif-2.1.0"
    assert first.observed_at == "2026-01-04T00:00:00Z"
    assert first.source_artifact.artifact_sha256 == artifact_sha256
    assert first.source_artifact.media_type == "application/sarif+json"
    assert first.source_document_sha256 == sha256_digest(source)
    assert len(first.findings) == len(first.mappings) == 2
    assert {item.severity for item in first.findings} == {"high", "medium"}
    assert {item.technical_identifiers for item in first.findings} == {
        ("SYNTH-RULE-001",),
        ("SYNTH-RULE-002",),
    }
    assert {item.source_record_refs for item in first.mappings} == {
        ("/runs/0/results/0",),
        ("/runs/0/results/1",),
    }
    assert any("sarif_rule_default_level_used" in item.notices for item in first.mappings)
    assert all(not value for value in first.non_claims.values())


def test_cyclonedx_adapter_preserves_every_vulnerability_affect_pair():
    batch = _cyclonedx_batch()

    assert batch.adapter_id == "cyclonedx-1.6"
    assert batch.source_artifact.media_type == "application/vnd.cyclonedx+json"
    assert len(batch.findings) == len(batch.mappings) == 3
    assert {item.asset_ref for item in batch.findings} == {
        "synthetic-component:pkg:pypi/synthetic-a@1.0.0",
        "synthetic-component:pkg:pypi/synthetic-b@2.0.0",
    }
    assert sum(item.severity == "critical" for item in batch.findings) == 2
    informational = [item for item in batch.findings if item.severity == "informational"]
    assert len(informational) == 1
    assert any(
        "cyclonedx_severity_unmapped_defaulted_to_informational" in item.notices
        for item in batch.mappings
    )
    assert any(
        item.technical_identifiers == ("CVE-2099-0002", "CWE-79")
        for item in batch.findings
    )
    assert all(len(item.source_record_refs) == 2 for item in batch.mappings)


def test_repeated_source_records_are_not_silently_deduplicated():
    source, _ = _artifact("synthetic-cyclonedx.json")
    source["vulnerabilities"] = [copy.deepcopy(source["vulnerabilities"][0])]
    source["vulnerabilities"][0]["affects"].append(
        copy.deepcopy(source["vulnerabilities"][0]["affects"][0])
    )

    batch = _cyclonedx_batch(source)

    assert len(batch.findings) == len(batch.mappings) == 3
    assert len({item.finding_id for item in batch.findings}) == 3


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(version="2.2.0"), "SARIF version"),
        (
            lambda value: value["runs"][0]["results"][0].pop("message"),
            "message must be a JSON object",
        ),
        (lambda value: value["runs"][0].update(results=[]), "no mappable"),
    ],
)
def test_sarif_adapter_fails_closed_for_unsupported_or_incomplete_records(
    mutation, message
):
    source, _ = _artifact("synthetic-sarif.json")
    mutation(source)
    with pytest.raises(ValueError, match=message):
        _sarif_batch(source)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(specVersion="1.4"), "specVersion"),
        (
            lambda value: value["vulnerabilities"][0].pop("affects"),
            "affects must be a non-empty JSON array",
        ),
        (
            lambda value: value["vulnerabilities"][0].update(cwes=[0]),
            "positive integer",
        ),
    ],
)
def test_cyclonedx_adapter_fails_closed_for_unsupported_or_incomplete_records(
    mutation, message
):
    source, _ = _artifact("synthetic-cyclonedx.json")
    mutation(source)
    with pytest.raises(ValueError, match=message):
        _cyclonedx_batch(source)


def test_intake_batch_rejects_weakened_non_claims_and_mapping_drift():
    document = _sarif_batch().to_dict()
    document["non_claims"]["scanner_accuracy_established"] = True
    with pytest.raises(ValueError, match="non_claims"):
        IntakeBatch.from_dict(document)

    document = _sarif_batch().to_dict()
    document["mappings"][0]["finding_id"] = "FIND-UNKNOWN"
    with pytest.raises(ValueError, match="cover every finding"):
        IntakeBatch.from_dict(document)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("source_record_refs", (), "must not be empty"),
        ("mapped_fields", (), "must not be empty"),
        ("source_record_sha256", "bad", "SHA-256"),
        ("notices", ("same", "same"), "duplicate"),
    ],
)
def test_intake_mapping_rejects_invalid_provenance(field, value, message):
    mapping = _sarif_batch().mappings[0]
    with pytest.raises(ValueError, match=message):
        replace(mapping, **{field: value})


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["adapter"].update(
                source_format="unknown", source_format_version="1"
            ),
            "unsupported intake format",
        ),
        (lambda value: value["adapter"].update(adapter_id="sarif-9"), "adapter_id"),
        (lambda value: value["adapter"].update(adapter_version="intake.v2"), "adapter_version"),
        (lambda value: value.update(findings=[]), "must not be empty"),
        (lambda value: value["mappings"].pop(), "exactly one mapping"),
        (
            lambda value: value["findings"][0].update(
                first_observed_at="2026-02-01T00:00:00Z"
            ),
            "batch observed_at",
        ),
        (
            lambda value: value["findings"][0].update(evidence_refs=["EVD-OTHER"]),
            "source artifact evidence",
        ),
    ],
)
def test_intake_batch_rejects_contract_drift(mutation, message):
    document = _sarif_batch().to_dict()
    mutation(document)
    with pytest.raises(ValueError, match=message):
        IntakeBatch.from_dict(document)


def test_adapter_context_requires_boolean_synthetic_flag():
    source, _ = _artifact("synthetic-sarif.json")
    common = _common("synthetic-sarif.json")
    common["synthetic"] = "yes"
    with pytest.raises(ValueError, match="synthetic must be a boolean"):
        adapt_sarif(source, asset_ref="synthetic-asset:repository-001", **common)


def test_sarif_supports_nested_rule_identity_and_explicit_severity_fallbacks():
    source, _ = _artifact("synthetic-sarif.json")
    result = source["runs"][0]["results"][0]
    result["rule"] = {"id": result.pop("ruleId")}
    result.pop("level")
    source["runs"][0]["tool"]["driver"]["rules"][0].pop("defaultConfiguration")
    batch = _sarif_batch(source)
    mapped = [item for item in batch.findings if item.technical_identifiers == ("SYNTH-RULE-001",)]
    assert mapped[0].severity == "informational"
    assert any(
        "sarif_level_missing_defaulted_to_informational" in item.notices
        for item in batch.mappings
    )

    source, _ = _artifact("synthetic-sarif.json")
    source["runs"][0]["results"][0]["level"] = "vendor-priority"
    batch = _sarif_batch(source)
    assert any(
        "sarif_level_unmapped_defaulted_to_informational" in item.notices
        for item in batch.mappings
    )


def test_sarif_rejects_ambiguous_rules_and_empty_messages():
    source, _ = _artifact("synthetic-sarif.json")
    source["runs"][0]["tool"]["driver"]["rules"].append(
        copy.deepcopy(source["runs"][0]["tool"]["driver"]["rules"][0])
    )
    with pytest.raises(ValueError, match="duplicate SARIF rule"):
        _sarif_batch(source)

    source, _ = _artifact("synthetic-sarif.json")
    source["runs"][0]["results"][0]["message"] = {}
    with pytest.raises(ValueError, match="must contain text or markdown"):
        _sarif_batch(source)


def test_cyclonedx_supports_v15_and_records_missing_rating_or_title_fallbacks():
    source, _ = _artifact("synthetic-cyclonedx.json")
    source["specVersion"] = "1.5"
    candidate = source["vulnerabilities"][1]
    candidate["ratings"] = [{}]
    candidate.pop("detail")
    batch = _cyclonedx_batch(source)

    assert batch.adapter_id == "cyclonedx-1.5"
    fallback = [
        item
        for item in batch.findings
        if item.technical_identifiers == ("SYNTH-ADVISORY-0001",)
    ]
    assert fallback[0].title == "SYNTH-ADVISORY-0001"
    assert any(
        "cyclonedx_rating_without_severity_ignored" in item.notices
        for item in batch.mappings
    )


def test_cyclonedx_rejects_the_wrong_bom_format():
    source, _ = _artifact("synthetic-cyclonedx.json")
    source["bomFormat"] = "Other"
    with pytest.raises(ValueError, match="bomFormat"):
        _cyclonedx_batch(source)
