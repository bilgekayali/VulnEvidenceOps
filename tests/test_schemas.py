from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from vulnevidenceops import (
    DocumentValidationError,
    adapt_cyclonedx,
    adapt_sarif,
    assess_case,
    assess_exposure_context,
    assess_portfolio,
    validate_document,
)

from .helpers import (
    ROOT,
    case,
    case_document,
    exposure_bundle,
    exposure_document,
    policy,
    policy_document,
    portfolio_bundle,
    portfolio_document,
)


def test_every_public_schema_is_draft_2020_12_and_well_formed():
    schemas = sorted((ROOT / "schemas").glob("*.schema.json"))
    assert len(schemas) == 18
    for path in schemas:
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        Draft202012Validator.check_schema(schema)


def test_examples_matrix_and_generated_dossier_validate():
    validate_document(ROOT / "schemas" / "case-bundle.schema.json", case_document())
    validate_document(ROOT / "schemas" / "vulnerability-policy.schema.json", policy_document())
    matrix = json.loads(
        (ROOT / "configs" / "control-evidence-matrix.json").read_text(encoding="utf-8")
    )
    validate_document(ROOT / "schemas" / "control-evidence-matrix.schema.json", matrix)

    dossier = assess_case(case(), policy=policy(), assessed_at="2026-01-20T00:00:00Z")
    validate_document(ROOT / "schemas" / "assurance-dossier.schema.json", dossier.to_dict())


def test_schema_validation_reports_stable_paths_and_formats():
    document = case_document()
    document["finding"]["first_observed_at"] = "not-a-time"
    document["unexpected"] = True

    with pytest.raises(DocumentValidationError) as captured:
        validate_document(ROOT / "schemas" / "case-bundle.schema.json", document)

    message = str(captured.value)
    assert "unexpected" in message
    assert "finding/first_observed_at" in message


def test_generated_intake_batches_validate_against_the_public_schema():
    import hashlib

    sarif_path = ROOT / "examples" / "synthetic-sarif.json"
    cyclonedx_path = ROOT / "examples" / "synthetic-cyclonedx.json"
    common = {
        "collected_at": "2026-01-05T00:00:00Z",
        "observed_at": "2026-01-04T00:00:00Z",
        "source_identity": "synthetic-source:reference-v1",
        "source_ref": "synthetic-source:export-001",
        "synthetic": True,
    }
    sarif_raw = sarif_path.read_bytes()
    sarif = adapt_sarif(
        json.loads(sarif_raw),
        artifact_ref="synthetic://intake/sarif.json",
        artifact_sha256=hashlib.sha256(sarif_raw).hexdigest(),
        asset_ref="synthetic-asset:repository-001",
        **common,
    )
    cyclonedx_raw = cyclonedx_path.read_bytes()
    cyclonedx = adapt_cyclonedx(
        json.loads(cyclonedx_raw),
        artifact_ref="synthetic://intake/cyclonedx.json",
        artifact_sha256=hashlib.sha256(cyclonedx_raw).hexdigest(),
        asset_ref_prefix="synthetic-component:",
        **common,
    )
    schema = ROOT / "schemas" / "intake-batch.schema.json"
    validate_document(schema, sarif.to_dict())
    validate_document(schema, cyclonedx.to_dict())


def test_exposure_example_and_generated_assessment_validate():
    document = exposure_document()
    validate_document(
        ROOT / "schemas" / "exposure-context-bundle.schema.json",
        document,
    )
    validate_document(
        ROOT / "schemas" / "exploit-intelligence.schema.json",
        document["exploit_intelligence"][0],
    )
    validate_document(
        ROOT / "schemas" / "business-criticality.schema.json",
        document["business_criticality"][0],
    )
    assessment = assess_exposure_context(
        exposure_bundle(),
        assessed_at="2026-01-20T00:00:00Z",
    )
    validate_document(
        ROOT / "schemas" / "exposure-context-assessment.schema.json",
        assessment.to_dict(),
    )


def test_portfolio_example_and_generated_view_validate():
    document = portfolio_document()
    validate_document(
        ROOT / "schemas" / "portfolio-bundle.schema.json",
        document,
    )
    view = assess_portfolio(
        portfolio_bundle(),
        assessed_at="2026-01-20T00:00:00Z",
    )
    validate_document(
        ROOT / "schemas" / "portfolio-assurance-view.schema.json",
        view.to_dict(),
    )
