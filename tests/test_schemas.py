from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from vulnevidenceops import DocumentValidationError, assess_case, validate_document

from .helpers import ROOT, case, case_document, policy, policy_document


def test_every_public_schema_is_draft_2020_12_and_well_formed():
    schemas = sorted((ROOT / "schemas").glob("*.schema.json"))
    assert len(schemas) == 10
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
