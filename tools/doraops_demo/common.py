"""Pinned DORAOps consumer schemas and explicit, separately owned governance context."""

from __future__ import annotations

import hashlib
import json

from jsonschema import Draft202012Validator

from tools.datagovops_demo.common import FORMATS, ROOT, DemoRejected, read_json

CONTRACT_PATH = ROOT / "examples/doraops-demo/demo-contract.json"
CONTEXT_PATH = ROOT / "examples/doraops-demo/governance-context.json"
INPUT_SCHEMA_PATH = ROOT / "examples/doraops-demo/risk-remediation-input.schema.json"


def load_contract() -> dict:
    contract = read_json(CONTRACT_PATH)
    if (
        contract.get("schema_version")
        != "vulnevidenceops.doraops-risk-remediation-demo-contract.v1"
    ):
        raise DemoRejected("contract_mismatch", "unsupported DORAOps demo contract")
    return contract


def load_context(contract: dict) -> dict:
    context = read_json(CONTEXT_PATH)
    if (
        hashlib.sha256(CONTEXT_PATH.read_bytes()).hexdigest()
        != contract["governance_context_sha256"]
        or context.get("schema_version") != "vulnevidenceops.doraops-demo-governance-context.v1"
        or context.get("scope") != "local-synthetic-demo"
        or context.get("treatment") != "mitigate"
        or context.get("max_control_credit") != 0
        or context.get("human_judgment_is_synthetic") is not True
        or context.get("incident_classification_performed") is not False
        or context.get("regulatory_applicability_determined") is not False
    ):
        raise DemoRejected("context_mismatch", "pinned consumer governance context differs")
    return context


class Schemas:
    def __init__(self, contract: dict):
        if (
            hashlib.sha256(INPUT_SCHEMA_PATH.read_bytes()).hexdigest()
            != contract["input_schema_sha256"]
        ):
            raise DemoRejected("contract_mismatch", "DORAOps demo input schema differs")
        self.schemas = {"input": read_json(INPUT_SCHEMA_PATH)}
        for name, entry in contract["consumer"]["schemas"].items():
            raw = entry["content"].encode("utf-8")
            blob = hashlib.sha1(
                f"blob {len(raw)}\0".encode("ascii") + raw, usedforsecurity=False
            ).hexdigest()
            if hashlib.sha256(raw).hexdigest() != entry["sha256"] or blob != entry["blob"]:
                raise DemoRejected("contract_mismatch", "exact DORAOps schema snapshot differs")
            self.schemas[name] = json.loads(raw)
        for schema in self.schemas.values():
            Draft202012Validator.check_schema(schema)

    def validate(self, name: str, document: object) -> None:
        validator = Draft202012Validator(self.schemas[name], format_checker=FORMATS)
        if next(validator.iter_errors(document), None) is not None:
            raise DemoRejected(
                "schema_incompatible", f"DORAOps {name} schema rejected the document"
            )
