"""Consume a local dossier through the real DataGovOps v1 registry.

This module deliberately does not import VulnEvidenceOps. Schema/integrity checks
belong to this adapter; evidence registration and matrix evaluation belong to DataGovOps.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from datagovops import (
    ControlDefinition,
    ControlDomain,
    ControlEvidenceReference,
    ControlEvidenceRegistry,
    EvidenceRequirement,
    EvidenceSourceBoundary,
    GovernanceError,
    canonical_json,
)

from .common import (
    DemoRejected,
    Schemas,
    check_runtime,
    digest,
    load_contract,
    read_json,
    timestamp,
    write_json,
)

PACKET_PARTS = ("case", "policy", "materials", "dossier", "handoff")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise DemoRejected(code, message)


def validate_packet(packet: dict, contract: dict, schemas: Schemas, verified_at: str) -> dict:
    _require(set(packet) == set(PACKET_PARTS), "invalid_packet", "unexpected packet parts")
    case, policy, materials, dossier, handoff = (packet[key] for key in PACKET_PARTS)
    for name, value in (
        ("integration-handoff", handoff),
        ("case-bundle", case),
        ("vulnerability-policy", policy),
    ):
        schemas.validate("producer", name, value)
    _require(
        digest(dossier) == handoff["payload_sha256"],
        "payload_digest_mismatch",
        "dossier content differs from the handoff digest",
    )
    schemas.validate("producer", "assurance-dossier", dossier)
    consumer = contract["consumer"]
    peer = consumer["schemas"]["control-evidence-reference"]
    expected_peer = {
        "schema_version": "vulnevidenceops.peer-contract-identity.v1",
        "system": "datagovops",
        "contract_role": "consumer",
        "repository": consumer["repository"],
        "commit": consumer["commit"],
        "tree": consumer["tree"],
        "path": peer["source_path"],
        "blob": peer["blob"],
    }
    expected_binding = {
        "profile": "datagovops-control-evidence",
        "producer_system": "vulnevidenceops",
        "consumer_system": "datagovops",
        "relationship": "control_evidence",
        "payload_type": "application/vnd.vulnevidenceops.assurance-dossier.v1+json",
        "peer_contract": expected_peer,
    }
    _require(
        all(handoff[key] == value for key, value in expected_binding.items()),
        "profile_mismatch",
        "handoff does not target the pinned DataGovOps contract",
    )
    _require(
        handoff["synthetic"] is True, "non_synthetic_input", "demo only accepts synthetic input"
    )
    _require(
        handoff["subject_ref"] == dossier["case_id"] == case["case_id"]
        and dossier["finding_id"] == case["finding"]["finding_id"],
        "subject_mismatch",
        "case, finding and handoff subjects differ",
    )
    _require(
        dossier["input_sha256"] == digest(case) and dossier["policy_sha256"] == digest(policy),
        "snapshot_digest_mismatch",
        "case or policy snapshot differs from the dossier",
    )
    observed = timestamp(dossier["assessed_at"])
    created = timestamp(handoff["created_at"])
    verified = timestamp(verified_at)
    _require(handoff["valid_until"] is not None, "handoff_not_current", "explicit expiry required")
    expiry = timestamp(handoff["valid_until"])
    _require(
        observed <= created <= verified < expiry,
        "handoff_not_current",
        "dossier/handoff is future, expired or temporally inconsistent",
    )

    catalog = case["evidence_catalog"]
    identifiers = [item["evidence_id"] for item in catalog]
    _require(
        bool(catalog) and len(identifiers) == len(set(identifiers)),
        "evidence_link_mismatch",
        "evidence catalog must be nonempty and unique",
    )
    _require(
        isinstance(materials, dict) and set(materials) == set(identifiers),
        "evidence_link_mismatch",
        "every catalog entry needs one local synthetic material",
    )
    for item in catalog:
        material = materials[item["evidence_id"]]
        _require(
            item["synthetic"] is True
            and isinstance(material, dict)
            and material.get("synthetic") is True
            and item["artifact_ref"].startswith("synthetic://"),
            "non_synthetic_input",
            "non-synthetic material is outside the demo boundary",
        )
        _require(
            digest(material) == item["artifact_sha256"],
            "material_digest_mismatch",
            "local synthetic material differs from its evidence reference",
        )
        _require(
            material.get("finding_id") == dossier["finding_id"],
            "subject_mismatch",
            "material references another finding",
        )
        _require(
            timestamp(item["collected_at"]) <= observed,
            "evidence_not_current",
            "evidence collection postdates the dossier assessment",
        )
    inventory_keys = (
        "evidence_id",
        "artifact_ref",
        "artifact_sha256",
        "collected_at",
        "source_identity",
        "synthetic",
    )
    expected_inventory = sorted(
        ({key: item[key] for key in inventory_keys} for item in catalog),
        key=lambda item: item["evidence_id"],
    )
    _require(
        sorted(dossier["evidence_inventory"], key=lambda item: item["evidence_id"])
        == expected_inventory,
        "evidence_link_mismatch",
        "dossier inventory differs from case",
    )
    for name in ("triage", "remediation", "risk_acceptance", "verification"):
        if name in case:
            _require(
                case[name]["finding_id"] == dossier["finding_id"],
                "subject_mismatch",
                "case record references another finding",
            )
    rows = dossier["control_evidence"]
    row_ids = [row["control_id"] for row in rows]
    _require(
        len(row_ids) == len(set(row_ids)) and set(row_ids) == set(contract["controls"]),
        "control_mapping_mismatch",
        "expected exactly the six explicit VEO control rows",
    )
    for row in rows:
        _require(
            set(row["evidence_refs"]).issubset(identifiers)
            and (row["status"] != "represented" or bool(row["evidence_refs"])),
            "evidence_link_mismatch",
            "represented control requires linked evidence",
        )
    _require(
        any(row["status"] != "not_applicable" for row in rows),
        "control_mapping_mismatch",
        "at least one applicable control is required",
    )
    return {
        "schema_version": "vulnevidenceops.datagovops-demo-validation.v1",
        "scope": "local-synthetic-demo",
        "verified_at": verified_at,
        "dossier_sha256": digest(dossier),
        "handoff_sha256": digest(handoff),
        "case_sha256": digest(case),
        "policy_sha256": digest(policy),
        "materials_sha256": digest(materials),
        "demo_contract_sha256": digest(contract),
        "producer_schema_set_sha256": contract["producer"]["schema_set_sha256"],
        "consumer_schema_sha256": peer["sha256"],
        "payload_schema_valid": True,
        "payload_digest_valid": True,
        "snapshot_binding_valid": True,
        "local_material_digests_valid": True,
        "handoff_current": True,
        "non_claims": {
            "producer_authority_established": False,
            "producer_assurance_semantics_verified": False,
            "source_observation_truth_established": False,
            "production_interoperability_established": False,
        },
    }


def _document(value):
    return json.loads(canonical_json(value))


def consume(packet: dict, *, verified_at: str | None = None, installed_wheel: bool = False) -> dict:
    contract = load_contract()
    runtime = check_runtime(contract["consumer"], installed_wheel=installed_wheel)
    schemas = Schemas(contract)
    verified_at = verified_at or contract["verified_at"]
    validation = validate_packet(packet, contract, schemas, verified_at)
    dossier, handoff = packet["dossier"], packet["handoff"]
    observed = timestamp(dossier["assessed_at"])
    expiry = timestamp(handoff["valid_until"])
    verified = timestamp(verified_at)
    rows = sorted(dossier["control_evidence"], key=lambda item: item["control_id"])
    included = [row for row in rows if row["status"] != "not_applicable"]
    registry = ControlEvidenceRegistry()
    definitions, references = [], []
    try:
        for row in included:
            evidence_type = contract["controls"][row["control_id"]]
            definition = ControlDefinition(
                institution_id=contract["institution_id"],
                control_id=row["control_id"],
                control_version=1,
                title="Synthetic dossier metadata: " + row["control_id"],
                domain=ControlDomain.PRIVACY_SECURITY,
                owner_id="synthetic-vulnerability-owner",
                objective="Index current dossier metadata; do not infer control effectiveness.",
                evidence_requirements=(
                    EvidenceRequirement(
                        evidence_type,
                        (EvidenceSourceBoundary.GOVERNANCE_DOSSIER,),
                    ),
                ),
                framework_references=(),
                registered_at=observed,
            )
            schemas.validate("consumer", "control-definition", _document(definition))
            registry.register_control(definition)
            definitions.append(definition)
            if row["status"] == "represented":
                reference = ControlEvidenceReference(
                    institution_id=contract["institution_id"],
                    evidence_id=handoff["handoff_id"] + "/" + row["control_id"],
                    control_digest=definition.artifact_digest,
                    evidence_type=evidence_type,
                    source_boundary=EvidenceSourceBoundary.GOVERNANCE_DOSSIER,
                    artifact_type=dossier["schema_version"],
                    source_artifact_digest=digest(dossier),
                    source_snapshot_digest=digest(packet["case"]),
                    observed_at=observed,
                    # Handoff expiry is exclusive; DataGovOps' deadline is inclusive.
                    revalidate_after=expiry - 1,
                    verifier_id=contract["verifier_id"],
                    verification_evidence_digest=digest(validation),
                )
                schemas.validate("consumer", "control-evidence-reference", _document(reference))
                references.append(reference)
        matrix_args = {
            "institution_id": contract["institution_id"],
            "matrix_id": "synthetic-vulnerability-demo",
            "matrix_version": 1,
            "control_ids": tuple(item.control_id for item in definitions),
        }
        before = registry.build_matrix(**matrix_args, assessed_at=verified)
        registered = [registry.register_evidence(item) for item in references]
        assessments = [
            registry.assess_control(
                contract["institution_id"], item.control_id, assessed_at=verified
            )
            for item in definitions
        ]
        after = registry.build_matrix(**matrix_args, assessed_at=verified)
        stale = registry.build_matrix(**matrix_args, assessed_at=expiry)
        for assessment in assessments:
            schemas.validate("consumer", "control-assessment", _document(assessment))
        for matrix in (before, after, stale):
            schemas.validate("consumer", "control-evidence-matrix", _document(matrix))
    except GovernanceError as exc:
        raise DemoRejected(
            "datagovops_rejected", "DataGovOps rejected the evidence registration"
        ) from exc
    receipt = {
        "schema_version": "vulnevidenceops.datagovops-demo-receipt.v1",
        "scope": "local-synthetic-demo",
        "accepted": True,
        "consumer_backend": "datagovops.ControlEvidenceRegistry",
        "runtime": runtime,
        "consumer_source_commit": contract["consumer"]["commit"],
        "demo_contract_sha256": digest(contract),
        "dossier_sha256": digest(dossier),
        "handoff_sha256": digest(handoff),
        "validation_report_sha256": digest(validation),
        "registered_evidence_digests": registered,
        "excluded_controls": [row for row in rows if row["status"] == "not_applicable"],
        "matrix_before_digest": before.artifact_digest,
        "matrix_after_digest": after.artifact_digest,
        "matrix_at_expiry_digest": stale.artifact_digest,
        "requires_human_review": True,
        "non_claims": {
            "independent_review_completed": False,
            "control_effectiveness_determined": False,
            "legal_compliance_determined": False,
            "regulatory_compliance_determined": False,
            "remote_delivery_established": False,
            "production_interoperability_established": False,
            "source_observation_truth_established": False,
        },
    }
    return {
        "validation-report.json": validation,
        "control-definitions.json": [_document(item) for item in definitions],
        "evidence-references.json": [_document(item) for item in references],
        "control-assessments.json": [_document(item) for item in assessments],
        "matrix-before.json": _document(before),
        "matrix-after.json": _document(after),
        "matrix-at-expiry.json": _document(stale),
        "receipt.json": receipt,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--as-of")
    parser.add_argument("--installed-wheel", action="store_true")
    args = parser.parse_args(argv)
    try:
        _require(
            not args.output_dir.exists(), "output_exists", "refusing to overwrite prior evidence"
        )
        packet = {key: read_json(args.packet_dir / (key + ".json")) for key in PACKET_PARTS}
        result = consume(packet, verified_at=args.as_of, installed_wheel=args.installed_wheel)
        # No files/accepted receipt are written until every adapter and DataGovOps check succeeds.
        for name, value in result.items():
            write_json(args.output_dir / name, value)
        print(json.dumps({"accepted": True, "matrix_state": result["matrix-after.json"]["state"]}))
        return 0
    except (DemoRejected, OSError) as exc:
        print(
            json.dumps(
                {
                    "accepted": False,
                    "error_code": getattr(exc, "code", "io_error"),
                    "message": str(exc),
                }
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
