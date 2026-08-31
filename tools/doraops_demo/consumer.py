"""Consume synthetic evidence through real DORAOps risk and resilience APIs.

No producer runtime import, scanner execution, incident classification, operational
deployment-control substitution, real risk approval, or production trust assertion.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from doraops import (
    BusinessFunction,
    DependencyEdge,
    DependencyRelationship,
    FinancialEntity,
    FindingSeverity,
    FunctionClassification,
    GovernanceError,
    ICTAsset,
    ICTRiskPolicy,
    ICTRiskScenario,
    ICTService,
    Impact,
    InventoryRegistry,
    Likelihood,
    NodeKind,
    NodeRef,
    ResilienceTestType,
    RetestOutcome,
    RiskTreatmentPlan,
    TestExecutionOutcome,
    TreatmentType,
    assert_risk_decision_current,
    assess_ict_risk,
    build_resilience_test_plan,
    canonical_json,
    create_finding,
    create_remediation,
    create_retest,
    record_test_execution,
    resolve_test,
)

from tools.datagovops_demo.common import (
    DemoRejected,
    check_runtime,
    digest,
    read_json,
    timestamp,
    write_json,
)
from tools.datagovops_demo.consumer import consume as consume_datagovops

from .common import Schemas, load_context, load_contract
from .signatures import verify_packet_signature


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise DemoRejected(code, message)


def _document(value):
    return json.loads(canonical_json(value))


def validate_packet(
    packet: dict,
    contract: dict,
    context: dict,
    schemas: Schemas,
    verified_at: str,
    installed_wheel: bool,
) -> dict:
    _require(
        isinstance(packet, dict) and "signed_envelope" in packet,
        "doraops_signature_required",
        "a separate DORAOps signature is required; upstream signing cannot substitute",
    )
    schemas.validate("input", packet)
    handoff = packet["handoff"]
    _require(
        handoff["profile"] == contract["profile"]
        and handoff["boundary"] == contract["boundary"]
        and handoff["consumer_commit"] == contract["consumer"]["commit"]
        and handoff["consumer_tree"] == contract["consumer"]["tree"]
        and handoff["demo_contract_sha256"] == digest(contract)
        and handoff["governance_context_sha256"] == contract["governance_context_sha256"],
        "boundary_mismatch",
        "handoff is not the pinned risk/remediation consumer contract",
    )
    for name in ("source_packet", "datagovops_receipt", "change_completion"):
        _require(
            digest(packet[name]) == handoff[name + "_sha256"],
            "input_digest_mismatch",
            "handoff does not bind the supplied input bytes",
        )
    verified = timestamp(verified_at)
    _require(
        handoff["created_at"] == contract["created_at"]
        and handoff["valid_until"] == contract["valid_until"]
        and timestamp(handoff["created_at"]) <= verified < timestamp(handoff["valid_until"]),
        "handoff_not_current",
        "risk/remediation handoff is future, expired or retimed",
    )
    # A supplied accepted:true receipt is not trusted. Repeat actual DataGovOps consumption
    # at the recorded fixture time and compare the complete independently generated receipt.
    upstream = consume_datagovops(packet["source_packet"], installed_wheel=installed_wheel)
    _require(
        upstream["receipt.json"] == packet["datagovops_receipt"],
        "upstream_receipt_mismatch",
        "supplied receipt differs from actual DataGovOps consumption",
    )
    # Also re-evaluate currentness/signatures at the DORAOps consumption time.
    _require(
        timestamp(upstream["validation-report.json"]["verified_at"])
        <= timestamp(handoff["created_at"]),
        "upstream_receipt_future",
        "handoff cannot predate the DataGovOps receipt",
    )
    if verified_at != upstream["validation-report.json"]["verified_at"]:
        consume_datagovops(
            packet["source_packet"], verified_at=verified_at, installed_wheel=installed_wheel
        )
    source = packet["source_packet"]
    case, finding = source["case"], source["case"]["finding"]
    _require(
        handoff["case_id"] == case["case_id"]
        and handoff["finding_id"] == finding["finding_id"]
        and handoff["source_asset_ref"] == finding["asset_ref"],
        "subject_mismatch",
        "source case/finding/asset identity differs",
    )
    _require(
        finding["asset_ref"] in context["asset_mapping"]
        and handoff["target_node"] == context["asset_mapping"][finding["asset_ref"]],
        "asset_mapping_mismatch",
        "source asset has no exact consumer-owned inventory mapping",
    )
    _require(
        "remediation" in case
        and "triage" in case
        and case["triage"]["disposition"] == "confirmed"
        and "risk_acceptance" not in case,
        "unsupported_treatment",
        "demo requires confirmed mitigation; it does not approve risk acceptance",
    )
    remediation, completion = case["remediation"], packet["change_completion"]
    _require(
        completion["finding_id"] == finding["finding_id"]
        and completion["remediation_id"] == remediation["remediation_id"]
        and completion["change_ref"] == remediation["change_ref"]
        and completion["owner_role"] == remediation["owner_role"]
        and completion["evidence_id"]
        not in {item["evidence_id"] for item in case["evidence_catalog"]},
        "completion_binding_mismatch",
        "additional completion does not bind this remediation plan",
    )
    _require(
        timestamp(remediation["planned_at"])
        <= timestamp(completion["completed_at"])
        <= timestamp(completion["collected_at"])
        <= timestamp(handoff["created_at"]),
        "completion_not_current",
        "completion is future or predates its plan",
    )
    _require(
        context["independent_reviewer_id"] != remediation["owner_role"]
        and remediation["owner_role"].startswith("synthetic-")
        and (
            "verification" not in case
            or case["verification"]["verifier_role"].startswith("synthetic-")
        ),
        "reviewer_not_independent",
        "demo roles must remain synthetic and separate",
    )
    catalog = {item["evidence_id"]: item for item in case["evidence_catalog"]}
    stages = [(finding, "observation", "first_observed_at"), (remediation, "change", "planned_at")]
    if "verification" in case:
        stages.append((case["verification"], "retest", "performed_at"))
    for record, kind, time_field in stages:
        _require(
            bool(record["evidence_refs"]) and set(record["evidence_refs"]).issubset(catalog),
            "stage_evidence_mismatch",
            "each risk/remediation stage requires linked evidence",
        )
        _require(
            timestamp(record[time_field]) <= timestamp(source["dossier"]["assessed_at"]),
            "stage_evidence_not_current",
            "stage event postdates the source dossier assessment",
        )
        for ref in record["evidence_refs"]:
            material = source["materials"][ref]
            _require(
                material.get("kind") == kind
                and timestamp(record[time_field]) <= timestamp(catalog[ref]["collected_at"]),
                "stage_evidence_mismatch",
                "stage kind or event/collection ordering differs",
            )
            if kind == "observation":
                _require(
                    material.get("asset_ref") == finding["asset_ref"],
                    "stage_evidence_mismatch",
                    "observation names another asset",
                )
            elif kind == "change":
                _require(
                    material.get("change_ref") == remediation["change_ref"],
                    "stage_evidence_mismatch",
                    "change material names another change",
                )
            else:
                expected = {
                    "effective": "expected-synthetic-result-observed",
                    "ineffective": "synthetic-finding-persists",
                    "partial": "synthetic-retest-partial",
                }[record["outcome"]]
                _require(
                    material.get("verifier_role") == record["verifier_role"]
                    and material.get("result") == expected,
                    "stage_evidence_mismatch",
                    "retest material differs from the verification",
                )
    return upstream


def build_inventory(context: dict, asset_ref: str):
    registry = InventoryRegistry()
    entity_id = context["entity_id"]
    entity = FinancialEntity(entity_id, context["legal_name"], context["country_code"])
    registry.register_entity(entity)
    function = BusinessFunction(
        entity_id,
        context["business_function_id"],
        "Synthetic reference function",
        FunctionClassification(context["business_function_classification"]),
        context["risk_owner_id"],
        "Fictional consumer-owned classification; no regulatory applicability claim.",
    )
    service = ICTService(
        entity_id,
        context["service_id"],
        "Synthetic web service",
        "synthetic-service-owner",
        "synthetic-reference-service",
    )
    target = context["asset_mapping"][asset_ref]
    node_ref = NodeRef(target["entity_id"], NodeKind(target["kind"]), target["node_id"])
    asset = ICTAsset(
        entity_id,
        node_ref.node_id,
        "Synthetic web asset",
        "synthetic-service-owner",
        "synthetic-reference-asset",
    )
    for node in (function, service, asset):
        registry.register_node(node)
    function_ref = NodeRef(entity_id, NodeKind.BUSINESS_FUNCTION, function.function_id)
    service_ref = NodeRef(entity_id, NodeKind.ICT_SERVICE, service.service_id)
    edges = (
        DependencyEdge(
            entity_id,
            "synthetic-function-service",
            function_ref,
            service_ref,
            DependencyRelationship.SUPPORTED_BY,
            "Explicit synthetic context mapping.",
        ),
        DependencyEdge(
            entity_id,
            "synthetic-service-asset",
            service_ref,
            node_ref,
            DependencyRelationship.HOSTED_ON,
            "Explicit synthetic context mapping.",
        ),
    )
    for edge in edges:
        registry.register_edge(edge)
    return (
        registry,
        node_ref,
        {
            "entity": _document(entity),
            "nodes": [_document(node) for node in (function, service, asset)],
            "edges": [_document(edge) for edge in edges],
            "snapshot_manifest": registry.snapshot_manifest(entity_id),
            "snapshot_digest": registry.snapshot_digest(entity_id),
        },
    )


def build_native_records(packet: dict, context: dict):
    """All scores and lifecycle transitions below are computed by actual DORAOps APIs."""
    case = packet["source_packet"]["case"]
    finding_source, remediation_source = case["finding"], case["remediation"]
    completion = packet["change_completion"]
    registry, node_ref, inventory = build_inventory(context, finding_source["asset_ref"])
    scenario = ICTRiskScenario(
        entity_id=context["entity_id"],
        scenario_id="synthetic-risk:" + case["case_id"],
        title="Synthetic vulnerability risk scenario",
        threat="Fictional exploitation scenario.",
        vulnerability=finding_source["title"],
        risk_owner_id=context["risk_owner_id"],
        affected_nodes=(node_ref,),
        likelihood=Likelihood(context["risk_likelihood"]),
        impact=Impact(context["risk_impact"]),
    )
    policy = ICTRiskPolicy(
        entity_id=context["entity_id"],
        policy_id=context["risk_policy_id"],
        version=context["risk_policy_version"],
        medium_threshold=context["medium_threshold"],
        high_threshold=context["high_threshold"],
        critical_threshold=context["critical_threshold"],
        max_control_credit=context["max_control_credit"],
    )
    treatment = RiskTreatmentPlan(
        TreatmentType.MITIGATE,
        remediation_source["owner_role"],
        "Synthetic mitigation plan; separate completion evidence does not reduce risk by itself.",
        timestamp(remediation_source["due_at"]),
    )
    risk = assess_ict_risk(registry, scenario, (), policy, treatment)
    assert_risk_decision_current(risk, registry, scenario, (), policy)
    plan = build_resilience_test_plan(
        registry,
        (risk,),
        entity_id=context["entity_id"],
        test_id=context["test_id"],
        title="Synthetic vulnerability-assessment replay",
        test_type=ResilienceTestType.VULNERABILITY_ASSESSMENT,
        objective="Represent the explicit synthetic test context; do not execute a scanner.",
        test_owner_id=context["test_owner_id"],
        independent_reviewer_id=context["independent_reviewer_id"],
        scope_nodes=(node_ref,),
        scenario=context["execution_basis"],
        planned_at=timestamp(context["planned_at"]),
    )
    catalog = {item["evidence_id"]: item for item in case["evidence_catalog"]}
    execution = record_test_execution(
        plan,
        registry,
        (risk,),
        execution_id="synthetic-execution:" + case["case_id"],
        executed_at=timestamp(context["executed_at"]),
        executor_id=context["executor_id"],
        outcome=TestExecutionOutcome.PASSED_WITH_FINDINGS,
        evidence_digests=tuple(
            catalog[ref]["artifact_sha256"] for ref in finding_source["evidence_refs"]
        ),
        notes=context["execution_basis"],
    )
    finding = create_finding(
        plan,
        execution,
        finding_id=finding_source["finding_id"],
        severity=FindingSeverity(finding_source["severity"]),
        title=finding_source["title"],
        owner_id=remediation_source["owner_role"],
        identified_at=timestamp(finding_source["first_observed_at"]),
        evidence_digest=digest(finding_source),
    )
    before = resolve_test(plan, execution, (finding,))
    remediation = create_remediation(
        finding,
        remediation_id=remediation_source["remediation_id"],
        owner_id=completion["owner_role"],
        completed_at=timestamp(completion["completed_at"]),
        summary=completion["statement"],
        evidence_digest=digest(completion),
    )
    after_remediation = resolve_test(plan, execution, (finding,), (remediation,))
    verification = case.get("verification")
    retest = None
    if verification is not None and verification["outcome"] in ("effective", "ineffective"):
        retest = create_retest(
            plan,
            finding,
            remediation,
            retest_id=verification["verification_id"],
            reviewer_id=verification["verifier_role"],
            tested_at=timestamp(verification["performed_at"]),
            outcome=RetestOutcome.PASSED
            if verification["outcome"] == "effective"
            else RetestOutcome.FAILED,
            notes="Synthetic record only: " + verification["method"],
            evidence_digest=digest(verification),
        )
    final = resolve_test(
        plan, execution, (finding,), (remediation,), () if retest is None else (retest,)
    )
    records = {
        "risk-scenario": scenario,
        "risk-policy": policy,
        "risk-treatment": treatment,
        "risk-decision": risk,
        "test-plan": plan,
        "test-execution": execution,
        "finding": finding,
        "remediation": remediation,
        "resolution-before": before,
        "resolution-remediation": after_remediation,
        "resolution-final": final,
    }
    if retest is not None:
        records["retest"] = retest
    return registry, records, inventory


def consume(packet: dict, *, verified_at: str | None = None, installed_wheel: bool = False) -> dict:
    contract = load_contract()
    context = load_context(contract)
    schemas = Schemas(contract)
    runtime = check_runtime(contract["consumer"], installed_wheel=installed_wheel)
    verified_at = verified_at or contract["verified_at"]
    upstream = validate_packet(packet, contract, context, schemas, verified_at, installed_wheel)
    signature = verify_packet_signature(packet, contract, verified_at)
    try:
        _, native, inventory = build_native_records(packet, context)
    except (GovernanceError, ValueError) as exc:
        raise DemoRejected(
            "doraops_rejected", "DORAOps rejected the risk/remediation evidence: " + str(exc)
        ) from exc
    documents = {name + ".json": _document(value) for name, value in native.items()}
    for name, document in documents.items():
        kind = name.removesuffix(".json")
        schema = (
            "ict-risk"
            if kind.startswith("risk-")
            else "resilience-test-resolution"
            if kind.startswith("resolution-")
            else "resilience-" + kind
        )
        schemas.validate(schema, document)
    schemas.validate("financial-entity", inventory["entity"])
    for node in inventory["nodes"]:
        schemas.validate("inventory-node", node)
    for edge in inventory["edges"]:
        schemas.validate("dependency-edge", edge)
    documents["inventory.json"] = inventory
    documents["governance-context.json"] = context
    documents["signature-verification.json"] = signature
    final, risk = native["resolution-final"], native["risk-decision"]
    documents["receipt.json"] = {
        "schema_version": "vulnevidenceops.doraops-risk-remediation-demo-receipt.v2",
        "scope": "local-synthetic-demo",
        "accepted": True,
        "consumer_backend": "doraops.assess_ict_risk + doraops.resolve_test",
        "runtime": runtime,
        "consumer_source_commit": contract["consumer"]["commit"],
        "verified_at": verified_at,
        "demo_contract_sha256": digest(contract),
        "handoff_sha256": digest(packet["handoff"]),
        "source_packet_sha256": digest(packet["source_packet"]),
        "upstream_receipt_sha256": digest(upstream["receipt.json"]),
        "upstream_datagovops_reconsumed": True,
        "change_completion_sha256": digest(packet["change_completion"]),
        "doraops_handoff_signature_verified": True,
        "signature_verification_sha256": digest(signature),
        "signed_envelope_sha256": digest(packet["signed_envelope"]),
        "native_artifact_sha256": {
            name: digest(value) for name, value in sorted(documents.items())
        },
        "finding_status": final.finding_resolutions[0].status.value,
        "resolution_state": final.state.value,
        "risk_residual_level": risk.residual_level.value,
        "risk_control_credit": risk.control_credit,
        "risk_remediation_required": risk.remediation_required,
        "requires_human_review": True,
        "non_claims": {
            "incident_classification_performed": False,
            "incident_created": False,
            "operational_deployment_controls_verified": False,
            "real_independent_review_completed": False,
            "real_change_execution_verified": False,
            "real_remediation_effectiveness_established": False,
            "risk_acceptance_approved": False,
            "risk_reduced_by_dossier_closure": False,
            "regulatory_compliance_determined": False,
            "production_sender_identity_established": False,
            "production_signing_authority_established": False,
            "private_key_custody_established": False,
            "production_interoperability_established": False,
        },
    }
    return documents


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--as-of")
    parser.add_argument("--installed-wheel", action="store_true")
    args = parser.parse_args(argv)
    try:
        _require(not args.output_dir.exists(), "output_exists", "prior evidence is retained")
        documents = consume(
            read_json(args.input), verified_at=args.as_of, installed_wheel=args.installed_wheel
        )
        for name, document in documents.items():
            write_json(args.output_dir / name, document)
        print(
            json.dumps(
                {"accepted": True, "finding_status": documents["receipt.json"]["finding_status"]}
            )
        )
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
