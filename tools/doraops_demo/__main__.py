"""Run signed DataGovOps indexing, then actual DORAOps risk/remediation consumption."""

from __future__ import annotations

import argparse
import copy
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path

from tools.datagovops_demo.__main__ import produce
from tools.datagovops_demo.__main__ import run_demo as run_datagovops_demo
from tools.datagovops_demo.common import (
    ROOT,
    DemoRejected,
    check_runtime,
    digest,
    read_json,
    write_json,
)
from tools.datagovops_demo.consumer import PACKET_PARTS
from tools.datagovops_demo.consumer import consume as consume_datagovops
from tools.demo_evidence import EvidenceRejected, finalize_bundle, source_identity

from .common import load_context, load_contract
from .demo_signer import sign_packet, signature_scenarios


def make_packet(
    source: dict | None = None, receipt: dict | None = None, completion: dict | None = None
) -> dict:
    contract = load_contract()
    context = load_context(contract)
    source = produce()[0] if source is None else copy.deepcopy(source)
    receipt = (
        consume_datagovops(source)["receipt.json"] if receipt is None else copy.deepcopy(receipt)
    )
    completion = (
        read_json(ROOT / "examples/doraops-demo/change-completion.json")
        if completion is None
        else copy.deepcopy(completion)
    )
    case = source["case"]
    packet = {
        "schema_version": "vulnevidenceops.doraops-risk-remediation-input.v2",
        "source_packet": source,
        "datagovops_receipt": receipt,
        "change_completion": completion,
        "handoff": {
            "schema_version": "vulnevidenceops.doraops-risk-remediation-handoff.v1",
            "handoff_id": "HANDOFF-SYNTH-DORA-RISK-001",
            "profile": contract["profile"],
            "consumer_system": "doraops",
            "consumer_commit": contract["consumer"]["commit"],
            "consumer_tree": contract["consumer"]["tree"],
            "boundary": contract["boundary"],
            "demo_contract_sha256": digest(contract),
            "governance_context_sha256": contract["governance_context_sha256"],
            "source_packet_sha256": digest(source),
            "datagovops_receipt_sha256": digest(receipt),
            "change_completion_sha256": digest(completion),
            "case_id": case["case_id"],
            "finding_id": case["finding"]["finding_id"],
            "source_asset_ref": case["finding"]["asset_ref"],
            "target_node": context["asset_mapping"][case["finding"]["asset_ref"]],
            "created_at": contract["created_at"],
            "valid_until": contract["valid_until"],
            "synthetic": True,
            "incident_created": False,
            "requires_human_review": True,
        },
    }
    packet["signed_envelope"] = sign_packet(packet)
    return packet


def variant_packet(*, verification_outcome: str | None = "effective", reviewer: str | None = None):
    case = read_json(ROOT / "examples/synthetic-case.json")
    materials = read_json(ROOT / "examples/datagovops-demo/evidence-materials.json")
    if verification_outcome is None:
        case.pop("verification")
    else:
        case["verification"]["outcome"] = verification_outcome
        materials["EVD-SYNTH-VER-001"]["result"] = {
            "effective": "expected-synthetic-result-observed",
            "ineffective": "synthetic-finding-persists",
            "partial": "synthetic-retest-partial",
        }[verification_outcome]
        if reviewer is not None:
            case["verification"]["verifier_role"] = reviewer
            materials["EVD-SYNTH-VER-001"]["verifier_role"] = reviewer
    return make_packet(produce(case_document=case, materials_document=materials)[0])


def scenarios(packet: dict):
    corrupted = copy.deepcopy(packet)
    corrupted["source_packet"]["dossier"]["finding_id"] = "SYNTH-CORRUPTED"
    incompatible = copy.deepcopy(packet)
    incompatible["handoff"]["schema_version"] = (
        "vulnevidenceops.doraops-risk-remediation-handoff.v999"
    )
    wrong_boundary = copy.deepcopy(packet)
    wrong_boundary["handoff"]["profile"] = "doraops-operational-control-evidence"
    forged_receipt = copy.deepcopy(packet)
    forged_receipt["datagovops_receipt"]["matrix_after_digest"] = "a" * 64
    forged_receipt["handoff"]["datagovops_receipt_sha256"] = digest(
        forged_receipt["datagovops_receipt"]
    )
    plan_only = copy.deepcopy(packet)
    plan_only["change_completion"].pop("completed_at")
    plan_only["handoff"]["change_completion_sha256"] = digest(plan_only["change_completion"])
    wrong_reviewer = variant_packet(reviewer="synthetic-other-reviewer")
    chronology = copy.deepcopy(packet)
    chronology["change_completion"]["completed_at"] = "2026-01-17T00:00:00Z"
    chronology["change_completion"]["collected_at"] = "2026-01-17T00:00:00Z"
    chronology["handoff"]["change_completion_sha256"] = digest(chronology["change_completion"])
    chronology["signed_envelope"] = sign_packet(chronology)
    return (
        ("modified-input", corrupted, "input_digest_mismatch"),
        ("incompatible-schema", incompatible, "schema_incompatible"),
        ("wrong-operational-boundary", wrong_boundary, "boundary_mismatch"),
        ("forged-datagovops-receipt", forged_receipt, "upstream_receipt_mismatch"),
        ("plan-is-not-completion", plan_only, "schema_incompatible"),
        ("wrong-independent-reviewer", wrong_reviewer, "doraops_rejected"),
        ("retest-before-completion", chronology, "doraops_rejected"),
        *signature_scenarios(packet),
    )


def _consumer(packet_path: Path, output: Path, installed: bool):
    command = [
        sys.executable,
        "-m",
        "tools.doraops_demo.consumer",
        "--input",
        str(packet_path),
        "--output-dir",
        str(output),
    ]
    if installed:
        command.append("--installed-wheel")
    return subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, check=False, timeout=90
    )


def run_demo(output: Path, *, installed_wheels: bool = False) -> dict:
    if output.exists():
        raise DemoRejected("output_exists", "choose a new directory; prior evidence is retained")
    source_identity_value = source_identity(ROOT)
    contract = load_contract()
    runtime = check_runtime(contract["consumer"], installed_wheel=installed_wheels)
    upstream_summary = run_datagovops_demo(output / "datagovops", installed_wheels=installed_wheels)
    source = {
        name: read_json(output / "datagovops/producer" / (name + ".json")) for name in PACKET_PARTS
    }
    upstream_receipt = read_json(output / "datagovops/consumer/receipt.json")
    packet = make_packet(source, upstream_receipt)
    write_json(output / "doraops/input.json", packet)
    result = _consumer(output / "doraops/input.json", output / "doraops/consumer", installed_wheels)
    if result.returncode:
        raise DemoRejected("positive_case_failed", result.stderr.strip())
    receipt = read_json(output / "doraops/consumer/receipt.json")
    phases = {
        phase: read_json(output / "doraops/consumer" / ("resolution-" + phase + ".json"))
        for phase in ("before", "remediation", "final")
    }
    states = {name: value["finding_resolutions"][0]["status"] for name, value in phases.items()}
    if (
        states != {"before": "open", "remediation": "remediation_submitted", "final": "closed"}
        or receipt["risk_residual_level"] != "high"
        or receipt["risk_control_credit"] != 0
        or receipt["risk_remediation_required"] is not True
    ):
        raise DemoRejected("unexpected_consumer_state", "DORAOps governance transition differs")
    negatives = {}
    for name, candidate, expected in scenarios(packet):
        directory = output / "negative" / name
        write_json(directory / "input.json", candidate)
        result = _consumer(directory / "input.json", directory / "consumer", installed_wheels)
        if result.returncode != 2:
            raise DemoRejected("negative_case_failed", f"{name} did not fail closed")
        rejected = json.loads(result.stderr)
        if rejected.get("error_code") != expected or (directory / "consumer").exists():
            raise DemoRejected("negative_case_failed", f"{name} failed at the wrong boundary")
        negatives[name] = {"exit_code": 2, **rejected}
        write_json(directory / "rejection.json", negatives[name])
    attention = {}
    for name, outcome, expected in (
        ("missing-retest", None, "remediation_submitted"),
        ("failed-retest", "ineffective", "retest_failed"),
    ):
        directory = output / "attention" / name
        candidate = variant_packet(verification_outcome=outcome)
        write_json(directory / "input.json", candidate)
        result = _consumer(directory / "input.json", directory / "consumer", installed_wheels)
        if result.returncode:
            raise DemoRejected(
                "attention_case_failed", f"{name} did not preserve incomplete evidence"
            )
        candidate_receipt = read_json(directory / "consumer/receipt.json")
        if (
            candidate_receipt["finding_status"] != expected
            or candidate_receipt["resolution_state"] != "blocked"
        ):
            raise DemoRejected("attention_case_failed", f"{name} was incorrectly closed")
        attention[name] = {
            "metadata_accepted": True,
            "finding_status": expected,
            "resolution_state": "blocked",
        }
    summary = {
        "schema_version": "vulnevidenceops.doraops-risk-remediation-demo-summary.v2",
        "scope": "local-synthetic-demo",
        "positive_case_accepted": True,
        "upstream_datagovops_accepted": upstream_summary["positive_case_accepted"],
        "upstream_signature_verified": upstream_summary["consumer_signature_verified"],
        "doraops_signature_verified": receipt["doraops_handoff_signature_verified"],
        "consumer_backend": receipt["consumer_backend"],
        "runtime": runtime,
        "finding_phases": states,
        "risk_residual_level": "high",
        "risk_control_credit": 0,
        "negative_cases": negatives,
        "attention_cases": attention,
        "requires_human_review": True,
        "incident_created": False,
        "production_interoperability_established": False,
    }
    write_json(output / "summary.json", summary)
    write_json(
        output / "execution-environment.json",
        {
            "python": platform.python_version(),
            "installation_mode": "isolated-wheels" if installed_wheels else "prepared-environment",
            "dependency_versions": {
                name: importlib.metadata.version(name)
                for name in (
                    "vulnevidenceops",
                    "datagovops",
                    "doraops",
                    "cryptography",
                    "jsonschema",
                    "referencing",
                )
            },
            "dependency_wheel_reproducibility_established": False,
        },
    )
    report = (
        "# VulnEvidenceOps → DataGovOps → DORAOps evidence report\n\n"
        "Result: **PASS — bounded synthetic risk/remediation consumption**.\n\n"
        f"Source: `{source_identity_value['commit_sha']}`; "
        f"clean: `{source_identity_value['worktree_clean']}`.\n\n"
        f"Tree: `{source_identity_value['tree_sha']}`.\n\n"
        f"DORAOps exact pin: `{contract['consumer']['commit']}`.\n\n"
        "| Stage | Actual consumer outcome |\n|---|---|\n"
        "| Signed DataGovOps indexing | Accepted under public RFC demo-key policy |\n"
        "| Separate DORAOps input signature | All four inputs bound to DORAOps audience/purpose |\n"
        "| DORAOps risk | High, 9 → 9; zero automatic control credit |\n"
        "| Finding before remediation | Open; resolution blocked |\n"
        "| Separate completion evidence | Remediation submitted; still blocked |\n"
        "| Configured synthetic independent retest | Closed; successful_with_findings |\n"
        "| Missing or failed retest | Metadata accepted; finding remains blocked |\n"
        f"| {len(negatives)} malformed/misbound/signature scenarios | "
        "Rejected without an accepted receipt |\n\n"
        "Inspect [DORAOps receipt](doraops/consumer/receipt.json), "
        "[native risk decision](doraops/consumer/risk-decision.json), "
        "[resolution](doraops/consumer/resolution-final.json), "
        "[DataGovOps report](datagovops/REPORT.md), and [summary](summary.json).\n\n"
        "A remediation plan is not completed work; completion is additional fictional evidence. "
        "Finding closure does not reduce the independently assessed risk "
        "or approve risk acceptance. No vulnerability is classified as an incident, "
        "and no deployment controls are fabricated.\n\n"
        "DataGovOps and DORAOps transcripts have separately verified demo signatures. "
        "The DORAOps signature binds the handoff, source, upstream receipt and completion. "
        "The RFC test keys are public and forgeable: this does NOT establish production sender "
        "identity or real change execution. All identities, judgments and dates are synthetic. "
        "No real test execution, reviewer approval, remediation effectiveness, "
        "regulatory compliance "
        "or production integration is established. Human review remains required.\n"
    )
    finalize_bundle(
        output, source=source_identity_value, contract_sha256=digest(contract), report=report
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--installed-wheels", action="store_true")
    args = parser.parse_args()
    try:
        summary = run_demo(args.output_dir.resolve(), installed_wheels=args.installed_wheels)
    except (DemoRejected, EvidenceRejected, OSError, subprocess.SubprocessError) as exc:
        print(f"Demo failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True, indent=2))
    print("Evidence: " + str(args.output_dir.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
