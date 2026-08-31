"""Produce a dossier, invoke an independent consumer process, and exercise rejections."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path

from vulnevidenceops import (
    VulnerabilityCase,
    VulnerabilityPolicy,
    assess_case,
    build_integration_handoff,
    verify_integration_handoff,
)

from .common import (
    ROOT,
    DemoRejected,
    check_runtime,
    digest,
    load_contract,
    read_json,
    write_json,
)


def produce() -> tuple[dict, dict]:
    contract = load_contract()
    materials = read_json(ROOT / "examples/datagovops-demo/evidence-materials.json")
    document = read_json(ROOT / "examples/synthetic-case.json")
    for item in document["evidence_catalog"]:
        item["artifact_sha256"] = digest(materials[item["evidence_id"]])
    case = VulnerabilityCase.from_dict(document)
    policy = VulnerabilityPolicy.from_dict(read_json(ROOT / "examples/synthetic-policy.json"))
    dossier = assess_case(case, policy=policy, assessed_at=contract["assessed_at"]).to_dict()
    handoff = build_integration_handoff(
        dossier,
        handoff_id="HANDOFF-SYNTH-DATAGOVOPS-001",
        profile="datagovops-control-evidence",
        subject_ref=case.case_id,
        created_at=contract["assessed_at"],
        valid_until=contract["valid_until"],
        synthetic=True,
    )
    peer = contract["consumer"]["schemas"]["control-evidence-reference"]
    verification = verify_integration_handoff(
        handoff,
        dossier,
        (ROOT / peer["path"]).read_bytes(),
        verified_at=contract["verified_at"],
    ).to_dict()
    return {
        "case": case.to_dict(),
        "policy": policy.to_dict(),
        "materials": materials,
        "dossier": dossier,
        "handoff": handoff.to_dict(),
    }, verification


def _packet_files(path: Path, packet: dict) -> None:
    for name, value in packet.items():
        write_json(path / (name + ".json"), value)


def _consumer(packet_dir: Path, output: Path, installed_wheels: bool):
    command = [
        sys.executable,
        "-m",
        "tools.datagovops_demo.consumer",
        "--packet-dir",
        str(packet_dir),
        "--output-dir",
        str(output),
    ]
    if installed_wheels:
        command.append("--installed-wheel")
    return subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, check=False, timeout=90
    )


def run_demo(output: Path, *, installed_wheels: bool = False) -> dict:
    if output.exists():
        raise DemoRejected(
            "output_exists", "choose a new output directory; prior evidence is retained"
        )
    contract = load_contract()
    producer_runtime = check_runtime(contract["producer"], installed_wheel=installed_wheels)
    consumer_runtime = check_runtime(contract["consumer"], installed_wheel=installed_wheels)
    packet, verification = produce()
    _packet_files(output / "producer", packet)
    write_json(output / "producer/local-handoff-verification.json", verification)
    result = _consumer(output / "producer", output / "consumer", installed_wheels)
    if result.returncode != 0:
        raise DemoRejected("positive_case_failed", result.stderr.strip())
    receipt = read_json(output / "consumer/receipt.json")
    before = read_json(output / "consumer/matrix-before.json")
    after = read_json(output / "consumer/matrix-after.json")
    stale = read_json(output / "consumer/matrix-at-expiry.json")
    if (
        receipt["accepted"] is not True
        or before["gap_control_count"] != 5
        or after["represented_control_count"] != 5
        or after["state"] != "represented"
        or stale["revalidation_required_control_count"] != 5
    ):
        raise DemoRejected("unexpected_consumer_state", "DataGovOps matrix transition differs")

    corrupted = copy.deepcopy(packet)
    corrupted["dossier"]["finding_id"] = "FIND-SYNTH-CORRUPTED"
    incompatible = copy.deepcopy(packet)
    incompatible["dossier"]["schema_version"] = "vulnevidenceops.assurance-dossier.v999"
    # Re-hash deliberately: a digest/profile-only validator accepts this payload.
    incompatible["handoff"]["payload_sha256"] = digest(incompatible["dossier"])
    from vulnevidenceops import IntegrationHandoff

    peer = contract["consumer"]["schemas"]["control-evidence-reference"]
    incompatible_local = verify_integration_handoff(
        IntegrationHandoff.from_dict(incompatible["handoff"]),
        incompatible["dossier"],
        (ROOT / peer["path"]).read_bytes(),
        verified_at=contract["verified_at"],
    ).to_dict()
    if incompatible_local["integration_position"] != "verified":
        raise DemoRejected("unexpected_local_state", "rehashed schema scenario was not constructed")
    negatives = {}
    for name, candidate, expected in (
        ("corrupted-content", corrupted, "payload_digest_mismatch"),
        ("incompatible-schema", incompatible, "schema_incompatible"),
    ):
        directory = output / "negative" / name
        _packet_files(directory / "packet", candidate)
        result = _consumer(directory / "packet", directory / "consumer", installed_wheels)
        if result.returncode != 2:
            raise DemoRejected("negative_case_failed", f"{name} did not fail closed")
        rejection = json.loads(result.stderr)
        if rejection.get("error_code") != expected or (directory / "consumer").exists():
            raise DemoRejected("negative_case_failed", f"{name} failed at an unexpected boundary")
        negatives[name] = {"exit_code": result.returncode, **rejection}
        write_json(directory / "rejection.json", negatives[name])
    write_json(
        output / "negative/incompatible-schema/local-handoff-verification.json", incompatible_local
    )
    summary = {
        "schema_version": "vulnevidenceops.datagovops-demo-summary.v1",
        "scope": "local-synthetic-demo",
        "positive_case_accepted": receipt["accepted"],
        "consumer_backend": receipt["consumer_backend"],
        "matrix_before": before["state"],
        "matrix_after": after["state"],
        "matrix_at_expiry": stale["state"],
        "registered_evidence_count": len(receipt["registered_evidence_digests"]),
        "excluded_control_count": len(receipt["excluded_controls"]),
        "negative_cases": negatives,
        "incompatible_schema_passes_digest_only_check": True,
        "producer_runtime": producer_runtime,
        "consumer_runtime": consumer_runtime,
        "requires_human_review": True,
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
                    "cryptography",
                    "jsonschema",
                    "referencing",
                    "attrs",
                    "jsonschema-specifications",
                    "rpds-py",
                )
            },
            "dependency_wheel_reproducibility_established": False,
        },
    )
    files = [
        {
            "path": path.relative_to(output).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(output.rglob("*.json"))
    ]
    write_json(
        output / "manifest.json",
        {
            "schema_version": "vulnevidenceops.datagovops-demo-manifest.v1",
            "demo_contract_sha256": digest(contract),
            "artifacts": files,
        },
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--installed-wheels", action="store_true")
    args = parser.parse_args()
    try:
        summary = run_demo(args.output_dir.resolve(), installed_wheels=args.installed_wheels)
    except (DemoRejected, OSError, subprocess.SubprocessError) as exc:
        print(f"Demo failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("Evidence: " + str(args.output_dir.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
