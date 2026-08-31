"""Produce a dossier, invoke an independent consumer process, and exercise rejections."""

from __future__ import annotations

import argparse
import base64
import copy
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path

from tools.demo_evidence import EvidenceRejected, finalize_bundle, source_identity
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
    Schemas,
    canonical_bytes,
    check_runtime,
    digest,
    load_contract,
    read_json,
    write_json,
)
from .demo_signer import sign_packet
from .signatures import load_signing_policy, transcript


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
    packet = {
        "case": case.to_dict(),
        "policy": policy.to_dict(),
        "materials": materials,
        "dossier": dossier,
        "handoff": handoff.to_dict(),
    }
    packet["signed-envelope"] = sign_packet(packet)
    return packet, verification


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
    source = source_identity(ROOT)
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
    # A valid signature must not turn an incompatible payload into accepted evidence.
    incompatible["signed-envelope"] = sign_packet(incompatible)
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
    wrong_key = copy.deepcopy(packet)
    wrong_key["signed-envelope"] = sign_packet(wrong_key, wrong_key=True)
    untrusted = copy.deepcopy(packet)
    untrusted["signed-envelope"] = sign_packet(untrusted, key_id="synthetic-untrusted")
    revoked = copy.deepcopy(packet)
    revoked["signed-envelope"] = sign_packet(revoked, key_id="synthetic-rfc8032-revoked")
    tampered = copy.deepcopy(packet)
    tampered["dossier"]["overdue"] = not tampered["dossier"]["overdue"]
    tampered["handoff"]["payload_sha256"] = digest(tampered["dossier"])
    key_policy = load_signing_policy(contract, Schemas(contract))
    changed_transcript = transcript(tampered, contract, key_policy)
    # Attacker updates every exposed digest and signed payload, but cannot retain the signature.
    tampered["signed-envelope"]["payload_base64"] = base64.b64encode(
        canonical_bytes(changed_transcript)
    ).decode()
    tampered["signed-envelope"]["payload_sha256"] = digest(changed_transcript)
    for name, candidate, expected in (
        ("corrupted-content", corrupted, "payload_digest_mismatch"),
        ("incompatible-schema", incompatible, "schema_incompatible"),
        ("wrong-key", wrong_key, "signature_invalid"),
        ("untrusted-key", untrusted, "key_not_trusted"),
        ("revoked-key", revoked, "key_revoked"),
        ("rehashed-signed-content", tampered, "signature_invalid"),
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
        "consumer_signature_verified": True,
        "public_test_keys_only": True,
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
    write_json(output / "consumer/key-policy.json", key_policy)
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
    ci = source["github_actions"]
    report = (
        "# VulnEvidenceOps → DataGovOps evidence report\n\n"
        "Result: **PASS — local synthetic consumer acceptance**.\n\n"
        f"Source commit: `{source['commit_sha']}`\n\n"
        f"Source tree: `{source['tree_sha']}`; clean worktree: `{source['worktree_clean']}`.\n\n"
        + (
            f"CI run: [{ci['run_id']}]({ci['run_url']}), attempt {ci['run_attempt']}.\n\n"
            if ci
            else "Local run (not a CI attestation).\n\n"
        )
        + f"DataGovOps pin: `{contract['consumer']['commit']}`.\n\n"
        "| Observation | DataGovOps result |\n|---|---|\n"
        "| Before registration | 5 gaps |\n"
        "| After registration | 5 represented controls |\n"
        "| At expiry | 5 controls require revalidation |\n"
        "| Non-applicable risk acceptance | 1 explicitly excluded control |\n"
        "| Modified dossier | Rejected: payload_digest_mismatch |\n"
        "| Rehashed incompatible schema | Rejected: schema_incompatible |\n"
        "| Wrong private key | Rejected: signature_invalid |\n"
        "| Untrusted key ID | Rejected: key_not_trusted |\n"
        "| Revoked key, backdated signature | Rejected: key_revoked |\n"
        "| Rehashed signed content | Rejected: signature_invalid |\n\n"
        "Inspect [receipt](consumer/receipt.json), [summary](summary.json), "
        "[runtime](execution-environment.json), and [file manifest](manifest.json).\n\n"
        "The consumer verified Ed25519 over all packet members and the exact consumer contract "
        "using its pinned **public RFC demo key** policy. Anyone knows these test keys; "
        "this is not production origin authentication. The manifest checks file integrity. "
        "A rebuilt manifest "
        "is not a trusted signature. Compare the exact source SHA and manifest digest with "
        "the trusted CI run. Human review remains required; no real remediation, sender "
        "authority, production interoperability or regulatory compliance is established.\n"
    )
    finalize_bundle(output, source=source, contract_sha256=digest(contract), report=report)
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
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("Evidence: " + str(args.output_dir.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
