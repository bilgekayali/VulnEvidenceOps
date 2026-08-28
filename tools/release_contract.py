"""Emit and verify the VulnEvidenceOps v1.0.0 stable-reference contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "release" / "release-contract.json"
GOVERNANCE = ROOT / "release" / "repository-governance.json"
SCHEMA_DIR = ROOT / "schemas"
MATRIX = ROOT / "configs" / "control-evidence-matrix.json"
EXAMPLE = ROOT / "examples" / "synthetic-case.json"
POLICY = ROOT / "examples" / "synthetic-policy.json"
SARIF_EXAMPLE = ROOT / "examples" / "synthetic-sarif.json"
CYCLONEDX_EXAMPLE = ROOT / "examples" / "synthetic-cyclonedx.json"
EXPOSURE_EXAMPLE = ROOT / "examples" / "synthetic-exposure-context.json"
PORTFOLIO_EXAMPLE = ROOT / "examples" / "synthetic-portfolio.json"
BUILD_PROVENANCE_EXAMPLE = ROOT / "examples" / "synthetic-build-provenance.json"
VERIFICATION_KEY_EXAMPLE = ROOT / "examples" / "synthetic-verification-key.json"
SIGNED_ENVELOPE_EXAMPLE = ROOT / "examples" / "synthetic-signed-evidence-envelope.json"
ANCHOR_RECEIPT_EXAMPLE = ROOT / "examples" / "synthetic-anchor-receipt.json"
INTAKE_MODULE = ROOT / "src" / "vulnevidenceops" / "intake.py"
EXPOSURE_MODULE = ROOT / "src" / "vulnevidenceops" / "exposure.py"
PORTFOLIO_MODULE = ROOT / "src" / "vulnevidenceops" / "portfolio.py"
SIGNED_EVIDENCE_MODULE = ROOT / "src" / "vulnevidenceops" / "signed_evidence.py"
INTEGRATION_MODULE = ROOT / "src" / "vulnevidenceops" / "integration.py"
ASSURANCE_DOSSIER_EXAMPLE = ROOT / "examples" / "synthetic-assurance-dossier.json"
AI_THREAT_REPORT_EXAMPLE = ROOT / "examples" / "synthetic-ai-threat-evaluation-report.json"
PEER_CONTRACT_DIR = ROOT / "examples" / "peer-contracts"
INTEGRATION_EXAMPLES = {
    "ai-threat-evaluation": {
        "payload": AI_THREAT_REPORT_EXAMPLE,
        "peer": PEER_CONTRACT_DIR / "ai-threat-evaluation-report.schema.json",
    },
    "datagovops-control-evidence": {
        "payload": ASSURANCE_DOSSIER_EXAMPLE,
        "peer": PEER_CONTRACT_DIR / "datagovops-control-evidence-reference.schema.json",
    },
    "doraops-operational-control-evidence": {
        "payload": ASSURANCE_DOSSIER_EXAMPLE,
        "peer": PEER_CONTRACT_DIR / "doraops-operational-control-evidence.schema.json",
    },
    "modelriskops-assurance-evidence": {
        "payload": ASSURANCE_DOSSIER_EXAMPLE,
        "peer": PEER_CONTRACT_DIR / "modelriskops-assurance-evidence-reference.schema.json",
    },
}
WORKFLOWS = ROOT / ".github" / "workflows"
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def _public_api() -> dict[str, object]:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    import vulnevidenceops

    symbols = list(vulnevidenceops.__all__)
    if len(symbols) != len(set(symbols)):
        raise SystemExit("vulnevidenceops.__all__ contains duplicate symbols")
    if missing := [name for name in symbols if not hasattr(vulnevidenceops, name)]:
        raise SystemExit("public symbols are missing: " + ", ".join(sorted(missing)))
    symbols.sort()
    return {"symbol_count": len(symbols), "sha256": _sha(symbols)}


def _schema_set() -> dict[str, object]:
    entries = []
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema = _json(path)
        Draft202012Validator.check_schema(schema)
        entries.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    if not entries:
        raise SystemExit("public schema set is empty")
    return {"file_count": len(entries), "sha256": _sha(entries)}


def _control_matrix() -> dict[str, object]:
    matrix = _json(MATRIX)
    controls = matrix.get("controls")
    if not isinstance(controls, list) or not controls:
        raise SystemExit("control/evidence matrix is empty")
    identifiers = [item.get("control_id") for item in controls]
    if len(identifiers) != len(set(identifiers)):
        raise SystemExit("control/evidence matrix contains duplicate control IDs")
    return {
        "control_count": len(controls),
        "sha256": hashlib.sha256(MATRIX.read_bytes()).hexdigest(),
    }


def _synthetic_example() -> dict[str, object]:
    example = _json(EXAMPLE)
    catalog = example.get("evidence_catalog")
    if not isinstance(catalog, list) or not catalog:
        raise SystemExit("synthetic example evidence catalog is empty")
    if any(item.get("synthetic") is not True for item in catalog):
        raise SystemExit("every committed example evidence item must be explicitly synthetic")
    return {
        "case_id": example.get("case_id"),
        "sha256": hashlib.sha256(EXAMPLE.read_bytes()).hexdigest(),
    }


def _intake_adapters() -> dict[str, object]:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from vulnevidenceops.intake import INTAKE_ADAPTER_VERSION, SUPPORTED_INTAKE_FORMATS

    entries = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in (INTAKE_MODULE, CYCLONEDX_EXAMPLE, SARIF_EXAMPLE)
    ]
    return {
        "adapter_contract": INTAKE_ADAPTER_VERSION,
        "example_count": 2,
        "formats": list(SUPPORTED_INTAKE_FORMATS),
        "sha256": _sha(entries),
    }


def _exposure_context() -> dict[str, object]:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from vulnevidenceops.exposure import (
        CONTEXT_POSITIONS,
        CURRENTNESS_STATES,
        EXPOSURE_CONTEXT_CONTRACT,
    )

    entries = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in (EXPOSURE_MODULE, EXPOSURE_EXAMPLE)
    ]
    return {
        "context_positions": sorted(CONTEXT_POSITIONS),
        "contract": EXPOSURE_CONTEXT_CONTRACT,
        "currentness_states": sorted(CURRENTNESS_STATES),
        "example_count": 1,
        "sha256": _sha(entries),
    }


def _portfolio_assurance() -> dict[str, object]:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from vulnevidenceops.portfolio import (
        EXCEPTION_AGE_BANDS,
        PORTFOLIO_ASSURANCE_CONTRACT,
        PORTFOLIO_POSITIONS,
        SLA_COHORTS,
    )

    entries = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in (PORTFOLIO_MODULE, PORTFOLIO_EXAMPLE)
    ]
    return {
        "age_bands": sorted(EXCEPTION_AGE_BANDS),
        "contract": PORTFOLIO_ASSURANCE_CONTRACT,
        "example_case_count": 3,
        "portfolio_positions": sorted(PORTFOLIO_POSITIONS),
        "sha256": _sha(entries),
        "sla_cohorts": sorted(SLA_COHORTS),
    }


def _signed_evidence() -> dict[str, object]:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from vulnevidenceops.signed_evidence import (
        ANCHOR_TYPES,
        KEY_STATES,
        SIGNATURE_ALGORITHMS,
        SIGNED_EVIDENCE_CONTRACT,
        VERIFICATION_POSITIONS,
    )

    entries = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in (
            SIGNED_EVIDENCE_MODULE,
            BUILD_PROVENANCE_EXAMPLE,
            VERIFICATION_KEY_EXAMPLE,
            SIGNED_ENVELOPE_EXAMPLE,
            ANCHOR_RECEIPT_EXAMPLE,
        )
    ]
    return {
        "algorithms": sorted(SIGNATURE_ALGORITHMS),
        "anchor_types": sorted(ANCHOR_TYPES),
        "contract": SIGNED_EVIDENCE_CONTRACT,
        "example_count": 4,
        "key_states": sorted(KEY_STATES),
        "sha256": _sha(entries),
        "verification_positions": sorted(VERIFICATION_POSITIONS),
    }


def _integration_contracts() -> dict[str, object]:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from vulnevidenceops.integration import (
        INTEGRATION_CONTRACT,
        INTEGRATION_POSITIONS,
        INTEGRATION_PROFILES,
        INTEGRATION_SYSTEMS,
    )

    example_paths = []
    for profile, paths in sorted(INTEGRATION_EXAMPLES.items()):
        example_paths.extend(
            (
                paths["payload"],
                paths["peer"],
                ROOT / "examples" / f"synthetic-{profile}-handoff.json",
                ROOT / "examples" / f"synthetic-{profile}-verification.json",
            )
        )
    entries = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in (INTEGRATION_MODULE, *dict.fromkeys(example_paths))
    ]
    return {
        "contract": INTEGRATION_CONTRACT,
        "example_count": len(INTEGRATION_EXAMPLES),
        "peer_contract_count": len(INTEGRATION_EXAMPLES),
        "profiles": sorted(INTEGRATION_PROFILES),
        "systems": sorted(INTEGRATION_SYSTEMS),
        "verification_positions": sorted(INTEGRATION_POSITIONS),
        "sha256": _sha(entries),
    }


def compute() -> dict[str, dict[str, object]]:
    return {
        "public_api": _public_api(),
        "schema_set": _schema_set(),
        "control_matrix": _control_matrix(),
        "synthetic_example": _synthetic_example(),
        "intake_adapters": _intake_adapters(),
        "exposure_context": _exposure_context(),
        "portfolio_assurance": _portfolio_assurance(),
        "signed_evidence": _signed_evidence(),
        "integration_contracts": _integration_contracts(),
    }


def _verify_action_pins() -> None:
    failures = []
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        for spec in _USES.findall(path.read_text(encoding="utf-8")):
            if spec.startswith("./"):
                continue
            if "@" not in spec or not _SHA40.fullmatch(spec.rsplit("@", 1)[1]):
                failures.append(f"{path.relative_to(ROOT)}: {spec}")
    if failures:
        raise SystemExit("GitHub Actions must use exact commit pins:\n" + "\n".join(failures))


def _verify_examples() -> None:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from vulnevidenceops import (
        VulnerabilityCase,
        VulnerabilityPolicy,
        assess_case,
        validate_document,
    )

    example = _json(EXAMPLE)
    policy = _json(POLICY)
    validate_document(SCHEMA_DIR / "case-bundle.schema.json", example)
    validate_document(SCHEMA_DIR / "vulnerability-policy.schema.json", policy)
    dossier = assess_case(
        VulnerabilityCase.from_dict(example),
        policy=VulnerabilityPolicy.from_dict(policy),
        assessed_at="2026-01-20T00:00:00Z",
    ).to_dict()
    validate_document(SCHEMA_DIR / "assurance-dossier.schema.json", dossier)
    if dossier["lifecycle_state"] != "closed_verified" or dossier["gaps"]:
        raise SystemExit("synthetic reference case must close with no evidence gaps")
    if any(dossier["non_claims"].values()):
        raise SystemExit("synthetic dossier non-claims must remain explicit false values")
    matrix = _json(MATRIX)
    validate_document(SCHEMA_DIR / "control-evidence-matrix.schema.json", matrix)
    matrix_ids = sorted(item["control_id"] for item in matrix["controls"])
    dossier_ids = sorted(item["control_id"] for item in dossier["control_evidence"])
    if dossier_ids != matrix_ids:
        raise SystemExit("assessor control IDs differ from the control/evidence matrix")


def _verify_intake_examples() -> None:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from vulnevidenceops import adapt_cyclonedx, adapt_sarif, validate_document

    common = {
        "collected_at": "2026-01-05T00:00:00Z",
        "observed_at": "2026-01-04T00:00:00Z",
        "source_identity": "synthetic-source:reference-v1",
        "source_ref": "synthetic-source:export-001",
        "synthetic": True,
    }
    sarif_raw = SARIF_EXAMPLE.read_bytes()
    cyclonedx_raw = CYCLONEDX_EXAMPLE.read_bytes()
    batches = [
        adapt_sarif(
            _json(SARIF_EXAMPLE),
            artifact_ref="synthetic://intake/sarif.json",
            artifact_sha256=hashlib.sha256(sarif_raw).hexdigest(),
            asset_ref="synthetic-asset:repository-001",
            **common,
        ),
        adapt_cyclonedx(
            _json(CYCLONEDX_EXAMPLE),
            artifact_ref="synthetic://intake/cyclonedx.json",
            artifact_sha256=hashlib.sha256(cyclonedx_raw).hexdigest(),
            asset_ref_prefix="synthetic-component:",
            **common,
        ),
    ]
    if [len(batch.findings) for batch in batches] != [2, 3]:
        raise SystemExit("synthetic intake examples have unexpected mapping cardinality")
    for batch in batches:
        document = batch.to_dict()
        validate_document(SCHEMA_DIR / "intake-batch.schema.json", document)
        if batch.source_artifact.synthetic is not True:
            raise SystemExit("committed intake evidence must be explicitly synthetic")
        if len(batch.findings) != len(batch.mappings):
            raise SystemExit("every synthetic intake finding must have one source mapping")
        if any(document["non_claims"].values()):
            raise SystemExit("intake non-claims must remain explicit false values")


def _verify_exposure_example() -> None:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from vulnevidenceops import (
        ExposureContextBundle,
        assess_exposure_context,
        validate_document,
    )

    example = _json(EXPOSURE_EXAMPLE)
    validate_document(SCHEMA_DIR / "exposure-context-bundle.schema.json", example)
    for record in example["exploit_intelligence"]:
        validate_document(SCHEMA_DIR / "exploit-intelligence.schema.json", record)
    for record in example["business_criticality"]:
        validate_document(SCHEMA_DIR / "business-criticality.schema.json", record)
    assessment = assess_exposure_context(
        ExposureContextBundle.from_dict(example),
        assessed_at="2026-01-20T00:00:00Z",
    ).to_dict()
    validate_document(
        SCHEMA_DIR / "exposure-context-assessment.schema.json",
        assessment,
    )
    if assessment["context_position"] != "current" or assessment["gaps"]:
        raise SystemExit("synthetic exposure context must be current with no gaps")
    if any(assessment["non_claims"].values()):
        raise SystemExit("exposure non-claims must remain explicit false values")
    if any(item.get("synthetic") is not True for item in example["evidence_catalog"]):
        raise SystemExit("committed exposure evidence must be explicitly synthetic")


def _verify_portfolio_example() -> None:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from vulnevidenceops import PortfolioBundle, assess_portfolio, validate_document

    example = _json(PORTFOLIO_EXAMPLE)
    validate_document(SCHEMA_DIR / "portfolio-bundle.schema.json", example)
    view = assess_portfolio(
        PortfolioBundle.from_dict(example),
        assessed_at="2026-01-20T00:00:00Z",
    ).to_dict()
    validate_document(SCHEMA_DIR / "portfolio-assurance-view.schema.json", view)
    if view["portfolio_position"] != "current" or view["gaps"]:
        raise SystemExit("synthetic portfolio must be current with no gaps")
    expected_totals = {
        "case_count": 3,
        "closed_case_count": 2,
        "deduplication_decision_count": 1,
        "exception_count": 1,
        "finding_count": 3,
        "open_case_count": 1,
        "portfolio_gap_count": 0,
    }
    if view["totals"] != expected_totals:
        raise SystemExit("synthetic portfolio totals differ from the v0.4 reference")
    if any(view["non_claims"].values()):
        raise SystemExit("portfolio non-claims must remain explicit false values")
    if any(
        evidence.get("synthetic") is not True
        for case in example["cases"]
        for evidence in case["evidence_catalog"]
    ):
        raise SystemExit("committed portfolio evidence must be explicitly synthetic")
    forbidden_metrics = {"compliance_percentage", "priority_score", "risk_score"}
    if forbidden_metrics.intersection(view["totals"]):
        raise SystemExit("portfolio totals must not introduce percentages or scores")


def _verify_signed_evidence_examples() -> None:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from vulnevidenceops import (
        AnchorReceipt,
        BuildProvenance,
        SignedEvidenceEnvelope,
        VerificationKey,
        validate_document,
        verify_signed_evidence,
    )

    provenance_document = _json(BUILD_PROVENANCE_EXAMPLE)
    key_document = _json(VERIFICATION_KEY_EXAMPLE)
    envelope_document = _json(SIGNED_ENVELOPE_EXAMPLE)
    receipt_document = _json(ANCHOR_RECEIPT_EXAMPLE)
    for schema_name, document in (
        ("build-provenance.schema.json", provenance_document),
        ("verification-key.schema.json", key_document),
        ("signed-evidence-envelope.schema.json", envelope_document),
        ("anchor-receipt.schema.json", receipt_document),
    ):
        validate_document(SCHEMA_DIR / schema_name, document)

    provenance = BuildProvenance.from_dict(provenance_document)
    key = VerificationKey.from_dict(key_document)
    envelope = SignedEvidenceEnvelope.from_dict(envelope_document)
    receipt = AnchorReceipt.from_dict(receipt_document)
    if envelope.payload_document() != provenance.to_dict():
        raise SystemExit("signed reference payload differs from exact build provenance")
    verification = verify_signed_evidence(
        envelope,
        key,
        verified_at="2026-01-20T00:05:00Z",
        anchor_receipts=(receipt,),
    ).to_dict()
    validate_document(SCHEMA_DIR / "signature-verification.schema.json", verification)
    if verification["verification_position"] != "cryptographically_valid":
        raise SystemExit("reference envelope must be cryptographically valid")
    if verification["gaps"]:
        raise SystemExit("reference signed-evidence chain must have no local verification gaps")
    if not verification["signature_valid"] or not verification["payload_digest_valid"]:
        raise SystemExit("reference signature and payload digest must verify")
    if verification["key_state"] != "current":
        raise SystemExit("reference key must be current at the claimed signing time")
    if verification["envelope_key_id"] != verification["verification_key_id"]:
        raise SystemExit("reference envelope and verification key IDs must match")
    if verification["verification_key_sha256"] != key.public_key_sha256:
        raise SystemExit("reference verification result must bind the exact public-key digest")
    if verification["signed_at"] != envelope.signed_at:
        raise SystemExit("reference verification result must preserve the claimed signing time")
    anchor = verification["anchor_receipts"][0]
    if anchor["binding_state"] != "bound" or anchor["temporal_state"] != "current":
        raise SystemExit("reference anchor must be locally bound and temporally current")
    if anchor["external_validation_performed"] is not False:
        raise SystemExit("external anchor validation must remain explicit false")
    if any(verification["non_claims"].values()):
        raise SystemExit("signed-evidence non-claims must remain explicit false values")
    if not all(
        document.get("synthetic") is True
        for document in (provenance_document, key_document, receipt_document)
    ):
        raise SystemExit("committed provenance, key and anchor examples must be synthetic")
    example_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            BUILD_PROVENANCE_EXAMPLE,
            VERIFICATION_KEY_EXAMPLE,
            SIGNED_ENVELOPE_EXAMPLE,
            ANCHOR_RECEIPT_EXAMPLE,
        )
    )
    if "PRIVATE KEY" in example_text or "private_key" in example_text:
        raise SystemExit("committed signed-evidence examples must not contain private keys")


def _verify_integration_examples() -> None:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from vulnevidenceops import (
        IntegrationHandoff,
        VulnerabilityCase,
        VulnerabilityPolicy,
        assess_case,
        git_blob_id,
        validate_document,
        verify_integration_handoff,
    )

    generated_dossier = assess_case(
        VulnerabilityCase.from_dict(_json(EXAMPLE)),
        policy=VulnerabilityPolicy.from_dict(_json(POLICY)),
        assessed_at="2026-01-20T00:00:00Z",
    ).to_dict()
    committed_dossier = _json(ASSURANCE_DOSSIER_EXAMPLE)
    if committed_dossier != generated_dossier:
        raise SystemExit("committed integration dossier differs from deterministic assessment")
    validate_document(SCHEMA_DIR / "assurance-dossier.schema.json", committed_dossier)
    validate_document(
        INTEGRATION_EXAMPLES["ai-threat-evaluation"]["peer"],
        _json(AI_THREAT_REPORT_EXAMPLE),
    )

    for profile, paths in sorted(INTEGRATION_EXAMPLES.items()):
        handoff_path = ROOT / "examples" / f"synthetic-{profile}-handoff.json"
        verification_path = ROOT / "examples" / f"synthetic-{profile}-verification.json"
        handoff_document = _json(handoff_path)
        verification_document = _json(verification_path)
        validate_document(SCHEMA_DIR / "integration-handoff.schema.json", handoff_document)
        validate_document(
            SCHEMA_DIR / "peer-contract-identity.schema.json",
            handoff_document["peer_contract"],
        )
        handoff = IntegrationHandoff.from_dict(handoff_document)
        peer_bytes = paths["peer"].read_bytes()
        if git_blob_id(peer_bytes) != handoff.peer_contract.blob:
            raise SystemExit(f"{profile} peer snapshot differs from its exact Git blob")
        verification = verify_integration_handoff(
            handoff,
            _json(paths["payload"]),
            peer_bytes,
            verified_at="2026-01-20T00:15:00Z",
        ).to_dict()
        if verification != verification_document:
            raise SystemExit(f"{profile} verification differs from the reference output")
        validate_document(
            SCHEMA_DIR / "integration-verification.schema.json",
            verification,
        )
        if verification["integration_position"] != "verified" or verification["gaps"]:
            raise SystemExit(f"{profile} reference handoff must verify without local gaps")
        if any(verification["non_claims"].values()):
            raise SystemExit(f"{profile} non-claims must remain explicit false values")
        if handoff.synthetic is not True:
            raise SystemExit(f"{profile} committed handoff must be explicitly synthetic")


def verify() -> dict[str, dict[str, object]]:
    manifest = _json(MANIFEST)
    computed = compute()
    for key, value in computed.items():
        if manifest.get(key) != value:
            raise SystemExit(f"{key} mismatch: expected {manifest.get(key)!r}, computed {value!r}")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if project.get("version") != manifest.get("current_release_version") or project.get(
        "version"
    ) != "1.0.0":
        raise SystemExit("package and release-contract versions must equal 1.0.0")
    if manifest.get("target_stable_version") != "1.0.0":
        raise SystemExit("stable target must remain 1.0.0")
    if manifest.get("release_stage") != "stable-reference":
        raise SystemExit("v1 release stage must remain stable-reference")
    if manifest.get("independent_review_completed") is not False:
        raise SystemExit("release must not imply completed independent review")
    if manifest.get("independent_review_requirement") != "waived-by-owner":
        raise SystemExit("release must preserve the explicit owner waiver")
    if "Development Status :: 5 - Production/Stable" not in project.get("classifiers", []):
        raise SystemExit("v1 package classifier must remain Production/Stable")
    if sorted(project.get("scripts", {})) != ["vulnevidenceops"]:
        raise SystemExit("console-script surface differs from the v1 stable contract")
    if project.get("dependencies") != ["cryptography>=44,<47", "jsonschema>=4.23,<5"]:
        raise SystemExit("runtime dependency surface differs from the v1 stable contract")
    from vulnevidenceops.cli import STABLE_CLI_COMMANDS

    if list(STABLE_CLI_COMMANDS) != manifest.get("stable_cli_commands"):
        raise SystemExit("CLI command surface differs from the release contract")
    if manifest.get("requires_human_release_decision") is not True:
        raise SystemExit("tagging and publication must remain human decisions")
    if manifest.get("human_release_decision_recorded") is not True:
        raise SystemExit("v1 release requires a recorded human decision")
    if manifest.get("source_promotion_only") is not False:
        raise SystemExit("v1 final release must not remain source-promotion-only")
    if manifest.get("git_tag_and_github_release_authorized") is not True:
        raise SystemExit("v1 tag and GitHub Release authorization is missing")
    if manifest.get("package_publication_authorized") is not False:
        raise SystemExit("package publication must remain unauthorized")
    if manifest.get("deployment_authorized") is not False:
        raise SystemExit("deployment must remain unauthorized")
    if any(manifest.get("non_claims", {}).values()):
        raise SystemExit("release non-claims must remain explicit false values")

    governance = _json(GOVERNANCE)
    if governance.get("enforcement_verified") is not False:
        raise SystemExit("live repository enforcement must not be inferred")
    if manifest.get("repository_governance_enforcement_verified") is not False:
        raise SystemExit("release contract must preserve unverified repository enforcement")
    if governance.get("required_workflow_names") != [
        "CI",
        "CodeQL",
        "Reference Gate",
        "Stable Release",
    ]:
        raise SystemExit("repository governance workflow set differs from the stable contract")

    required_docs = [
        ROOT / "CHANGELOG.md",
        ROOT / "COMPATIBILITY.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "SECURITY.md",
        ROOT / "docs" / "ARCHITECTURE.md",
        ROOT / "docs" / "CONTROL_EVIDENCE_MATRIX.md",
        ROOT / "docs" / "EXPOSURE_CONTEXT.md",
        ROOT / "docs" / "INTAKE_ADAPTERS.md",
        ROOT / "docs" / "INTEGRATION_CONTRACTS.md",
        ROOT / "docs" / "PORTFOLIO_ASSURANCE.md",
        ROOT / "docs" / "ROADMAP.md",
        ROOT / "docs" / "RELEASE_PROCESS.md",
        ROOT / "docs" / "SECURITY_BOUNDARY.md",
        ROOT / "docs" / "SIGNED_EVIDENCE.md",
        ROOT / "docs" / "THREAT_MODEL.md",
        ROOT / "docs" / "V1_STABLE_REFERENCE.md",
    ]
    missing = [
        path.relative_to(ROOT).as_posix() for path in required_docs if not path.is_file()
    ]
    if missing:
        raise SystemExit("required documentation is missing: " + ", ".join(missing))

    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    if not re.search(r"^version:\s*1\.0\.0\s*$", citation, re.MULTILINE):
        raise SystemExit("CITATION.cff version differs from the package version")

    _verify_action_pins()
    _verify_examples()
    _verify_intake_examples()
    _verify_exposure_example()
    _verify_portfolio_example()
    _verify_signed_evidence_examples()
    _verify_integration_examples()
    from stable_candidate import verify as verify_stable_candidate

    verify_stable_candidate()
    return computed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit", action="store_true")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    computed = compute()
    if args.emit:
        print(json.dumps(computed, indent=2, sort_keys=True))
        if not args.verify:
            return 0
    if args.verify:
        verify()
        print(json.dumps(computed, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
