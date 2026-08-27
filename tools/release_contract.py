"""Emit and verify the VulnEvidenceOps v0.2 release contract."""

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
INTAKE_MODULE = ROOT / "src" / "vulnevidenceops" / "intake.py"
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


def compute() -> dict[str, dict[str, object]]:
    return {
        "public_api": _public_api(),
        "schema_set": _schema_set(),
        "control_matrix": _control_matrix(),
        "synthetic_example": _synthetic_example(),
        "intake_adapters": _intake_adapters(),
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


def verify() -> dict[str, dict[str, object]]:
    manifest = _json(MANIFEST)
    computed = compute()
    for key, value in computed.items():
        if manifest.get(key) != value:
            raise SystemExit(f"{key} mismatch: expected {manifest.get(key)!r}, computed {value!r}")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if project.get("version") != manifest.get("current_release_version") or project.get(
        "version"
    ) != "0.2.0":
        raise SystemExit("package and release-contract versions must equal 0.2.0")
    if manifest.get("release_stage") != "alpha-reference":
        raise SystemExit("v0.2 release stage must remain alpha-reference")
    if "Development Status :: 3 - Alpha" not in project.get("classifiers", []):
        raise SystemExit("v0.2 package classifier must remain Alpha")
    if sorted(project.get("scripts", {})) != ["vulnevidenceops"]:
        raise SystemExit("console-script surface differs from the v0.2 contract")
    from vulnevidenceops.cli import STABLE_CLI_COMMANDS

    if list(STABLE_CLI_COMMANDS) != manifest.get("stable_cli_commands"):
        raise SystemExit("CLI command surface differs from the release contract")
    if manifest.get("requires_human_release_decision") is not True:
        raise SystemExit("tagging and publication must remain human decisions")
    if manifest.get("source_promotion_only") is not True:
        raise SystemExit("v0.2 source promotion boundary was removed")
    if any(manifest.get("non_claims", {}).values()):
        raise SystemExit("release non-claims must remain explicit false values")

    governance = _json(GOVERNANCE)
    if governance.get("enforcement_verified") is not False:
        raise SystemExit("live repository enforcement must not be inferred")
    if manifest.get("repository_governance_enforcement_verified") is not False:
        raise SystemExit("release contract must preserve unverified repository enforcement")
    if governance.get("required_workflow_names") != ["CI", "CodeQL", "Reference Gate"]:
        raise SystemExit("repository governance workflow set differs from v0.1")

    required_docs = [
        ROOT / "CHANGELOG.md",
        ROOT / "COMPATIBILITY.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "SECURITY.md",
        ROOT / "docs" / "ARCHITECTURE.md",
        ROOT / "docs" / "CONTROL_EVIDENCE_MATRIX.md",
        ROOT / "docs" / "INTAKE_ADAPTERS.md",
        ROOT / "docs" / "ROADMAP.md",
        ROOT / "docs" / "RELEASE_PROCESS.md",
        ROOT / "docs" / "SECURITY_BOUNDARY.md",
        ROOT / "docs" / "THREAT_MODEL.md",
    ]
    missing = [
        path.relative_to(ROOT).as_posix() for path in required_docs if not path.is_file()
    ]
    if missing:
        raise SystemExit("required documentation is missing: " + ", ".join(missing))

    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    if not re.search(r"^version:\s*0\.2\.0\s*$", citation, re.MULTILINE):
        raise SystemExit("CITATION.cff version differs from the package version")

    _verify_action_pins()
    _verify_examples()
    _verify_intake_examples()
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
