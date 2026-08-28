"""Emit and verify the frozen VulnEvidenceOps v1 compatibility baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "compatibility" / "v1-stable-baseline.json"
REVIEW = ROOT / "release" / "independent-review.json"
EVIDENCE = ROOT / "release" / "v1.0.0rc1-evidence.json"


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def compute_baseline() -> dict[str, object]:
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    import vulnevidenceops
    from vulnevidenceops.cli import STABLE_CLI_COMMANDS

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    schemas = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted((ROOT / "schemas").glob("*.schema.json"))
    ]
    return {
        "schema_version": "vulnevidenceops.compatibility-baseline.v1",
        "target_stable_version": "1.0.0",
        "python_api_symbols": sorted(vulnevidenceops.__all__),
        "cli_commands": list(STABLE_CLI_COMMANDS),
        "console_scripts": project["scripts"],
        "runtime_dependencies": project["dependencies"],
        "requires_python": project["requires-python"],
        "supported_python": ["3.11", "3.12", "3.13"],
        "schemas": schemas,
    }


def verify(*, require_final_review: bool = False) -> dict[str, object]:
    expected = _json(BASELINE)
    computed = compute_baseline()
    if expected != computed:
        raise SystemExit("v1 compatibility baseline drifted")

    review = _json(REVIEW)
    if review.get("schema_version") != "vulnevidenceops.independent-review.v1":
        raise SystemExit("independent-review schema version differs")
    completed = review.get("review_completed")
    if not isinstance(completed, bool):
        raise SystemExit("review_completed must be a boolean")
    reviewer = review.get("reviewer")
    evidence_refs = review.get("evidence_refs")
    if completed and (not isinstance(reviewer, str) or not reviewer.strip()):
        raise SystemExit("a completed review requires an identified reviewer")
    if completed and (not isinstance(evidence_refs, list) or not evidence_refs):
        raise SystemExit("a completed review requires evidence references")
    if not completed and (reviewer is not None or evidence_refs != []):
        raise SystemExit("a pending review must not imply reviewer identity or evidence")
    requirement_status = review.get("requirement_status")
    waiver = review.get("waiver")
    if requirement_status not in {"required", "waived-by-owner"}:
        raise SystemExit("independent-review requirement status differs")
    waived = requirement_status == "waived-by-owner"
    if waived:
        if not isinstance(waiver, dict):
            raise SystemExit("an owner waiver requires an accountable waiver record")
        if not all(
            isinstance(waiver.get(field), str) and waiver[field].strip()
            for field in ("approved_by", "approved_at", "reason")
        ):
            raise SystemExit("owner waiver identity, date and reason are required")
    elif waiver is not None:
        raise SystemExit("a required review must not contain a waiver")
    if require_final_review and not (completed or waived):
        raise SystemExit("final stable promotion is blocked: independent human review pending")

    evidence = _json(EVIDENCE)
    required_gates = ["CI", "CodeQL", "Reference Gate", "Stable Candidate"]
    if evidence.get("candidate_version") != "1.0.0rc1":
        raise SystemExit("candidate evidence version differs")
    if evidence.get("required_workflow_names") != required_gates:
        raise SystemExit("candidate evidence workflow set differs")
    if evidence.get("source_commit") is not None:
        raise SystemExit("pre-merge candidate evidence must not invent an exact source commit")
    if evidence.get("publication_completed") is not False:
        raise SystemExit("candidate evidence must not imply publication")
    if evidence.get("independent_review_completed") is not completed:
        raise SystemExit("candidate evidence and review status differ")
    if evidence.get("independent_review_requirement") != requirement_status:
        raise SystemExit("candidate evidence and review requirement differ")
    return computed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--require-final-review", action="store_true")
    args = parser.parse_args(argv)
    computed = compute_baseline()
    if args.emit:
        print(json.dumps(computed, indent=2, ensure_ascii=False))
    if args.verify or args.require_final_review:
        verify(require_final_review=args.require_final_review)
        if not args.emit:
            print(json.dumps(computed, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
