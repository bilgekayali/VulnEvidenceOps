"""Local command-line interface for vulnerability evidence contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from ._version import PACKAGE_VERSION
from .assurance import assess_case
from .canonical import sha256_digest
from .exposure import ExposureContextBundle, assess_exposure_context
from .intake import adapt_cyclonedx, adapt_sarif
from .models import VulnerabilityCase, VulnerabilityPolicy
from .schema import DocumentValidationError, validate_document

STABLE_CLI_COMMANDS = ("assess", "digest-json", "exposure", "intake", "schema")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_json_artifact(path: Path) -> tuple[Any, str]:
    artifact = path.read_bytes()
    return json.loads(artifact.decode("utf-8")), hashlib.sha256(artifact).hexdigest()


def _write_json(document: Any, output: Path | None) -> None:
    rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if output is None:
        print(rendered, end="")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnevidenceops",
        description="Deterministic vulnerability-evidence governance utilities.",
    )
    parser.add_argument("--version", action="version", version=PACKAGE_VERSION)
    commands = parser.add_subparsers(dest="command", required=True)

    digest = commands.add_parser("digest-json", help="Digest strict canonical JSON.")
    digest.add_argument("document", type=Path)

    schema = commands.add_parser("schema", help="Validate a document against a JSON Schema.")
    schema.add_argument("schema", type=Path)
    schema.add_argument("document", type=Path)

    intake = commands.add_parser(
        "intake",
        help="Map a supported source artifact to a digest-bound intake batch.",
    )
    intake.add_argument("source_format", choices=("cyclonedx", "sarif"))
    intake.add_argument("document", type=Path)
    intake.add_argument("--artifact-ref", required=True)
    intake.add_argument("--collected-at", required=True)
    intake.add_argument("--observed-at", required=True)
    intake.add_argument("--source-identity", required=True)
    intake.add_argument("--source-ref", required=True)
    intake.add_argument("--asset-ref")
    intake.add_argument("--asset-ref-prefix")
    intake.add_argument("--synthetic", action="store_true")
    intake.add_argument("--output", type=Path)

    assess = commands.add_parser("assess", help="Build a deterministic assurance dossier.")
    assess.add_argument("case", type=Path)
    assess.add_argument("--policy", type=Path)
    assess.add_argument("--as-of", required=True)
    assess.add_argument("--output", type=Path)

    exposure = commands.add_parser(
        "exposure",
        help="Assess evidence-backed exploit and business context currentness.",
    )
    exposure.add_argument("bundle", type=Path)
    exposure.add_argument("--as-of", required=True)
    exposure.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "digest-json":
            print(sha256_digest(_read_json(args.document)))
            return 0
        if args.command == "schema":
            validate_document(args.schema, _read_json(args.document))
            print("valid")
            return 0
        if args.command == "intake":
            document, artifact_sha256 = _read_json_artifact(args.document)
            common = {
                "artifact_ref": args.artifact_ref,
                "artifact_sha256": artifact_sha256,
                "collected_at": args.collected_at,
                "observed_at": args.observed_at,
                "source_identity": args.source_identity,
                "source_ref": args.source_ref,
                "synthetic": args.synthetic,
            }
            if args.source_format == "sarif":
                if args.asset_ref is None:
                    raise ValueError("--asset-ref is required for SARIF intake")
                if args.asset_ref_prefix is not None:
                    raise ValueError("--asset-ref-prefix is only valid for CycloneDX intake")
                batch = adapt_sarif(document, asset_ref=args.asset_ref, **common)
            else:
                if args.asset_ref_prefix is None:
                    raise ValueError("--asset-ref-prefix is required for CycloneDX intake")
                if args.asset_ref is not None:
                    raise ValueError("--asset-ref is only valid for SARIF intake")
                batch = adapt_cyclonedx(
                    document,
                    asset_ref_prefix=args.asset_ref_prefix,
                    **common,
                )
            _write_json(batch.to_dict(), args.output)
            return 0
        if args.command == "assess":
            case = VulnerabilityCase.from_dict(_read_json(args.case))
            policy = (
                VulnerabilityPolicy.from_dict(_read_json(args.policy))
                if args.policy is not None
                else VulnerabilityPolicy()
            )
            dossier = assess_case(case, assessed_at=args.as_of, policy=policy)
            _write_json(dossier.to_dict(), args.output)
            return 0
        if args.command == "exposure":
            bundle = ExposureContextBundle.from_dict(_read_json(args.bundle))
            assessment = assess_exposure_context(bundle, assessed_at=args.as_of)
            _write_json(assessment.to_dict(), args.output)
            return 0
    except (DocumentValidationError, KeyError, TypeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    raise AssertionError("unreachable command")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
