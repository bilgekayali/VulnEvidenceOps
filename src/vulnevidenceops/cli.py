"""Local command-line interface for vulnerability evidence contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._version import PACKAGE_VERSION
from .assurance import assess_case
from .canonical import sha256_digest
from .exposure import ExposureContextBundle, assess_exposure_context
from .intake import adapt_cyclonedx, adapt_sarif
from .models import VulnerabilityCase, VulnerabilityPolicy
from .portfolio import PortfolioBundle, assess_portfolio
from .schema import DocumentValidationError, validate_document
from .signed_evidence import (
    AnchorReceipt,
    SignedEvidenceEnvelope,
    VerificationKey,
    sign_evidence,
    verify_signed_evidence,
)

STABLE_CLI_COMMANDS = (
    "assess",
    "digest-json",
    "exposure",
    "intake",
    "portfolio",
    "schema",
    "sign-evidence",
    "verify-evidence",
)


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


def _read_ed25519_private_key(path: Path) -> Ed25519PrivateKey:
    private_key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("--private-key must contain an unencrypted Ed25519 PKCS#8 PEM key")
    return private_key


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

    portfolio = commands.add_parser(
        "portfolio",
        help="Build raw SLA, exception and accountability portfolio views.",
    )
    portfolio.add_argument("bundle", type=Path)
    portfolio.add_argument("--as-of", required=True)
    portfolio.add_argument("--output", type=Path)

    sign = commands.add_parser(
        "sign-evidence",
        help="Sign canonical JSON using an externally managed Ed25519 private key.",
    )
    sign.add_argument("payload", type=Path)
    sign.add_argument("--payload-type", required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--private-key", required=True, type=Path)
    sign.add_argument("--signed-at", required=True)
    sign.add_argument("--output", type=Path)

    verify = commands.add_parser(
        "verify-evidence",
        help="Verify local signature, digest, key-time and anchor-binding facts.",
    )
    verify.add_argument("envelope", type=Path)
    verify.add_argument("--key", required=True, type=Path)
    verify.add_argument("--receipt", action="append", default=[], type=Path)
    verify.add_argument("--as-of", required=True)
    verify.add_argument("--output", type=Path)
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
        if args.command == "portfolio":
            bundle = PortfolioBundle.from_dict(_read_json(args.bundle))
            view = assess_portfolio(bundle, assessed_at=args.as_of)
            _write_json(view.to_dict(), args.output)
            return 0
        if args.command == "sign-evidence":
            envelope = sign_evidence(
                _read_json(args.payload),
                payload_type=args.payload_type,
                key_id=args.key_id,
                private_key=_read_ed25519_private_key(args.private_key),
                signed_at=args.signed_at,
            )
            _write_json(envelope.to_dict(), args.output)
            return 0
        if args.command == "verify-evidence":
            envelope = SignedEvidenceEnvelope.from_dict(_read_json(args.envelope))
            key = VerificationKey.from_dict(_read_json(args.key))
            receipts = tuple(
                AnchorReceipt.from_dict(_read_json(path)) for path in args.receipt
            )
            verification = verify_signed_evidence(
                envelope,
                key,
                verified_at=args.as_of,
                anchor_receipts=receipts,
            )
            _write_json(verification.to_dict(), args.output)
            return 0
    except (DocumentValidationError, KeyError, TypeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    raise AssertionError("unreachable command")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
