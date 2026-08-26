"""Local command-line interface for vulnerability evidence contracts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ._version import PACKAGE_VERSION
from .assurance import assess_case
from .canonical import sha256_digest
from .models import VulnerabilityCase, VulnerabilityPolicy
from .schema import DocumentValidationError, validate_document

STABLE_CLI_COMMANDS = ("assess", "digest-json", "schema")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


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

    assess = commands.add_parser("assess", help="Build a deterministic assurance dossier.")
    assess.add_argument("case", type=Path)
    assess.add_argument("--policy", type=Path)
    assess.add_argument("--as-of", required=True)
    assess.add_argument("--output", type=Path)
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
    except (DocumentValidationError, KeyError, TypeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    raise AssertionError("unreachable command")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
