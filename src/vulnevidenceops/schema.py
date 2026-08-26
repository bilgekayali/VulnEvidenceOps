"""Draft 2020-12 validation for explicit public schema files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from ._validation import parse_timestamp

FORMAT_CHECKER = FormatChecker()


@FORMAT_CHECKER.checks("date-time", raises=ValueError)
def _is_datetime(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parse_timestamp("date-time", value)
    return True


class DocumentValidationError(ValueError):
    """Raised when a document does not satisfy its selected public schema."""


def validate_document(schema_path: str | Path, document: Any) -> None:
    """Validate a JSON-compatible document and report stable, ordered errors."""
    schema_path = Path(schema_path)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    registry = Registry()
    for candidate in sorted(schema_path.parent.glob("*.schema.json")):
        contents = json.loads(candidate.read_text(encoding="utf-8"))
        if "$id" in contents:
            registry = registry.with_resource(
                contents["$id"],
                Resource.from_contents(contents),
            )
    errors = sorted(
        Draft202012Validator(
            schema,
            registry=registry,
            format_checker=FORMAT_CHECKER,
        ).iter_errors(document),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        rendered = []
        for error in errors:
            location = "/".join(str(part) for part in error.absolute_path) or "<root>"
            rendered.append(f"{location}: {error.message}")
        raise DocumentValidationError("; ".join(rendered))
