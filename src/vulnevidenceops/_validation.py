"""Shared local invariants for public governance records."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def require_enum(name: str, value: str, allowed: frozenset[str]) -> None:
    if value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise ValueError(f"{name} must be one of: {choices}")


def require_sha256(name: str, value: str) -> None:
    if not _SHA256.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase 64-character SHA-256 digest")


def parse_timestamp(name: str, value: str) -> datetime:
    require_text(name, value)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(UTC)


def normalize_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def require_unique(name: str, values: Iterable[str]) -> None:
    values = tuple(values)
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must not contain duplicate values")


def require_record_fields(
    value: dict[str, Any],
    *,
    schema_version: str,
    required: Iterable[str],
    optional: Iterable[str] = (),
) -> None:
    required_fields = {"schema_version", *required}
    missing = sorted(required_fields - set(value))
    if missing:
        raise ValueError("missing required fields: " + ", ".join(missing))
    unexpected = sorted(set(value) - required_fields - set(optional))
    if unexpected:
        raise ValueError("unexpected fields: " + ", ".join(unexpected))
    if value["schema_version"] != schema_version:
        raise ValueError(f"schema_version must equal {schema_version}")
