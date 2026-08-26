"""Deterministic JSON identities for governance records."""

from __future__ import annotations

import hashlib
import json


def canonical_json_bytes(document: object) -> bytes:
    """Return strict, stable UTF-8 JSON bytes for a JSON-compatible document."""
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_digest(document: object) -> str:
    """Return the lowercase SHA-256 identity of a JSON-compatible document."""
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()
