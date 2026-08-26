import pytest

from vulnevidenceops import canonical_json_bytes, sha256_digest


def test_canonical_json_is_order_independent_and_strict():
    left = {"z": [2, 1], "a": "değer"}
    right = {"a": "değer", "z": [2, 1]}

    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert sha256_digest(left) == sha256_digest(right)
    assert len(sha256_digest(left)) == 64

    with pytest.raises(ValueError, match="Out of range float"):
        canonical_json_bytes({"not_json": float("nan")})
