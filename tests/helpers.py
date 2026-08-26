from __future__ import annotations

import copy
import json
from pathlib import Path

from vulnevidenceops import VulnerabilityCase, VulnerabilityPolicy

ROOT = Path(__file__).resolve().parents[1]


def case_document() -> dict:
    return copy.deepcopy(
        json.loads((ROOT / "examples" / "synthetic-case.json").read_text(encoding="utf-8"))
    )


def policy_document() -> dict:
    return copy.deepcopy(
        json.loads((ROOT / "examples" / "synthetic-policy.json").read_text(encoding="utf-8"))
    )


def case() -> VulnerabilityCase:
    return VulnerabilityCase.from_dict(case_document())


def policy() -> VulnerabilityPolicy:
    return VulnerabilityPolicy.from_dict(policy_document())
