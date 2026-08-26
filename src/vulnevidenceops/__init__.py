"""Intentional public surface for VulnEvidenceOps v0.1."""

from ._version import PACKAGE_VERSION
from .assurance import assess_case
from .canonical import canonical_json_bytes, sha256_digest
from .models import (
    AssuranceDossier,
    EvidenceReference,
    RemediationRecord,
    RiskAcceptance,
    TriageDecision,
    VerificationRecord,
    VulnerabilityCase,
    VulnerabilityFinding,
    VulnerabilityPolicy,
)
from .schema import DocumentValidationError, validate_document

__version__ = PACKAGE_VERSION

__all__ = [
    "AssuranceDossier",
    "DocumentValidationError",
    "EvidenceReference",
    "PACKAGE_VERSION",
    "RemediationRecord",
    "RiskAcceptance",
    "TriageDecision",
    "VerificationRecord",
    "VulnerabilityCase",
    "VulnerabilityFinding",
    "VulnerabilityPolicy",
    "assess_case",
    "canonical_json_bytes",
    "sha256_digest",
    "validate_document",
]
