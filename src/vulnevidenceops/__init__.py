"""Intentional public surface for VulnEvidenceOps v0.3."""

from ._version import PACKAGE_VERSION
from .assurance import assess_case
from .canonical import canonical_json_bytes, sha256_digest
from .exposure import (
    BusinessCriticality,
    ExploitIntelligence,
    ExposureContextAssessment,
    ExposureContextBundle,
    assess_exposure_context,
)
from .intake import IntakeBatch, IntakeMapping, adapt_cyclonedx, adapt_sarif
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
    "BusinessCriticality",
    "DocumentValidationError",
    "EvidenceReference",
    "ExploitIntelligence",
    "ExposureContextAssessment",
    "ExposureContextBundle",
    "IntakeBatch",
    "IntakeMapping",
    "PACKAGE_VERSION",
    "RemediationRecord",
    "RiskAcceptance",
    "TriageDecision",
    "VerificationRecord",
    "VulnerabilityCase",
    "VulnerabilityFinding",
    "VulnerabilityPolicy",
    "assess_case",
    "assess_exposure_context",
    "adapt_cyclonedx",
    "adapt_sarif",
    "canonical_json_bytes",
    "sha256_digest",
    "validate_document",
]
