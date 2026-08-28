"""Intentional public surface for VulnEvidenceOps v0.5."""

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
from .portfolio import PortfolioAssuranceView, PortfolioBundle, assess_portfolio
from .schema import DocumentValidationError, validate_document
from .signed_evidence import (
    AnchorReceipt,
    BuildProvenance,
    SignatureVerification,
    SignedEvidenceEnvelope,
    VerificationKey,
    sign_evidence,
    verify_signed_evidence,
)

__version__ = PACKAGE_VERSION

__all__ = [
    "AnchorReceipt",
    "AssuranceDossier",
    "BuildProvenance",
    "BusinessCriticality",
    "DocumentValidationError",
    "EvidenceReference",
    "ExploitIntelligence",
    "ExposureContextAssessment",
    "ExposureContextBundle",
    "IntakeBatch",
    "IntakeMapping",
    "PACKAGE_VERSION",
    "PortfolioAssuranceView",
    "PortfolioBundle",
    "RemediationRecord",
    "RiskAcceptance",
    "SignatureVerification",
    "SignedEvidenceEnvelope",
    "TriageDecision",
    "VerificationRecord",
    "VerificationKey",
    "VulnerabilityCase",
    "VulnerabilityFinding",
    "VulnerabilityPolicy",
    "assess_case",
    "assess_exposure_context",
    "assess_portfolio",
    "adapt_cyclonedx",
    "adapt_sarif",
    "canonical_json_bytes",
    "sha256_digest",
    "sign_evidence",
    "validate_document",
    "verify_signed_evidence",
]
