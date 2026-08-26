"""Immutable records for vulnerability-evidence governance."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ._validation import (
    parse_timestamp,
    require_enum,
    require_record_fields,
    require_sha256,
    require_text,
    require_unique,
)

SEVERITIES = frozenset({"critical", "high", "medium", "low", "informational"})
TRIAGE_DISPOSITIONS = frozenset({"confirmed", "duplicate", "false_positive"})
VERIFICATION_OUTCOMES = frozenset({"effective", "partial", "ineffective"})


@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    artifact_ref: str
    artifact_sha256: str
    media_type: str
    collected_at: str
    source_identity: str
    synthetic: bool = False

    def __post_init__(self) -> None:
        for name in ("evidence_id", "artifact_ref", "media_type", "source_identity"):
            require_text(name, getattr(self, name))
        require_sha256("artifact_sha256", self.artifact_sha256)
        parse_timestamp("collected_at", self.collected_at)
        if not isinstance(self.synthetic, bool):
            raise ValueError("synthetic must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.evidence-reference.v1",
            "evidence_id": self.evidence_id,
            "artifact_ref": self.artifact_ref,
            "artifact_sha256": self.artifact_sha256,
            "media_type": self.media_type,
            "collected_at": self.collected_at,
            "source_identity": self.source_identity,
            "synthetic": self.synthetic,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> EvidenceReference:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.evidence-reference.v1",
            required=(
                "evidence_id",
                "artifact_ref",
                "artifact_sha256",
                "media_type",
                "collected_at",
                "source_identity",
                "synthetic",
            ),
        )
        return cls(
            evidence_id=value["evidence_id"],
            artifact_ref=value["artifact_ref"],
            artifact_sha256=value["artifact_sha256"],
            media_type=value["media_type"],
            collected_at=value["collected_at"],
            source_identity=value["source_identity"],
            synthetic=value["synthetic"],
        )


@dataclass(frozen=True)
class VulnerabilityFinding:
    finding_id: str
    asset_ref: str
    source_ref: str
    title: str
    severity: str
    first_observed_at: str
    technical_identifiers: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("finding_id", "asset_ref", "source_ref", "title"):
            require_text(name, getattr(self, name))
        require_enum("severity", self.severity, SEVERITIES)
        parse_timestamp("first_observed_at", self.first_observed_at)
        for value in self.technical_identifiers:
            require_text("technical_identifier", value)
        for value in self.evidence_refs:
            require_text("evidence_ref", value)
        require_unique("technical_identifiers", self.technical_identifiers)
        require_unique("evidence_refs", self.evidence_refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.vulnerability-finding.v1",
            "finding_id": self.finding_id,
            "asset_ref": self.asset_ref,
            "source_ref": self.source_ref,
            "title": self.title,
            "severity": self.severity,
            "first_observed_at": self.first_observed_at,
            "technical_identifiers": list(self.technical_identifiers),
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> VulnerabilityFinding:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.vulnerability-finding.v1",
            required=(
                "finding_id",
                "asset_ref",
                "source_ref",
                "title",
                "severity",
                "first_observed_at",
                "technical_identifiers",
                "evidence_refs",
            ),
        )
        return cls(
            finding_id=value["finding_id"],
            asset_ref=value["asset_ref"],
            source_ref=value["source_ref"],
            title=value["title"],
            severity=value["severity"],
            first_observed_at=value["first_observed_at"],
            technical_identifiers=tuple(value["technical_identifiers"]),
            evidence_refs=tuple(value["evidence_refs"]),
        )


@dataclass(frozen=True)
class TriageDecision:
    decision_id: str
    finding_id: str
    decided_at: str
    accountable_role: str
    disposition: str
    rationale: str
    evidence_refs: tuple[str, ...] = ()
    duplicate_of: str | None = None

    def __post_init__(self) -> None:
        for name in ("decision_id", "finding_id", "accountable_role", "rationale"):
            require_text(name, getattr(self, name))
        parse_timestamp("decided_at", self.decided_at)
        require_enum("disposition", self.disposition, TRIAGE_DISPOSITIONS)
        require_unique("evidence_refs", self.evidence_refs)
        if self.disposition == "duplicate":
            if self.duplicate_of is None:
                raise ValueError("duplicate_of is required for duplicate dispositions")
            require_text("duplicate_of", self.duplicate_of)
            if self.duplicate_of == self.finding_id:
                raise ValueError("duplicate_of must reference a different finding")
        elif self.duplicate_of is not None:
            raise ValueError("duplicate_of is only valid for duplicate dispositions")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": "vulnevidenceops.triage-decision.v1",
            "decision_id": self.decision_id,
            "finding_id": self.finding_id,
            "decided_at": self.decided_at,
            "accountable_role": self.accountable_role,
            "disposition": self.disposition,
            "rationale": self.rationale,
            "evidence_refs": list(self.evidence_refs),
        }
        if self.duplicate_of is not None:
            result["duplicate_of"] = self.duplicate_of
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TriageDecision:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.triage-decision.v1",
            required=(
                "decision_id",
                "finding_id",
                "decided_at",
                "accountable_role",
                "disposition",
                "rationale",
                "evidence_refs",
            ),
            optional=("duplicate_of",),
        )
        return cls(
            decision_id=value["decision_id"],
            finding_id=value["finding_id"],
            decided_at=value["decided_at"],
            accountable_role=value["accountable_role"],
            disposition=value["disposition"],
            rationale=value["rationale"],
            evidence_refs=tuple(value["evidence_refs"]),
            duplicate_of=value.get("duplicate_of"),
        )


@dataclass(frozen=True)
class RemediationRecord:
    remediation_id: str
    finding_id: str
    owner_role: str
    planned_at: str
    due_at: str
    action: str
    change_ref: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("remediation_id", "finding_id", "owner_role", "action", "change_ref"):
            require_text(name, getattr(self, name))
        planned = parse_timestamp("planned_at", self.planned_at)
        due = parse_timestamp("due_at", self.due_at)
        if due < planned:
            raise ValueError("due_at must not precede planned_at")
        require_unique("evidence_refs", self.evidence_refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.remediation-record.v1",
            "remediation_id": self.remediation_id,
            "finding_id": self.finding_id,
            "owner_role": self.owner_role,
            "planned_at": self.planned_at,
            "due_at": self.due_at,
            "action": self.action,
            "change_ref": self.change_ref,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RemediationRecord:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.remediation-record.v1",
            required=(
                "remediation_id",
                "finding_id",
                "owner_role",
                "planned_at",
                "due_at",
                "action",
                "change_ref",
                "evidence_refs",
            ),
        )
        return cls(
            remediation_id=value["remediation_id"],
            finding_id=value["finding_id"],
            owner_role=value["owner_role"],
            planned_at=value["planned_at"],
            due_at=value["due_at"],
            action=value["action"],
            change_ref=value["change_ref"],
            evidence_refs=tuple(value["evidence_refs"]),
        )


@dataclass(frozen=True)
class RiskAcceptance:
    decision_id: str
    finding_id: str
    accepted_at: str
    expires_at: str
    risk_owner_role: str
    approver_role: str
    rationale: str
    compensating_control_refs: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "decision_id",
            "finding_id",
            "risk_owner_role",
            "approver_role",
            "rationale",
        ):
            require_text(name, getattr(self, name))
        accepted = parse_timestamp("accepted_at", self.accepted_at)
        expires = parse_timestamp("expires_at", self.expires_at)
        if expires <= accepted:
            raise ValueError("expires_at must be later than accepted_at")
        require_unique("compensating_control_refs", self.compensating_control_refs)
        require_unique("evidence_refs", self.evidence_refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.risk-acceptance.v1",
            "decision_id": self.decision_id,
            "finding_id": self.finding_id,
            "accepted_at": self.accepted_at,
            "expires_at": self.expires_at,
            "risk_owner_role": self.risk_owner_role,
            "approver_role": self.approver_role,
            "rationale": self.rationale,
            "compensating_control_refs": list(self.compensating_control_refs),
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RiskAcceptance:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.risk-acceptance.v1",
            required=(
                "decision_id",
                "finding_id",
                "accepted_at",
                "expires_at",
                "risk_owner_role",
                "approver_role",
                "rationale",
                "compensating_control_refs",
                "evidence_refs",
            ),
        )
        return cls(
            decision_id=value["decision_id"],
            finding_id=value["finding_id"],
            accepted_at=value["accepted_at"],
            expires_at=value["expires_at"],
            risk_owner_role=value["risk_owner_role"],
            approver_role=value["approver_role"],
            rationale=value["rationale"],
            compensating_control_refs=tuple(value["compensating_control_refs"]),
            evidence_refs=tuple(value["evidence_refs"]),
        )


@dataclass(frozen=True)
class VerificationRecord:
    verification_id: str
    finding_id: str
    performed_at: str
    verifier_role: str
    outcome: str
    method: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("verification_id", "finding_id", "verifier_role", "method"):
            require_text(name, getattr(self, name))
        parse_timestamp("performed_at", self.performed_at)
        require_enum("outcome", self.outcome, VERIFICATION_OUTCOMES)
        require_unique("evidence_refs", self.evidence_refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.verification-record.v1",
            "verification_id": self.verification_id,
            "finding_id": self.finding_id,
            "performed_at": self.performed_at,
            "verifier_role": self.verifier_role,
            "outcome": self.outcome,
            "method": self.method,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> VerificationRecord:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.verification-record.v1",
            required=(
                "verification_id",
                "finding_id",
                "performed_at",
                "verifier_role",
                "outcome",
                "method",
                "evidence_refs",
            ),
        )
        return cls(
            verification_id=value["verification_id"],
            finding_id=value["finding_id"],
            performed_at=value["performed_at"],
            verifier_role=value["verifier_role"],
            outcome=value["outcome"],
            method=value["method"],
            evidence_refs=tuple(value["evidence_refs"]),
        )


@dataclass(frozen=True)
class VulnerabilityCase:
    case_id: str
    finding: VulnerabilityFinding
    evidence_catalog: tuple[EvidenceReference, ...] = ()
    triage: TriageDecision | None = None
    remediation: RemediationRecord | None = None
    risk_acceptance: RiskAcceptance | None = None
    verification: VerificationRecord | None = None

    def __post_init__(self) -> None:
        require_text("case_id", self.case_id)
        evidence_ids = tuple(item.evidence_id for item in self.evidence_catalog)
        require_unique("evidence_catalog evidence_id", evidence_ids)
        for record in (self.triage, self.remediation, self.risk_acceptance, self.verification):
            if record is not None and record.finding_id != self.finding.finding_id:
                raise ValueError("all case records must reference the finding_id")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": "vulnevidenceops.case-bundle.v1",
            "case_id": self.case_id,
            "finding": self.finding.to_dict(),
            "evidence_catalog": [item.to_dict() for item in self.evidence_catalog],
        }
        for name in ("triage", "remediation", "risk_acceptance", "verification"):
            record = getattr(self, name)
            if record is not None:
                result[name] = record.to_dict()
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> VulnerabilityCase:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.case-bundle.v1",
            required=("case_id", "finding", "evidence_catalog"),
            optional=("triage", "remediation", "risk_acceptance", "verification"),
        )
        return cls(
            case_id=value["case_id"],
            finding=VulnerabilityFinding.from_dict(value["finding"]),
            evidence_catalog=tuple(
                EvidenceReference.from_dict(item) for item in value["evidence_catalog"]
            ),
            triage=(TriageDecision.from_dict(value["triage"]) if "triage" in value else None),
            remediation=(
                RemediationRecord.from_dict(value["remediation"])
                if "remediation" in value
                else None
            ),
            risk_acceptance=(
                RiskAcceptance.from_dict(value["risk_acceptance"])
                if "risk_acceptance" in value
                else None
            ),
            verification=(
                VerificationRecord.from_dict(value["verification"])
                if "verification" in value
                else None
            ),
        )


@dataclass(frozen=True)
class VulnerabilityPolicy:
    severity_sla_days: dict[str, int] = field(
        default_factory=lambda: {
            "critical": 7,
            "high": 30,
            "medium": 90,
            "low": 180,
            "informational": 365,
        }
    )
    max_risk_acceptance_days: int = 90
    independent_verification_required: bool = True

    def __post_init__(self) -> None:
        if set(self.severity_sla_days) != set(SEVERITIES):
            raise ValueError("severity_sla_days must define every supported severity exactly once")
        if any(
            not isinstance(value, int) or value <= 0
            for value in self.severity_sla_days.values()
        ):
            raise ValueError("severity SLA values must be positive integers")
        if not isinstance(self.max_risk_acceptance_days, int) or self.max_risk_acceptance_days <= 0:
            raise ValueError("max_risk_acceptance_days must be a positive integer")
        if not isinstance(self.independent_verification_required, bool):
            raise ValueError("independent_verification_required must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.vulnerability-policy.v1",
            "severity_sla_days": dict(sorted(self.severity_sla_days.items())),
            "max_risk_acceptance_days": self.max_risk_acceptance_days,
            "independent_verification_required": self.independent_verification_required,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> VulnerabilityPolicy:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.vulnerability-policy.v1",
            required=(
                "severity_sla_days",
                "max_risk_acceptance_days",
                "independent_verification_required",
            ),
        )
        return cls(
            severity_sla_days=dict(value["severity_sla_days"]),
            max_risk_acceptance_days=value["max_risk_acceptance_days"],
            independent_verification_required=value["independent_verification_required"],
        )


@dataclass(frozen=True)
class AssuranceDossier:
    case_id: str
    finding_id: str
    assessed_at: str
    input_sha256: str
    policy_sha256: str
    lifecycle_state: str
    assurance_position: str
    remediation_due_at: str
    overdue: bool
    gaps: tuple[str, ...]
    control_evidence: tuple[dict[str, Any], ...]
    evidence_inventory: tuple[dict[str, Any], ...]
    non_claims: dict[str, bool]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.assurance-dossier.v1",
            "case_id": self.case_id,
            "finding_id": self.finding_id,
            "assessed_at": self.assessed_at,
            "input_sha256": self.input_sha256,
            "policy_sha256": self.policy_sha256,
            "lifecycle_state": self.lifecycle_state,
            "assurance_position": self.assurance_position,
            "remediation_due_at": self.remediation_due_at,
            "overdue": self.overdue,
            "gaps": list(self.gaps),
            "control_evidence": list(self.control_evidence),
            "evidence_inventory": list(self.evidence_inventory),
            "non_claims": dict(sorted(self.non_claims.items())),
        }
