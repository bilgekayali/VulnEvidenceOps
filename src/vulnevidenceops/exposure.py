"""Evidence-backed exposure context without autonomous prioritization."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ._validation import (
    normalize_timestamp,
    parse_timestamp,
    require_enum,
    require_record_fields,
    require_sha256,
    require_text,
    require_unique,
)
from .canonical import sha256_digest
from .models import EvidenceReference, VulnerabilityFinding

EXPOSURE_CONTEXT_CONTRACT = "vulnevidenceops.exposure-context.v1"
EXPLOIT_SIGNALS = frozenset(
    {
        "active_exploitation_reported",
        "known_exploited_catalogued",
        "no_exploitation_signal_reported",
        "proof_of_concept_reported",
        "public_exploit_reported",
        "unknown",
    }
)
BUSINESS_CRITICALITY_CLASSES = frozenset(
    {
        "business_critical",
        "business_supporting",
        "mission_critical",
        "non_critical",
        "unclassified",
    }
)
CONTEXT_POSITIONS = frozenset(
    {"current", "partial", "stale", "unavailable", "with_gaps"}
)
CURRENTNESS_STATES = frozenset(
    {
        "current",
        "evidence_future",
        "evidence_missing",
        "evidence_source_mismatch",
        "evidence_unlinked",
        "expired",
        "future",
    }
)
EXPOSURE_NON_CLAIMS = {
    "autonomous_prioritization_established": False,
    "business_impact_established": False,
    "exploitability_established": False,
    "remediation_sla_established": False,
    "risk_score_established": False,
    "source_assertion_truth_established": False,
}


@dataclass(frozen=True)
class ExploitIntelligence:
    """A time-bounded source assertion about one finding identifier."""

    intelligence_id: str
    finding_id: str
    technical_identifier: str
    signal: str
    source_identity: str
    source_ref: str
    asserted_at: str
    valid_until: str
    statement: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "intelligence_id",
            "finding_id",
            "technical_identifier",
            "source_identity",
            "source_ref",
            "statement",
        ):
            require_text(name, getattr(self, name))
        require_enum("signal", self.signal, EXPLOIT_SIGNALS)
        asserted = parse_timestamp("asserted_at", self.asserted_at)
        valid_until = parse_timestamp("valid_until", self.valid_until)
        if valid_until <= asserted:
            raise ValueError("valid_until must be later than asserted_at")
        for evidence_ref in self.evidence_refs:
            require_text("evidence_ref", evidence_ref)
        require_unique("evidence_refs", self.evidence_refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.exploit-intelligence.v1",
            "intelligence_id": self.intelligence_id,
            "finding_id": self.finding_id,
            "technical_identifier": self.technical_identifier,
            "signal": self.signal,
            "source_identity": self.source_identity,
            "source_ref": self.source_ref,
            "asserted_at": self.asserted_at,
            "valid_until": self.valid_until,
            "statement": self.statement,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ExploitIntelligence:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.exploit-intelligence.v1",
            required=(
                "intelligence_id",
                "finding_id",
                "technical_identifier",
                "signal",
                "source_identity",
                "source_ref",
                "asserted_at",
                "valid_until",
                "statement",
                "evidence_refs",
            ),
        )
        return cls(
            intelligence_id=value["intelligence_id"],
            finding_id=value["finding_id"],
            technical_identifier=value["technical_identifier"],
            signal=value["signal"],
            source_identity=value["source_identity"],
            source_ref=value["source_ref"],
            asserted_at=value["asserted_at"],
            valid_until=value["valid_until"],
            statement=value["statement"],
            evidence_refs=tuple(value["evidence_refs"]),
        )


@dataclass(frozen=True)
class BusinessCriticality:
    """A time-bounded, accountable business-service classification assertion."""

    classification_id: str
    asset_ref: str
    business_service_ref: str
    criticality: str
    accountable_role: str
    source_identity: str
    source_ref: str
    classified_at: str
    valid_until: str
    rationale: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "classification_id",
            "asset_ref",
            "business_service_ref",
            "accountable_role",
            "source_identity",
            "source_ref",
            "rationale",
        ):
            require_text(name, getattr(self, name))
        require_enum("criticality", self.criticality, BUSINESS_CRITICALITY_CLASSES)
        classified = parse_timestamp("classified_at", self.classified_at)
        valid_until = parse_timestamp("valid_until", self.valid_until)
        if valid_until <= classified:
            raise ValueError("valid_until must be later than classified_at")
        for evidence_ref in self.evidence_refs:
            require_text("evidence_ref", evidence_ref)
        require_unique("evidence_refs", self.evidence_refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.business-criticality.v1",
            "classification_id": self.classification_id,
            "asset_ref": self.asset_ref,
            "business_service_ref": self.business_service_ref,
            "criticality": self.criticality,
            "accountable_role": self.accountable_role,
            "source_identity": self.source_identity,
            "source_ref": self.source_ref,
            "classified_at": self.classified_at,
            "valid_until": self.valid_until,
            "rationale": self.rationale,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> BusinessCriticality:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.business-criticality.v1",
            required=(
                "classification_id",
                "asset_ref",
                "business_service_ref",
                "criticality",
                "accountable_role",
                "source_identity",
                "source_ref",
                "classified_at",
                "valid_until",
                "rationale",
                "evidence_refs",
            ),
        )
        return cls(
            classification_id=value["classification_id"],
            asset_ref=value["asset_ref"],
            business_service_ref=value["business_service_ref"],
            criticality=value["criticality"],
            accountable_role=value["accountable_role"],
            source_identity=value["source_identity"],
            source_ref=value["source_ref"],
            classified_at=value["classified_at"],
            valid_until=value["valid_until"],
            rationale=value["rationale"],
            evidence_refs=tuple(value["evidence_refs"]),
        )


@dataclass(frozen=True)
class ExposureContextBundle:
    """External context records bound to one normalized vulnerability finding."""

    context_id: str
    finding: VulnerabilityFinding
    evidence_catalog: tuple[EvidenceReference, ...] = ()
    exploit_intelligence: tuple[ExploitIntelligence, ...] = ()
    business_criticality: tuple[BusinessCriticality, ...] = ()

    def __post_init__(self) -> None:
        require_text("context_id", self.context_id)
        if not isinstance(self.finding, VulnerabilityFinding):
            raise ValueError("finding must be a VulnerabilityFinding")
        evidence_ids = tuple(item.evidence_id for item in self.evidence_catalog)
        intelligence_ids = tuple(item.intelligence_id for item in self.exploit_intelligence)
        classification_ids = tuple(
            item.classification_id for item in self.business_criticality
        )
        require_unique("evidence_catalog evidence_id", evidence_ids)
        require_unique("exploit intelligence_id", intelligence_ids)
        require_unique("business classification_id", classification_ids)
        for intelligence in self.exploit_intelligence:
            if intelligence.finding_id != self.finding.finding_id:
                raise ValueError("exploit intelligence must reference the bundle finding_id")
            if intelligence.technical_identifier not in self.finding.technical_identifiers:
                raise ValueError(
                    "exploit intelligence technical_identifier must exist on the finding"
                )
        for classification in self.business_criticality:
            if classification.asset_ref != self.finding.asset_ref:
                raise ValueError("business criticality must reference the finding asset_ref")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.exposure-context-bundle.v1",
            "context_id": self.context_id,
            "finding": self.finding.to_dict(),
            "evidence_catalog": [item.to_dict() for item in self.evidence_catalog],
            "exploit_intelligence": [item.to_dict() for item in self.exploit_intelligence],
            "business_criticality": [item.to_dict() for item in self.business_criticality],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ExposureContextBundle:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.exposure-context-bundle.v1",
            required=(
                "context_id",
                "finding",
                "evidence_catalog",
                "exploit_intelligence",
                "business_criticality",
            ),
        )
        return cls(
            context_id=value["context_id"],
            finding=VulnerabilityFinding.from_dict(value["finding"]),
            evidence_catalog=tuple(
                EvidenceReference.from_dict(item) for item in value["evidence_catalog"]
            ),
            exploit_intelligence=tuple(
                ExploitIntelligence.from_dict(item) for item in value["exploit_intelligence"]
            ),
            business_criticality=tuple(
                BusinessCriticality.from_dict(item) for item in value["business_criticality"]
            ),
        )


@dataclass(frozen=True)
class ExposureContextAssessment:
    """Currentness result for external context, with no score or priority decision."""

    context_id: str
    finding_id: str
    asset_ref: str
    assessed_at: str
    input_sha256: str
    context_position: str
    exploit_intelligence: tuple[dict[str, Any], ...]
    business_criticality: tuple[dict[str, Any], ...]
    gaps: tuple[str, ...]
    evidence_inventory: tuple[dict[str, Any], ...]
    non_claims: dict[str, bool]

    def __post_init__(self) -> None:
        for name in ("context_id", "finding_id", "asset_ref"):
            require_text(name, getattr(self, name))
        parse_timestamp("assessed_at", self.assessed_at)
        require_sha256("input_sha256", self.input_sha256)
        require_enum("context_position", self.context_position, CONTEXT_POSITIONS)
        require_unique("gaps", self.gaps)
        for record in (*self.exploit_intelligence, *self.business_criticality):
            require_enum("currentness", record.get("currentness"), CURRENTNESS_STATES)
        if self.non_claims != EXPOSURE_NON_CLAIMS:
            raise ValueError("exposure non_claims must preserve every explicit false value")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.exposure-context-assessment.v1",
            "context_id": self.context_id,
            "finding_id": self.finding_id,
            "asset_ref": self.asset_ref,
            "assessed_at": self.assessed_at,
            "input_sha256": self.input_sha256,
            "context_position": self.context_position,
            "exploit_intelligence": list(self.exploit_intelligence),
            "business_criticality": list(self.business_criticality),
            "gaps": list(self.gaps),
            "evidence_inventory": list(self.evidence_inventory),
            "non_claims": dict(sorted(self.non_claims.items())),
        }


def _currentness(
    *,
    starts_at: str,
    valid_until: str,
    source_identity: str,
    evidence_refs: tuple[str, ...],
    catalog: dict[str, EvidenceReference],
    assessed_at: datetime,
) -> str:
    if parse_timestamp("starts_at", starts_at) > assessed_at:
        return "future"
    if parse_timestamp("valid_until", valid_until) <= assessed_at:
        return "expired"
    if not evidence_refs:
        return "evidence_missing"
    if any(evidence_ref not in catalog for evidence_ref in evidence_refs):
        return "evidence_unlinked"
    evidence = tuple(catalog[evidence_ref] for evidence_ref in evidence_refs)
    if any(item.source_identity != source_identity for item in evidence):
        return "evidence_source_mismatch"
    if any(parse_timestamp("collected_at", item.collected_at) > assessed_at for item in evidence):
        return "evidence_future"
    return "current"


def _domain_gaps(prefix: str, records: tuple[Any, ...], statuses: tuple[str, ...]) -> set[str]:
    if "current" in statuses:
        return set()
    if not records:
        return {f"{prefix}_missing"}
    return {
        f"{prefix}_no_current_record",
        *(f"{prefix}_{status}" for status in sorted(set(statuses))),
    }


def _exploit_conflict(records: tuple[dict[str, Any], ...]) -> bool:
    by_identifier: dict[str, set[str]] = {}
    for record in records:
        if record["currentness"] == "current":
            by_identifier.setdefault(record["technical_identifier"], set()).add(
                record["signal"]
            )
    for signals in by_identifier.values():
        positive = signals - {"no_exploitation_signal_reported", "unknown"}
        if positive and "no_exploitation_signal_reported" in signals:
            return True
    return False


def _criticality_conflict(records: tuple[dict[str, Any], ...]) -> bool:
    by_service: dict[str, set[str]] = {}
    for record in records:
        if record["currentness"] == "current":
            by_service.setdefault(record["business_service_ref"], set()).add(
                record["criticality"]
            )
    return any(len(values) > 1 for values in by_service.values())


def assess_exposure_context(
    bundle: ExposureContextBundle,
    *,
    assessed_at: str,
) -> ExposureContextAssessment:
    """Assess source linkage and currentness without computing risk or priority."""
    assessed = parse_timestamp("assessed_at", assessed_at)
    observed = parse_timestamp("first_observed_at", bundle.finding.first_observed_at)
    if assessed < observed:
        raise ValueError("assessed_at must not precede first_observed_at")
    catalog = {item.evidence_id: item for item in bundle.evidence_catalog}

    exploit_records = tuple(
        {
            "intelligence_id": item.intelligence_id,
            "technical_identifier": item.technical_identifier,
            "signal": item.signal,
            "source_identity": item.source_identity,
            "source_ref": item.source_ref,
            "asserted_at": item.asserted_at,
            "valid_until": item.valid_until,
            "statement": item.statement,
            "currentness": _currentness(
                starts_at=item.asserted_at,
                valid_until=item.valid_until,
                source_identity=item.source_identity,
                evidence_refs=item.evidence_refs,
                catalog=catalog,
                assessed_at=assessed,
            ),
            "evidence_refs": list(item.evidence_refs),
        }
        for item in sorted(
            bundle.exploit_intelligence, key=lambda record: record.intelligence_id
        )
    )
    criticality_records = tuple(
        {
            "classification_id": item.classification_id,
            "business_service_ref": item.business_service_ref,
            "criticality": item.criticality,
            "accountable_role": item.accountable_role,
            "source_identity": item.source_identity,
            "source_ref": item.source_ref,
            "classified_at": item.classified_at,
            "valid_until": item.valid_until,
            "rationale": item.rationale,
            "currentness": _currentness(
                starts_at=item.classified_at,
                valid_until=item.valid_until,
                source_identity=item.source_identity,
                evidence_refs=item.evidence_refs,
                catalog=catalog,
                assessed_at=assessed,
            ),
            "evidence_refs": list(item.evidence_refs),
        }
        for item in sorted(
            bundle.business_criticality, key=lambda record: record.classification_id
        )
    )

    exploit_statuses = tuple(item["currentness"] for item in exploit_records)
    criticality_statuses = tuple(item["currentness"] for item in criticality_records)
    gaps = _domain_gaps(
        "exploit_intelligence", bundle.exploit_intelligence, exploit_statuses
    )
    gaps.update(
        _domain_gaps(
            "business_criticality", bundle.business_criticality, criticality_statuses
        )
    )
    conflicting = False
    if _exploit_conflict(exploit_records):
        gaps.add("exploit_intelligence_conflict")
        conflicting = True
    if _criticality_conflict(criticality_records):
        gaps.add("business_criticality_conflict")
        conflicting = True

    exploit_current = "current" in exploit_statuses
    criticality_current = "current" in criticality_statuses
    if conflicting:
        context_position = "with_gaps"
    elif exploit_current and criticality_current:
        context_position = "current"
    elif exploit_current or criticality_current:
        context_position = "partial"
    elif not bundle.exploit_intelligence and not bundle.business_criticality:
        context_position = "unavailable"
    else:
        context_position = "stale"

    inventory = tuple(
        {
            "evidence_id": item.evidence_id,
            "artifact_ref": item.artifact_ref,
            "artifact_sha256": item.artifact_sha256,
            "media_type": item.media_type,
            "collected_at": item.collected_at,
            "source_identity": item.source_identity,
            "synthetic": item.synthetic,
        }
        for item in sorted(bundle.evidence_catalog, key=lambda record: record.evidence_id)
    )
    return ExposureContextAssessment(
        context_id=bundle.context_id,
        finding_id=bundle.finding.finding_id,
        asset_ref=bundle.finding.asset_ref,
        assessed_at=normalize_timestamp(assessed),
        input_sha256=sha256_digest(bundle.to_dict()),
        context_position=context_position,
        exploit_intelligence=exploit_records,
        business_criticality=criticality_records,
        gaps=tuple(sorted(gaps)),
        evidence_inventory=inventory,
        non_claims=dict(EXPOSURE_NON_CLAIMS),
    )
