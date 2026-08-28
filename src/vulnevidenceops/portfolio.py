"""Deterministic portfolio views without scoring or autonomous prioritization."""

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
from .assurance import assess_case
from .canonical import sha256_digest
from .models import AssuranceDossier, VulnerabilityCase, VulnerabilityPolicy

PORTFOLIO_ASSURANCE_CONTRACT = "vulnevidenceops.portfolio-assurance.v1"
PORTFOLIO_POSITIONS = frozenset(
    {"attention_required", "current", "unavailable", "with_gaps"}
)
SLA_COHORTS = frozenset(
    {
        "accepted_exception",
        "closed",
        "due_later",
        "due_today",
        "due_within_30_days",
        "due_within_7_days",
        "overdue",
        "revalidation_required",
    }
)
DEDUPLICATION_TARGET_STATES = frozenset(
    {"linked", "target_is_duplicate", "target_out_of_scope"}
)
DECISION_CURRENTNESS_STATES = frozenset({"current", "future"})
EVIDENCE_LINK_STATES = frozenset({"future", "linked", "missing", "unlinked"})
EXCEPTION_STATES = frozenset({"current", "expired", "future"})
EXCEPTION_AGE_BANDS = frozenset(
    {"0_30_days", "31_60_days", "61_90_days", "91_plus_days", "future"}
)
EXCEPTION_POLICY_STATES = frozenset({"exceeds_policy", "within_policy"})
PORTFOLIO_TOTAL_KEYS = frozenset(
    {
        "case_count",
        "closed_case_count",
        "deduplication_decision_count",
        "exception_count",
        "finding_count",
        "open_case_count",
        "portfolio_gap_count",
    }
)
PORTFOLIO_NON_CLAIMS = {
    "asset_inventory_completeness_established": False,
    "automatic_deduplication_established": False,
    "compliance_percentage_established": False,
    "cross_system_identity_established": False,
    "executive_approval_established": False,
    "portfolio_risk_rank_established": False,
    "remediation_priority_established": False,
    "risk_acceptance_validity_established": False,
    "sla_compliance_established": False,
}


@dataclass(frozen=True)
class PortfolioBundle:
    """Self-contained cases, policy and accountable scope for one portfolio view."""

    portfolio_id: str
    scope_ref: str
    accountable_role: str
    cases: tuple[VulnerabilityCase, ...]
    policy: VulnerabilityPolicy

    def __post_init__(self) -> None:
        for name in ("portfolio_id", "scope_ref", "accountable_role"):
            require_text(name, getattr(self, name))
        if not isinstance(self.policy, VulnerabilityPolicy):
            raise ValueError("policy must be a VulnerabilityPolicy")
        if any(not isinstance(case, VulnerabilityCase) for case in self.cases):
            raise ValueError("cases must contain only VulnerabilityCase records")
        require_unique("case_id", (case.case_id for case in self.cases))
        require_unique(
            "portfolio finding_id",
            (case.finding.finding_id for case in self.cases),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.portfolio-bundle.v1",
            "portfolio_id": self.portfolio_id,
            "scope_ref": self.scope_ref,
            "accountable_role": self.accountable_role,
            "cases": [case.to_dict() for case in self.cases],
            "policy": self.policy.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> PortfolioBundle:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.portfolio-bundle.v1",
            required=("portfolio_id", "scope_ref", "accountable_role", "cases", "policy"),
        )
        return cls(
            portfolio_id=value["portfolio_id"],
            scope_ref=value["scope_ref"],
            accountable_role=value["accountable_role"],
            cases=tuple(VulnerabilityCase.from_dict(case) for case in value["cases"]),
            policy=VulnerabilityPolicy.from_dict(value["policy"]),
        )


@dataclass(frozen=True)
class PortfolioAssuranceView:
    """Raw portfolio counts and accountable records with explicit non-claims."""

    portfolio_id: str
    scope_ref: str
    accountable_role: str
    assessed_at: str
    input_sha256: str
    policy_sha256: str
    portfolio_position: str
    totals: dict[str, int]
    case_summaries: tuple[dict[str, Any], ...]
    deduplication_decisions: tuple[dict[str, Any], ...]
    sla_cohorts: tuple[dict[str, Any], ...]
    exception_ageing: tuple[dict[str, Any], ...]
    accountability_view: tuple[dict[str, Any], ...]
    gaps: tuple[str, ...]
    non_claims: dict[str, bool]

    def __post_init__(self) -> None:
        for name in ("portfolio_id", "scope_ref", "accountable_role"):
            require_text(name, getattr(self, name))
        parse_timestamp("assessed_at", self.assessed_at)
        require_sha256("input_sha256", self.input_sha256)
        require_sha256("policy_sha256", self.policy_sha256)
        require_enum("portfolio_position", self.portfolio_position, PORTFOLIO_POSITIONS)
        if set(self.totals) != PORTFOLIO_TOTAL_KEYS:
            raise ValueError("portfolio totals must preserve the exact public counter set")
        if any(not isinstance(value, int) or value < 0 for value in self.totals.values()):
            raise ValueError("portfolio totals must be non-negative integers")
        require_unique("gaps", self.gaps)
        case_ids = tuple(record["case_id"] for record in self.case_summaries)
        finding_ids = tuple(record["finding_id"] for record in self.case_summaries)
        require_unique("case summary case_id", case_ids)
        require_unique("case summary finding_id", finding_ids)
        closed_count = sum(
            record["lifecycle_state"] in {"closed_dispositioned", "closed_verified"}
            for record in self.case_summaries
        )
        expected_totals = {
            "case_count": len(self.case_summaries),
            "closed_case_count": closed_count,
            "deduplication_decision_count": len(self.deduplication_decisions),
            "exception_count": len(self.exception_ageing),
            "finding_count": len(set(finding_ids)),
            "open_case_count": len(self.case_summaries) - closed_count,
            "portfolio_gap_count": len(self.gaps),
        }
        if self.totals != expected_totals:
            raise ValueError("portfolio totals must match the represented records and gaps")
        for record in self.deduplication_decisions:
            require_enum(
                "decision_currentness",
                record.get("decision_currentness"),
                DECISION_CURRENTNESS_STATES,
            )
            require_enum(
                "target_state",
                record.get("target_state"),
                DEDUPLICATION_TARGET_STATES,
            )
            require_enum(
                "evidence_state",
                record.get("evidence_state"),
                EVIDENCE_LINK_STATES,
            )
        for record in self.sla_cohorts:
            require_enum("cohort", record.get("cohort"), SLA_COHORTS)
            if record.get("case_count") != len(record.get("case_ids", ())):
                raise ValueError("SLA cohort case_count must match case_ids")
            if record.get("case_count") != len(record.get("finding_ids", ())):
                raise ValueError("SLA cohort case_count must match finding_ids")
        cohort_case_ids = tuple(
            case_id for record in self.sla_cohorts for case_id in record["case_ids"]
        )
        require_unique("SLA cohort case_id", cohort_case_ids)
        if set(cohort_case_ids) != set(case_ids):
            raise ValueError("SLA cohorts must cover every represented case exactly once")
        for record in self.exception_ageing:
            require_enum("exception_state", record.get("exception_state"), EXCEPTION_STATES)
            require_enum("age_band", record.get("age_band"), EXCEPTION_AGE_BANDS)
            require_enum(
                "policy_state",
                record.get("policy_state"),
                EXCEPTION_POLICY_STATES,
            )
            require_enum(
                "evidence_state",
                record.get("evidence_state"),
                EVIDENCE_LINK_STATES,
            )
        for record in self.accountability_view:
            if record.get("case_count") != len(record.get("case_ids", ())):
                raise ValueError("accountability case_count must match case_ids")
            if record.get("case_count") != len(record.get("finding_ids", ())):
                raise ValueError("accountability case_count must match finding_ids")
        if self.non_claims != PORTFOLIO_NON_CLAIMS:
            raise ValueError("portfolio non_claims must preserve every explicit false value")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.portfolio-assurance-view.v1",
            "portfolio_id": self.portfolio_id,
            "scope_ref": self.scope_ref,
            "accountable_role": self.accountable_role,
            "assessed_at": self.assessed_at,
            "input_sha256": self.input_sha256,
            "policy_sha256": self.policy_sha256,
            "portfolio_position": self.portfolio_position,
            "totals": dict(sorted(self.totals.items())),
            "case_summaries": list(self.case_summaries),
            "deduplication_decisions": list(self.deduplication_decisions),
            "sla_cohorts": list(self.sla_cohorts),
            "exception_ageing": list(self.exception_ageing),
            "accountability_view": list(self.accountability_view),
            "gaps": list(self.gaps),
            "non_claims": dict(sorted(self.non_claims.items())),
        }


def _evidence_state(
    case: VulnerabilityCase,
    evidence_refs: tuple[str, ...],
    assessed_at: datetime,
) -> str:
    if not evidence_refs:
        return "missing"
    catalog = {evidence.evidence_id: evidence for evidence in case.evidence_catalog}
    if any(evidence_ref not in catalog for evidence_ref in evidence_refs):
        return "unlinked"
    if any(
        parse_timestamp("collected_at", catalog[evidence_ref].collected_at) > assessed_at
        for evidence_ref in evidence_refs
    ):
        return "future"
    return "linked"


def _case_summary(
    case: VulnerabilityCase,
    dossier: AssuranceDossier,
) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "finding_id": case.finding.finding_id,
        "asset_ref": case.finding.asset_ref,
        "severity": case.finding.severity,
        "lifecycle_state": dossier.lifecycle_state,
        "assurance_position": dossier.assurance_position,
        "remediation_due_at": dossier.remediation_due_at,
        "overdue": dossier.overdue,
        "input_sha256": dossier.input_sha256,
        "dossier_sha256": sha256_digest(dossier.to_dict()),
        "gaps": list(dossier.gaps),
    }


def _deduplication_decisions(
    cases: tuple[VulnerabilityCase, ...],
    assessed_at: datetime,
) -> tuple[tuple[dict[str, Any], ...], set[str]]:
    finding_ids = {case.finding.finding_id for case in cases}
    duplicate_ids = {
        case.finding.finding_id
        for case in cases
        if case.triage is not None and case.triage.disposition == "duplicate"
    }
    records = []
    gaps: set[str] = set()
    for case in sorted(cases, key=lambda item: item.finding.finding_id):
        triage = case.triage
        if triage is None or triage.disposition != "duplicate":
            continue
        decision_currentness = (
            "current"
            if parse_timestamp("decided_at", triage.decided_at) <= assessed_at
            else "future"
        )
        target = triage.duplicate_of
        if target not in finding_ids:
            target_state = "target_out_of_scope"
        elif target in duplicate_ids:
            target_state = "target_is_duplicate"
        else:
            target_state = "linked"
        evidence_state = _evidence_state(case, triage.evidence_refs, assessed_at)
        finding_id = case.finding.finding_id
        if decision_currentness != "current":
            gaps.add(f"deduplication_decision_future:{finding_id}")
        if target_state != "linked":
            gaps.add(f"deduplication_{target_state}:{finding_id}")
        if evidence_state != "linked":
            gaps.add(f"deduplication_evidence_{evidence_state}:{finding_id}")
        records.append(
            {
                "decision_id": triage.decision_id,
                "duplicate_finding_id": finding_id,
                "target_finding_id": target,
                "decided_at": triage.decided_at,
                "accountable_role": triage.accountable_role,
                "rationale": triage.rationale,
                "decision_currentness": decision_currentness,
                "target_state": target_state,
                "evidence_state": evidence_state,
                "evidence_refs": list(triage.evidence_refs),
            }
        )
    return tuple(records), gaps


def _sla_cohort(dossier: AssuranceDossier, assessed_at: datetime) -> str:
    if dossier.lifecycle_state in {"closed_dispositioned", "closed_verified"}:
        return "closed"
    if dossier.lifecycle_state == "risk_accepted":
        return "accepted_exception"
    if dossier.lifecycle_state == "revalidation_required":
        return "revalidation_required"
    if dossier.overdue:
        return "overdue"
    due = parse_timestamp("remediation_due_at", dossier.remediation_due_at)
    days_to_due = (due.date() - assessed_at.date()).days
    if days_to_due == 0:
        return "due_today"
    if days_to_due <= 7:
        return "due_within_7_days"
    if days_to_due <= 30:
        return "due_within_30_days"
    return "due_later"


def _sla_cohorts(
    cases: tuple[VulnerabilityCase, ...],
    dossiers: dict[str, AssuranceDossier],
    assessed_at: datetime,
) -> tuple[dict[str, Any], ...]:
    groups: dict[tuple[str, str], list[VulnerabilityCase]] = {}
    for case in cases:
        cohort = _sla_cohort(dossiers[case.case_id], assessed_at)
        groups.setdefault((cohort, case.finding.severity), []).append(case)
    return tuple(
        {
            "cohort": cohort,
            "severity": severity,
            "case_count": len(group),
            "case_ids": sorted(case.case_id for case in group),
            "finding_ids": sorted(case.finding.finding_id for case in group),
        }
        for (cohort, severity), group in sorted(groups.items())
    )


def _age_band(age_days: int | None) -> str:
    if age_days is None:
        return "future"
    if age_days <= 30:
        return "0_30_days"
    if age_days <= 60:
        return "31_60_days"
    if age_days <= 90:
        return "61_90_days"
    return "91_plus_days"


def _exception_ageing(
    cases: tuple[VulnerabilityCase, ...],
    policy: VulnerabilityPolicy,
    assessed_at: datetime,
) -> tuple[tuple[dict[str, Any], ...], set[str]]:
    records = []
    gaps: set[str] = set()
    for case in sorted(cases, key=lambda item: item.case_id):
        acceptance = case.risk_acceptance
        if acceptance is None:
            continue
        accepted = parse_timestamp("accepted_at", acceptance.accepted_at)
        expires = parse_timestamp("expires_at", acceptance.expires_at)
        if assessed_at < accepted:
            exception_state = "future"
            age_days = None
        elif expires <= assessed_at:
            exception_state = "expired"
            age_days = (assessed_at.date() - accepted.date()).days
        else:
            exception_state = "current"
            age_days = (assessed_at.date() - accepted.date()).days
        duration_days = (expires - accepted).days
        policy_state = (
            "within_policy"
            if duration_days <= policy.max_risk_acceptance_days
            else "exceeds_policy"
        )
        evidence_state = _evidence_state(case, acceptance.evidence_refs, assessed_at)
        finding_id = case.finding.finding_id
        if exception_state != "current":
            gaps.add(f"exception_{exception_state}:{finding_id}")
        if policy_state != "within_policy":
            gaps.add(f"exception_exceeds_policy:{finding_id}")
        if evidence_state != "linked":
            gaps.add(f"exception_evidence_{evidence_state}:{finding_id}")
        records.append(
            {
                "decision_id": acceptance.decision_id,
                "case_id": case.case_id,
                "finding_id": finding_id,
                "accepted_at": acceptance.accepted_at,
                "expires_at": acceptance.expires_at,
                "risk_owner_role": acceptance.risk_owner_role,
                "approver_role": acceptance.approver_role,
                "rationale": acceptance.rationale,
                "exception_state": exception_state,
                "age_band": _age_band(age_days),
                "age_days": age_days,
                "days_until_expiry": (expires.date() - assessed_at.date()).days,
                "policy_state": policy_state,
                "evidence_state": evidence_state,
                "compensating_control_refs": list(acceptance.compensating_control_refs),
                "evidence_refs": list(acceptance.evidence_refs),
            }
        )
    return tuple(records), gaps


def _accountability_view(
    bundle: PortfolioBundle,
) -> tuple[tuple[dict[str, Any], ...], set[str]]:
    roles: dict[str, dict[str, set[str]]] = {}

    def add(role: str, responsibility: str, case: VulnerabilityCase) -> None:
        record = roles.setdefault(
            role,
            {"responsibilities": set(), "case_ids": set(), "finding_ids": set()},
        )
        record["responsibilities"].add(responsibility)
        record["case_ids"].add(case.case_id)
        record["finding_ids"].add(case.finding.finding_id)

    for case in bundle.cases:
        add(bundle.accountable_role, "portfolio_oversight", case)

    gaps: set[str] = set()
    for case in bundle.cases:
        accountable = False
        if case.triage is not None:
            add(case.triage.accountable_role, "triage_decision", case)
            accountable = True
        if case.remediation is not None:
            add(case.remediation.owner_role, "remediation", case)
            accountable = True
        if case.risk_acceptance is not None:
            add(case.risk_acceptance.risk_owner_role, "risk_ownership", case)
            add(case.risk_acceptance.approver_role, "risk_approval", case)
            accountable = True
        if case.verification is not None:
            add(case.verification.verifier_role, "verification", case)
            accountable = True
        if not accountable:
            gaps.add(f"case_accountability_missing:{case.case_id}")

    return (
        tuple(
            {
                "accountable_role": role,
                "responsibilities": sorted(record["responsibilities"]),
                "case_count": len(record["case_ids"]),
                "case_ids": sorted(record["case_ids"]),
                "finding_ids": sorted(record["finding_ids"]),
            }
            for role, record in sorted(roles.items())
        ),
        gaps,
    )


def assess_portfolio(
    bundle: PortfolioBundle,
    *,
    assessed_at: str,
) -> PortfolioAssuranceView:
    """Build raw portfolio cohorts and accountability records at one explicit time."""
    assessed = parse_timestamp("assessed_at", assessed_at)
    dossiers = {
        case.case_id: assess_case(case, assessed_at=assessed_at, policy=bundle.policy)
        for case in bundle.cases
    }
    case_summaries = tuple(
        _case_summary(case, dossiers[case.case_id])
        for case in sorted(bundle.cases, key=lambda item: item.case_id)
    )
    gaps = {
        f"case:{summary['case_id']}:{gap}"
        for summary in case_summaries
        for gap in summary["gaps"]
    }
    deduplication_decisions, deduplication_gaps = _deduplication_decisions(
        bundle.cases,
        assessed,
    )
    gaps.update(deduplication_gaps)
    exception_ageing, exception_gaps = _exception_ageing(
        bundle.cases,
        bundle.policy,
        assessed,
    )
    gaps.update(exception_gaps)
    accountability_view, accountability_gaps = _accountability_view(bundle)
    gaps.update(accountability_gaps)
    if not bundle.cases:
        gaps.add("portfolio_cases_missing")

    attention_required = any(
        dossier.assurance_position in {"overdue", "revalidation_required"}
        for dossier in dossiers.values()
    )
    if not bundle.cases:
        portfolio_position = "unavailable"
    elif attention_required:
        portfolio_position = "attention_required"
    elif gaps:
        portfolio_position = "with_gaps"
    else:
        portfolio_position = "current"

    closed_states = {"closed_dispositioned", "closed_verified"}
    closed_count = sum(
        dossier.lifecycle_state in closed_states for dossier in dossiers.values()
    )
    totals = {
        "case_count": len(bundle.cases),
        "closed_case_count": closed_count,
        "deduplication_decision_count": len(deduplication_decisions),
        "exception_count": len(exception_ageing),
        "finding_count": len(bundle.cases),
        "open_case_count": len(bundle.cases) - closed_count,
        "portfolio_gap_count": len(gaps),
    }
    return PortfolioAssuranceView(
        portfolio_id=bundle.portfolio_id,
        scope_ref=bundle.scope_ref,
        accountable_role=bundle.accountable_role,
        assessed_at=normalize_timestamp(assessed),
        input_sha256=sha256_digest(bundle.to_dict()),
        policy_sha256=sha256_digest(bundle.policy.to_dict()),
        portfolio_position=portfolio_position,
        totals=totals,
        case_summaries=case_summaries,
        deduplication_decisions=deduplication_decisions,
        sla_cohorts=_sla_cohorts(bundle.cases, dossiers, assessed),
        exception_ageing=exception_ageing,
        accountability_view=accountability_view,
        gaps=tuple(sorted(gaps)),
        non_claims=dict(PORTFOLIO_NON_CLAIMS),
    )
