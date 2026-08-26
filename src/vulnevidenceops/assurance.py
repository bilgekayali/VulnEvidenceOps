"""Deterministic vulnerability lifecycle and evidence assurance."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from ._validation import normalize_timestamp, parse_timestamp
from .canonical import sha256_digest
from .models import AssuranceDossier, VulnerabilityCase, VulnerabilityPolicy


def _linked(refs: Iterable[str], catalog: set[str]) -> bool:
    refs = tuple(refs)
    return bool(refs) and set(refs).issubset(catalog)


def _control(
    control_id: str,
    status: str,
    reason: str,
    evidence_refs: Iterable[str] = (),
) -> dict[str, Any]:
    return {
        "control_id": control_id,
        "status": status,
        "reason": reason,
        "evidence_refs": sorted(evidence_refs),
    }


def assess_case(
    case: VulnerabilityCase,
    *,
    assessed_at: str,
    policy: VulnerabilityPolicy | None = None,
) -> AssuranceDossier:
    """Assess one immutable case bundle at an explicit point in time."""
    policy = policy or VulnerabilityPolicy()
    assessed = parse_timestamp("assessed_at", assessed_at)
    observed = parse_timestamp("first_observed_at", case.finding.first_observed_at)
    if assessed < observed:
        raise ValueError("assessed_at must not precede first_observed_at")

    due = observed + timedelta(days=policy.severity_sla_days[case.finding.severity])
    catalog = {item.evidence_id for item in case.evidence_catalog}
    gaps: set[str] = set()

    finding_evidence_ok = _linked(case.finding.evidence_refs, catalog)
    if not case.finding.evidence_refs:
        gaps.add("finding_evidence_missing")
    elif not finding_evidence_ok:
        gaps.add("finding_evidence_unlinked")

    triage = case.triage
    triage_current = (
        triage is not None and parse_timestamp("decided_at", triage.decided_at) <= assessed
    )
    triage_evidence_ok = triage_current and _linked(triage.evidence_refs, catalog)
    if triage is None:
        gaps.add("triage_decision_missing")
    elif not triage_current:
        gaps.add("triage_decision_future")
    elif not triage.evidence_refs:
        gaps.add("triage_evidence_missing")
    elif not triage_evidence_ok:
        gaps.add("triage_evidence_unlinked")

    remediation = case.remediation
    remediation_current = remediation is not None and (
        parse_timestamp("planned_at", remediation.planned_at) <= assessed
    )
    remediation_evidence_ok = remediation_current and _linked(remediation.evidence_refs, catalog)
    if remediation is not None and not remediation_current:
        gaps.add("remediation_record_future")
    elif remediation_current and not remediation.evidence_refs:
        gaps.add("remediation_evidence_missing")
    elif remediation_current and not remediation_evidence_ok:
        gaps.add("remediation_evidence_unlinked")

    acceptance = case.risk_acceptance
    acceptance_current = acceptance is not None and (
        parse_timestamp("accepted_at", acceptance.accepted_at) <= assessed
    )
    acceptance_evidence_ok = acceptance_current and _linked(acceptance.evidence_refs, catalog)
    acceptance_valid = False
    acceptance_expired = False
    if acceptance is not None and not acceptance_current:
        gaps.add("risk_acceptance_future")
    elif acceptance_current:
        accepted = parse_timestamp("accepted_at", acceptance.accepted_at)
        expires = parse_timestamp("expires_at", acceptance.expires_at)
        duration = (expires - accepted).days
        acceptance_expired = expires <= assessed
        if duration > policy.max_risk_acceptance_days:
            gaps.add("risk_acceptance_exceeds_policy")
        if not acceptance.compensating_control_refs:
            gaps.add("compensating_controls_missing")
        if not acceptance.evidence_refs:
            gaps.add("risk_acceptance_evidence_missing")
        elif not acceptance_evidence_ok:
            gaps.add("risk_acceptance_evidence_unlinked")
        if acceptance_expired:
            gaps.add("risk_acceptance_expired")
        acceptance_valid = (
            not acceptance_expired
            and duration <= policy.max_risk_acceptance_days
            and bool(acceptance.compensating_control_refs)
            and acceptance_evidence_ok
        )

    verification = case.verification
    verification_current = verification is not None and (
        parse_timestamp("performed_at", verification.performed_at) <= assessed
    )
    verification_evidence_ok = verification_current and _linked(
        verification.evidence_refs, catalog
    )
    verification_independent = (
        verification_current
        and (
            not policy.independent_verification_required
            or remediation is None
            or verification.verifier_role != remediation.owner_role
        )
    )
    verification_effective = (
        verification_current
        and verification.outcome == "effective"
        and verification_evidence_ok
        and verification_independent
        and remediation_current
        and remediation_evidence_ok
    )
    if verification is not None and not verification_current:
        gaps.add("verification_record_future")
    elif verification_current:
        if verification.outcome != "effective":
            gaps.add("verification_not_effective")
        if not verification.evidence_refs:
            gaps.add("verification_evidence_missing")
        elif not verification_evidence_ok:
            gaps.add("verification_evidence_unlinked")
        if not verification_independent:
            gaps.add("verification_not_independent")
        if not remediation_current:
            gaps.add("verified_remediation_record_missing")

    disposition = triage.disposition if triage_current else None
    lifecycle_state = "detected"
    closed = False
    if disposition in {"duplicate", "false_positive"}:
        if triage_evidence_ok and finding_evidence_ok:
            lifecycle_state = "closed_dispositioned"
            closed = True
        else:
            lifecycle_state = "triaged"
    elif disposition == "confirmed":
        if verification_effective and finding_evidence_ok and triage_evidence_ok:
            lifecycle_state = "closed_verified"
            closed = True
        elif acceptance_expired:
            lifecycle_state = "revalidation_required"
        elif acceptance_valid:
            lifecycle_state = "risk_accepted"
        elif remediation_current:
            lifecycle_state = "verification_pending"
            if verification is None:
                gaps.add("verification_missing")
        else:
            lifecycle_state = "triaged"
            gaps.add("remediation_or_acceptance_missing")

    overdue = not closed and lifecycle_state != "risk_accepted" and assessed > due
    if lifecycle_state == "revalidation_required":
        assurance_position = "revalidation_required"
    elif overdue:
        assurance_position = "overdue"
    elif closed or lifecycle_state == "risk_accepted":
        assurance_position = "current" if not gaps else "with_gaps"
    else:
        assurance_position = "with_gaps"

    controls = [
        _control(
            "VEO-INV-001",
            "represented" if finding_evidence_ok else "gap",
            "finding evidence is digest-bound and linked"
            if finding_evidence_ok
            else "finding evidence is missing or unlinked",
            case.finding.evidence_refs,
        ),
        _control(
            "VEO-TRI-001",
            "represented" if triage_current and triage_evidence_ok else "gap",
            "triage is accountable and evidence-linked"
            if triage_current and triage_evidence_ok
            else "current evidence-linked triage is absent",
            triage.evidence_refs if triage_current else (),
        ),
    ]

    if disposition != "confirmed":
        controls.extend(
            [
                _control(
                    "VEO-REM-001",
                    "not_applicable",
                    "confirmed remediation path not selected",
                ),
                _control("VEO-ACC-001", "not_applicable", "risk-acceptance path not selected"),
                _control(
                    "VEO-VER-001",
                    "not_applicable",
                    "confirmed remediation path not selected",
                ),
            ]
        )
    else:
        remediation_status = (
            "represented" if remediation_current and remediation_evidence_ok else "gap"
        )
        controls.append(
            _control(
                "VEO-REM-001",
                remediation_status,
                "remediation is owned, planned and evidence-linked"
                if remediation_status == "represented"
                else "current evidence-linked remediation is absent",
                remediation.evidence_refs if remediation_current else (),
            )
        )
        if acceptance is None and not acceptance_current:
            controls.append(
                _control("VEO-ACC-001", "not_applicable", "risk-acceptance path not selected")
            )
        else:
            controls.append(
                _control(
                    "VEO-ACC-001",
                    "represented" if acceptance_valid else "gap",
                    "risk acceptance is current, bounded and evidence-linked"
                    if acceptance_valid
                    else "risk acceptance is missing required current evidence or is expired",
                    acceptance.evidence_refs if acceptance_current else (),
                )
            )
        if remediation_current:
            controls.append(
                _control(
                    "VEO-VER-001",
                    "represented" if verification_effective else "gap",
                    "remediation has effective independent verification"
                    if verification_effective
                    else "effective independent verification is absent",
                    verification.evidence_refs if verification_current else (),
                )
            )
        else:
            controls.append(
                _control("VEO-VER-001", "not_applicable", "remediation path not selected")
            )

    controls.append(
        _control(
            "VEO-CLS-001",
            "represented" if closed else "gap",
            (
                "closure is supported by governed evidence"
                if closed
                else "finding is not evidence-closed"
            ),
            (
                verification.evidence_refs
                if lifecycle_state == "closed_verified" and verification is not None
                else triage.evidence_refs
                if lifecycle_state == "closed_dispositioned" and triage is not None
                else ()
            ),
        )
    )

    inventory = tuple(
        {
            "evidence_id": item.evidence_id,
            "artifact_ref": item.artifact_ref,
            "artifact_sha256": item.artifact_sha256,
            "collected_at": item.collected_at,
            "source_identity": item.source_identity,
            "synthetic": item.synthetic,
        }
        for item in sorted(case.evidence_catalog, key=lambda entry: entry.evidence_id)
    )
    return AssuranceDossier(
        case_id=case.case_id,
        finding_id=case.finding.finding_id,
        assessed_at=normalize_timestamp(assessed),
        input_sha256=sha256_digest(case.to_dict()),
        policy_sha256=sha256_digest(policy.to_dict()),
        lifecycle_state=lifecycle_state,
        assurance_position=assurance_position,
        remediation_due_at=normalize_timestamp(due),
        overdue=overdue,
        gaps=tuple(sorted(gaps)),
        control_evidence=tuple(sorted(controls, key=lambda item: item["control_id"])),
        evidence_inventory=inventory,
        non_claims={
            "asset_inventory_completeness_established": False,
            "production_remediation_established": False,
            "regulatory_compliance_established": False,
            "residual_risk_acceptability_established": False,
            "scanner_completeness_established": False,
            "vulnerability_absence_established": False,
        },
    )
