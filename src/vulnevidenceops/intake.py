"""Deterministic, scanner-neutral intake adapters for selected open formats."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._validation import (
    normalize_timestamp,
    parse_timestamp,
    require_record_fields,
    require_sha256,
    require_text,
    require_unique,
)
from .canonical import sha256_digest
from .models import EvidenceReference, VulnerabilityFinding

INTAKE_ADAPTER_VERSION = "vulnevidenceops.intake.v1"
SUPPORTED_INTAKE_FORMATS = ("cyclonedx-1.5", "cyclonedx-1.6", "sarif-2.1.0")
INTAKE_NON_CLAIMS = {
    "asset_identity_established": False,
    "scanner_accuracy_established": False,
    "scanner_coverage_established": False,
    "severity_correctness_established": False,
    "source_artifact_authenticity_established": False,
    "vulnerability_presence_established": False,
}

_SARIF_LEVELS = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "informational",
}
_SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_MEDIA_TYPES = {
    "cyclonedx": "application/vnd.cyclonedx+json",
    "sarif": "application/sarif+json",
}


@dataclass(frozen=True)
class IntakeMapping:
    """Trace one normalized finding back to exact records in the source artifact."""

    mapping_id: str
    finding_id: str
    source_record_refs: tuple[str, ...]
    source_record_sha256: str
    mapped_fields: tuple[str, ...]
    notices: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_text("mapping_id", self.mapping_id)
        require_text("finding_id", self.finding_id)
        require_sha256("source_record_sha256", self.source_record_sha256)
        if not self.source_record_refs:
            raise ValueError("source_record_refs must not be empty")
        if not self.mapped_fields:
            raise ValueError("mapped_fields must not be empty")
        for name, values in (
            ("source_record_refs", self.source_record_refs),
            ("mapped_fields", self.mapped_fields),
            ("notices", self.notices),
        ):
            for value in values:
                require_text(name, value)
            require_unique(name, values)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.intake-mapping.v1",
            "mapping_id": self.mapping_id,
            "finding_id": self.finding_id,
            "source_record_refs": list(self.source_record_refs),
            "source_record_sha256": self.source_record_sha256,
            "mapped_fields": list(self.mapped_fields),
            "notices": list(self.notices),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> IntakeMapping:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.intake-mapping.v1",
            required=(
                "mapping_id",
                "finding_id",
                "source_record_refs",
                "source_record_sha256",
                "mapped_fields",
                "notices",
            ),
        )
        return cls(
            mapping_id=value["mapping_id"],
            finding_id=value["finding_id"],
            source_record_refs=tuple(value["source_record_refs"]),
            source_record_sha256=value["source_record_sha256"],
            mapped_fields=tuple(value["mapped_fields"]),
            notices=tuple(value["notices"]),
        )


@dataclass(frozen=True)
class IntakeBatch:
    """A digest-bound collection of findings and their source mapping ledger."""

    intake_id: str
    adapter_id: str
    adapter_version: str
    source_format: str
    source_format_version: str
    observed_at: str
    source_document_sha256: str
    mapping_context_sha256: str
    source_artifact: EvidenceReference
    findings: tuple[VulnerabilityFinding, ...]
    mappings: tuple[IntakeMapping, ...]
    non_claims: dict[str, bool]

    def __post_init__(self) -> None:
        for name in (
            "intake_id",
            "adapter_id",
            "adapter_version",
            "source_format",
            "source_format_version",
        ):
            require_text(name, getattr(self, name))
        parse_timestamp("observed_at", self.observed_at)
        require_sha256("source_document_sha256", self.source_document_sha256)
        require_sha256("mapping_context_sha256", self.mapping_context_sha256)
        format_id = f"{self.source_format}-{self.source_format_version}"
        if format_id not in SUPPORTED_INTAKE_FORMATS:
            raise ValueError(f"unsupported intake format: {format_id}")
        if self.adapter_id != format_id:
            raise ValueError("adapter_id must identify the selected source format and version")
        if self.adapter_version != INTAKE_ADAPTER_VERSION:
            raise ValueError(f"adapter_version must equal {INTAKE_ADAPTER_VERSION}")
        if not self.findings or not self.mappings:
            raise ValueError("intake findings and mappings must not be empty")
        if len(self.findings) != len(self.mappings):
            raise ValueError("every intake finding must have exactly one mapping")

        finding_ids = tuple(item.finding_id for item in self.findings)
        mapping_ids = tuple(item.mapping_id for item in self.mappings)
        mapped_finding_ids = tuple(item.finding_id for item in self.mappings)
        require_unique("intake finding_id", finding_ids)
        require_unique("intake mapping_id", mapping_ids)
        require_unique("mapped finding_id", mapped_finding_ids)
        if set(finding_ids) != set(mapped_finding_ids):
            raise ValueError("intake mappings must cover every finding exactly once")

        observed = parse_timestamp("observed_at", self.observed_at)
        for finding in self.findings:
            if parse_timestamp("first_observed_at", finding.first_observed_at) != observed:
                raise ValueError("intake findings must use the batch observed_at")
            if finding.evidence_refs != (self.source_artifact.evidence_id,):
                raise ValueError("intake findings must reference only the source artifact evidence")
        if self.non_claims != INTAKE_NON_CLAIMS:
            raise ValueError("intake non_claims must preserve every explicit false value")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.intake-batch.v1",
            "intake_id": self.intake_id,
            "adapter": {
                "adapter_id": self.adapter_id,
                "adapter_version": self.adapter_version,
                "source_format": self.source_format,
                "source_format_version": self.source_format_version,
            },
            "observed_at": self.observed_at,
            "source_document_sha256": self.source_document_sha256,
            "mapping_context_sha256": self.mapping_context_sha256,
            "source_artifact": self.source_artifact.to_dict(),
            "findings": [item.to_dict() for item in self.findings],
            "mappings": [item.to_dict() for item in self.mappings],
            "non_claims": dict(sorted(self.non_claims.items())),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> IntakeBatch:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.intake-batch.v1",
            required=(
                "intake_id",
                "adapter",
                "observed_at",
                "source_document_sha256",
                "mapping_context_sha256",
                "source_artifact",
                "findings",
                "mappings",
                "non_claims",
            ),
        )
        adapter = _object("adapter", value["adapter"])
        require_record_fields(
            {"schema_version": "vulnevidenceops.intake-adapter.v1", **adapter},
            schema_version="vulnevidenceops.intake-adapter.v1",
            required=(
                "adapter_id",
                "adapter_version",
                "source_format",
                "source_format_version",
            ),
        )
        return cls(
            intake_id=value["intake_id"],
            adapter_id=adapter["adapter_id"],
            adapter_version=adapter["adapter_version"],
            source_format=adapter["source_format"],
            source_format_version=adapter["source_format_version"],
            observed_at=value["observed_at"],
            source_document_sha256=value["source_document_sha256"],
            mapping_context_sha256=value["mapping_context_sha256"],
            source_artifact=EvidenceReference.from_dict(value["source_artifact"]),
            findings=tuple(VulnerabilityFinding.from_dict(item) for item in value["findings"]),
            mappings=tuple(IntakeMapping.from_dict(item) for item in value["mappings"]),
            non_claims=dict(value["non_claims"]),
        )


def _object(name: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return value


def _array(name: str, value: Any, *, allow_empty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (not value and not allow_empty):
        qualifier = "a JSON array" if allow_empty else "a non-empty JSON array"
        raise ValueError(f"{name} must be {qualifier}")
    return value


def _text(name: str, value: Any) -> str:
    require_text(name, value)
    return value.strip()


def _normalize_time(name: str, value: str) -> str:
    return normalize_timestamp(parse_timestamp(name, value))


def _mapping_identity(prefix: str, value: object) -> str:
    return f"{prefix}-{sha256_digest(value)[:24].upper()}"


def _context(
    *,
    artifact_ref: str,
    artifact_sha256: str,
    collected_at: str,
    observed_at: str,
    source_identity: str,
    source_ref: str,
    synthetic: bool,
    asset_context: dict[str, str],
) -> dict[str, Any]:
    for name, value in (
        ("artifact_ref", artifact_ref),
        ("source_identity", source_identity),
        ("source_ref", source_ref),
    ):
        require_text(name, value)
    for name, value in asset_context.items():
        require_text(name, value)
    require_sha256("artifact_sha256", artifact_sha256)
    if not isinstance(synthetic, bool):
        raise ValueError("synthetic must be a boolean")
    return {
        "artifact_ref": artifact_ref,
        "artifact_sha256": artifact_sha256,
        "collected_at": _normalize_time("collected_at", collected_at),
        "observed_at": _normalize_time("observed_at", observed_at),
        "source_identity": source_identity,
        "source_ref": source_ref,
        "synthetic": synthetic,
        **dict(sorted(asset_context.items())),
    }


def _batch(
    document: dict[str, Any],
    *,
    source_format: str,
    source_format_version: str,
    context: dict[str, Any],
    records: list[tuple[VulnerabilityFinding, IntakeMapping]],
) -> IntakeBatch:
    if not records:
        raise ValueError("source document contains no mappable vulnerability records")
    adapter_id = f"{source_format}-{source_format_version}"
    source_document_sha256 = sha256_digest(document)
    mapping_context_sha256 = sha256_digest(context)
    evidence = EvidenceReference(
        evidence_id=f"EVD-INTAKE-{context['artifact_sha256'][:24].upper()}",
        artifact_ref=context["artifact_ref"],
        artifact_sha256=context["artifact_sha256"],
        media_type=_MEDIA_TYPES[source_format],
        collected_at=context["collected_at"],
        source_identity=context["source_identity"],
        synthetic=context["synthetic"],
    )
    ordered = sorted(records, key=lambda item: (item[0].finding_id, item[1].mapping_id))
    return IntakeBatch(
        intake_id=_mapping_identity(
            "INTAKE",
            {
                "adapter_id": adapter_id,
                "adapter_version": INTAKE_ADAPTER_VERSION,
                "mapping_context_sha256": mapping_context_sha256,
                "source_document_sha256": source_document_sha256,
            },
        ),
        adapter_id=adapter_id,
        adapter_version=INTAKE_ADAPTER_VERSION,
        source_format=source_format,
        source_format_version=source_format_version,
        observed_at=context["observed_at"],
        source_document_sha256=source_document_sha256,
        mapping_context_sha256=mapping_context_sha256,
        source_artifact=evidence,
        findings=tuple(item[0] for item in ordered),
        mappings=tuple(item[1] for item in ordered),
        non_claims=dict(INTAKE_NON_CLAIMS),
    )


def _sarif_rule_index(driver: dict[str, Any], run_index: int) -> dict[str, dict[str, Any]]:
    rules = driver.get("rules", [])
    rules = _array(f"runs[{run_index}].tool.driver.rules", rules, allow_empty=True)
    indexed: dict[str, dict[str, Any]] = {}
    for rule_index, candidate in enumerate(rules):
        rule = _object(f"runs[{run_index}].tool.driver.rules[{rule_index}]", candidate)
        rule_id = _text(f"runs[{run_index}].tool.driver.rules[{rule_index}].id", rule.get("id"))
        if rule_id in indexed:
            raise ValueError(f"runs[{run_index}] contains duplicate SARIF rule id {rule_id}")
        indexed[rule_id] = rule
    return indexed


def _sarif_rule_id(result: dict[str, Any], location: str) -> str:
    rule_id = result.get("ruleId")
    if rule_id is None:
        rule = _object(f"{location}.rule", result.get("rule"))
        rule_id = rule.get("id")
    return _text(f"{location}.ruleId", rule_id)


def _sarif_title(result: dict[str, Any], location: str) -> tuple[str, tuple[str, ...]]:
    message = _object(f"{location}.message", result.get("message"))
    if message.get("text") is not None:
        return _text(f"{location}.message.text", message["text"]), ()
    if message.get("markdown") is not None:
        return (
            _text(f"{location}.message.markdown", message["markdown"]),
            ("sarif_markdown_message_used",),
        )
    raise ValueError(f"{location}.message must contain text or markdown")


def _sarif_severity(
    result: dict[str, Any],
    rule: dict[str, Any] | None,
    location: str,
) -> tuple[str, tuple[str, ...], str]:
    level = result.get("level")
    level_source = "result.level"
    notices: list[str] = []
    if level is None and rule is not None:
        default = rule.get("defaultConfiguration")
        if default is not None:
            default = _object(f"{location}.rule.defaultConfiguration", default)
            level = default.get("level")
            if level is not None:
                level_source = "rule.defaultConfiguration.level"
                notices.append("sarif_rule_default_level_used")
    if level is None:
        return (
            "informational",
            ("sarif_level_missing_defaulted_to_informational",),
            "adapter.default",
        )
    level = _text(f"{location}.level", level).lower()
    if level not in _SARIF_LEVELS:
        notices.append("sarif_level_unmapped_defaulted_to_informational")
        return "informational", tuple(notices), level_source
    return _SARIF_LEVELS[level], tuple(notices), level_source


def adapt_sarif(
    document: dict[str, Any],
    *,
    artifact_ref: str,
    artifact_sha256: str,
    collected_at: str,
    observed_at: str,
    source_identity: str,
    source_ref: str,
    asset_ref: str,
    synthetic: bool = False,
) -> IntakeBatch:
    """Map every SARIF 2.1.0 result to one digest-bound vulnerability finding."""
    document = _object("document", document)
    version = _text("version", document.get("version"))
    if version != "2.1.0":
        raise ValueError("SARIF version must equal 2.1.0")
    context = _context(
        artifact_ref=artifact_ref,
        artifact_sha256=artifact_sha256,
        collected_at=collected_at,
        observed_at=observed_at,
        source_identity=source_identity,
        source_ref=source_ref,
        synthetic=synthetic,
        asset_context={"asset_ref": asset_ref},
    )
    source_document_sha256 = sha256_digest(document)
    mapping_context_sha256 = sha256_digest(context)
    evidence_id = f"EVD-INTAKE-{artifact_sha256[:24].upper()}"
    runs = _array("runs", document.get("runs"))
    records: list[tuple[VulnerabilityFinding, IntakeMapping]] = []

    for run_index, candidate in enumerate(runs):
        run_location = f"runs[{run_index}]"
        run = _object(run_location, candidate)
        tool = _object(f"{run_location}.tool", run.get("tool"))
        driver = _object(f"{run_location}.tool.driver", tool.get("driver"))
        _text(f"{run_location}.tool.driver.name", driver.get("name"))
        rules = _sarif_rule_index(driver, run_index)
        results = _array(f"{run_location}.results", run.get("results", []), allow_empty=True)
        for result_index, candidate_result in enumerate(results):
            location = f"{run_location}.results[{result_index}]"
            pointer = f"/runs/{run_index}/results/{result_index}"
            result = _object(location, candidate_result)
            rule_id = _sarif_rule_id(result, location)
            title, title_notices = _sarif_title(result, location)
            severity, severity_notices, severity_source = _sarif_severity(
                result,
                rules.get(rule_id),
                location,
            )
            source_record_sha256 = sha256_digest(result)
            finding_id = _mapping_identity(
                "FIND-INTAKE",
                {
                    "adapter_id": "sarif-2.1.0",
                    "mapping_context_sha256": mapping_context_sha256,
                    "source_document_sha256": source_document_sha256,
                    "source_record_ref": pointer,
                    "source_record_sha256": source_record_sha256,
                },
            )
            finding = VulnerabilityFinding(
                finding_id=finding_id,
                asset_ref=asset_ref,
                source_ref=source_ref,
                title=title,
                severity=severity,
                first_observed_at=context["observed_at"],
                technical_identifiers=(rule_id,),
                evidence_refs=(evidence_id,),
            )
            mapped_fields = (
                "asset_ref<=adapter_context.asset_ref",
                "evidence_refs<=source_artifact.evidence_id",
                "first_observed_at<=adapter_context.observed_at",
                "severity<=" + severity_source,
                "technical_identifiers<=ruleId",
                "title<=message.text|message.markdown",
            )
            mapping = IntakeMapping(
                mapping_id=_mapping_identity(
                    "MAP-INTAKE", {"finding_id": finding_id, "source_record_ref": pointer}
                ),
                finding_id=finding_id,
                source_record_refs=(pointer,),
                source_record_sha256=source_record_sha256,
                mapped_fields=mapped_fields,
                notices=tuple(sorted({*title_notices, *severity_notices})),
            )
            records.append((finding, mapping))

    return _batch(
        document,
        source_format="sarif",
        source_format_version=version,
        context=context,
        records=records,
    )


def _cyclonedx_severity(
    vulnerability: dict[str, Any], location: str
) -> tuple[str, tuple[str, ...]]:
    ratings = _array(f"{location}.ratings", vulnerability.get("ratings", []), allow_empty=True)
    mapped: list[str] = []
    notices: set[str] = set()
    for index, candidate in enumerate(ratings):
        rating = _object(f"{location}.ratings[{index}]", candidate)
        raw = rating.get("severity")
        if raw is None:
            notices.add("cyclonedx_rating_without_severity_ignored")
            continue
        raw = _text(f"{location}.ratings[{index}].severity", raw).lower()
        normalized = "informational" if raw == "info" else raw
        if normalized in _SEVERITY_ORDER:
            mapped.append(normalized)
        else:
            notices.add("cyclonedx_severity_unmapped_defaulted_to_informational")
    if not mapped:
        notices.add("cyclonedx_severity_missing_defaulted_to_informational")
        return "informational", tuple(sorted(notices))
    if len(set(mapped)) > 1:
        notices.add("cyclonedx_highest_rating_selected")
    return max(mapped, key=_SEVERITY_ORDER.__getitem__), tuple(sorted(notices))


def _cyclonedx_identifiers(vulnerability: dict[str, Any], location: str) -> tuple[str, ...]:
    identifiers = [_text(f"{location}.id", vulnerability.get("id"))]
    cwes = _array(f"{location}.cwes", vulnerability.get("cwes", []), allow_empty=True)
    for index, cwe in enumerate(cwes):
        if not isinstance(cwe, int) or isinstance(cwe, bool) or cwe <= 0:
            raise ValueError(f"{location}.cwes[{index}] must be a positive integer")
        identifiers.append(f"CWE-{cwe}")
    require_unique(f"{location} technical identifiers", identifiers)
    return tuple(identifiers)


def _cyclonedx_title(vulnerability: dict[str, Any], location: str) -> tuple[str, str]:
    for field in ("description", "detail"):
        if vulnerability.get(field) is not None:
            return _text(f"{location}.{field}", vulnerability[field]), field
    return _text(f"{location}.id", vulnerability.get("id")), "id"


def adapt_cyclonedx(
    document: dict[str, Any],
    *,
    artifact_ref: str,
    artifact_sha256: str,
    collected_at: str,
    observed_at: str,
    source_identity: str,
    source_ref: str,
    asset_ref_prefix: str,
    synthetic: bool = False,
) -> IntakeBatch:
    """Map each CycloneDX 1.5/1.6 vulnerability-affect pair to one finding."""
    document = _object("document", document)
    if _text("bomFormat", document.get("bomFormat")) != "CycloneDX":
        raise ValueError("bomFormat must equal CycloneDX")
    version = _text("specVersion", document.get("specVersion"))
    if version not in {"1.5", "1.6"}:
        raise ValueError("CycloneDX specVersion must equal 1.5 or 1.6")
    context = _context(
        artifact_ref=artifact_ref,
        artifact_sha256=artifact_sha256,
        collected_at=collected_at,
        observed_at=observed_at,
        source_identity=source_identity,
        source_ref=source_ref,
        synthetic=synthetic,
        asset_context={"asset_ref_prefix": asset_ref_prefix},
    )
    source_document_sha256 = sha256_digest(document)
    mapping_context_sha256 = sha256_digest(context)
    evidence_id = f"EVD-INTAKE-{artifact_sha256[:24].upper()}"
    vulnerabilities = _array("vulnerabilities", document.get("vulnerabilities"))
    records: list[tuple[VulnerabilityFinding, IntakeMapping]] = []

    for vulnerability_index, candidate in enumerate(vulnerabilities):
        location = f"vulnerabilities[{vulnerability_index}]"
        vulnerability_pointer = f"/vulnerabilities/{vulnerability_index}"
        vulnerability = _object(location, candidate)
        identifiers = _cyclonedx_identifiers(vulnerability, location)
        title, title_source = _cyclonedx_title(vulnerability, location)
        severity, notices = _cyclonedx_severity(vulnerability, location)
        affects = _array(f"{location}.affects", vulnerability.get("affects"))
        for affect_index, candidate_affect in enumerate(affects):
            affect_location = f"{location}.affects[{affect_index}]"
            affect_pointer = f"{vulnerability_pointer}/affects/{affect_index}"
            affect = _object(affect_location, candidate_affect)
            component_ref = _text(f"{affect_location}.ref", affect.get("ref"))
            asset_ref = asset_ref_prefix + component_ref
            source_record_sha256 = sha256_digest(
                {"affected_component": affect, "vulnerability": vulnerability}
            )
            finding_id = _mapping_identity(
                "FIND-INTAKE",
                {
                    "adapter_id": f"cyclonedx-{version}",
                    "mapping_context_sha256": mapping_context_sha256,
                    "source_document_sha256": source_document_sha256,
                    "source_record_refs": [vulnerability_pointer, affect_pointer],
                    "source_record_sha256": source_record_sha256,
                },
            )
            finding = VulnerabilityFinding(
                finding_id=finding_id,
                asset_ref=asset_ref,
                source_ref=source_ref,
                title=title,
                severity=severity,
                first_observed_at=context["observed_at"],
                technical_identifiers=identifiers,
                evidence_refs=(evidence_id,),
            )
            mapped_fields = [
                "asset_ref<=asset_ref_prefix+affects[].ref",
                "evidence_refs<=source_artifact.evidence_id",
                "first_observed_at<=adapter_context.observed_at",
                "severity<=ratings[].severity",
                "technical_identifiers<=id|cwes[]",
                f"title<={title_source}",
            ]
            mapping = IntakeMapping(
                mapping_id=_mapping_identity(
                    "MAP-INTAKE",
                    {
                        "finding_id": finding_id,
                        "source_record_refs": [vulnerability_pointer, affect_pointer],
                    },
                ),
                finding_id=finding_id,
                source_record_refs=(vulnerability_pointer, affect_pointer),
                source_record_sha256=source_record_sha256,
                mapped_fields=tuple(mapped_fields),
                notices=notices,
            )
            records.append((finding, mapping))

    return _batch(
        document,
        source_format="cyclonedx",
        source_format_version=version,
        context=context,
        records=records,
    )
