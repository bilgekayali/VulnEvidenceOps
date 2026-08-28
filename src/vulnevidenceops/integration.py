"""Digest-bound peer handoffs without interoperability or trust conclusions."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
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

INTEGRATION_CONTRACT = "vulnevidenceops.integration-contract.v1"
INTEGRATION_PROFILES = frozenset(
    {
        "ai-threat-evaluation",
        "datagovops-control-evidence",
        "doraops-operational-control-evidence",
        "modelriskops-assurance-evidence",
    }
)
INTEGRATION_SYSTEMS = frozenset(
    {
        "ai-threat-detection-framework",
        "datagovops",
        "doraops",
        "modelriskops",
        "vulnevidenceops",
    }
)
CONTRACT_ROLES = frozenset({"consumer", "producer"})
TEMPORAL_STATES = frozenset({"current", "expired", "future"})
INTEGRATION_POSITIONS = frozenset({"invalid", "verified", "with_gaps"})
INTEGRATION_NON_CLAIMS = {
    "artifact_safety_established": False,
    "consumer_acceptance_established": False,
    "cross_system_identity_established": False,
    "delivery_established": False,
    "payload_schema_conformance_established": False,
    "payload_truth_established": False,
    "peer_contract_semantic_compatibility_established": False,
    "peer_repository_authenticity_established": False,
    "producer_authority_established": False,
    "production_interoperability_established": False,
    "regulatory_compliance_established": False,
}

_GIT_OBJECT_ID_LENGTH = 40
_PROFILE_BINDINGS: dict[str, dict[str, str]] = {
    "datagovops-control-evidence": {
        "producer_system": "vulnevidenceops",
        "consumer_system": "datagovops",
        "relationship": "control_evidence",
        "payload_type": "application/vnd.vulnevidenceops.assurance-dossier.v1+json",
        "contract_role": "consumer",
        "repository": "https://github.com/bilgekayali/DataGovOps",
        "commit": "8bfd1b9558ae996e15f4c3d21158e8688d657f16",
        "tree": "d9230e35735f75988a9018333ece9ee4399fa1bf",
        "path": "schemas/control-evidence-reference.schema.json",
        "blob": "0c5fa5ac54aca4d482079fed5c8300609ef4439d",
    },
    "doraops-operational-control-evidence": {
        "producer_system": "vulnevidenceops",
        "consumer_system": "doraops",
        "relationship": "operational_control_evidence",
        "payload_type": "application/vnd.vulnevidenceops.assurance-dossier.v1+json",
        "contract_role": "consumer",
        "repository": "https://github.com/bilgekayali/DORAOps",
        "commit": "c4a565f425084f64018ec91e5aec91ba9084f4fa",
        "tree": "8271b9cafe8912ce67ed9a58d089bb63b9371ac5",
        "path": "schemas/operational-control-evidence.schema.json",
        "blob": "1b0e8338a002560baffba9eb49e1e1f84303ee9b",
    },
    "modelriskops-assurance-evidence": {
        "producer_system": "vulnevidenceops",
        "consumer_system": "modelriskops",
        "relationship": "model_security_assurance_evidence",
        "payload_type": "application/vnd.vulnevidenceops.assurance-dossier.v1+json",
        "contract_role": "consumer",
        "repository": "https://github.com/bilgekayali/ModelRiskOps",
        "commit": "a4c35ff28d2a157b49f0d72958c84629ccd32e1a",
        "tree": "b29ea0dc3cbdb2d93ed9d31dd80dee1728af2aae",
        "path": "schemas/assurance-evidence-reference.schema.json",
        "blob": "c132e9531ab5263b2d741bccdf6167d60ae87f1e",
    },
    "ai-threat-evaluation": {
        "producer_system": "ai-threat-detection-framework",
        "consumer_system": "vulnevidenceops",
        "relationship": "alert_evaluation_evidence",
        "payload_type": "application/vnd.ai-threat-detection.evaluation-report.v1+json",
        "contract_role": "producer",
        "repository": "https://github.com/bilgekayali/ai-threat-detection-framework",
        "commit": "3c268ebfbd57a4ce7885cc1901ceb34d852f7191",
        "tree": "89e69bb5b8ac0fad2d988a1b3086b549c5ce46d1",
        "path": "schemas/evaluation-report.schema.json",
        "blob": "4a05d6bb24ef8b08c71240a1f22e0f830a81f4c1",
    },
}


def _require_git_object_id(name: str, value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != _GIT_OBJECT_ID_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} must be a lowercase 40-character Git object ID")


def git_blob_id(content: bytes) -> str:
    """Return Git's SHA-1 blob identity; this is identity, not a trust primitive."""

    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


@dataclass(frozen=True)
class PeerContractIdentity:
    """Immutable Git identity for one public peer contract snapshot."""

    system: str
    contract_role: str
    repository: str
    commit: str
    tree: str
    path: str
    blob: str

    def __post_init__(self) -> None:
        require_enum("system", self.system, INTEGRATION_SYSTEMS)
        if self.system == "vulnevidenceops":
            raise ValueError("peer contract system must be external to VulnEvidenceOps")
        require_enum("contract_role", self.contract_role, CONTRACT_ROLES)
        for name in ("repository", "path"):
            require_text(name, getattr(self, name))
        if not self.repository.startswith("https://github.com/"):
            raise ValueError("repository must be an https://github.com URL")
        if self.path.startswith("/") or ".." in self.path.split("/"):
            raise ValueError("path must be a repository-relative path")
        for name in ("commit", "tree", "blob"):
            _require_git_object_id(name, getattr(self, name))

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": "vulnevidenceops.peer-contract-identity.v1",
            "system": self.system,
            "contract_role": self.contract_role,
            "repository": self.repository,
            "commit": self.commit,
            "tree": self.tree,
            "path": self.path,
            "blob": self.blob,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> PeerContractIdentity:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.peer-contract-identity.v1",
            required=(
                "system",
                "contract_role",
                "repository",
                "commit",
                "tree",
                "path",
                "blob",
            ),
        )
        return cls(
            system=value["system"],
            contract_role=value["contract_role"],
            repository=value["repository"],
            commit=value["commit"],
            tree=value["tree"],
            path=value["path"],
            blob=value["blob"],
        )


def _peer_contract(profile: str) -> PeerContractIdentity:
    binding = _PROFILE_BINDINGS[profile]
    peer_system = (
        binding["consumer_system"]
        if binding["contract_role"] == "consumer"
        else binding["producer_system"]
    )
    return PeerContractIdentity(
        system=peer_system,
        contract_role=binding["contract_role"],
        repository=binding["repository"],
        commit=binding["commit"],
        tree=binding["tree"],
        path=binding["path"],
        blob=binding["blob"],
    )


@dataclass(frozen=True)
class IntegrationHandoff:
    """One payload digest and the exact peer contract it is intended to meet."""

    handoff_id: str
    profile: str
    producer_system: str
    consumer_system: str
    relationship: str
    payload_type: str
    payload_sha256: str
    subject_ref: str
    peer_contract: PeerContractIdentity
    created_at: str
    valid_until: str | None
    synthetic: bool
    non_claims: dict[str, bool]

    def __post_init__(self) -> None:
        for name in ("handoff_id", "relationship", "payload_type", "subject_ref"):
            require_text(name, getattr(self, name))
        require_enum("profile", self.profile, INTEGRATION_PROFILES)
        require_enum("producer_system", self.producer_system, INTEGRATION_SYSTEMS)
        require_enum("consumer_system", self.consumer_system, INTEGRATION_SYSTEMS)
        if self.producer_system == self.consumer_system:
            raise ValueError("producer_system and consumer_system must differ")
        if "vulnevidenceops" not in {self.producer_system, self.consumer_system}:
            raise ValueError("one handoff endpoint must be VulnEvidenceOps")
        require_sha256("payload_sha256", self.payload_sha256)
        if not isinstance(self.peer_contract, PeerContractIdentity):
            raise ValueError("peer_contract must be a PeerContractIdentity")
        created = parse_timestamp("created_at", self.created_at)
        if self.valid_until is not None:
            valid_until = parse_timestamp("valid_until", self.valid_until)
            if valid_until <= created:
                raise ValueError("valid_until must be later than created_at")
        if not isinstance(self.synthetic, bool):
            raise ValueError("synthetic must be a boolean")
        if self.non_claims != INTEGRATION_NON_CLAIMS:
            raise ValueError("integration non_claims must preserve every explicit false value")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.integration-handoff.v1",
            "handoff_id": self.handoff_id,
            "profile": self.profile,
            "producer_system": self.producer_system,
            "consumer_system": self.consumer_system,
            "relationship": self.relationship,
            "payload_type": self.payload_type,
            "payload_sha256": self.payload_sha256,
            "subject_ref": self.subject_ref,
            "peer_contract": self.peer_contract.to_dict(),
            "created_at": self.created_at,
            "valid_until": self.valid_until,
            "synthetic": self.synthetic,
            "non_claims": dict(sorted(self.non_claims.items())),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> IntegrationHandoff:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.integration-handoff.v1",
            required=(
                "handoff_id",
                "profile",
                "producer_system",
                "consumer_system",
                "relationship",
                "payload_type",
                "payload_sha256",
                "subject_ref",
                "peer_contract",
                "created_at",
                "valid_until",
                "synthetic",
                "non_claims",
            ),
        )
        return cls(
            handoff_id=value["handoff_id"],
            profile=value["profile"],
            producer_system=value["producer_system"],
            consumer_system=value["consumer_system"],
            relationship=value["relationship"],
            payload_type=value["payload_type"],
            payload_sha256=value["payload_sha256"],
            subject_ref=value["subject_ref"],
            peer_contract=PeerContractIdentity.from_dict(value["peer_contract"]),
            created_at=value["created_at"],
            valid_until=value["valid_until"],
            synthetic=value["synthetic"],
            non_claims=dict(value["non_claims"]),
        )


def _profile_matches(handoff: IntegrationHandoff) -> bool:
    binding = _PROFILE_BINDINGS[handoff.profile]
    return (
        handoff.producer_system == binding["producer_system"]
        and handoff.consumer_system == binding["consumer_system"]
        and handoff.relationship == binding["relationship"]
        and handoff.payload_type == binding["payload_type"]
        and handoff.peer_contract == _peer_contract(handoff.profile)
    )


def build_integration_handoff(
    payload: dict[str, Any],
    *,
    handoff_id: str,
    profile: str,
    subject_ref: str,
    created_at: str,
    valid_until: str | None,
    synthetic: bool,
) -> IntegrationHandoff:
    """Bind canonical payload bytes to one frozen peer-contract profile."""

    require_enum("profile", profile, INTEGRATION_PROFILES)
    if not isinstance(payload, dict):
        raise TypeError("payload must be a JSON object")
    binding = _PROFILE_BINDINGS[profile]
    return IntegrationHandoff(
        handoff_id=handoff_id,
        profile=profile,
        producer_system=binding["producer_system"],
        consumer_system=binding["consumer_system"],
        relationship=binding["relationship"],
        payload_type=binding["payload_type"],
        payload_sha256=sha256_digest(payload),
        subject_ref=subject_ref,
        peer_contract=_peer_contract(profile),
        created_at=normalize_timestamp(parse_timestamp("created_at", created_at)),
        valid_until=(
            normalize_timestamp(parse_timestamp("valid_until", valid_until))
            if valid_until is not None
            else None
        ),
        synthetic=synthetic,
        non_claims=dict(INTEGRATION_NON_CLAIMS),
    )


@dataclass(frozen=True)
class IntegrationVerification:
    """Local digest, profile, Git-blob and time checks with exact gaps."""

    handoff_id: str
    handoff_sha256: str
    profile: str
    verified_at: str
    profile_binding_valid: bool
    payload_digest_valid: bool
    peer_contract_blob_valid: bool
    temporal_state: str
    integration_position: str
    gaps: tuple[str, ...]
    non_claims: dict[str, bool]

    def __post_init__(self) -> None:
        require_text("handoff_id", self.handoff_id)
        require_sha256("handoff_sha256", self.handoff_sha256)
        require_enum("profile", self.profile, INTEGRATION_PROFILES)
        parse_timestamp("verified_at", self.verified_at)
        for name in (
            "profile_binding_valid",
            "payload_digest_valid",
            "peer_contract_blob_valid",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be a boolean")
        require_enum("temporal_state", self.temporal_state, TEMPORAL_STATES)
        require_enum("integration_position", self.integration_position, INTEGRATION_POSITIONS)
        require_unique("gaps", self.gaps)
        expected_gaps = set()
        if not self.profile_binding_valid:
            expected_gaps.add("profile_binding_mismatch")
        if not self.payload_digest_valid:
            expected_gaps.add("payload_digest_mismatch")
        if not self.peer_contract_blob_valid:
            expected_gaps.add("peer_contract_blob_mismatch")
        if self.temporal_state != "current":
            expected_gaps.add(f"handoff_{self.temporal_state}")
        if set(self.gaps) != expected_gaps:
            raise ValueError("integration gaps must exactly match represented failures")
        invalid = not (
            self.profile_binding_valid
            and self.payload_digest_valid
            and self.peer_contract_blob_valid
        )
        expected_position = "invalid" if invalid else ("with_gaps" if self.gaps else "verified")
        if self.integration_position != expected_position:
            raise ValueError("integration_position must match represented checks and gaps")
        if self.non_claims != INTEGRATION_NON_CLAIMS:
            raise ValueError("integration non_claims must preserve every explicit false value")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.integration-verification.v1",
            "handoff_id": self.handoff_id,
            "handoff_sha256": self.handoff_sha256,
            "profile": self.profile,
            "verified_at": self.verified_at,
            "profile_binding_valid": self.profile_binding_valid,
            "payload_digest_valid": self.payload_digest_valid,
            "peer_contract_blob_valid": self.peer_contract_blob_valid,
            "temporal_state": self.temporal_state,
            "integration_position": self.integration_position,
            "gaps": list(self.gaps),
            "non_claims": dict(sorted(self.non_claims.items())),
        }


def verify_integration_handoff(
    handoff: IntegrationHandoff,
    payload: dict[str, Any],
    peer_contract_bytes: bytes,
    *,
    verified_at: str,
) -> IntegrationVerification:
    """Verify local facts only; no network, authority or semantic validation occurs."""

    if not isinstance(handoff, IntegrationHandoff):
        raise TypeError("handoff must be an IntegrationHandoff")
    if not isinstance(payload, dict):
        raise TypeError("payload must be a JSON object")
    verified = parse_timestamp("verified_at", verified_at)
    created = parse_timestamp("created_at", handoff.created_at)
    if verified < created:
        temporal_state = "future"
    elif handoff.valid_until is not None and verified >= parse_timestamp(
        "valid_until", handoff.valid_until
    ):
        temporal_state = "expired"
    else:
        temporal_state = "current"
    profile_binding_valid = _profile_matches(handoff)
    payload_digest_valid = sha256_digest(payload) == handoff.payload_sha256
    peer_contract_blob_valid = git_blob_id(peer_contract_bytes) == handoff.peer_contract.blob
    gaps = []
    if not profile_binding_valid:
        gaps.append("profile_binding_mismatch")
    if not payload_digest_valid:
        gaps.append("payload_digest_mismatch")
    if not peer_contract_blob_valid:
        gaps.append("peer_contract_blob_mismatch")
    if temporal_state != "current":
        gaps.append(f"handoff_{temporal_state}")
    invalid = not (
        profile_binding_valid and payload_digest_valid and peer_contract_blob_valid
    )
    position = "invalid" if invalid else ("with_gaps" if gaps else "verified")
    return IntegrationVerification(
        handoff_id=handoff.handoff_id,
        handoff_sha256=sha256_digest(handoff.to_dict()),
        profile=handoff.profile,
        verified_at=normalize_timestamp(verified),
        profile_binding_valid=profile_binding_valid,
        payload_digest_valid=payload_digest_valid,
        peer_contract_blob_valid=peer_contract_blob_valid,
        temporal_state=temporal_state,
        integration_position=position,
        gaps=tuple(sorted(gaps)),
        non_claims=dict(INTEGRATION_NON_CLAIMS),
    )
