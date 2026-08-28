"""Ed25519 evidence envelopes with explicit trust and timestamp non-claims."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._validation import (
    normalize_timestamp,
    parse_timestamp,
    require_enum,
    require_record_fields,
    require_sha256,
    require_text,
    require_unique,
)
from .canonical import canonical_json_bytes, sha256_digest

SIGNED_EVIDENCE_CONTRACT = "vulnevidenceops.signed-evidence.v1"
SIGNATURE_ALGORITHMS = frozenset({"ed25519"})
KEY_STATES = frozenset({"current", "expired", "future", "revoked"})
ANCHOR_TYPES = frozenset({"ledger", "other", "rfc3161", "transparency_log"})
ANCHOR_BINDING_STATES = frozenset({"bound", "unbound"})
ANCHOR_TEMPORAL_STATES = frozenset({"before_signing", "current", "future"})
VERIFICATION_POSITIONS = frozenset(
    {"cryptographically_valid", "invalid", "with_gaps"}
)
SIGNED_EVIDENCE_NON_CLAIMS = {
    "artifact_safety_established": False,
    "build_reproducibility_established": False,
    "external_anchor_authenticity_established": False,
    "non_repudiation_established": False,
    "payload_schema_conformance_established": False,
    "signer_identity_established": False,
    "signing_authority_established": False,
    "source_material_trust_established": False,
    "trusted_signing_time_established": False,
    "verification_key_authenticity_established": False,
}

_GIT_OBJECT_ID = re.compile(r"^[0-9a-f]{40}$")


def _decode_base64(name: str, value: str, *, expected_length: int | None = None) -> bytes:
    require_text(name, value)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{name} must be strict base64") from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError(f"{name} must decode to exactly {expected_length} bytes")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{name} must use canonical padded base64")
    return decoded


def _require_git_object_id(name: str, value: str) -> None:
    if not isinstance(value, str) or not _GIT_OBJECT_ID.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase 40-character Git object ID")


@dataclass(frozen=True)
class BuildProvenance:
    """Exact caller-supplied build identities without a build-trust conclusion."""

    provenance_id: str
    subject_name: str
    subject_sha256: str
    source_repository: str
    source_commit: str
    source_tree: str
    source_ref: str
    builder_identity: str
    build_type: str
    invocation_id: str
    started_at: str
    finished_at: str
    materials: tuple[dict[str, str], ...]
    synthetic: bool

    def __post_init__(self) -> None:
        for name in (
            "provenance_id",
            "subject_name",
            "source_repository",
            "source_ref",
            "builder_identity",
            "build_type",
            "invocation_id",
        ):
            require_text(name, getattr(self, name))
        require_sha256("subject_sha256", self.subject_sha256)
        _require_git_object_id("source_commit", self.source_commit)
        _require_git_object_id("source_tree", self.source_tree)
        started = parse_timestamp("started_at", self.started_at)
        finished = parse_timestamp("finished_at", self.finished_at)
        if finished < started:
            raise ValueError("finished_at must not precede started_at")
        if not isinstance(self.synthetic, bool):
            raise ValueError("synthetic must be a boolean")
        if not self.materials:
            raise ValueError("materials must contain at least one exact input identity")
        material_uris = []
        for material in self.materials:
            if set(material) != {"uri", "sha256"}:
                raise ValueError("each material must contain exactly uri and sha256")
            require_text("material uri", material["uri"])
            require_sha256("material sha256", material["sha256"])
            material_uris.append(material["uri"])
        require_unique("material uri", material_uris)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.build-provenance.v1",
            "provenance_id": self.provenance_id,
            "subject_name": self.subject_name,
            "subject_sha256": self.subject_sha256,
            "source_repository": self.source_repository,
            "source_commit": self.source_commit,
            "source_tree": self.source_tree,
            "source_ref": self.source_ref,
            "builder_identity": self.builder_identity,
            "build_type": self.build_type,
            "invocation_id": self.invocation_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "materials": [dict(sorted(material.items())) for material in self.materials],
            "synthetic": self.synthetic,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> BuildProvenance:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.build-provenance.v1",
            required=(
                "provenance_id",
                "subject_name",
                "subject_sha256",
                "source_repository",
                "source_commit",
                "source_tree",
                "source_ref",
                "builder_identity",
                "build_type",
                "invocation_id",
                "started_at",
                "finished_at",
                "materials",
                "synthetic",
            ),
        )
        return cls(
            provenance_id=value["provenance_id"],
            subject_name=value["subject_name"],
            subject_sha256=value["subject_sha256"],
            source_repository=value["source_repository"],
            source_commit=value["source_commit"],
            source_tree=value["source_tree"],
            source_ref=value["source_ref"],
            builder_identity=value["builder_identity"],
            build_type=value["build_type"],
            invocation_id=value["invocation_id"],
            started_at=value["started_at"],
            finished_at=value["finished_at"],
            materials=tuple(value["materials"]),
            synthetic=value["synthetic"],
        )


@dataclass(frozen=True)
class VerificationKey:
    """One Ed25519 public key and its caller-supplied lifecycle metadata."""

    key_id: str
    algorithm: str
    public_key_base64: str
    public_key_sha256: str
    issuer_identity: str
    valid_from: str
    valid_until: str | None
    revoked_at: str | None
    synthetic: bool

    def __post_init__(self) -> None:
        require_text("key_id", self.key_id)
        require_enum("algorithm", self.algorithm, SIGNATURE_ALGORITHMS)
        public_key = _decode_base64(
            "public_key_base64",
            self.public_key_base64,
            expected_length=32,
        )
        require_sha256("public_key_sha256", self.public_key_sha256)
        if hashlib.sha256(public_key).hexdigest() != self.public_key_sha256:
            raise ValueError("public_key_sha256 must match the decoded public key")
        Ed25519PublicKey.from_public_bytes(public_key)
        require_text("issuer_identity", self.issuer_identity)
        valid_from = parse_timestamp("valid_from", self.valid_from)
        if self.valid_until is not None:
            valid_until = parse_timestamp("valid_until", self.valid_until)
            if valid_until <= valid_from:
                raise ValueError("valid_until must be later than valid_from")
        if self.revoked_at is not None:
            parse_timestamp("revoked_at", self.revoked_at)
        if not isinstance(self.synthetic, bool):
            raise ValueError("synthetic must be a boolean")

    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(
            _decode_base64(
                "public_key_base64",
                self.public_key_base64,
                expected_length=32,
            )
        )

    def state_at(self, claimed_signing_time: datetime) -> str:
        valid_from = parse_timestamp("valid_from", self.valid_from)
        if claimed_signing_time < valid_from:
            return "future"
        if self.revoked_at is not None and claimed_signing_time >= parse_timestamp(
            "revoked_at", self.revoked_at
        ):
            return "revoked"
        if self.valid_until is not None and claimed_signing_time >= parse_timestamp(
            "valid_until", self.valid_until
        ):
            return "expired"
        return "current"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.verification-key.v1",
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_base64": self.public_key_base64,
            "public_key_sha256": self.public_key_sha256,
            "issuer_identity": self.issuer_identity,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "revoked_at": self.revoked_at,
            "synthetic": self.synthetic,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> VerificationKey:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.verification-key.v1",
            required=(
                "key_id",
                "algorithm",
                "public_key_base64",
                "public_key_sha256",
                "issuer_identity",
                "valid_from",
                "valid_until",
                "revoked_at",
                "synthetic",
            ),
        )
        return cls(
            key_id=value["key_id"],
            algorithm=value["algorithm"],
            public_key_base64=value["public_key_base64"],
            public_key_sha256=value["public_key_sha256"],
            issuer_identity=value["issuer_identity"],
            valid_from=value["valid_from"],
            valid_until=value["valid_until"],
            revoked_at=value["revoked_at"],
            synthetic=value["synthetic"],
        )


@dataclass(frozen=True)
class SignedEvidenceEnvelope:
    """Canonical JSON payload plus one context-bound Ed25519 signature."""

    payload_type: str
    payload_base64: str
    payload_sha256: str
    key_id: str
    algorithm: str
    signed_at: str
    signature_base64: str

    def __post_init__(self) -> None:
        require_text("payload_type", self.payload_type)
        payload = _decode_base64("payload_base64", self.payload_base64)
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("payload_base64 must encode a JSON document") from exc
        if not isinstance(document, dict):
            raise ValueError("payload_base64 must encode a JSON object")
        if canonical_json_bytes(document) != payload:
            raise ValueError("payload_base64 must encode strict canonical JSON bytes")
        require_sha256("payload_sha256", self.payload_sha256)
        require_text("key_id", self.key_id)
        require_enum("algorithm", self.algorithm, SIGNATURE_ALGORITHMS)
        parse_timestamp("signed_at", self.signed_at)
        _decode_base64("signature_base64", self.signature_base64, expected_length=64)

    def payload_bytes(self) -> bytes:
        return _decode_base64("payload_base64", self.payload_base64)

    def payload_document(self) -> dict[str, Any]:
        return json.loads(self.payload_bytes().decode("utf-8"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.signed-evidence-envelope.v1",
            "payload_type": self.payload_type,
            "payload_base64": self.payload_base64,
            "payload_sha256": self.payload_sha256,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "signed_at": self.signed_at,
            "signature_base64": self.signature_base64,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SignedEvidenceEnvelope:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.signed-evidence-envelope.v1",
            required=(
                "payload_type",
                "payload_base64",
                "payload_sha256",
                "key_id",
                "algorithm",
                "signed_at",
                "signature_base64",
            ),
        )
        return cls(
            payload_type=value["payload_type"],
            payload_base64=value["payload_base64"],
            payload_sha256=value["payload_sha256"],
            key_id=value["key_id"],
            algorithm=value["algorithm"],
            signed_at=value["signed_at"],
            signature_base64=value["signature_base64"],
        )


@dataclass(frozen=True)
class AnchorReceipt:
    """Opaque external anchor receipt metadata; external authenticity is not verified."""

    receipt_id: str
    envelope_sha256: str
    provider_identity: str
    anchor_type: str
    anchored_at: str
    artifact_ref: str
    artifact_sha256: str
    synthetic: bool

    def __post_init__(self) -> None:
        for name in ("receipt_id", "provider_identity", "artifact_ref"):
            require_text(name, getattr(self, name))
        require_sha256("envelope_sha256", self.envelope_sha256)
        require_enum("anchor_type", self.anchor_type, ANCHOR_TYPES)
        parse_timestamp("anchored_at", self.anchored_at)
        require_sha256("artifact_sha256", self.artifact_sha256)
        if not isinstance(self.synthetic, bool):
            raise ValueError("synthetic must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.anchor-receipt.v1",
            "receipt_id": self.receipt_id,
            "envelope_sha256": self.envelope_sha256,
            "provider_identity": self.provider_identity,
            "anchor_type": self.anchor_type,
            "anchored_at": self.anchored_at,
            "artifact_ref": self.artifact_ref,
            "artifact_sha256": self.artifact_sha256,
            "synthetic": self.synthetic,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AnchorReceipt:
        require_record_fields(
            value,
            schema_version="vulnevidenceops.anchor-receipt.v1",
            required=(
                "receipt_id",
                "envelope_sha256",
                "provider_identity",
                "anchor_type",
                "anchored_at",
                "artifact_ref",
                "artifact_sha256",
                "synthetic",
            ),
        )
        return cls(
            receipt_id=value["receipt_id"],
            envelope_sha256=value["envelope_sha256"],
            provider_identity=value["provider_identity"],
            anchor_type=value["anchor_type"],
            anchored_at=value["anchored_at"],
            artifact_ref=value["artifact_ref"],
            artifact_sha256=value["artifact_sha256"],
            synthetic=value["synthetic"],
        )


@dataclass(frozen=True)
class SignatureVerification:
    """Cryptographic result kept separate from identity, authority, time and build trust."""

    envelope_sha256: str
    payload_type: str
    payload_sha256: str
    envelope_key_id: str
    algorithm: str
    verification_key_id: str
    verification_key_sha256: str
    signed_at: str
    verified_at: str
    signature_valid: bool
    payload_digest_valid: bool
    key_state: str
    anchor_receipts: tuple[dict[str, Any], ...]
    verification_position: str
    gaps: tuple[str, ...]
    non_claims: dict[str, bool]

    def __post_init__(self) -> None:
        require_sha256("envelope_sha256", self.envelope_sha256)
        require_text("payload_type", self.payload_type)
        require_sha256("payload_sha256", self.payload_sha256)
        require_text("envelope_key_id", self.envelope_key_id)
        require_enum("algorithm", self.algorithm, SIGNATURE_ALGORITHMS)
        require_text("verification_key_id", self.verification_key_id)
        require_sha256("verification_key_sha256", self.verification_key_sha256)
        signed = parse_timestamp("signed_at", self.signed_at)
        verified = parse_timestamp("verified_at", self.verified_at)
        for name in ("signature_valid", "payload_digest_valid"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be a boolean")
        require_enum("key_state", self.key_state, KEY_STATES)
        receipt_ids = []
        for receipt in self.anchor_receipts:
            required = {
                "receipt_id",
                "provider_identity",
                "anchor_type",
                "anchored_at",
                "artifact_ref",
                "artifact_sha256",
                "receipt_sha256",
                "binding_state",
                "temporal_state",
                "external_validation_performed",
                "synthetic",
            }
            if set(receipt) != required:
                raise ValueError("anchor verification records must preserve the exact field set")
            require_text("receipt_id", receipt["receipt_id"])
            require_text("provider_identity", receipt["provider_identity"])
            require_enum("anchor_type", receipt["anchor_type"], ANCHOR_TYPES)
            parse_timestamp("anchored_at", receipt["anchored_at"])
            require_text("artifact_ref", receipt["artifact_ref"])
            require_sha256("artifact_sha256", receipt["artifact_sha256"])
            require_sha256("receipt_sha256", receipt["receipt_sha256"])
            require_enum(
                "binding_state",
                receipt["binding_state"],
                ANCHOR_BINDING_STATES,
            )
            require_enum(
                "temporal_state",
                receipt["temporal_state"],
                ANCHOR_TEMPORAL_STATES,
            )
            if receipt["external_validation_performed"] is not False:
                raise ValueError("external anchor validation must remain explicit false")
            if not isinstance(receipt["synthetic"], bool):
                raise ValueError("anchor synthetic must be a boolean")
            receipt_ids.append(receipt["receipt_id"])
        require_unique("anchor receipt_id", receipt_ids)
        require_enum(
            "verification_position",
            self.verification_position,
            VERIFICATION_POSITIONS,
        )
        require_unique("gaps", self.gaps)
        represented_gaps = set()
        if self.envelope_key_id != self.verification_key_id:
            represented_gaps.add("verification_key_id_mismatch")
        if not self.signature_valid:
            represented_gaps.add("signature_invalid")
        if not self.payload_digest_valid:
            represented_gaps.add("payload_digest_mismatch")
        if self.key_state != "current":
            represented_gaps.add(
                f"verification_key_{self.key_state}_at_claimed_signing_time"
            )
        if signed > verified:
            represented_gaps.add("claimed_signing_time_future")
        for receipt in self.anchor_receipts:
            if receipt["binding_state"] != "bound":
                represented_gaps.add(f"anchor_receipt_unbound:{receipt['receipt_id']}")
            if receipt["temporal_state"] != "current":
                represented_gaps.add(
                    f"anchor_receipt_{receipt['temporal_state']}:{receipt['receipt_id']}"
                )
        if set(self.gaps) != represented_gaps:
            raise ValueError("gaps must exactly match the represented verification failures")
        invalid = (
            not self.signature_valid
            or not self.payload_digest_valid
            or self.key_state != "current"
        )
        expected_position = (
            "invalid"
            if invalid
            else "with_gaps"
            if self.gaps
            else "cryptographically_valid"
        )
        if self.verification_position != expected_position:
            raise ValueError("verification_position must match the represented verification state")
        if self.non_claims != SIGNED_EVIDENCE_NON_CLAIMS:
            raise ValueError("signed-evidence non_claims must preserve every explicit false value")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "vulnevidenceops.signature-verification.v1",
            "envelope_sha256": self.envelope_sha256,
            "payload_type": self.payload_type,
            "payload_sha256": self.payload_sha256,
            "envelope_key_id": self.envelope_key_id,
            "algorithm": self.algorithm,
            "verification_key_id": self.verification_key_id,
            "verification_key_sha256": self.verification_key_sha256,
            "signed_at": self.signed_at,
            "verified_at": self.verified_at,
            "signature_valid": self.signature_valid,
            "payload_digest_valid": self.payload_digest_valid,
            "key_state": self.key_state,
            "anchor_receipts": list(self.anchor_receipts),
            "verification_position": self.verification_position,
            "gaps": list(self.gaps),
            "non_claims": dict(sorted(self.non_claims.items())),
        }


def _signature_input(
    *,
    payload_type: str,
    payload_sha256: str,
    key_id: str,
    algorithm: str,
    signed_at: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": "vulnevidenceops.signature-input.v1",
            "payload_type": payload_type,
            "payload_sha256": payload_sha256,
            "key_id": key_id,
            "algorithm": algorithm,
            "signed_at": signed_at,
        }
    )


def sign_evidence(
    payload: dict[str, Any],
    *,
    payload_type: str,
    key_id: str,
    private_key: Ed25519PrivateKey,
    signed_at: str,
) -> SignedEvidenceEnvelope:
    """Sign canonical JSON with an in-memory Ed25519 private key object."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    require_text("payload_type", payload_type)
    require_text("key_id", key_id)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private_key must be an Ed25519PrivateKey")
    normalized_signed_at = normalize_timestamp(parse_timestamp("signed_at", signed_at))
    payload_bytes = canonical_json_bytes(payload)
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    signature = private_key.sign(
        _signature_input(
            payload_type=payload_type,
            payload_sha256=payload_sha256,
            key_id=key_id,
            algorithm="ed25519",
            signed_at=normalized_signed_at,
        )
    )
    return SignedEvidenceEnvelope(
        payload_type=payload_type,
        payload_base64=base64.b64encode(payload_bytes).decode("ascii"),
        payload_sha256=payload_sha256,
        key_id=key_id,
        algorithm="ed25519",
        signed_at=normalized_signed_at,
        signature_base64=base64.b64encode(signature).decode("ascii"),
    )


def verify_signed_evidence(
    envelope: SignedEvidenceEnvelope,
    key: VerificationKey,
    *,
    verified_at: str,
    anchor_receipts: tuple[AnchorReceipt, ...] = (),
) -> SignatureVerification:
    """Verify local cryptographic facts without promoting them to trust conclusions."""
    if not isinstance(envelope, SignedEvidenceEnvelope):
        raise ValueError("envelope must be a SignedEvidenceEnvelope")
    if not isinstance(key, VerificationKey):
        raise ValueError("key must be a VerificationKey")
    if any(not isinstance(receipt, AnchorReceipt) for receipt in anchor_receipts):
        raise ValueError("anchor_receipts must contain only AnchorReceipt records")
    require_unique("anchor receipt_id", (receipt.receipt_id for receipt in anchor_receipts))

    verified = parse_timestamp("verified_at", verified_at)
    signed = parse_timestamp("signed_at", envelope.signed_at)
    payload_digest_valid = (
        hashlib.sha256(envelope.payload_bytes()).hexdigest() == envelope.payload_sha256
    )
    key_matches = key.key_id == envelope.key_id and key.algorithm == envelope.algorithm
    signature_valid = False
    if key_matches:
        try:
            key.public_key().verify(
                _decode_base64(
                    "signature_base64",
                    envelope.signature_base64,
                    expected_length=64,
                ),
                _signature_input(
                    payload_type=envelope.payload_type,
                    payload_sha256=envelope.payload_sha256,
                    key_id=envelope.key_id,
                    algorithm=envelope.algorithm,
                    signed_at=envelope.signed_at,
                ),
            )
            signature_valid = True
        except InvalidSignature:
            pass

    key_state = key.state_at(signed)
    gaps = set()
    if not key_matches:
        gaps.add("verification_key_id_mismatch")
    if not signature_valid:
        gaps.add("signature_invalid")
    if not payload_digest_valid:
        gaps.add("payload_digest_mismatch")
    if key_state != "current":
        gaps.add(f"verification_key_{key_state}_at_claimed_signing_time")
    if signed > verified:
        gaps.add("claimed_signing_time_future")

    envelope_sha256 = sha256_digest(envelope.to_dict())
    receipt_results = []
    for receipt in sorted(anchor_receipts, key=lambda item: item.receipt_id):
        binding_state = (
            "bound" if receipt.envelope_sha256 == envelope_sha256 else "unbound"
        )
        anchored = parse_timestamp("anchored_at", receipt.anchored_at)
        if anchored < signed:
            temporal_state = "before_signing"
        elif anchored > verified:
            temporal_state = "future"
        else:
            temporal_state = "current"
        if binding_state != "bound":
            gaps.add(f"anchor_receipt_unbound:{receipt.receipt_id}")
        if temporal_state != "current":
            gaps.add(f"anchor_receipt_{temporal_state}:{receipt.receipt_id}")
        receipt_results.append(
            {
                "receipt_id": receipt.receipt_id,
                "provider_identity": receipt.provider_identity,
                "anchor_type": receipt.anchor_type,
                "anchored_at": receipt.anchored_at,
                "artifact_ref": receipt.artifact_ref,
                "artifact_sha256": receipt.artifact_sha256,
                "receipt_sha256": sha256_digest(receipt.to_dict()),
                "binding_state": binding_state,
                "temporal_state": temporal_state,
                "external_validation_performed": False,
                "synthetic": receipt.synthetic,
            }
        )

    invalid = not signature_valid or not payload_digest_valid or key_state != "current"
    verification_position = (
        "invalid" if invalid else "with_gaps" if gaps else "cryptographically_valid"
    )
    return SignatureVerification(
        envelope_sha256=envelope_sha256,
        payload_type=envelope.payload_type,
        payload_sha256=envelope.payload_sha256,
        envelope_key_id=envelope.key_id,
        algorithm=envelope.algorithm,
        verification_key_id=key.key_id,
        verification_key_sha256=key.public_key_sha256,
        signed_at=envelope.signed_at,
        verified_at=normalize_timestamp(verified),
        signature_valid=signature_valid,
        payload_digest_valid=payload_digest_valid,
        key_state=key_state,
        anchor_receipts=tuple(receipt_results),
        verification_position=verification_position,
        gaps=tuple(sorted(gaps)),
        non_claims=dict(SIGNED_EVIDENCE_NON_CLAIMS),
    )
