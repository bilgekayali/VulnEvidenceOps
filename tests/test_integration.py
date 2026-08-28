from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest

from vulnevidenceops import (
    IntegrationHandoff,
    IntegrationVerification,
    build_integration_handoff,
    git_blob_id,
    verify_integration_handoff,
)
from vulnevidenceops.cli import main
from vulnevidenceops.integration import INTEGRATION_NON_CLAIMS

from .helpers import ROOT

PROFILES = {
    "ai-threat-evaluation": {
        "payload": "synthetic-ai-threat-evaluation-report.json",
        "peer": "ai-threat-evaluation-report.schema.json",
        "producer": "ai-threat-detection-framework",
        "consumer": "vulnevidenceops",
        "role": "producer",
    },
    "datagovops-control-evidence": {
        "payload": "synthetic-assurance-dossier.json",
        "peer": "datagovops-control-evidence-reference.schema.json",
        "producer": "vulnevidenceops",
        "consumer": "datagovops",
        "role": "consumer",
    },
    "doraops-operational-control-evidence": {
        "payload": "synthetic-assurance-dossier.json",
        "peer": "doraops-operational-control-evidence.schema.json",
        "producer": "vulnevidenceops",
        "consumer": "doraops",
        "role": "consumer",
    },
    "modelriskops-assurance-evidence": {
        "payload": "synthetic-assurance-dossier.json",
        "peer": "modelriskops-assurance-evidence-reference.schema.json",
        "producer": "vulnevidenceops",
        "consumer": "modelriskops",
        "role": "consumer",
    },
}


def _json(path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _handoff(profile: str) -> IntegrationHandoff:
    path = ROOT / "examples" / f"synthetic-{profile}-handoff.json"
    return IntegrationHandoff.from_dict(_json(path))


def _payload(profile: str) -> dict:
    return _json(ROOT / "examples" / PROFILES[profile]["payload"])


def _peer_bytes(profile: str) -> bytes:
    return (ROOT / "examples" / "peer-contracts" / PROFILES[profile]["peer"]).read_bytes()


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_reference_handoffs_round_trip_and_verify(profile):
    handoff = _handoff(profile)
    expected = PROFILES[profile]
    assert handoff.to_dict() == _json(
        ROOT / "examples" / f"synthetic-{profile}-handoff.json"
    )
    assert handoff.producer_system == expected["producer"]
    assert handoff.consumer_system == expected["consumer"]
    assert handoff.peer_contract.contract_role == expected["role"]
    assert git_blob_id(_peer_bytes(profile)) == handoff.peer_contract.blob

    verification = verify_integration_handoff(
        handoff,
        _payload(profile),
        _peer_bytes(profile),
        verified_at="2026-01-20T00:15:00Z",
    )
    assert verification.to_dict() == _json(
        ROOT / "examples" / f"synthetic-{profile}-verification.json"
    )
    assert verification.integration_position == "verified"
    assert verification.gaps == ()
    assert not any(verification.non_claims.values())


def test_builder_freezes_profile_and_canonical_payload_identity():
    payload = {"z": 1, "a": {"value": True}}
    handoff = build_integration_handoff(
        payload,
        handoff_id="HANDOFF-TEST-001",
        profile="datagovops-control-evidence",
        subject_ref="synthetic:test",
        created_at="2026-01-01T00:00:00+00:00",
        valid_until=None,
        synthetic=True,
    )
    reordered = {"a": {"value": True}, "z": 1}
    assert handoff.payload_sha256 == build_integration_handoff(
        reordered,
        handoff_id="HANDOFF-TEST-002",
        profile="datagovops-control-evidence",
        subject_ref="synthetic:test",
        created_at="2026-01-01T00:00:00Z",
        valid_until=None,
        synthetic=True,
    ).payload_sha256
    assert handoff.peer_contract.system == "datagovops"
    assert handoff.created_at == "2026-01-01T00:00:00Z"
    assert handoff.non_claims == INTEGRATION_NON_CLAIMS


def test_tampered_payload_is_invalid_with_exact_gap():
    handoff = _handoff("datagovops-control-evidence")
    payload = _payload(handoff.profile)
    payload["case_id"] = "CASE-TAMPERED"
    result = verify_integration_handoff(
        handoff,
        payload,
        _peer_bytes(handoff.profile),
        verified_at="2026-01-20T00:15:00Z",
    )
    assert result.integration_position == "invalid"
    assert result.gaps == ("payload_digest_mismatch",)


def test_wrong_peer_contract_is_invalid_with_exact_gap():
    handoff = _handoff("doraops-operational-control-evidence")
    result = verify_integration_handoff(
        handoff,
        _payload(handoff.profile),
        _peer_bytes("datagovops-control-evidence"),
        verified_at="2026-01-20T00:15:00Z",
    )
    assert result.integration_position == "invalid"
    assert result.gaps == ("peer_contract_blob_mismatch",)


def test_profile_drift_is_invalid_even_when_payload_and_blob_match():
    handoff = _handoff("datagovops-control-evidence")
    drifted = replace(handoff, relationship="operational_control_evidence")
    result = verify_integration_handoff(
        drifted,
        _payload(handoff.profile),
        _peer_bytes(handoff.profile),
        verified_at="2026-01-20T00:15:00Z",
    )
    assert result.integration_position == "invalid"
    assert result.gaps == ("profile_binding_mismatch",)


@pytest.mark.parametrize(
    ("verified_at", "state", "gap"),
    [
        ("2026-01-19T23:59:59Z", "future", "handoff_future"),
        ("2027-01-20T00:10:00Z", "expired", "handoff_expired"),
    ],
)
def test_temporal_gaps_are_visible_without_breaking_local_identity(
    verified_at,
    state,
    gap,
):
    handoff = _handoff("modelriskops-assurance-evidence")
    result = verify_integration_handoff(
        handoff,
        _payload(handoff.profile),
        _peer_bytes(handoff.profile),
        verified_at=verified_at,
    )
    assert result.temporal_state == state
    assert result.integration_position == "with_gaps"
    assert result.gaps == (gap,)


def test_verification_record_rejects_inconsistent_gaps_and_position():
    handoff = _handoff("datagovops-control-evidence")
    result = verify_integration_handoff(
        handoff,
        _payload(handoff.profile),
        _peer_bytes(handoff.profile),
        verified_at="2026-01-20T00:15:00Z",
    )
    with pytest.raises(ValueError, match="gaps must exactly match"):
        replace(result, gaps=("payload_digest_mismatch",))
    with pytest.raises(ValueError, match="integration_position"):
        replace(result, integration_position="with_gaps")


def test_strict_record_validation_rejects_invalid_contracts():
    document = _handoff("datagovops-control-evidence").to_dict()
    invalid = copy.deepcopy(document)
    invalid["unexpected"] = True
    with pytest.raises(ValueError, match="unexpected fields"):
        IntegrationHandoff.from_dict(invalid)
    with pytest.raises(ValueError, match="valid_until"):
        replace(
            _handoff("datagovops-control-evidence"),
            valid_until="2026-01-19T00:00:00Z",
        )
    with pytest.raises(ValueError, match="one handoff endpoint"):
        replace(
            _handoff("datagovops-control-evidence"),
            producer_system="datagovops",
            consumer_system="doraops",
        )
    with pytest.raises(ValueError, match="must differ"):
        replace(
            _handoff("datagovops-control-evidence"),
            consumer_system="vulnevidenceops",
        )
    with pytest.raises(ValueError, match="non_claims"):
        replace(_handoff("datagovops-control-evidence"), non_claims={})
    with pytest.raises(ValueError, match="PeerContractIdentity"):
        replace(_handoff("datagovops-control-evidence"), peer_contract="not-a-record")
    with pytest.raises(ValueError, match="synthetic must be a boolean"):
        replace(_handoff("datagovops-control-evidence"), synthetic=1)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("repository", "ssh://github.com/example/repo", "https://github.com"),
        ("path", "/schemas/example.json", "repository-relative"),
        ("commit", "A" * 40, "Git object ID"),
        ("blob", "a" * 39, "Git object ID"),
    ],
)
def test_peer_contract_identity_rejects_unbounded_identity(field, value, message):
    peer = _handoff("datagovops-control-evidence").peer_contract
    with pytest.raises(ValueError, match=message):
        replace(peer, **{field: value})


def test_peer_contract_cannot_point_back_to_vulnevidenceops():
    peer = _handoff("datagovops-control-evidence").peer_contract
    with pytest.raises(ValueError, match="external to VulnEvidenceOps"):
        replace(peer, system="vulnevidenceops")


def test_git_blob_id_and_argument_types_are_strict():
    assert git_blob_id(b"test\n") == "9daeafb9864cf43055ae93beb0afd6c7d144bfa4"
    with pytest.raises(TypeError, match="bytes"):
        git_blob_id("test")
    with pytest.raises(TypeError, match="JSON object"):
        build_integration_handoff(
            [],
            handoff_id="HANDOFF-TEST",
            profile="datagovops-control-evidence",
            subject_ref="synthetic:test",
            created_at="2026-01-01T00:00:00Z",
            valid_until=None,
            synthetic=True,
        )
    with pytest.raises(ValueError, match="profile"):
        build_integration_handoff(
            {},
            handoff_id="HANDOFF-TEST",
            profile="unknown-profile",
            subject_ref="synthetic:test",
            created_at="2026-01-01T00:00:00Z",
            valid_until=None,
            synthetic=True,
        )
    with pytest.raises(TypeError, match="IntegrationHandoff"):
        verify_integration_handoff(
            object(),
            {},
            b"{}\n",
            verified_at="2026-01-01T00:00:00Z",
        )
    with pytest.raises(TypeError, match="JSON object"):
        verify_integration_handoff(
            _handoff("datagovops-control-evidence"),
            [],
            _peer_bytes("datagovops-control-evidence"),
            verified_at="2026-01-01T00:00:00Z",
        )


def test_verification_requires_real_booleans_and_exact_nonclaims():
    handoff = _handoff("datagovops-control-evidence")
    result = verify_integration_handoff(
        handoff,
        _payload(handoff.profile),
        _peer_bytes(handoff.profile),
        verified_at="2026-01-20T00:15:00Z",
    )
    with pytest.raises(ValueError, match="must be a boolean"):
        replace(result, profile_binding_valid=1)
    with pytest.raises(ValueError, match="non_claims"):
        replace(result, non_claims={})


def test_cli_builds_and_verifies_integration_handoff(tmp_path):
    payload = ROOT / "examples" / "synthetic-assurance-dossier.json"
    peer = (
        ROOT
        / "examples"
        / "peer-contracts"
        / "datagovops-control-evidence-reference.schema.json"
    )
    handoff_path = tmp_path / "handoff.json"
    verification_path = tmp_path / "verification.json"
    assert (
        main(
            [
                "integration-handoff",
                str(payload),
                "--profile",
                "datagovops-control-evidence",
                "--handoff-id",
                "HANDOFF-CLI-001",
                "--subject-ref",
                "synthetic:cli",
                "--created-at",
                "2026-01-20T00:10:00Z",
                "--valid-until",
                "2027-01-20T00:10:00Z",
                "--synthetic",
                "--output",
                str(handoff_path),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "verify-integration",
                str(handoff_path),
                str(payload),
                "--peer-contract",
                str(peer),
                "--as-of",
                "2026-01-20T00:15:00Z",
                "--output",
                str(verification_path),
            ]
        )
        == 0
    )
    assert _json(verification_path)["integration_position"] == "verified"


def test_integration_verification_from_dict_is_not_part_of_the_wire_input_surface():
    result = _json(
        ROOT
        / "examples"
        / "synthetic-datagovops-control-evidence-verification.json"
    )
    record = IntegrationVerification(
        handoff_id=result["handoff_id"],
        handoff_sha256=result["handoff_sha256"],
        profile=result["profile"],
        verified_at=result["verified_at"],
        profile_binding_valid=result["profile_binding_valid"],
        payload_digest_valid=result["payload_digest_valid"],
        peer_contract_blob_valid=result["peer_contract_blob_valid"],
        temporal_state=result["temporal_state"],
        integration_position=result["integration_position"],
        gaps=tuple(result["gaps"]),
        non_claims=result["non_claims"],
    )
    assert record.to_dict() == result
