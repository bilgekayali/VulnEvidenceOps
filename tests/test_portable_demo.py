"""Offline validators use explicit tiny fake wheels; actual replay runs in matrix CI."""

from __future__ import annotations

import copy
import io
import json
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest

from tools import demo_environment as env
from tools import demo_release_bundle as bundle
from tools.demo_evidence import EvidenceRejected, finalize_bundle
from tools.publish_demo import load_policy

SOURCE = {
    "schema_version": "vulnevidenceops.demo-source-provenance.v1",
    "commit_sha": "a" * 40,
    "tree_sha": "b" * 40,
    "worktree_clean": True,
    "github_actions": {
        "repository": "bilgekayali/VulnEvidenceOps",
        "run_id": 42,
        "run_attempt": 1,
        "event": "push",
        "run_url": "https://github.com/bilgekayali/VulnEvidenceOps/actions/runs/42",
    },
    "source_authentication_established": False,
}


def write_wheel(directory, name, version):
    normalized = name.replace("-", "_")
    path = directory / f"{normalized}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"{normalized}-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        )
    return path


@pytest.fixture
def wheels(tmp_path, monkeypatch):
    monkeypatch.setattr(env, "source_identity", lambda *a, **k: copy.deepcopy(SOURCE))
    monkeypatch.setattr(bundle, "source_identity", lambda *a, **k: copy.deepcopy(SOURCE))
    directory = tmp_path / "wheels"
    directory.mkdir()
    for name, version in env.expected_distributions(env.load_lock()).items():
        write_wheel(directory, name, version)
    env.freeze_wheelhouse(directory)
    return directory


def test_complete_exact_dependency_lock():
    lock = env.load_lock()
    assert set(lock["runtime"]) == env.RUNTIME_NAMES
    assert set(lock["build"]) == env.BUILD_NAMES
    assert len(env.expected_distributions(lock)) == 12


@pytest.mark.parametrize("value", ["latest", ">=1", "1.*", "1.0; extra", None, True])
def test_unpinned_dependency_versions_are_rejected(tmp_path, value):
    lock = env.load_lock()
    lock["runtime"]["cryptography"] = value
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(lock))
    with pytest.raises(EvidenceRejected, match="exact"):
        env.load_lock(path)


def test_unknown_and_missing_dependencies_rejected(tmp_path):
    lock = env.load_lock()
    lock["runtime"].pop("cffi")
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(lock))
    with pytest.raises(EvidenceRejected, match="closure"):
        env.load_lock(path)


def test_wheel_inventory_and_hash_requirements(wheels):
    manifest = env.verify_wheelhouse(wheels)
    assert len(manifest["wheels"]) == 12
    assert (wheels / "requirements.txt").read_bytes() == env.requirements(manifest["wheels"])
    assert not manifest["independent_rebuild_is_bit_reproducible"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_commit_sha", "c" * 40),
        ("source_tree_sha", "c" * 40),
        ("runtime", {"system": "Other"}),
        ("peer_commits", {}),
        ("dependency_lock_sha256", "c" * 64),
        ("build_tool_versions", {}),
        ("source_or_publisher_authentication_established", True),
    ],
)
def test_wrong_source_platform_lock_and_claims_rejected(wheels, field, value):
    path = wheels / env.MANIFEST
    manifest = json.loads(path.read_text())
    manifest[field] = value
    path.write_text(json.dumps(manifest))
    with pytest.raises(EvidenceRejected, match="identity"):
        env.verify_wheelhouse(wheels)


def test_wheel_byte_tampering_rejected_before_installation(wheels, monkeypatch):
    path = next(wheels.glob("*.whl"))
    path.write_bytes(path.read_bytes() + b"tampered")
    monkeypatch.setattr(env.subprocess, "run", lambda *a, **k: pytest.fail("must not install"))
    with pytest.raises(EvidenceRejected, match="SHA-256"):
        env.install_wheelhouse(Path("synthetic-python"), wheels, {})


def test_requirements_cannot_add_network_or_disable_hashes(wheels):
    (wheels / "requirements.txt").write_text("--index-url https://invalid.example\n")
    with pytest.raises(EvidenceRejected, match="requirements"):
        env.verify_wheelhouse(wheels)


def test_duplicate_inventory_rejected(wheels):
    path = wheels / env.MANIFEST
    manifest = json.loads(path.read_text())
    manifest["wheels"].append(copy.deepcopy(manifest["wheels"][0]))
    path.write_text(json.dumps(manifest))
    with pytest.raises(EvidenceRejected, match="duplicated"):
        env.verify_wheelhouse(wheels)


def test_missing_and_unlisted_wheels_rejected(wheels):
    path = next(wheels.glob("*.whl"))
    path.rename(path.with_suffix(".retained"))
    with pytest.raises(EvidenceRejected, match="unknown"):
        env.verify_wheelhouse(wheels)


def test_symlinked_wheel_and_root_rejected(wheels, tmp_path):
    (wheels / "link.whl").symlink_to(next(wheels.glob("*.whl")))
    with pytest.raises(EvidenceRejected, match="links"):
        env.verify_wheelhouse(wheels)
    link = tmp_path / "wheel-link"
    link.symlink_to(wheels, target_is_directory=True)
    with pytest.raises(EvidenceRejected, match="regular"):
        env.verify_wheelhouse(link)


def test_dirty_checkout_cannot_claim_exact_wheel_replay(wheels, monkeypatch):
    monkeypatch.setattr(env, "source_identity", lambda *a, **k: {**SOURCE, "worktree_clean": False})
    with pytest.raises(EvidenceRejected):
        env.verify_wheelhouse(wheels)


def test_invalid_inventory_path_type_fails_closed(wheels):
    path = wheels / env.MANIFEST
    manifest = json.loads(path.read_text())
    manifest["wheels"][0]["filename"] = []
    path.write_text(json.dumps(manifest))
    with pytest.raises(EvidenceRejected):
        env.verify_wheelhouse(wheels)


def test_offline_installer_flags_and_pip_check(wheels, monkeypatch):
    calls = []
    monkeypatch.setattr(
        env.subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs))
    )
    env.install_wheelhouse(Path("synthetic-python"), wheels, {})
    command, kwargs = calls[0]
    assert {"--isolated", "--no-index", "--no-deps", "--require-hashes"} <= set(command)
    assert kwargs["cwd"] == wheels and kwargs["check"] is True
    assert calls[1][0][-1] == "check"


def test_existing_wheelhouse_is_not_overwritten(wheels):
    before = (wheels / env.MANIFEST).read_bytes()
    with pytest.raises(EvidenceRejected, match="exists"):
        env.prepare_wheelhouse(wheels, {})
    assert (wheels / env.MANIFEST).read_bytes() == before


def test_archives_are_sorted_and_deterministic(tmp_path):
    raw = bundle.archive_bytes({"z.json": b"{}", "nested/a.txt": b"synthetic"})
    assert raw == bundle.archive_bytes({"nested/a.txt": b"synthetic", "z.json": b"{}"})
    target = tmp_path / "unpacked"
    bundle.unpack_bounded(raw, target)
    assert (target / "nested/a.txt").read_bytes() == b"synthetic"


@pytest.mark.parametrize(
    "name", ["../outside", "/absolute", "a/../../b", "C:/absolute", "a\\b", "./a"]
)
def test_unsafe_archive_paths_rejected_before_output(tmp_path, name):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, b"synthetic")
    target = tmp_path / "unpacked"
    with pytest.raises(EvidenceRejected):
        bundle.unpack_bounded(buffer.getvalue(), target)
    assert not target.exists()


def test_archive_symlinks_rejected_before_output(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "../outside")
    with pytest.raises(EvidenceRejected):
        bundle.unpack_bounded(buffer.getvalue(), tmp_path / "out")


def test_casefold_duplicate_archive_entries_rejected(tmp_path):
    raw = bundle.archive_bytes({"a.json": b"{}", "A.json": b"{}"})
    with pytest.raises(EvidenceRejected):
        bundle.unpack_bounded(raw, tmp_path / "out")


def test_expanded_archive_size_is_bounded(tmp_path):
    raw = bundle.archive_bytes({"large.txt": b"0" * 2_000_001})
    with pytest.raises(EvidenceRejected):
        bundle.unpack_bounded(raw, tmp_path / "out")


@pytest.fixture
def candidate_inputs(wheels, tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    summary = {
        "positive_case_accepted": True,
        "upstream_signature_verified": True,
        "doraops_signature_verified": True,
        "risk_residual_level": "high",
        "risk_control_credit": 0,
        "finding_phases": {
            "before": "open",
            "remediation": "remediation_submitted",
            "final": "closed",
        },
        "production_interoperability_established": False,
        "negative_cases": {
            name: {"exit_code": 2, "accepted": False, "error_code": code}
            for name, code in bundle.REQUIRED_NEGATIVES.items()
        },
        "attention_cases": {
            name: {"resolution_state": "blocked"} for name in ("missing-retest", "failed-retest")
        },
    }
    (evidence / "summary.json").write_text(json.dumps(summary))
    (evidence / "execution-environment.json").write_text(
        json.dumps(
            {
                "installation_mode": "isolated-wheels",
                "exact_runtime_wheel_bytes_verified": True,
            }
        )
    )
    shutil.copyfile(wheels / env.MANIFEST, evidence / env.MANIFEST)
    finalize_bundle(
        evidence, source=SOURCE, contract_sha256="d" * 64, report="# Synthetic unit fixture\n"
    )
    replay = tmp_path / "replay"
    shutil.copytree(evidence, replay)
    policy = {**load_policy(), "enabled": False, "require_visual_report": False}
    return evidence, replay, wheels, policy


def test_durable_candidate_roundtrip_and_exact_replay(candidate_inputs, tmp_path):
    evidence, replay, wheels, policy = candidate_inputs
    output = tmp_path / "candidate"
    result = bundle.create_candidate(evidence, replay, wheels, output, policy)
    assert result["offline_replay_byte_identical"] is True
    assert set(path.name for path in output.iterdir()) == bundle.ASSET_NAMES
    assert (
        bundle.verify_candidate(output, expected_sha=SOURCE["commit_sha"], policy=policy) == result
    )


def test_different_replay_evidence_is_rejected(candidate_inputs, tmp_path):
    evidence, replay, wheels, policy = candidate_inputs
    (replay / "REPORT.md").write_text("changed")
    with pytest.raises(EvidenceRejected):
        bundle.create_candidate(evidence, replay, wheels, tmp_path / "candidate", policy)


def test_visual_stage_cannot_publish_without_a_presentation(candidate_inputs, tmp_path):
    evidence, replay, wheels, policy = candidate_inputs
    policy["require_visual_report"] = True
    with pytest.raises(EvidenceRejected, match="presentation"):
        bundle.create_candidate(evidence, replay, wheels, tmp_path / "candidate", policy)


@pytest.mark.parametrize("filename", sorted(bundle.ASSET_NAMES))
def test_every_release_asset_is_tamper_checked(candidate_inputs, tmp_path, filename):
    evidence, replay, wheels, policy = candidate_inputs
    output = tmp_path / "candidate"
    bundle.create_candidate(evidence, replay, wheels, output, policy)
    path = output / filename
    path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises((EvidenceRejected, ValueError)):
        bundle.verify_candidate(output, expected_sha=SOURCE["commit_sha"], policy=policy)


def test_existing_candidate_is_retained(candidate_inputs, tmp_path):
    evidence, replay, wheels, policy = candidate_inputs
    output = tmp_path / "candidate"
    bundle.create_candidate(evidence, replay, wheels, output, policy)
    old = (output / "SHA256SUMS").read_bytes()
    with pytest.raises(EvidenceRejected, match="exists"):
        bundle.create_candidate(evidence, replay, wheels, output, policy)
    assert (output / "SHA256SUMS").read_bytes() == old


def test_bootstrap_refuses_contradictory_modes(tmp_path):
    result = subprocess.run(
        [
            "python3",
            "tools/demo_doraops.py",
            "--prepared-environment",
            "--wheelhouse",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "prepared mode" in result.stderr
