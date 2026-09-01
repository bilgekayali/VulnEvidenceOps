"""Publication state-machine tests; actual archive/wheel replay is separately tested in CI."""

from __future__ import annotations

import copy
import hashlib
import subprocess
from pathlib import Path

import pytest

from tools import publish_demo as publish
from tools.demo_evidence import EvidenceRejected
from tools.demo_release_bundle import ASSET_NAMES, archive_bytes

TARGET, OLD = "a" * 40, "b" * 40


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class FakeAPI:
    def __init__(self, policy):
        self.policy, self.main, self.protected = policy, TARGET, publish.PROTECTED_COMMIT
        self.reference, self.release = None, None
        self.commands, self.mutations = [], []
        self.files = {name: ("synthetic unit fixture " + name).encode() for name in ASSET_NAMES}
        self.raw = archive_bytes(self.files)
        self.download_override, self.move_during_download, self.corrupt_upload = None, False, False
        self.runs = [
            {
                "id": 42 + index,
                "name": name,
                "path": path,
                "head_sha": TARGET,
                "head_branch": "main",
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "head_repository": {"full_name": policy["repository"]},
                "run_attempt": 1,
            }
            for index, (path, name) in enumerate(policy["required_workflows"].items())
        ]
        ci = next(run for run in self.runs if run["name"] == "CI")
        self.run_id = ci["id"]
        self.artifacts = [
            {
                "id": 91,
                "name": f"portfolio-demo-candidate-{TARGET}-py3.12-{ci['id']}-1",
                "expired": False,
                "size_in_bytes": len(self.raw),
                "digest": digest(self.raw),
                "workflow_run": {"id": ci["id"], "head_sha": TARGET},
            }
        ]

    def get(self, path, *, optional=False):
        if path == "/git/ref/heads/main":
            return {"object": {"type": "commit", "sha": self.main}}
        if path == "/git/ref/tags/v1.0.0":
            return {"object": {"type": "commit", "sha": self.protected}}
        if path.startswith("/git/ref/tags/"):
            return self.reference
        if path.startswith("/releases/tags/"):
            return self.release
        if path.startswith("/releases?"):
            return [] if self.release is None else [self.release]
        if path.startswith("/actions/runs?"):
            return {"workflow_runs": self.runs}
        if "/artifacts?" in path:
            return {"artifacts": self.artifacts}
        raise AssertionError(path)

    def asset(self, name):
        return {"name": name, "state": "uploaded", "digest": digest(self.files[name])}

    def command(self, command, **kwargs):
        assert kwargs["check"] is True
        assert "--clobber" not in command and "DELETE" not in command and "PATCH" not in command
        self.commands.append(command)
        if command[:2] == ["gh", "api"] and command[-1].endswith("/zip"):
            if self.move_during_download:
                self.main = OLD
            raw = self.raw if self.download_override is None else self.download_override
            return subprocess.CompletedProcess(command, 0, stdout=raw)
        self.mutations.append(command)
        if command[:2] == ["gh", "api"]:
            assert "POST" in command and "ref=refs/tags/" + self.policy["tag"] in command
            assert "sha=" + TARGET in command
            self.reference = {"object": {"type": "commit", "sha": TARGET}}
        elif command[:3] == ["gh", "release", "create"]:
            assert (
                "--draft" in command and "--prerelease" in command and "--latest=false" in command
            )
            self.release = {
                "tag_name": self.policy["tag"],
                "draft": True,
                "prerelease": True,
                "assets": [],
            }
        elif command[:3] == ["gh", "release", "upload"]:
            for argument in command:
                path = Path(argument)
                if path.name in ASSET_NAMES:
                    self.release["assets"].append(
                        {
                            "name": path.name,
                            "state": "uploaded",
                            "digest": digest(path.read_bytes())
                            if not self.corrupt_upload
                            else "sha256:" + "f" * 64,
                        }
                    )
        elif command[:3] == ["gh", "release", "edit"]:
            assert "--draft=false" in command and "--latest=false" in command
            self.release["draft"] = False
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, stdout="")


@pytest.fixture
def policy():
    return {**publish.load_policy(), "enabled": True, "require_visual_report": True}


def test_repository_policy_enables_one_visual_prerelease():
    configured = publish.load_policy()
    assert configured["enabled"] is True
    assert configured["require_visual_report"] is True
    assert configured["tag"] == "demo-v1.0.0"
    assert configured["prerelease"] is True
    assert configured["make_latest"] is False


@pytest.fixture
def api(policy, monkeypatch):
    value = FakeAPI(policy)
    # The real validator's tamper/closure/archive tests are in test_portable_demo;
    # this fixture isolates GitHub write ordering and resumption without network writes.
    monkeypatch.setattr(
        publish,
        "verify_candidate",
        lambda *a, **k: {
            "source": {
                "github_actions": {
                    "repository": policy["repository"],
                    "event": "push",
                    "run_id": value.run_id,
                    "run_attempt": 1,
                }
            }
        },
    )
    return value


def test_disabled_phase_is_a_read_only_noop(policy, api):
    policy["enabled"] = False
    assert not publish.readiness(api, policy, TARGET)["ready"]
    assert "disabled" in publish.publish(api, policy, TARGET, run_command=api.command)
    assert api.commands == []


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("authorized", False),
        ("authorized_by", "someone-else"),
        ("tag", "v1.0.0"),
        ("protected_tag_commit", TARGET),
        ("prerelease", False),
        ("make_latest", True),
        ("notes_path", "../outside"),
        ("required_workflows", {}),
        ("require_visual_report", False),
    ],
)
def test_unsafe_policy_cannot_enable_publication(policy, monkeypatch, key, value):
    policy[key] = value
    monkeypatch.setattr(publish, "_read_json", lambda _: policy)
    with pytest.raises(EvidenceRejected):
        publish.load_policy()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("head_sha", OLD),
        ("event", "pull_request"),
        ("head_branch", "agent/untrusted"),
        ("head_repository", {"full_name": "untrusted/fork"}),
        ("conclusion", "failure"),
        ("conclusion", "skipped"),
        ("status", "in_progress"),
        ("path", ".github/workflows/other.yml"),
    ],
)
def test_only_successful_exact_main_push_workflows_can_publish(policy, api, key, value):
    api.runs[0][key] = value
    assert not publish.readiness(api, policy, TARGET)["ready"]
    publish.publish(api, policy, TARGET, run_command=api.command)
    assert not api.commands


def test_later_failed_attempt_overrides_success(policy, api):
    api.runs.append({**api.runs[0], "run_attempt": 2, "conclusion": "failure"})
    assert not publish.readiness(api, policy, TARGET)["ready"]


def test_protected_v1_tag_drift_blocks_every_write(policy, api):
    api.protected = OLD
    with pytest.raises(EvidenceRejected, match="protected"):
        publish.publish(api, policy, TARGET, run_command=api.command)
    assert not api.commands


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("expired", True),
        ("digest", "missing"),
        ("size_in_bytes", 0),
        ("workflow_run", {"id": 42, "head_sha": OLD}),
        ("name", "untrusted-artifact"),
    ],
)
def test_artifact_origin_digest_and_expiry_are_required(policy, api, key, value):
    api.artifacts[0][key] = value
    with pytest.raises(EvidenceRejected):
        publish.publish(api, policy, TARGET, run_command=api.command)
    assert not api.commands


def test_duplicate_candidate_artifact_is_rejected(policy, api):
    api.artifacts.append(copy.deepcopy(api.artifacts[0]))
    with pytest.raises(EvidenceRejected, match="ambiguous"):
        publish.readiness(api, policy, TARGET)


def test_download_zip_must_match_external_github_digest(policy, api):
    api.download_override = b"tampered download"
    with pytest.raises(EvidenceRejected, match="artifact digest"):
        publish.publish(api, policy, TARGET, run_command=api.command)
    assert not api.mutations


def test_main_moving_during_verification_prevents_tag_creation(policy, api):
    api.move_during_download = True
    with pytest.raises(EvidenceRejected, match="changed"):
        publish.publish(api, policy, TARGET, run_command=api.command)
    assert not api.mutations


def test_candidate_validation_failure_prevents_every_external_write(policy, api, monkeypatch):
    def rejected(*args, **kwargs):
        raise EvidenceRejected("bad candidate")

    monkeypatch.setattr(publish, "verify_candidate", rejected)
    with pytest.raises(EvidenceRejected):
        publish.publish(api, policy, TARGET, run_command=api.command)
    assert not api.mutations


def test_success_creates_tag_draft_verifies_assets_then_publishes_once(policy, api):
    result = publish.publish(api, policy, TARGET, run_command=api.command)
    assert "Published demo-v1.0.0" in result
    assert api.reference["object"]["sha"] == TARGET
    assert api.protected == publish.PROTECTED_COMMIT
    assert api.release["draft"] is False
    assert {item["name"] for item in api.release["assets"]} == ASSET_NAMES
    count = len(api.mutations)
    assert "retained" in publish.publish(api, policy, TARGET, run_command=api.command)
    assert len(api.mutations) == count


def test_existing_published_demo_on_older_sha_is_never_edited(policy, api):
    api.reference = {"object": {"type": "commit", "sha": OLD}}
    api.release = {
        "tag_name": policy["tag"],
        "draft": False,
        "prerelease": True,
        "assets": [api.asset(name) for name in ASSET_NAMES],
    }
    assert "retained" in publish.publish(api, policy, TARGET, run_command=api.command)
    assert not api.commands


def test_orphaned_tag_on_other_sha_is_never_moved(policy, api):
    api.reference = {"object": {"type": "commit", "sha": OLD}}
    with pytest.raises(EvidenceRejected, match="not be moved"):
        publish.publish(api, policy, TARGET, run_command=api.command)
    assert not api.commands


def test_same_sha_partial_draft_resumes_without_clobber(policy, api):
    api.reference = {"object": {"type": "commit", "sha": TARGET}}
    api.release = {
        "tag_name": policy["tag"],
        "draft": True,
        "prerelease": True,
        "assets": [api.asset("REPLAY.md")],
    }
    publish.publish(api, policy, TARGET, run_command=api.command)
    assert len(api.mutations) == 2
    assert api.mutations[0][2] == "upload"
    assert api.mutations[1][2] == "edit"
    assert len(api.release["assets"]) == 5


def test_conflicting_draft_asset_is_retained_and_not_overwritten(policy, api):
    api.reference = {"object": {"type": "commit", "sha": TARGET}}
    api.release = {
        "tag_name": policy["tag"],
        "draft": True,
        "prerelease": True,
        "assets": [{**api.asset("REPLAY.md"), "digest": "sha256:" + "f" * 64}],
    }
    with pytest.raises(EvidenceRejected, match="clobber"):
        publish.publish(api, policy, TARGET, run_command=api.command)
    assert not api.mutations


def test_bad_uploaded_asset_prevents_draft_publication(policy, api):
    api.corrupt_upload = True
    with pytest.raises(EvidenceRejected, match="uploaded"):
        publish.publish(api, policy, TARGET, run_command=api.command)
    assert api.release["draft"] is True
    assert all(command[:3] != ["gh", "release", "edit"] for command in api.mutations)


def test_published_demo_with_missing_assets_is_not_silently_repaired(policy, api):
    api.reference = {"object": {"type": "commit", "sha": TARGET}}
    api.release = {"tag_name": policy["tag"], "draft": False, "prerelease": True, "assets": []}
    with pytest.raises(EvidenceRejected, match="incomplete"):
        publish.publish(api, policy, TARGET, run_command=api.command)
    assert not api.commands
