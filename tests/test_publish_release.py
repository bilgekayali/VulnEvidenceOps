from __future__ import annotations

import copy
import urllib.error

import pytest

from tools.publish_release import GitHub, gate, load_policy, publish, tag_commit, workflow_gaps

TARGET = "a" * 40
OLD = "b" * 40


@pytest.fixture
def policy():
    return load_policy()


@pytest.fixture
def runs(policy):
    return [
        {
            "id": index + 1,
            "name": name,
            "path": path,
            "head_sha": TARGET,
            "head_branch": "main",
            "head_repository": {"full_name": policy["repository"]},
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "run_attempt": 1,
        }
        for index, (path, name) in enumerate(policy["required_workflows"].items())
    ]


class FakeGitHub:
    def __init__(self, runs):
        self.runs = runs
        self.main = TARGET
        self.reference = None
        self.release = None
        self.commands = []

    def get(self, path, *, optional=False):
        if path == "/git/ref/heads/main":
            return {"object": {"sha": self.main}}
        if path.startswith("/actions/runs?"):
            page = int(path.rsplit("=", 1)[1])
            return {"workflow_runs": self.runs[(page - 1) * 100 : page * 100]}
        if path.startswith("/git/ref/tags/"):
            return self.reference
        if path.startswith("/releases/tags/"):
            return self.release
        if path.startswith("/git/tags/"):
            return {"object": {"type": "commit", "sha": OLD}}
        raise AssertionError(path)

    def command(self, command, **kwargs):
        assert kwargs["check"] is True
        self.commands.append(command)
        if command[:2] == ["gh", "api"]:
            assert "PATCH" not in command
            self.reference = {"object": {"type": "commit", "sha": TARGET}}
        else:
            assert "--verify-tag" in command
            self.release = {"tag_name": "v1.0.0", "draft": False, "prerelease": False}


def test_all_exact_main_push_workflows_are_required(policy, runs):
    assert workflow_gaps(runs, policy, TARGET) == []
    assert gate(FakeGitHub(runs), policy, TARGET) == []
    assert workflow_gaps(runs[:-1], policy, TARGET)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("head_sha", OLD),
        ("head_branch", "agent/untrusted"),
        ("head_repository", {"full_name": "untrusted/fork"}),
        ("event", "pull_request"),
        ("path", ".github/workflows/other.yml"),
        ("name", "Other"),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("conclusion", "cancelled"),
        ("conclusion", "skipped"),
        ("conclusion", None),
    ],
)
def test_untrusted_missing_or_non_successful_runs_block_publication(policy, runs, field, value):
    runs[0][field] = value
    api = FakeGitHub(runs)
    with pytest.raises(ValueError, match="publication blocked"):
        publish(api, policy, TARGET, api.command)
    assert not api.commands


def test_new_failed_run_overrides_old_success(policy, runs):
    newer = dict(runs[0], id=50, conclusion="failure")
    assert workflow_gaps([*runs, newer], policy, TARGET)


def test_latest_rerun_attempt_must_succeed(policy, runs):
    rerun = dict(runs[0], run_attempt=2, status="queued", conclusion=None)
    assert workflow_gaps([*runs, rerun], policy, TARGET)


def test_main_moving_blocks_publication(policy, runs):
    api = FakeGitHub(runs)
    api.main = OLD
    with pytest.raises(ValueError, match="current main SHA"):
        publish(api, policy, TARGET, api.command)
    assert not api.commands


def test_short_sha_is_rejected(policy, runs):
    with pytest.raises(ValueError, match="exact 40-character SHA"):
        gate(FakeGitHub(runs), policy, TARGET[:7])


def test_gate_reads_all_pages(policy, runs):
    unrelated = dict(runs[0], path=".github/workflows/other.yml")
    assert gate(FakeGitHub([unrelated] * 100 + runs), policy, TARGET) == []


def test_new_release_creates_tag_once_then_requires_it(policy, runs):
    api = FakeGitHub(runs)
    assert "Published v1.0.0" in publish(api, policy, TARGET, api.command)
    assert len(api.commands) == 2
    assert "sha=" + TARGET in api.commands[0]
    assert "--verify-tag" in api.commands[1]
    assert "no writes" in publish(api, policy, TARGET, api.command)
    assert len(api.commands) == 2


def test_existing_release_on_older_commit_is_never_moved_or_edited(policy, runs):
    api = FakeGitHub(runs)
    api.reference = {"object": {"type": "commit", "sha": OLD}}
    api.release = {"tag_name": "v1.0.0", "draft": False, "prerelease": False}
    assert OLD in publish(api, policy, TARGET, api.command)
    assert not api.commands


def test_annotated_existing_tag_is_resolved_without_writing(policy, runs):
    api = FakeGitHub(runs)
    api.reference = {"object": {"type": "tag", "sha": "c" * 40}}
    api.release = {"tag_name": "v1.0.0", "draft": False, "prerelease": False}
    assert OLD in publish(api, policy, TARGET, api.command)
    assert not api.commands


def test_orphaned_wrong_tag_is_not_reused(policy, runs):
    api = FakeGitHub(runs)
    api.reference = {"object": {"type": "commit", "sha": OLD}}
    with pytest.raises(ValueError, match="will not be moved"):
        publish(api, policy, TARGET, api.command)
    assert not api.commands


def test_release_after_interrupted_tag_creation_uses_same_sha(policy, runs):
    api = FakeGitHub(runs)
    api.reference = {"object": {"type": "commit", "sha": TARGET}}
    publish(api, policy, TARGET, api.command)
    assert len(api.commands) == 1
    assert api.commands[0][:3] == ["gh", "release", "create"]


def test_inconsistent_existing_release_fails_closed(policy, runs):
    api = FakeGitHub(runs)
    api.release = {"tag_name": "v1.0.0", "draft": True, "prerelease": False}
    with pytest.raises(ValueError, match="refusing any overwrite"):
        publish(api, policy, TARGET, api.command)
    assert not api.commands


def test_invalid_tag_object_is_rejected(runs):
    with pytest.raises(ValueError, match="bounded commit identity"):
        tag_commit(FakeGitHub(runs), {"object": {"type": "tree", "sha": TARGET}})


@pytest.mark.parametrize("status", [403, 429, 500])
def test_permission_and_service_errors_cannot_be_treated_as_absence(monkeypatch, status):
    def failed(*args, **kwargs):
        raise urllib.error.HTTPError("https://api.github.com", status, "failure", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", failed)
    with pytest.raises(RuntimeError, match=f"HTTP {status}"):
        GitHub("owner/repo", "synthetic-test-token").get("/releases/tags/v1", optional=True)


def test_missing_optional_release_is_distinct_from_permission_failure(monkeypatch):
    def missing(*args, **kwargs):
        raise urllib.error.HTTPError("https://api.github.com", 404, "missing", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", missing)
    assert GitHub("owner/repo", "synthetic-test-token").get("/tags/v1", optional=True) is None


@pytest.mark.parametrize("authorized", [False, None, "true"])
def test_policy_requires_explicit_authorization(tmp_path, policy, authorized):
    import json

    mutated = copy.deepcopy(policy)
    mutated["authorized"] = authorized
    (tmp_path / "release").mkdir()
    (tmp_path / "release" / "publish-policy.json").write_text(json.dumps(mutated))
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.0.0"\n')
    with pytest.raises(ValueError, match="not been authorized"):
        load_policy(tmp_path)
