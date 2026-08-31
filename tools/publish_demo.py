"""Publish one owner-authorized demo from an exact-main, successful CI artifact.

Only GitHub Actions' configured token is used. No moving tags, --clobber, stable
package publication, deletion or edits to an existing published demo are permitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from tools.demo_environment import ROOT
from tools.demo_evidence import EvidenceRejected, _read_json
from tools.demo_release_bundle import (
    ASSET_NAMES,
    MAX_ARCHIVE_BYTES,
    unpack_bounded,
    verify_candidate,
)
from tools.publish_release import GitHub, tag_commit
from tools.publish_release import gate as workflow_gate

PROTECTED_COMMIT = "de04044e2092888e56c5a973a38b0122452fb207"


def load_policy() -> dict:
    policy = _read_json(ROOT / "demo/publish-policy.json")
    if (
        policy.get("schema_version") != "vulnevidenceops.portfolio-demo-publication.v1"
        or policy.get("repository") != "bilgekayali/VulnEvidenceOps"
        or policy.get("authorized") is not True
        or policy.get("authorized_by") != "bilgekayali"
        or type(policy.get("enabled")) is not bool
        or type(policy.get("require_visual_report")) is not bool
        or (policy["enabled"] and policy["require_visual_report"] is not True)
        or not re.fullmatch(r"demo-v[0-9]+\.[0-9]+\.[0-9]+", policy.get("tag", ""))
        or policy.get("prerelease") is not True
        or policy.get("make_latest") is not False
        or policy.get("protected_tag") != "v1.0.0"
        or policy.get("protected_tag_commit") != PROTECTED_COMMIT
        or policy.get("notes_path") != "demo/release-notes.md"
        or policy.get("candidate_artifact_prefix") != "portfolio-demo-candidate"
        or policy.get("required_workflows")
        != {
            ".github/workflows/ci.yml": "CI",
            ".github/workflows/codeql.yml": "CodeQL",
            ".github/workflows/reference-gate.yml": "Reference Gate",
            ".github/workflows/stable-release.yml": "Stable Release",
        }
    ):
        raise EvidenceRejected("invalid or unsafe demo publication policy")
    return policy


def protected_tag_check(api, policy: dict) -> None:
    reference = api.get("/git/ref/tags/" + policy["protected_tag"])
    if tag_commit(api, reference) != policy["protected_tag_commit"]:
        raise EvidenceRejected("protected v1.0.0 identity changed; refusing publication")


def _release(api, tag: str):
    release = api.get("/releases/tags/" + tag, optional=True)
    if release is not None:
        return release
    # Some API contexts omit drafts from by-tag lookups; never create a duplicate.
    for page in range(1, 11):
        batch = api.get(f"/releases?per_page=100&page={page}")
        matches = [item for item in batch if item.get("tag_name") == tag]
        if len(matches) > 1:
            raise EvidenceRejected("ambiguous existing demo releases")
        if matches:
            return matches[0]
        if len(batch) < 100:
            return None
    raise EvidenceRejected("incomplete release pagination")


def _asset_map(release: dict) -> dict:
    assets = release.get("assets", [])
    result = {asset["name"]: asset for asset in assets}
    if len(result) != len(assets) or not set(result) <= ASSET_NAMES:
        raise EvidenceRejected("duplicate or unknown existing release assets")
    return result


def existing_publication(api, policy: dict):
    reference = api.get("/git/ref/tags/" + policy["tag"], optional=True)
    release = _release(api, policy["tag"])
    if release is None:
        return reference, None
    if (
        reference is None
        or release.get("tag_name") != policy["tag"]
        or release.get("prerelease") is not True
        or type(release.get("draft")) is not bool
    ):
        raise EvidenceRejected("existing demo publication is inconsistent")
    tag_commit(api, reference)
    assets = _asset_map(release)
    if not release["draft"] and (
        set(assets) != ASSET_NAMES
        or any(
            not re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("digest", ""))
            or item.get("state") != "uploaded"
            for item in assets.values()
        )
    ):
        raise EvidenceRejected("published demo has incomplete asset evidence; no overwrite allowed")
    return reference, release


def _candidate_artifact(api, policy: dict, sha: str) -> dict:
    runs = []
    for page in range(1, 11):
        batch = api.get(
            f"/actions/runs?head_sha={sha}&event=push&branch=main&per_page=100&page={page}"
        )["workflow_runs"]
        runs.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise EvidenceRejected("incomplete CI run pagination")
    matches = [
        run
        for run in runs
        if (
            run.get("head_sha") == sha
            and run.get("head_branch") == "main"
            and run.get("event") == "push"
            and run.get("path") == ".github/workflows/ci.yml"
            and run.get("name") == "CI"
            and run.get("head_repository", {}).get("full_name") == policy["repository"]
        )
    ]
    if not matches:
        raise EvidenceRejected("missing exact-main CI run")
    run = max(matches, key=lambda item: (item["id"], item.get("run_attempt", 1)))
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise EvidenceRejected("latest exact-main CI is not successful")
    name = f"portfolio-demo-candidate-{sha}-py3.12-{run['id']}-{run.get('run_attempt', 1)}"
    artifacts = []
    for page in range(1, 11):
        batch = api.get(f"/actions/runs/{run['id']}/artifacts?per_page=100&page={page}")[
            "artifacts"
        ]
        artifacts.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise EvidenceRejected("incomplete artifact pagination")
    matches = [artifact for artifact in artifacts if artifact.get("name") == name]
    if len(matches) != 1:
        raise EvidenceRejected("missing or ambiguous exact-run demo candidate artifact")
    artifact = matches[0]
    if (
        artifact.get("expired") is not False
        or not 0 < artifact.get("size_in_bytes", 0) <= MAX_ARCHIVE_BYTES
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest", ""))
        or artifact.get("workflow_run", {}).get("id") != run["id"]
        or artifact["workflow_run"].get("head_sha") != sha
    ):
        raise EvidenceRejected("artifact digest, origin, expiry or size is invalid")
    return {
        "run_id": run["id"],
        "run_attempt": run.get("run_attempt", 1),
        "artifact_id": artifact["id"],
        "artifact_digest": artifact["digest"],
    }


def readiness(api, policy: dict, sha: str) -> dict:
    if not policy["enabled"]:
        return {"ready": False, "reason": "publication disabled until presentation phase"}
    protected_tag_check(api, policy)
    reference, release = existing_publication(api, policy)
    if release is not None and not release["draft"]:
        return {
            "ready": False,
            "reason": "existing published demo retained without writes",
            "retained_sha": tag_commit(api, reference),
        }
    if gaps := workflow_gate(api, policy, sha):
        return {"ready": False, "reason": "; ".join(gaps)}
    if reference is not None and tag_commit(api, reference) != sha:
        raise EvidenceRejected("existing demo tag differs; it will not be moved")
    return {"ready": True, **_candidate_artifact(api, policy, sha)}


def publish(api, policy: dict, sha: str, *, run_command=subprocess.run) -> str:
    selected = readiness(api, policy, sha)
    if not selected["ready"]:
        return selected["reason"]
    # Download by immutable artifact ID, compare GitHub's external ZIP digest BEFORE extraction.
    response = run_command(
        [
            "gh",
            "api",
            f"repos/{policy['repository']}/actions/artifacts/{selected['artifact_id']}/zip",
        ],
        check=True,
        capture_output=True,
        timeout=180,
    )
    raw = response.stdout
    if (
        not isinstance(raw, bytes)
        or len(raw) > MAX_ARCHIVE_BYTES
        or "sha256:" + hashlib.sha256(raw).hexdigest() != selected["artifact_digest"]
    ):
        raise EvidenceRejected("downloaded CI artifact differs from GitHub's exact artifact digest")
    with tempfile.TemporaryDirectory(prefix="veo-publish-demo-") as temporary:
        directory = Path(temporary) / "assets"
        unpack_bounded(raw, directory, wheelhouse=True)
        manifest = verify_candidate(directory, expected_sha=sha, policy=policy)
        ci = manifest["source"].get("github_actions", {})
        if (
            ci.get("repository") != policy["repository"]
            or ci.get("event") != "push"
            or ci.get("run_id") != selected["run_id"]
            or ci.get("run_attempt") != selected["run_attempt"]
        ):
            raise EvidenceRejected("candidate provenance is not the selected main CI attempt")
        if readiness(api, policy, sha) != selected:
            raise EvidenceRejected("publication gate changed during artifact verification")
        reference, release = existing_publication(api, policy)
        if reference is None:
            run_command(
                [
                    "gh",
                    "api",
                    "--method",
                    "POST",
                    f"repos/{policy['repository']}/git/refs",
                    "-f",
                    f"ref=refs/tags/{policy['tag']}",
                    "-f",
                    f"sha={sha}",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
        reference = api.get("/git/ref/tags/" + policy["tag"])
        if tag_commit(api, reference) != sha:
            raise EvidenceRejected("demo tag does not equal verified source; no tag move allowed")
        if release is None:
            run_command(
                [
                    "gh",
                    "release",
                    "create",
                    policy["tag"],
                    "--repo",
                    policy["repository"],
                    "--verify-tag",
                    "--target",
                    sha,
                    "--title",
                    policy["title"],
                    "--notes-file",
                    str(ROOT / policy["notes_path"]),
                    "--draft",
                    "--prerelease",
                    "--latest=false",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
        release = _release(api, policy["tag"])
        if release is None or release.get("draft") is not True:
            raise EvidenceRejected("only this exact new draft can receive demo assets")
        expected = {
            path.name: "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.iterdir()
        }
        assets = _asset_map(release)
        for name, asset in assets.items():
            if asset.get("digest") != expected[name] or asset.get("state") != "uploaded":
                raise EvidenceRejected("existing draft asset differs; refusing clobber")
        missing = sorted(ASSET_NAMES - assets.keys())
        if missing:
            run_command(
                [
                    "gh",
                    "release",
                    "upload",
                    policy["tag"],
                    *[str(directory / name) for name in missing],
                    "--repo",
                    policy["repository"],
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=180,
            )
        release = _release(api, policy["tag"])
        assets = _asset_map(release)
        if set(assets) != ASSET_NAMES or any(
            item.get("digest") != expected[name] or item.get("state") != "uploaded"
            for name, item in assets.items()
        ):
            raise EvidenceRejected(
                "uploaded release asset hashes do not match the verified candidate"
            )
        if readiness(api, policy, sha) != selected:
            raise EvidenceRejected("gate changed before draft publication; draft retained")
        run_command(
            [
                "gh",
                "release",
                "edit",
                policy["tag"],
                "--repo",
                policy["repository"],
                "--draft=false",
                "--prerelease",
                "--latest=false",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        protected_tag_check(api, policy)
        _, published = existing_publication(api, policy)
        if published is None or published["draft"]:
            raise EvidenceRejected("demo publication was not confirmed")
    return f"Published {policy['tag']} at {sha}; five verified assets, v1.0.0 retained"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["gate", "publish"])
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    policy = load_policy()
    if os.environ.get("GITHUB_REPOSITORY") != policy["repository"]:
        raise EvidenceRejected("workflow repository differs from owner authorization")
    actual = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True, timeout=15
    ).stdout.strip()
    if actual != args.sha or not re.fullmatch(r"[0-9a-f]{40}", args.sha):
        raise EvidenceRejected("checkout must equal the exact candidate SHA")
    api = GitHub(policy["repository"], os.environ.get("GH_TOKEN", ""))
    if args.mode == "publish":
        print(publish(api, policy, args.sha))
    else:
        result = readiness(api, policy, args.sha)
        print(json.dumps(result, sort_keys=True))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"ready={'true' if result['ready'] else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
