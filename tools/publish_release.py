"""Publish an authorized GitHub release only after exact-main-SHA workflow success.

Only GitHub Actions' configured GH_TOKEN is used. Existing tags are never moved.
The same gate is rechecked immediately before the write operation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 in peer repositories
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


class GitHub:
    def __init__(self, repository: str, token: str):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("invalid repository")
        if not token:
            raise ValueError("GH_TOKEN is required")
        self.base = "https://api.github.com/repos/" + repository
        self.token = token

    def get(self, path: str, *, optional: bool = False):
        request = urllib.request.Request(
            self.base + path,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if optional and exc.code == 404:
                return None
            raise RuntimeError(f"GitHub read failed: HTTP {exc.code}") from None


def load_policy(root: Path = ROOT) -> dict:
    policy = json.loads((root / "release" / "publish-policy.json").read_text(encoding="utf-8"))
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if policy.get("schema_version") != "github-release-policy.v1":
        raise ValueError("unknown publication policy")
    if policy.get("authorized") is not True:
        raise ValueError("publication has not been authorized")
    version = policy.get("release_version", "")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError("only an explicitly authorized stable version may be published")
    if project.get("version") != version:
        raise ValueError("package version differs from the authorized release version")
    if "Development Status :: 5 - Production/Stable" not in project.get("classifiers", []):
        raise ValueError("package must declare the stable reference boundary")
    required = policy.get("required_workflows")
    if not isinstance(required, dict) or not required:
        raise ValueError("required workflow set must not be empty")
    for path, name in required.items():
        if not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_-]+\.yml", path) or not name:
            raise ValueError("invalid required workflow identity")
    notes = (root / policy["notes_path"]).resolve()
    if not notes.is_relative_to((root / "release").resolve()) or not notes.is_file():
        raise ValueError("release notes must be a committed release file")
    return policy


def workflow_gaps(runs: list[dict], policy: dict, sha: str) -> list[str]:
    gaps = []
    for path, name in policy["required_workflows"].items():
        matches = [
            run
            for run in runs
            if run.get("head_sha") == sha
            and run.get("head_branch") == "main"
            and run.get("event") == "push"
            and run.get("head_repository", {}).get("full_name") == policy["repository"]
            and run.get("path") == path
            and run.get("name") == name
        ]
        if not matches:
            gaps.append(f"{name}: missing exact-SHA main push run")
            continue
        latest = max(matches, key=lambda item: (item["id"], item.get("run_attempt", 1)))
        if latest.get("status") != "completed" or latest.get("conclusion") != "success":
            gaps.append(f"{name}: latest attempt is not successful")
    return gaps


def gate(api, policy: dict, sha: str) -> list[str]:
    if not SHA.fullmatch(sha):
        raise ValueError("candidate must be an exact 40-character SHA")
    if api.get("/git/ref/heads/main")["object"]["sha"] != sha:
        return ["candidate is no longer the current main SHA"]
    runs = []
    for page in range(1, 11):
        batch = api.get(
            f"/actions/runs?head_sha={sha}&event=push&branch=main&per_page=100&page={page}"
        )["workflow_runs"]
        runs.extend(batch)
        if len(batch) < 100:
            return workflow_gaps(runs, policy, sha)
    raise ValueError("workflow pagination limit reached; refusing incomplete evidence")


def tag_commit(api, reference: dict) -> str:
    obj = reference["object"]
    for _ in range(5):
        if obj["type"] == "commit" and SHA.fullmatch(obj["sha"]):
            return obj["sha"]
        if obj["type"] != "tag" or not SHA.fullmatch(obj["sha"]):
            break
        obj = api.get("/git/tags/" + obj["sha"])["object"]
    raise ValueError("tag does not resolve to a bounded commit identity")


def publish(api, policy: dict, sha: str, run_command=subprocess.run) -> str:
    if gaps := gate(api, policy, sha):
        raise ValueError("publication blocked: " + "; ".join(gaps))
    tag = "v" + policy["release_version"]
    ref_path = "/git/ref/tags/" + tag
    reference = api.get(ref_path, optional=True)
    release = api.get("/releases/tags/" + tag, optional=True)
    if release is not None:
        if (
            reference is None
            or release.get("tag_name") != tag
            or release.get("draft") is not False
            or release.get("prerelease") is not False
        ):
            raise ValueError("existing publication is inconsistent; refusing any overwrite")
        return f"Existing {tag} retained at {tag_commit(api, reference)}; no writes"
    repository = policy["repository"]
    if reference is None:
        run_command(
            [
                "gh", "api", "--method", "POST", f"repos/{repository}/git/refs",
                "-f", f"ref=refs/tags/{tag}", "-f", f"sha={sha}",
            ],
            check=True, capture_output=True, text=True,
        )
        reference = api.get(ref_path)
    if tag_commit(api, reference) != sha:
        raise ValueError("existing tag differs from the tested candidate; it will not be moved")
    run_command(
        [
            "gh", "release", "create", tag, "--repo", repository, "--verify-tag",
            "--target", sha,
            "--title", policy["release_title"], "--notes-file", str(ROOT / policy["notes_path"]),
        ],
        check=True, capture_output=True, text=True,
    )
    return f"Published {tag} at exact tested SHA {sha}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["gate", "publish"])
    parser.add_argument("--sha", required=True)
    args = parser.parse_args(argv)
    policy = load_policy()
    if os.environ.get("GITHUB_REPOSITORY") != policy["repository"]:
        raise ValueError("workflow repository differs from publication policy")
    actual = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if actual != args.sha:
        raise ValueError("checkout differs from candidate SHA")
    api = GitHub(policy["repository"], os.environ.get("GH_TOKEN", ""))
    if args.mode == "publish":
        print(publish(api, policy, args.sha))
    else:
        gaps = gate(api, policy, args.sha)
        print(json.dumps({"sha": args.sha, "ready": not gaps, "gaps": gaps}, sort_keys=True))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"ready={'false' if gaps else 'true'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
