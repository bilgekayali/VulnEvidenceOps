"""Create/verify a bounded evidence directory; stdlib only, no archive extraction."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

MANIFEST_VERSION = "vulnevidenceops.demo-evidence-manifest.v2"
MAX_FILE_BYTES = 2_000_000
MAX_FILES = 512
MAX_TOTAL_BYTES = 32_000_000


class EvidenceRejected(ValueError):
    """A bundle, source identity, or expected external pin is invalid."""


def _hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value) is not None
    )


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceRejected("duplicate JSON key")
        value[key] = item
    return value


def _constant(_value):
    raise EvidenceRejected("non-finite JSON value")


def _read_json(path: Path):
    content = _read_bytes(path)
    try:
        return json.loads(
            content.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceRejected("invalid UTF-8 JSON") from exc


def _read_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise EvidenceRejected("evidence must contain bounded regular files")
    content = path.read_bytes()
    if len(content) > MAX_FILE_BYTES:
        raise EvidenceRejected("evidence file exceeds size limit")
    return content


def _path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value)
        or any(part in ("", ".", "..") for part in value.split("/"))
        or PurePosixPath(value).as_posix() != value
    ):
        raise EvidenceRejected("unsafe evidence path")
    return value


def _files(directory: Path) -> dict[str, bytes]:
    if directory.is_symlink() or not directory.is_dir():
        raise EvidenceRejected("evidence root must be a regular directory")
    result = {}
    total = 0
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise EvidenceRejected("symlinks are not evidence")
        if path.is_dir():
            continue
        name = _path(path.relative_to(directory).as_posix())
        content = _read_bytes(path)
        result[name] = content
        total += len(content)
        if len(result) > MAX_FILES or total > MAX_TOTAL_BYTES:
            raise EvidenceRejected("evidence bundle exceeds size limit")
    return result


def source_identity(root: Path, environment: dict | None = None) -> dict:
    """Record the actual checkout; fail closed on a mislabeled or dirty CI checkout."""
    environment = dict(os.environ) if environment is None else environment

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True, check=True, timeout=15
        ).stdout.strip()

    commit, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
    clean = not git("status", "--porcelain", "--untracked-files=normal")
    if not _hex(commit, 40) or not _hex(tree, 40):
        raise EvidenceRejected("full source commit and tree identities are required")
    ci = None
    if environment.get("GITHUB_ACTIONS") == "true":
        repository = environment.get("GITHUB_REPOSITORY", "")
        run_id = environment.get("GITHUB_RUN_ID", "")
        attempt = environment.get("GITHUB_RUN_ATTEMPT", "")
        event = environment.get("GITHUB_EVENT_NAME", "")
        if (
            environment.get("DEMO_SOURCE_SHA") != commit
            or not clean
            or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository
            )
            or not re.fullmatch(r"[1-9][0-9]*", run_id)
            or not re.fullmatch(r"[1-9][0-9]*", attempt)
            or event not in ("push", "pull_request", "workflow_dispatch")
        ):
            raise EvidenceRejected("CI source SHA, clean checkout, and run identity must match")
        ci = {
            "repository": repository,
            "run_id": int(run_id),
            "run_attempt": int(attempt),
            "event": event,
            "run_url": f"https://github.com/{repository}/actions/runs/{run_id}",
        }
    return {
        "schema_version": "vulnevidenceops.demo-source-provenance.v1",
        "commit_sha": commit,
        "tree_sha": tree,
        "worktree_clean": clean,
        "github_actions": ci,
        "source_authentication_established": False,
    }


def finalize_bundle(directory: Path, *, source: dict, contract_sha256: str, report: str) -> dict:
    """Write the report/provenance last, freeze a complete file inventory, then verify it."""
    if not _hex(contract_sha256, 64):
        raise EvidenceRejected("invalid demo contract digest")
    for name, content in (
        ("source-provenance.json", _json_bytes(source)),
        ("REPORT.md", report.encode("utf-8")),
    ):
        with (directory / name).open("xb") as output:
            output.write(content)
    files = _files(directory)
    if "manifest.json" in files:
        raise EvidenceRejected("an existing evidence manifest cannot be overwritten")
    manifest = {
        "schema_version": MANIFEST_VERSION,
        "demo_contract_sha256": contract_sha256,
        "source_commit_sha": source["commit_sha"],
        "source_tree_sha": source["tree_sha"],
        "artifacts": [
            {
                "path": name,
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for name, content in files.items()
        ],
    }
    with (directory / "manifest.json").open("xb") as output:
        output.write(_json_bytes(manifest))
    return verify_bundle(directory, expected_source_sha=source["commit_sha"])


def verify_bundle(
    directory: Path,
    *,
    expected_source_sha: str | None = None,
    expected_manifest_sha256: str | None = None,
) -> dict:
    files = _files(directory)
    if not {"manifest.json", "REPORT.md", "source-provenance.json", "summary.json"} <= files.keys():
        raise EvidenceRejected("required bundle files are missing")
    manifest_hash = hashlib.sha256(files.pop("manifest.json")).hexdigest()
    if expected_manifest_sha256 is not None and (
        not _hex(expected_manifest_sha256, 64) or manifest_hash != expected_manifest_sha256
    ):
        raise EvidenceRejected("manifest differs from the externally supplied digest")
    manifest = _read_json(directory / "manifest.json")
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "schema_version",
            "demo_contract_sha256",
            "source_commit_sha",
            "source_tree_sha",
            "artifacts",
        }
        or manifest["schema_version"] != MANIFEST_VERSION
        or not _hex(manifest["demo_contract_sha256"], 64)
        or not _hex(manifest["source_commit_sha"], 40)
        or not _hex(manifest["source_tree_sha"], 40)
        or not isinstance(manifest["artifacts"], list)
    ):
        raise EvidenceRejected("invalid evidence manifest")
    listed = []
    for item in manifest["artifacts"]:
        if not isinstance(item, dict) or set(item) != {"path", "size_bytes", "sha256"}:
            raise EvidenceRejected("invalid manifest entry")
        name = _path(item["path"])
        if (
            name not in files
            or type(item["size_bytes"]) is not int
            or item["size_bytes"] != len(files[name])
            or not _hex(item["sha256"], 64)
            or item["sha256"] != hashlib.sha256(files[name]).hexdigest()
        ):
            raise EvidenceRejected("missing or modified evidence file")
        listed.append(name)
    if listed != sorted(files):
        raise EvidenceRejected("duplicate, unordered, or unlisted evidence file")
    source = _read_json(directory / "source-provenance.json")
    if (
        not isinstance(source, dict)
        or source.get("schema_version") != "vulnevidenceops.demo-source-provenance.v1"
        or source.get("commit_sha") != manifest["source_commit_sha"]
        or source.get("tree_sha") != manifest["source_tree_sha"]
        or type(source.get("worktree_clean")) is not bool
        or source.get("source_authentication_established") is not False
    ):
        raise EvidenceRejected("source provenance differs from manifest")
    if expected_source_sha is not None and (
        not _hex(expected_source_sha, 40) or expected_source_sha != source["commit_sha"]
    ):
        raise EvidenceRejected("checkout differs from the expected exact source SHA")
    return {
        "verified": True,
        "source_commit_sha": source["commit_sha"],
        "manifest_sha256": manifest_hash,
        "artifact_count": len(files),
        "authentication_established": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()
    try:
        result = verify_bundle(
            args.directory,
            expected_source_sha=args.expected_source_sha,
            expected_manifest_sha256=args.expected_manifest_sha256,
        )
        if args.report:
            print((args.directory / "REPORT.md").read_text(encoding="utf-8"))
            print(f"\nManifest SHA-256: `{result['manifest_sha256']}`")
        else:
            print(json.dumps(result, sort_keys=True))
    except (EvidenceRejected, OSError, ValueError) as exc:
        print(f"Evidence rejected: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
