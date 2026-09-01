"""Freeze a durable demo candidate and verify bounded archives before publication.

Run as python -m tools.demo_release_bundle. This module has no external write API.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import stat
import tempfile
import zipfile
from pathlib import Path

from tools.demo_environment import (
    LOCK_PATH,
    MANIFEST,
    ROOT,
    _json_bytes,
    verify_wheelhouse,
)
from tools.demo_evidence import (
    EvidenceRejected,
    _files,
    _hex,
    _path,
    _read_json,
    source_identity,
    verify_bundle,
)
from tools.demo_presentation import NEGATIVE_EXPECTATIONS, verify_presentation

ASSET_NAMES = {
    "portfolio-evidence.zip",
    "portfolio-wheels.zip",
    "REPLAY.md",
    "demo-release-manifest.json",
    "SHA256SUMS",
}
MAX_ARCHIVE_BYTES = 150_000_000
REQUIRED_NEGATIVES = NEGATIVE_EXPECTATIONS


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def archive_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted(files.items()):
            info = zipfile.ZipInfo(_path(name), date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, raw)
    return buffer.getvalue()


def unpack_bounded(raw: bytes, directory: Path, *, wheelhouse: bool = False) -> None:
    """No extractall: validate names, links, duplicates and limits before creating files."""
    if len(raw) > MAX_ARCHIVE_BYTES or directory.exists():
        raise EvidenceRejected("archive is oversized or destination already exists")
    limit = 100_000_000 if wheelhouse else 2_000_000
    total_limit = 250_000_000 if wheelhouse else 32_000_000
    entries, total, seen = [], 0, set()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for info in archive.infolist():
            name = _path(info.filename)
            mode = info.external_attr >> 16
            total += info.file_size
            if (
                name.casefold() in seen
                or info.is_dir()
                or (stat.S_IFMT(mode) not in {0, stat.S_IFREG})
                or info.flag_bits & 1
                or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                or info.file_size > limit
                or total > total_limit
                or len(entries) >= 512
                or (wheelhouse and "/" in name)
            ):
                raise EvidenceRejected("unsafe or oversized archive member")
            seen.add(name.casefold())
            entries.append((name, info))
        # Fully validate/read before any external-facing extraction output is created.
        contents = {name: archive.read(info) for name, info in entries}
    directory.mkdir(parents=True)
    for name, content in contents.items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(content)


def _replay_notes(sha: str, tag: str, wheel_manifest: dict) -> bytes:
    runtime = wheel_manifest["runtime"]
    return f"""# Replay this exact portfolio demo

Source commit: `{sha}`. Demo tag: `{tag}`. Core package remains `1.0.0`.
Recorded wheel target: {runtime["system"]} / {runtime["machine"]} /
{runtime["implementation"]} {runtime["python_minor"]}. Pip additionally checks wheel compatibility.

1. Download all five assets from this GitHub Release. Compare `SHA256SUMS` with the
   release asset digests shown by GitHub; treat that authenticated distribution as
   the external trust anchor, not a checksum supplied alongside an untrusted download.
   Run `sha256sum -c SHA256SUMS` (or your platform's SHA-256 verifier).
2. Clone `https://github.com/bilgekayali/VulnEvidenceOps.git` at `{tag}` and verify
   `git rev-parse HEAD` is exactly `{sha}`. Keep the checkout clean.
3. Safely unpack `portfolio-wheels.zip` into a new directory outside the checkout.
   From the exact checkout, with the recorded Python minor/OS/architecture, run:

   `python tools/demo_doraops.py --wheelhouse /absolute/path/to/wheels --test`

After the clone/download, replay needs no package index or GitHub network access.
Installation is isolated and uses `--no-index --no-deps --require-hashes`; every
wheel hash, distribution/version, peer pin, dependency lock and source identity is
checked before installation. A different platform or checkout is rejected.
The original source-based command remains `python tools/demo_doraops.py --test`;
that path fetches/builds version-pinned wheels and therefore needs network access.

`portfolio-evidence.zip` contains the published reports and underlying JSON. From
the same checkout, verify its extracted directory with:

`python tools/demo_evidence.py /path/to/evidence --expected-source-sha {sha}`

For independent manifest comparison, also pass `--expected-manifest-sha256` using
`evidence_manifest_sha256` in the externally verified release manifest.
All fixtures and signing keys are public/synthetic; neither replay nor a matching
hash establishes production authenticity or current dependency security.
""".encode()


def _assert_outcomes(evidence: Path, *, require_visual: bool) -> None:
    summary = _read_json(evidence / "summary.json")
    environment = _read_json(evidence / "execution-environment.json")
    if (
        not isinstance(summary, dict)
        or not isinstance(environment, dict)
        or not isinstance(summary.get("negative_cases"), dict)
        or not isinstance(summary.get("attention_cases"), dict)
        or any(not isinstance(value, dict) for value in summary["negative_cases"].values())
        or any(not isinstance(value, dict) for value in summary["attention_cases"].values())
    ):
        raise EvidenceRejected("invalid candidate outcome documents")
    if (
        summary.get("positive_case_accepted") is not True
        or summary.get("upstream_signature_verified") is not True
        or summary.get("doraops_signature_verified") is not True
        or summary.get("risk_residual_level") != "high"
        or summary.get("risk_control_credit") != 0
        or summary.get("finding_phases")
        != {"before": "open", "remediation": "remediation_submitted", "final": "closed"}
        or summary.get("production_interoperability_established") is not False
        or environment.get("installation_mode") != "isolated-wheels"
        or environment.get("exact_runtime_wheel_bytes_verified") is not True
        or set(summary.get("negative_cases", {})) != set(REQUIRED_NEGATIVES)
        or any(
            value.get("exit_code") != 2
            or value.get("accepted") is not False
            or value.get("error_code") != REQUIRED_NEGATIVES[name]
            for name, value in summary["negative_cases"].items()
        )
        or set(summary.get("attention_cases", {})) != {"missing-retest", "failed-retest"}
        or any(
            value.get("resolution_state") != "blocked"
            for value in summary["attention_cases"].values()
        )
    ):
        raise EvidenceRejected("demo candidate does not prove the required outcomes")
    visual_names = {"index.html", "presentation.json"}
    present = visual_names & _files(evidence).keys()
    if present and present != visual_names:
        raise EvidenceRejected("visual presentation is incomplete")
    if require_visual and present != visual_names:
        raise EvidenceRejected("publication requires the evidence-linked visual presentation")
    if present == visual_names:
        verify_presentation(evidence)


def create_candidate(
    evidence: Path, replay: Path, wheels: Path, output: Path, policy: dict
) -> dict:
    if output.exists():
        raise EvidenceRejected("candidate output exists; prior release bytes are retained")
    source = source_identity(ROOT)
    if not source["worktree_clean"]:
        raise EvidenceRejected("release candidate requires a clean exact checkout")
    primary = verify_bundle(evidence, expected_source_sha=source["commit_sha"])
    replay_result = verify_bundle(replay, expected_source_sha=source["commit_sha"])
    wheel_manifest = verify_wheelhouse(wheels)
    _assert_outcomes(evidence, require_visual=policy["require_visual_report"])
    if (
        primary["manifest_sha256"] != replay_result["manifest_sha256"]
        or _files(evidence) != _files(replay)
        or _read_json(evidence / MANIFEST) != wheel_manifest
    ):
        raise EvidenceRejected("offline replay differs from the original complete evidence bundle")
    files = {
        "portfolio-evidence.zip": archive_bytes(_files(evidence)),
        "portfolio-wheels.zip": archive_bytes(
            {path.name: path.read_bytes() for path in wheels.iterdir()}
        ),
        "REPLAY.md": _replay_notes(source["commit_sha"], policy["tag"], wheel_manifest),
    }
    manifest = {
        "schema_version": "vulnevidenceops.portfolio-demo-release.v1",
        "tag": policy["tag"],
        "source": source,
        "protected_core_tag": policy["protected_tag"],
        "protected_core_commit": policy["protected_tag_commit"],
        "dependency_lock_sha256": _hash(LOCK_PATH.read_bytes()),
        "peer_commits": wheel_manifest["peer_commits"],
        "wheel_runtime": wheel_manifest["runtime"],
        "evidence_manifest_sha256": primary["manifest_sha256"],
        "offline_replay_manifest_sha256": replay_result["manifest_sha256"],
        "offline_replay_byte_identical": True,
        "visual_presentation_included": (evidence / "index.html").is_file(),
        "assets": [
            {"name": name, "size_bytes": len(raw), "sha256": _hash(raw)}
            for name, raw in sorted(files.items())
        ],
        "independent_rebuild_is_bit_reproducible": False,
        "production_trust_established": False,
    }
    files["demo-release-manifest.json"] = _json_bytes(manifest)
    files["SHA256SUMS"] = "".join(
        f"{_hash(raw)}  {name}\n" for name, raw in sorted(files.items())
    ).encode("ascii")
    output.mkdir(parents=True)
    for name, raw in files.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
    verify_candidate(output, expected_sha=source["commit_sha"], policy=policy)
    return manifest


def verify_candidate(directory: Path, *, expected_sha: str, policy: dict) -> dict:
    if directory.is_symlink() or not directory.is_dir():
        raise EvidenceRejected("candidate must be a regular directory")
    paths = list(directory.iterdir())
    if {path.name for path in paths} != ASSET_NAMES or any(
        path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARCHIVE_BYTES
        for path in paths
    ):
        raise EvidenceRejected("unexpected candidate files, links or size")
    manifest = _read_json(directory / "demo-release-manifest.json")
    source = source_identity(ROOT, environment={})
    if (
        not isinstance(manifest, dict)
        or not isinstance(manifest.get("source"), dict)
        or manifest.get("schema_version") != "vulnevidenceops.portfolio-demo-release.v1"
        or manifest.get("tag") != policy["tag"]
        or not _hex(expected_sha, 40)
        or source["commit_sha"] != expected_sha
        or not source["worktree_clean"]
        or manifest.get("source", {}).get("commit_sha") != expected_sha
        or manifest["source"].get("tree_sha") != source["tree_sha"]
        or manifest["source"].get("worktree_clean") is not True
        or manifest.get("protected_core_tag") != policy["protected_tag"]
        or manifest.get("protected_core_commit") != policy["protected_tag_commit"]
        or manifest.get("dependency_lock_sha256") != _hash(LOCK_PATH.read_bytes())
        or manifest.get("offline_replay_byte_identical") is not True
        or manifest.get("offline_replay_manifest_sha256")
        != manifest.get("evidence_manifest_sha256")
        or manifest.get("independent_rebuild_is_bit_reproducible") is not False
        or manifest.get("production_trust_established") is not False
        or (
            policy["require_visual_report"]
            and manifest.get("visual_presentation_included") is not True
        )
    ):
        raise EvidenceRejected("candidate identity or replay assertions differ")
    raw_files = {path.name: path.read_bytes() for path in paths}
    expected = [
        {"name": name, "size_bytes": len(raw), "sha256": _hash(raw)}
        for name, raw in sorted(raw_files.items())
        if name not in {"demo-release-manifest.json", "SHA256SUMS"}
    ]
    if manifest.get("assets") != expected:
        raise EvidenceRejected("release asset hash inventory differs")
    sums = "".join(
        f"{_hash(raw)}  {name}\n" for name, raw in sorted(raw_files.items()) if name != "SHA256SUMS"
    )
    if raw_files["SHA256SUMS"] != sums.encode("ascii"):
        raise EvidenceRejected("release checksum file differs")
    with tempfile.TemporaryDirectory(prefix="veo-verify-demo-") as temporary:
        evidence, wheels = Path(temporary) / "evidence", Path(temporary) / "wheels"
        unpack_bounded(raw_files["portfolio-evidence.zip"], evidence)
        unpack_bounded(raw_files["portfolio-wheels.zip"], wheels, wheelhouse=True)
        verify_bundle(
            evidence,
            expected_source_sha=expected_sha,
            expected_manifest_sha256=manifest["evidence_manifest_sha256"],
        )
        _assert_outcomes(evidence, require_visual=policy["require_visual_report"])
        wheel_manifest = verify_wheelhouse(wheels)
        if (
            _read_json(evidence / MANIFEST) != wheel_manifest
            or wheel_manifest["peer_commits"] != manifest.get("peer_commits")
            or wheel_manifest["runtime"] != manifest.get("wheel_runtime")
        ):
            raise EvidenceRejected("evidence and retained wheel identities differ")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--replay-evidence", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    policy = _read_json(ROOT / "demo/publish-policy.json")
    manifest = create_candidate(
        args.evidence, args.replay_evidence, args.wheelhouse, args.output_dir, policy
    )
    print(
        json.dumps(
            {
                "candidate_verified": True,
                "source_sha": manifest["source"]["commit_sha"],
                "offline_replay_byte_identical": True,
                "assets": sorted(ASSET_NAMES),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
