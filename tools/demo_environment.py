"""Build and replay bounded, hash-verified demo wheelhouses using only stdlib.

Online acquisition uses the configured package index and exact peer Git commits.
Replay uses --no-index --no-deps --require-hashes in a new temporary environment.
It requires an exact Git checkout and the same OS/architecture/Python minor version.
"""

from __future__ import annotations

import email.parser
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

from tools.demo_evidence import EvidenceRejected, _hex, _read_bytes, _read_json, source_identity

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "demo/dependency-lock.json"
MANIFEST = "wheelhouse-manifest.json"
MAX_WHEEL_BYTES = 100_000_000
MAX_WHEELHOUSE_BYTES = 250_000_000
RUNTIME_NAMES = {
    "attrs",
    "cffi",
    "cryptography",
    "jsonschema",
    "jsonschema-specifications",
    "pycparser",
    "referencing",
    "rpds-py",
    "typing-extensions",
}
BUILD_NAMES = {"packaging", "setuptools", "wheel"}
WHEEL_ENV = "VULNEVIDENCEOPS_DEMO_WHEELHOUSE"


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def load_lock(path: Path = LOCK_PATH) -> dict:
    lock = _read_json(path)
    if (
        not isinstance(lock, dict)
        or lock.get("schema_version") != "vulnevidenceops.demo-dependency-lock.v1"
        or lock.get("scope") != "repository-demo-only"
    ):
        raise EvidenceRejected("unsupported demo dependency lock")
    for group, names in (("runtime", RUNTIME_NAMES), ("build", BUILD_NAMES)):
        values = lock.get(group)
        if not isinstance(values, dict) or set(values) != names:
            raise EvidenceRejected("demo dependency closure is incomplete or has unknown packages")
        if any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", value)
            for value in values.values()
        ):
            raise EvidenceRejected("every demo dependency needs an exact numeric version")
    return lock


def runtime_identity() -> dict:
    return {
        "implementation": platform.python_implementation(),
        "python_minor": f"{sys.version_info.major}.{sys.version_info.minor}",
        "system": platform.system(),
        "machine": platform.machine(),
    }


def peers() -> dict:
    return {
        name: _read_json(ROOT / f"examples/{name}-demo/demo-contract.json")["consumer"]
        for name in ("datagovops", "doraops")
    }


def expected_distributions(lock: dict) -> dict:
    return {
        **lock["runtime"],
        "vulnevidenceops": "1.0.0",
        **{name: peer["version"] for name, peer in peers().items()},
    }


def _wheels(directory: Path) -> dict[str, bytes]:
    if directory.is_symlink() or not directory.is_dir():
        raise EvidenceRejected("wheelhouse must be a regular directory")
    result, total = {}, 0
    for path in sorted(directory.iterdir()):
        if path.is_symlink() or not path.is_file():
            raise EvidenceRejected("wheelhouse cannot contain links or directories")
        if path.name in {MANIFEST, "requirements.txt"}:
            continue
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*\.whl", path.name)
            or path.stat().st_size > MAX_WHEEL_BYTES
        ):
            raise EvidenceRejected("unknown or oversized wheelhouse file")
        raw = path.read_bytes()
        total += len(raw)
        if len(raw) > MAX_WHEEL_BYTES or total > MAX_WHEELHOUSE_BYTES or len(result) >= 32:
            raise EvidenceRejected("wheelhouse exceeds bounded size")
        result[path.name] = raw
    return result


def _wheel_metadata(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as archive:
        entries = [
            entry for entry in archive.infolist() if entry.filename.endswith(".dist-info/METADATA")
        ]
        if len(entries) != 1 or entries[0].file_size > 500_000:
            raise EvidenceRejected("wheel must contain one bounded distribution metadata record")
        message = email.parser.BytesParser().parsebytes(archive.read(entries[0]))
    if len(message.get_all("Name", [])) != 1 or len(message.get_all("Version", [])) != 1:
        raise EvidenceRejected("ambiguous wheel distribution metadata")
    return re.sub(r"[-_.]+", "-", message["Name"]).lower(), message["Version"]


def requirements(entries: list[dict]) -> bytes:
    return "".join(
        f"./{entry['filename']} --hash=sha256:{entry['sha256']}\n" for entry in entries
    ).encode("ascii")


def freeze_wheelhouse(directory: Path, *, root: Path = ROOT) -> dict:
    lock = load_lock()
    source = source_identity(root)
    if not source["worktree_clean"]:
        raise EvidenceRejected("exported wheelhouse requires a clean exact source checkout")
    entries, versions = [], {}
    for filename, raw in _wheels(directory).items():
        name, version = _wheel_metadata(directory / filename)
        if name in versions:
            raise EvidenceRejected("duplicate wheel distribution")
        versions[name] = version
        entries.append(
            {
                "filename": filename,
                "distribution": name,
                "version": version,
                "size_bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    if versions != expected_distributions(lock):
        raise EvidenceRejected("resolved wheel closure differs from committed exact versions")
    manifest = {
        "schema_version": "vulnevidenceops.demo-wheelhouse.v1",
        "source_commit_sha": source["commit_sha"],
        "source_tree_sha": source["tree_sha"],
        "dependency_lock_sha256": hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest(),
        "runtime": runtime_identity(),
        "peer_commits": {name: peer["commit"] for name, peer in peers().items()},
        "build_tool_versions": lock["build"],
        "wheels": entries,
        "independent_rebuild_is_bit_reproducible": False,
        "source_or_publisher_authentication_established": False,
    }
    for name, raw in (
        ("requirements.txt", requirements(entries)),
        (MANIFEST, _json_bytes(manifest)),
    ):
        with (directory / name).open("xb") as output:
            output.write(raw)
    return verify_wheelhouse(directory, root=root)


def verify_wheelhouse(directory: Path, *, root: Path = ROOT) -> dict:
    if directory.is_symlink() or not directory.is_dir():
        raise EvidenceRejected("wheelhouse must be a regular directory")
    manifest = _read_json(directory / MANIFEST)
    # Verify actual Git bytes without claiming this caller is the originating CI run.
    lock, source = load_lock(), source_identity(root, environment={})
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "schema_version",
            "source_commit_sha",
            "source_tree_sha",
            "dependency_lock_sha256",
            "runtime",
            "peer_commits",
            "build_tool_versions",
            "wheels",
            "independent_rebuild_is_bit_reproducible",
            "source_or_publisher_authentication_established",
        }
        or manifest["schema_version"] != "vulnevidenceops.demo-wheelhouse.v1"
        or manifest["source_commit_sha"] != source["commit_sha"]
        or manifest["source_tree_sha"] != source["tree_sha"]
        or source["worktree_clean"] is not True
        or manifest["runtime"] != runtime_identity()
        or manifest["dependency_lock_sha256"] != hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()
        or manifest["peer_commits"] != {name: peer["commit"] for name, peer in peers().items()}
        or manifest["build_tool_versions"] != lock["build"]
        or manifest["independent_rebuild_is_bit_reproducible"] is not False
        or manifest["source_or_publisher_authentication_established"] is not False
        or not isinstance(manifest["wheels"], list)
    ):
        raise EvidenceRejected("wheelhouse source, platform, lock or peer identity differs")
    files, listed, versions = _wheels(directory), [], {}
    for entry in manifest["wheels"]:
        if not isinstance(entry, dict) or set(entry) != {
            "filename",
            "distribution",
            "version",
            "size_bytes",
            "sha256",
        }:
            raise EvidenceRejected("invalid wheel inventory entry")
        name = entry["filename"]
        if (
            not isinstance(name, str)
            or name not in files
            or type(entry["size_bytes"]) is not int
            or entry["size_bytes"] != len(files[name])
            or not _hex(entry["sha256"], 64)
            or entry["sha256"] != hashlib.sha256(files[name]).hexdigest()
        ):
            raise EvidenceRejected("wheel bytes differ from the recorded SHA-256")
        distribution, version = _wheel_metadata(directory / name)
        if (distribution, version) != (
            entry["distribution"],
            entry["version"],
        ) or distribution in versions:
            raise EvidenceRejected("wheel metadata differs or distribution is duplicated")
        versions[distribution] = version
        listed.append(name)
    if listed != sorted(files) or versions != expected_distributions(lock):
        raise EvidenceRejected("wheelhouse inventory does not cover the exact dependency closure")
    if _read_bytes(directory / "requirements.txt") != requirements(manifest["wheels"]):
        raise EvidenceRejected("hash-enforced installation requirements differ")
    return manifest


def python_in(directory: Path) -> Path:
    return directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def prepare_wheelhouse(directory: Path, environment: dict) -> dict:
    if directory.exists():
        raise EvidenceRejected("wheelhouse output exists; prior bytes are retained")
    lock = load_lock()
    if not source_identity(ROOT)["worktree_clean"]:
        raise EvidenceRejected(
            "default demo requires a clean checkout; use prepared developer mode"
        )
    directory.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="veo-demo-builder-") as temporary:
        builder = Path(temporary)
        venv.EnvBuilder(with_pip=True).create(builder)
        python = str(python_in(builder))
        subprocess.run(
            [
                python,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--no-deps",
                *[f"{name}=={version}" for name, version in sorted(lock["build"].items())],
            ],
            cwd=builder,
            env=environment,
            check=True,
            timeout=300,
        )
        constraints = builder / "runtime-constraints.txt"
        constraints.write_text(
            "".join(f"{name}=={version}\n" for name, version in sorted(lock["runtime"].items())),
            encoding="ascii",
        )
        subprocess.run(
            [
                python,
                "-m",
                "pip",
                "wheel",
                "--disable-pip-version-check",
                "--no-input",
                "--no-build-isolation",
                "--wheel-dir",
                str(directory),
                "--constraint",
                str(constraints),
                str(ROOT),
                *[
                    f"{name} @ git+{peer['repository']}.git@{peer['commit']}"
                    for name, peer in peers().items()
                ],
                *[f"{name}=={version}" for name, version in sorted(lock["runtime"].items())],
            ],
            cwd=builder,
            env=environment,
            check=True,
            timeout=600,
        )
    return freeze_wheelhouse(directory)


def install_wheelhouse(python: Path, directory: Path, environment: dict) -> dict:
    manifest = verify_wheelhouse(directory)
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "--isolated",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "--requirement",
            "requirements.txt",
        ],
        cwd=directory,
        env=environment,
        check=True,
        timeout=300,
    )
    subprocess.run(
        [str(python), "-m", "pip", "--isolated", "check"],
        cwd=directory,
        env=environment,
        check=True,
        timeout=30,
    )
    return manifest
