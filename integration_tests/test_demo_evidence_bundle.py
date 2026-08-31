"""Integrity and exact-checkout checks are independent of the producer runtime."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.demo_evidence import (
    EvidenceRejected,
    finalize_bundle,
    source_identity,
    verify_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = {
    "schema_version": "vulnevidenceops.demo-source-provenance.v1",
    "commit_sha": "a" * 40,
    "tree_sha": "b" * 40,
    "worktree_clean": True,
    "github_actions": None,
    "source_authentication_established": False,
}


class EvidenceBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "evidence"
        self.directory.mkdir()
        (self.directory / "summary.json").write_text('{"accepted":true}\n')
        self.result = finalize_bundle(
            self.directory,
            source=copy.deepcopy(SOURCE),
            contract_sha256="c" * 64,
            report="# Synthetic demo\n\nNo production assurance.\n",
        )

    def manifest(self):
        return json.loads((self.directory / "manifest.json").read_text())

    def change_manifest(self, value):
        (self.directory / "manifest.json").write_text(json.dumps(value))

    def test_complete_bundle_and_external_pins(self):
        self.assertEqual(self.result["artifact_count"], 3)
        self.assertFalse(self.result["authentication_established"])
        self.assertEqual(
            verify_bundle(
                self.directory,
                expected_source_sha="a" * 40,
                expected_manifest_sha256=self.result["manifest_sha256"],
            ),
            self.result,
        )

    def test_every_file_including_report_is_hashed(self):
        for name in ("summary.json", "REPORT.md", "source-provenance.json"):
            path = self.directory / name
            previous = path.read_bytes()
            path.write_bytes(previous + b"tampered")
            with self.subTest(name=name), self.assertRaises(EvidenceRejected):
                verify_bundle(self.directory)
            path.write_bytes(previous)

    def test_missing_and_unlisted_files_fail(self):
        path = self.directory / "extra.json"
        path.write_text("{}")
        with self.assertRaises(EvidenceRejected):
            verify_bundle(self.directory)
        path.unlink()
        (self.directory / "REPORT.md").unlink()
        with self.assertRaises(EvidenceRejected):
            verify_bundle(self.directory)

    def test_wrong_external_source_or_manifest_is_rejected(self):
        for kwargs in (
            {"expected_source_sha": "d" * 40},
            {"expected_source_sha": "main"},
            {"expected_manifest_sha256": "e" * 64},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(EvidenceRejected):
                verify_bundle(self.directory, **kwargs)

    def test_unsafe_duplicate_unordered_and_self_referencing_paths(self):
        original = self.manifest()
        for name in (
            "../outside",
            "/absolute",
            "a/../summary.json",
            "a//b",
            "a\\b",
            "manifest.json",
        ):
            candidate = copy.deepcopy(original)
            candidate["artifacts"][0]["path"] = name
            self.change_manifest(candidate)
            with self.subTest(path=name), self.assertRaises(EvidenceRejected):
                verify_bundle(self.directory)
        for entries in (
            original["artifacts"] * 2,
            list(reversed(original["artifacts"])),
            original["artifacts"][:-1],
        ):
            candidate = copy.deepcopy(original)
            candidate["artifacts"] = entries
            self.change_manifest(candidate)
            with self.assertRaises(EvidenceRejected):
                verify_bundle(self.directory)

    def test_symlink_files_directories_and_root_are_rejected(self):
        link = self.directory / "linked"
        for target in (self.directory / "summary.json", Path(self.temporary.name)):
            link.symlink_to(target)
            with self.assertRaises(EvidenceRejected):
                verify_bundle(self.directory)
            link.unlink()
        outside = Path(self.temporary.name) / "linked-root"
        outside.symlink_to(self.directory)
        with self.assertRaises(EvidenceRejected):
            verify_bundle(outside)

    def test_oversized_files_and_too_many_files_are_rejected(self):
        with patch("tools.demo_evidence.MAX_FILE_BYTES", 1), self.assertRaises(EvidenceRejected):
            verify_bundle(self.directory)
        with patch("tools.demo_evidence.MAX_FILES", 1), self.assertRaises(EvidenceRejected):
            verify_bundle(self.directory)
        with patch("tools.demo_evidence.MAX_TOTAL_BYTES", 1), self.assertRaises(EvidenceRejected):
            verify_bundle(self.directory)

    def test_manifest_and_provenance_must_agree(self):
        manifest = self.manifest()
        manifest["source_commit_sha"] = "d" * 40
        self.change_manifest(manifest)
        with self.assertRaises(EvidenceRejected):
            verify_bundle(self.directory)

    def test_manifest_strict_structure_and_duplicate_keys(self):
        for content in ('{"artifacts":[],"artifacts":[]}', "[1,2]", '{"x":NaN}'):
            (self.directory / "manifest.json").write_text(content)
            with self.subTest(content=content), self.assertRaises(EvidenceRejected):
                verify_bundle(self.directory)

    def test_preexisting_bundle_is_not_overwritten(self):
        previous = (self.directory / "manifest.json").read_bytes()
        with self.assertRaises(FileExistsError):
            finalize_bundle(
                self.directory, source=SOURCE, contract_sha256="c" * 64, report="changed"
            )
        self.assertEqual((self.directory / "manifest.json").read_bytes(), previous)

    def test_verifier_cli_is_standalone_and_rejects_tampering(self):
        command = [
            sys.executable,
            str(ROOT / "tools/demo_evidence.py"),
            str(self.directory),
            "--expected-source-sha",
            "a" * 40,
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["manifest_sha256"],
            hashlib.sha256((self.directory / "manifest.json").read_bytes()).hexdigest(),
        )
        (self.directory / "summary.json").write_text("{}")
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=20)
        self.assertEqual(result.returncode, 2)

    def test_ci_requires_actual_exact_sha_clean_checkout_and_run_identity(self):
        environment = {
            "GITHUB_ACTIONS": "true",
            "DEMO_SOURCE_SHA": "a" * 40,
            "GITHUB_REPOSITORY": "bilgekayali/VulnEvidenceOps",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_NAME": "pull_request",
        }

        def result(stdout):
            return subprocess.CompletedProcess([], 0, stdout, "")

        with patch(
            "tools.demo_evidence.subprocess.run",
            side_effect=[result("a" * 40), result("b" * 40), result("")],
        ):
            source = source_identity(ROOT, environment)
        self.assertEqual(source["commit_sha"], "a" * 40)
        self.assertEqual(source["github_actions"]["run_id"], 123)
        for changes, status in (
            ({"DEMO_SOURCE_SHA": "e" * 40}, ""),
            ({}, " M tracked.py"),
            ({"GITHUB_RUN_ID": "bad"}, ""),
            ({"GITHUB_REPOSITORY": "../bad"}, ""),
        ):
            with (
                patch(
                    "tools.demo_evidence.subprocess.run",
                    side_effect=[result("a" * 40), result("b" * 40), result(status)],
                ),
                self.assertRaises(EvidenceRejected),
            ):
                source_identity(ROOT, environment | changes)


if __name__ == "__main__":
    unittest.main()
