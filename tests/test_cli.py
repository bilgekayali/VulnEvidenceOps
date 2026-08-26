from __future__ import annotations

import json

import pytest

from vulnevidenceops.cli import main

from .helpers import ROOT


def test_cli_version_and_digest(capsys):
    with pytest.raises(SystemExit) as captured:
        main(["--version"])
    assert captured.value.code == 0
    assert capsys.readouterr().out.strip() == "0.1.0"

    assert main(["digest-json", str(ROOT / "examples" / "synthetic-policy.json")]) == 0
    assert len(capsys.readouterr().out.strip()) == 64


def test_cli_validates_and_assesses_to_file(tmp_path, capsys):
    case = ROOT / "examples" / "synthetic-case.json"
    policy = ROOT / "examples" / "synthetic-policy.json"
    output = tmp_path / "dossier.json"

    assert main(["schema", str(ROOT / "schemas" / "case-bundle.schema.json"), str(case)]) == 0
    assert capsys.readouterr().out.strip() == "valid"
    assert (
        main(
            [
                "assess",
                str(case),
                "--policy",
                str(policy),
                "--as-of",
                "2026-01-20T00:00:00Z",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text(encoding="utf-8"))["lifecycle_state"] == "closed_verified"


def test_cli_assesses_with_default_policy_to_stdout(capsys):
    assert (
        main(
            [
                "assess",
                str(ROOT / "examples" / "synthetic-case.json"),
                "--as-of",
                "2026-01-20T00:00:00Z",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["assurance_position"] == "current"


def test_cli_fails_cleanly_for_invalid_case(tmp_path):
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{}\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="case_id"):
        main(["assess", str(invalid), "--as-of", "2026-01-20T00:00:00Z"])
