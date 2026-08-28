from __future__ import annotations

import json

import pytest

from vulnevidenceops.cli import main

from .helpers import ROOT


def test_cli_version_and_digest(capsys):
    with pytest.raises(SystemExit) as captured:
        main(["--version"])
    assert captured.value.code == 0
    assert capsys.readouterr().out.strip() == "1.0.0"

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


def test_cli_assesses_exposure_context_to_file(tmp_path):
    output = tmp_path / "exposure-assessment.json"
    assert (
        main(
            [
                "exposure",
                str(ROOT / "examples" / "synthetic-exposure-context.json"),
                "--as-of",
                "2026-01-20T00:00:00Z",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assessment = json.loads(output.read_text(encoding="utf-8"))
    assert assessment["context_position"] == "current"
    assert assessment["gaps"] == []
    assert all(value is False for value in assessment["non_claims"].values())


def test_cli_builds_portfolio_assurance_view(tmp_path):
    output = tmp_path / "portfolio-view.json"
    assert (
        main(
            [
                "portfolio",
                str(ROOT / "examples" / "synthetic-portfolio.json"),
                "--as-of",
                "2026-01-20T00:00:00Z",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    view = json.loads(output.read_text(encoding="utf-8"))
    assert view["portfolio_position"] == "current"
    assert view["totals"]["case_count"] == 3
    assert "compliance_percentage" not in view["totals"]
    assert all(value is False for value in view["non_claims"].values())


def test_cli_fails_cleanly_for_invalid_case(tmp_path):
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{}\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="case_id"):
        main(["assess", str(invalid), "--as-of", "2026-01-20T00:00:00Z"])


@pytest.mark.parametrize(
    ("source_format", "example", "asset_option", "expected_count"),
    [
        ("sarif", "synthetic-sarif.json", "--asset-ref", 2),
        ("cyclonedx", "synthetic-cyclonedx.json", "--asset-ref-prefix", 3),
    ],
)
def test_cli_builds_supported_intake_batches(
    source_format, example, asset_option, expected_count, tmp_path
):
    output = tmp_path / f"{source_format}-intake.json"
    assert (
        main(
            [
                "intake",
                source_format,
                str(ROOT / "examples" / example),
                "--artifact-ref",
                f"synthetic://intake/{example}",
                "--collected-at",
                "2026-01-05T00:00:00Z",
                "--observed-at",
                "2026-01-04T00:00:00Z",
                "--source-identity",
                "synthetic-source:reference-v1",
                "--source-ref",
                "synthetic-source:export-001",
                asset_option,
                "synthetic-asset:",
                "--synthetic",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert len(json.loads(output.read_text(encoding="utf-8"))["findings"]) == expected_count


def test_cli_requires_the_format_specific_asset_option():
    with pytest.raises(SystemExit, match="--asset-ref is required"):
        main(
            [
                "intake",
                "sarif",
                str(ROOT / "examples" / "synthetic-sarif.json"),
                "--artifact-ref",
                "synthetic://intake/sarif.json",
                "--collected-at",
                "2026-01-05T00:00:00Z",
                "--observed-at",
                "2026-01-04T00:00:00Z",
                "--source-identity",
                "synthetic-source:reference-v1",
                "--source-ref",
                "synthetic-source:export-001",
            ]
        )


@pytest.mark.parametrize(
    ("source_format", "asset_args", "message"),
    [
        (
            "sarif",
            ["--asset-ref", "synthetic-asset:1", "--asset-ref-prefix", "prefix:"],
            "only valid for CycloneDX",
        ),
        ("cyclonedx", [], "--asset-ref-prefix is required"),
        (
            "cyclonedx",
            ["--asset-ref-prefix", "prefix:", "--asset-ref", "synthetic-asset:1"],
            "only valid for SARIF",
        ),
    ],
)
def test_cli_rejects_cross_format_asset_options(source_format, asset_args, message):
    example = "synthetic-sarif.json" if source_format == "sarif" else "synthetic-cyclonedx.json"
    with pytest.raises(SystemExit, match=message):
        main(
            [
                "intake",
                source_format,
                str(ROOT / "examples" / example),
                "--artifact-ref",
                f"synthetic://intake/{example}",
                "--collected-at",
                "2026-01-05T00:00:00Z",
                "--observed-at",
                "2026-01-04T00:00:00Z",
                "--source-identity",
                "synthetic-source:reference-v1",
                "--source-ref",
                "synthetic-source:export-001",
                *asset_args,
            ]
        )
