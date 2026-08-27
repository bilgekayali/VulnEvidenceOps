import json

from tools.build_sbom import DIRECT_RUNTIME_DEPENDENCIES, build_sbom, main


def test_sbom_binds_package_and_direct_dependencies():
    sbom = build_sbom()

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["version"] == "0.2.0"
    assert [item["name"] for item in sbom["components"]] == list(DIRECT_RUNTIME_DEPENDENCIES)


def test_sbom_output_is_deterministic(tmp_path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    assert main(["--output", str(first)]) == 0
    assert main(["--output", str(second)]) == 0
    assert first.read_bytes() == second.read_bytes()
    assert json.loads(first.read_text(encoding="utf-8"))["dependencies"]
