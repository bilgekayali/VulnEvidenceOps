"""Build deterministic direct-dependency CycloneDX evidence."""

from __future__ import annotations

import argparse
import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from vulnevidenceops import PACKAGE_VERSION

DIRECT_RUNTIME_DEPENDENCIES = ("cryptography", "jsonschema")
ROOT_REF = f"pkg:pypi/vulnevidenceops@{PACKAGE_VERSION}"


def build_sbom() -> dict:
    components = []
    dependency_refs = []
    for name in DIRECT_RUNTIME_DEPENDENCIES:
        try:
            resolved = version(name)
        except PackageNotFoundError as exc:
            raise SystemExit(f"required runtime dependency is not installed: {name}") from exc
        reference = f"pkg:pypi/{name}@{resolved}"
        dependency_refs.append(reference)
        components.append(
            {
                "type": "library",
                "bom-ref": reference,
                "name": name,
                "version": resolved,
                "purl": reference,
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": ROOT_REF,
                "name": "vulnevidenceops",
                "version": PACKAGE_VERSION,
                "purl": ROOT_REF,
            }
        },
        "components": components,
        "dependencies": [
            {"ref": ROOT_REF, "dependsOn": dependency_refs},
            *({"ref": reference, "dependsOn": []} for reference in dependency_refs),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(build_sbom(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
