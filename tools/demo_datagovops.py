"""One-command synthetic finding -> dossier -> real DataGovOps consumer demo.

Default: install both projects as wheels in a temporary, isolated environment.
Network access to GitHub and the configured Python package index is required only
during setup. The producer/consumer pipeline itself is completely offline.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(python: str, output: Path, *, tests: bool, installed: bool, environment: dict) -> None:
    if tests:
        subprocess.run(
            [python, "-m", "unittest", "discover", "-s", "integration_tests", "-v"],
            cwd=ROOT,
            env=environment,
            check=True,
        )
    command = [python, "-m", "tools.datagovops_demo", "--output-dir", str(output)]
    if installed:
        command.append("--installed-wheels")
    subprocess.run(command, cwd=ROOT, env=environment, check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts/datagovops-demo")
    parser.add_argument(
        "--test", action="store_true", help="also run the full integration test suite"
    )
    parser.add_argument(
        "--prepared-environment",
        action="store_true",
        help="offline developer mode; use already installed, hash-checked packages",
    )
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if sys.version_info < (3, 11):  # noqa: UP036 - bootstrap runs before package installation
        parser.error("Python 3.11 or newer is required")
    if output.exists():
        parser.error("output already exists; choose another directory to preserve prior evidence")
    environment = dict(os.environ)
    try:
        if args.prepared_environment:
            _run(sys.executable, output, tests=args.test, installed=False, environment=environment)
        else:
            # Prevent the parent checkout/PYTHONPATH from shadowing the installed wheels.
            environment.pop("PYTHONPATH", None)
            environment.pop("PYTHONHOME", None)
            contract = json.loads(
                (ROOT / "examples/datagovops-demo/demo-contract.json").read_text()
            )
            peer = contract["consumer"]
            dependency = f"datagovops @ git+{peer['repository']}.git@{peer['commit']}"
            with tempfile.TemporaryDirectory(prefix="vulnevidenceops-datagovops-") as temporary:
                directory = Path(temporary)
                venv.EnvBuilder(with_pip=True).create(directory)
                python = directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
                subprocess.run(
                    [
                        str(python),
                        "-m",
                        "pip",
                        "install",
                        "--disable-pip-version-check",
                        "--no-input",
                        str(ROOT),
                        dependency,
                    ],
                    cwd=directory,
                    env=environment,
                    check=True,
                )
                _run(str(python), output, tests=args.test, installed=True, environment=environment)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Demo did not complete: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
