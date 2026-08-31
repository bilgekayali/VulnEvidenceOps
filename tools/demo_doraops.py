"""One command: synthetic dossier -> signed DataGovOps indexing -> real DORAOps governance.

Stdlib-only bootstrap. Default installs all three projects as non-editable wheels
in a temporary environment; only installation needs network access.
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


def _run(python: str, output: Path, *, tests: bool, installed: bool, environment: dict):
    if tests:
        subprocess.run(
            [python, "-m", "unittest", "discover", "-s", "doraops_integration_tests", "-v"],
            cwd=ROOT,
            env=environment,
            check=True,
        )
    command = [python, "-m", "tools.doraops_demo", "--output-dir", str(output)]
    if installed:
        command.append("--installed-wheels")
    subprocess.run(command, cwd=ROOT, env=environment, check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts/doraops-demo")
    parser.add_argument(
        "--test", action="store_true", help="also run the DORAOps integration suite"
    )
    parser.add_argument(
        "--prepared-environment",
        action="store_true",
        help="use hash-checked installed packages offline",
    )
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11):  # noqa: UP036 - bootstrap runs before package installation
        parser.error("Python 3.11 or newer is required")
    output = args.output_dir.resolve()
    if output.exists():
        parser.error("output already exists; choose another directory to retain prior evidence")
    environment = dict(os.environ)
    try:
        if args.prepared_environment:
            _run(sys.executable, output, tests=args.test, installed=False, environment=environment)
        else:
            environment.pop("PYTHONPATH", None)
            environment.pop("PYTHONHOME", None)
            dependencies = []
            for name in ("datagovops", "doraops"):
                contract = json.loads(
                    (ROOT / f"examples/{name}-demo/demo-contract.json").read_text()
                )
                peer = contract["consumer"]
                dependencies.append(f"{name} @ git+{peer['repository']}.git@{peer['commit']}")
            with tempfile.TemporaryDirectory(prefix="vulnevidenceops-doraops-") as temporary:
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
                        *dependencies,
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
