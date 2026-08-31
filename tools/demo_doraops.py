"""One command: synthetic dossier -> signed DataGovOps indexing -> real DORAOps governance.

Stdlib-only bootstrap. Default installs all three projects as non-editable wheels
in a temporary environment; only installation needs network access.
"""

from __future__ import annotations

import argparse
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
    parser.add_argument(
        "--wheelhouse",
        type=Path,
        help="replay recorded wheel bytes without an index (exact checkout/platform required)",
    )
    parser.add_argument(
        "--export-wheelhouse",
        type=Path,
        help="retain the complete hash-verified wheelhouse in a new directory",
    )
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11):  # noqa: UP036 - bootstrap runs before package installation
        parser.error("Python 3.11 or newer is required")
    output = args.output_dir.resolve()
    if output.exists():
        parser.error("output already exists; choose another directory to retain prior evidence")
    if args.prepared_environment and (args.wheelhouse or args.export_wheelhouse):
        parser.error("prepared mode cannot claim or export isolated wheel replay")
    if args.wheelhouse and args.export_wheelhouse:
        parser.error("choose either replay or a new wheelhouse export")
    # This file is a standalone stdlib bootstrap; tools is imported from this exact checkout.
    sys.path.insert(0, str(ROOT))
    from tools.demo_environment import WHEEL_ENV, install_wheelhouse, prepare_wheelhouse
    from tools.demo_evidence import EvidenceRejected

    environment = dict(os.environ)
    environment.pop(WHEEL_ENV, None)
    try:
        if args.prepared_environment:
            _run(sys.executable, output, tests=args.test, installed=False, environment=environment)
        else:
            environment.pop("PYTHONPATH", None)
            environment.pop("PYTHONHOME", None)
            with tempfile.TemporaryDirectory(prefix="vulnevidenceops-doraops-") as temporary:
                directory = Path(temporary)
                wheels = (
                    args.wheelhouse.resolve()
                    if args.wheelhouse
                    else args.export_wheelhouse.resolve()
                    if args.export_wheelhouse
                    else directory / "wheels"
                )
                if not args.wheelhouse:
                    prepare_wheelhouse(wheels, environment)
                runtime = directory / "runtime"
                venv.EnvBuilder(with_pip=True).create(runtime)
                python = runtime / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
                install_wheelhouse(python, wheels, environment)
                environment[WHEEL_ENV] = str(wheels)
                _run(str(python), output, tests=args.test, installed=True, environment=environment)
    except (EvidenceRejected, OSError, subprocess.SubprocessError) as exc:
        print(f"Demo did not complete: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
