from __future__ import annotations

import subprocess
import sys

from .helpers import ROOT


def test_release_contract_verifies_exact_repository_state():
    result = subprocess.run(
        [sys.executable, "tools/release_contract.py", "--verify"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
