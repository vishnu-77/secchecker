"""The documented first-run commands must work.

`secchecker --version` reached the `scan` subparser and died with
"the following arguments are required: path", because the implicit-`scan`
shim in cli.main() only let -h/--help through. Anything documented as a
first-run command belongs here.
"""
import subprocess
import sys
from pathlib import Path

import secchecker

ROOT = Path(__file__).resolve().parent.parent


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "secchecker.cli", *args],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )


def test_version_flag_reports_the_package_version():
    result = _run("--version")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "secchecker {}".format(secchecker.__version__)


def test_bare_path_still_implies_scan():
    """--version must not break the `secchecker <path>` shorthand."""
    result = _run("bench/fixtures/safe", "--type", "llm")
    assert result.returncode == 0, result.stderr
    assert "No findings detected" in result.stdout
