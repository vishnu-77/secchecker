"""G7: LLM/AI behaviour findings in test/fixture files rank LOW; credentials never do."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from secchecker.reporter import get_severity, is_test_path

ROOT = Path(__file__).resolve().parent.parent
INJECTION = "LLM - Prompt Injection via f-string"


@pytest.mark.parametrize("path", [
    "tests/test_agent.py", "pkg/tests/helpers.py", "a/__tests__/x.ts", "test_x.py",
    "x_test.py", "conftest.py", "web/app.spec.ts", "src/b.test.js", "tests/cassettes/r.yaml",
    "bench/fixtures/v.py", r"pkg\tests\win.py",
])
def test_test_paths(path):
    assert is_test_path(path)


@pytest.mark.parametrize("path", ["src/agent.py", "contest.py", "latest/app.py", "docs/examples/demo.py"])
def test_production_paths(path):
    assert not is_test_path(path)


def test_behaviour_rule_downgraded_in_tests_only():
    assert get_severity(INJECTION) == "HIGH"
    assert get_severity(INJECTION, "src/app.py") == "HIGH"
    assert get_severity(INJECTION, "tests/test_app.py") == "LOW"


@pytest.mark.parametrize("rule", ["LLM - OpenAI API Key", "LLM - HuggingFace Token", "AWS Access Key"])
def test_credentials_keep_severity_in_tests(rule):
    assert get_severity(rule, "tests/test_app.py") == get_severity(rule)


def test_cli_threshold_and_report(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    line = 'prompt = f"Answer: {user_input}"\n'
    (tmp_path / "src" / "app.py").write_text(line)
    (tmp_path / "tests" / "test_app.py").write_text(line)
    out = tmp_path / "r.json"
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    subprocess.run([sys.executable, "-m", "secchecker.cli", "scan", str(tmp_path), "--type", "llm",
                    "--severity-threshold", "HIGH", "--format", "json", "--output", str(out)],
                   cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=120)
    files = [f.replace("\\", "/") for f in json.loads(out.read_text(encoding="utf-8"))["findings"]]
    assert any(f.endswith("src/app.py") for f in files)
    assert not any("tests/" in f for f in files)
