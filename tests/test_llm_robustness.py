"""T7 + T8 (docs/plans/llm-scanner-test-plan.md): the LLM scanner must survive odd input,
give the same answer every time, and keep its CLI contract (exit codes, parseable output)."""
import json
import os
import random
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from secchecker.llm_scanner import _scan_content, scan_directory_llm, scan_file_llm

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "bench" / "fixtures"
VULN_LINE = 'system_prompt = f"You are a helpful assistant. User query: {user_input}"'
RULE = "LLM - Prompt Injection via f-string"


# ---- T7: odd input ---------------------------------------------------------

def test_malformed_python_keeps_regex_findings(tmp_path):
    # AST parse fails; regex rules must still report
    f = tmp_path / "broken.py"
    f.write_text("def build(user_input):\n    " + VULN_LINE + "\ndef broken(:\n", encoding="utf-8")
    assert RULE in scan_file_llm(str(f))


def test_non_utf8_file_is_scanned(tmp_path):
    f = tmp_path / "latin.py"
    f.write_bytes(("# caf\xe9\n" + VULN_LINE + "\n").encode("latin-1"))
    assert RULE in scan_file_llm(str(f))


def test_empty_and_binary_files_do_not_crash(tmp_path):
    (tmp_path / "empty.py").write_bytes(b"")
    (tmp_path / "garbage.py").write_bytes(bytes(range(256)) * 40)
    assert scan_file_llm(str(tmp_path / "empty.py")) == {}
    scan_file_llm(str(tmp_path / "garbage.py"))  # must not raise


def test_notebook_cells_are_scanned(tmp_path):
    nb = {"cells": [{"cell_type": "code", "source": ["def build(user_input):\n", "    " + VULN_LINE + "\n"]}]}
    f = tmp_path / "nb.ipynb"
    f.write_text(json.dumps(nb), encoding="utf-8")
    findings = scan_file_llm(str(f))
    assert RULE in findings
    assert any("{user_input}" in s for s in findings[RULE])


def test_malformed_notebook_falls_back_to_raw_scan(tmp_path):
    f = tmp_path / "bad.ipynb"
    f.write_text('{"cells": [ ' + VULN_LINE, encoding="utf-8")
    assert RULE in scan_file_llm(str(f))


def test_random_input_never_raises_or_hangs():
    # fixed seed: reproducible; tokens chosen to hit rule prefixes (ReDoS bait)
    rng = random.Random(1234)
    tokens = ["f\"", "{user_input}", "system_prompt", "prompt", "<|system|>", "ignore previous",
              "instructions", "eval(", "os.system(", "mcp_result", "while True:", ".run()",
              "memory.append(", "\n", " ", "'''", "\"\"\"", "(", ")", "=", "#", "\\", "a" * 50]
    for _ in range(300):
        text = "".join(rng.choice(tokens) for _ in range(rng.randint(1, 400)))
        start = time.perf_counter()
        _scan_content(text)
        assert time.perf_counter() - start < 1.0, "slow input: {!r}".format(text[:200])


def test_scan_is_deterministic():
    a = scan_directory_llm(str(FIXTURES))
    b = scan_directory_llm(str(FIXTURES))
    assert json.dumps(a, sort_keys=False) == json.dumps(b, sort_keys=False)


# ---- T8: CLI contract ------------------------------------------------------

def _cli(tmp_path, *args):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    return subprocess.run([sys.executable, "-m", "secchecker.cli", "scan", *args],
                          cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=120)


@pytest.fixture
def dirs(tmp_path):
    clean, vuln = tmp_path / "clean", tmp_path / "vuln"
    clean.mkdir()
    vuln.mkdir()
    (clean / "ok.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (vuln / "bad.py").write_text("def build(user_input):\n    " + VULN_LINE + "\n", encoding="utf-8")
    return clean, vuln


def test_exit_codes(tmp_path, dirs):
    clean, vuln = dirs
    assert _cli(tmp_path, str(clean), "--type", "llm", "--output", "c.json", "--format", "json").returncode == 0
    assert _cli(tmp_path, str(vuln), "--type", "llm", "--output", "v.json", "--format", "json").returncode == 1
    assert _cli(tmp_path, str(tmp_path / "missing"), "--type", "llm").returncode == 2


def test_threshold_above_findings_exits_clean(tmp_path, dirs):
    _, vuln = dirs  # f-string injection is HIGH
    r = _cli(tmp_path, str(vuln), "--type", "llm", "--severity-threshold", "CRITICAL",
             "--format", "json", "--output", "t.json")
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("fmt,parse", [
    ("json", json.loads), ("sarif", json.loads), ("xml", ET.fromstring),
    ("md", lambda s: s.strip() or None), ("html", lambda s: s.strip() or None),
])
def test_every_format_parses_and_names_the_rule(tmp_path, dirs, fmt, parse):
    _, vuln = dirs
    out = tmp_path / ("r." + fmt)
    r = _cli(tmp_path, str(vuln), "--type", "llm", "--format", fmt, "--output", str(out))
    assert r.returncode == 1, r.stderr
    text = out.read_text(encoding="utf-8")
    assert parse(text) is not None
    assert "Prompt Injection via f-string" in text


def test_cli_json_is_deterministic(tmp_path):
    def run(name):
        _cli(tmp_path, str(FIXTURES), "--type", "llm", "--format", "json", "--output", name)
        data = json.loads((tmp_path / name).read_text(encoding="utf-8"))
        data.pop("metadata", None)  # holds the timestamp
        return data
    assert run("a.json") == run("b.json")
