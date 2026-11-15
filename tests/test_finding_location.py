"""T1 (docs/plans/llm-scanner-test-plan.md): every LLM finding must point at the vulnerable code.

Ground truth comes for free from the paired corpus: each safe fixture is its vulnerable twin
with the vulnerable line(s) replaced, so the lines that differ are where the finding must be.
Each reported snippet must (a) appear verbatim in the file and (b) sit on a changed line.
"""
import difflib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from secchecker.llm_scanner import scan_file_llm
from secchecker.sarif_reporter import _line_of

FIXTURES = Path(__file__).resolve().parent.parent / "bench" / "fixtures"
PAIRS = sorted(
    (v, FIXTURES / "safe" / "{}_{}".format(v.parent.name, v.name))
    for v in (FIXTURES / "vulnerable").rglob("*.py")
)


def _changed_lines(vuln, safe):
    a = vuln.read_text(encoding="utf-8").splitlines()
    b = safe.read_text(encoding="utf-8").splitlines()
    changed = set()
    for tag, i1, i2, _, _ in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag != "equal":
            changed.update(range(i1 + 1, max(i2, i1 + 1) + 1))
    return changed


def test_corpus_is_paired():
    assert PAIRS, "no fixtures found"
    missing = [str(s) for _, s in PAIRS if not s.exists()]
    assert not missing


@pytest.mark.parametrize("vuln,safe", PAIRS, ids=lambda p: p.stem)
def test_findings_point_at_vulnerable_lines(vuln, safe):
    content = vuln.read_text(encoding="utf-8")
    changed = _changed_lines(vuln, safe)
    findings = scan_file_llm(str(vuln))
    assert findings, "vulnerable fixture not flagged"
    for rule, snippets in findings.items():
        for s in snippets:
            assert s in content, "{}: snippet not in file: {!r}".format(rule, s)
            first = _line_of(content, s)
            span = set(range(first, first + s.count("\n") + 1))
            assert span & changed, "{}: line {} not in changed lines {}".format(
                rule, first, sorted(changed))


def test_sarif_lines_correct_when_run_outside_scan_root(tmp_path):
    """Directory results are keyed relative to the scan root; SARIF must still find the
    files (it used to open them relative to the cwd and fall back to line 1)."""
    target = tmp_path / "target"
    target.mkdir()
    for v, safe in PAIRS:
        shutil.copy(v, target / "{}_{}".format(v.parent.name, v.name))
    out = tmp_path / "r.sarif"
    root = Path(__file__).resolve().parent.parent
    env = dict(os.environ, PYTHONPATH=str(root))
    subprocess.run(
        [sys.executable, "-m", "secchecker.cli", "scan", str(target), "--type", "llm",
         "--format", "sarif", "--output", str(out)],
        cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=120,
    )
    # exact line of each rule's first snippet (validated by the test above); not just
    # "a changed line", because line 1 (the docstring) differs in every pair
    expected = {}
    for v, _ in PAIRS:
        content = v.read_text(encoding="utf-8")
        for rule, snippets in scan_file_llm(str(v)).items():
            expected[("{}_{}".format(v.parent.name, v.name), rule)] = _line_of(content, snippets[0])
    results = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"]
    assert len(results) == len(expected)
    for r in results:
        loc = r["locations"][0]["physicalLocation"]
        key = (loc["artifactLocation"]["uri"].split("/")[-1], r["ruleId"])
        assert loc["region"]["startLine"] == expected[key], key
