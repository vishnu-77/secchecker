"""The numbers quoted in the docs must match the benchmark artifact.

`bench/results/<version>.json` is the single source of truth for every
precision/recall figure. These tests exist because the adversarial score once
drifted to four different values across README.md, docs/EVALUATION.md,
TODO.txt and the artifact itself - in a project whose stated differentiator is
honest measurement.
"""
import json
import re
from pathlib import Path

import pytest

import secchecker

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "bench" / "results" / f"{secchecker.__version__}.json"


def _results():
    if not RESULTS.exists():
        pytest.skip(f"no benchmark artifact for {secchecker.__version__}")
    return json.loads(RESULTS.read_text(encoding="utf-8"))


def _read(relpath):
    return (ROOT / relpath).read_text(encoding="utf-8")


def test_adversarial_recall_matches_artifact_in_all_docs():
    adv = _results()["adversarial_corpus"]
    caught, total = adv["caught"], adv["total_fixtures"]
    pct = adv["recall"] * 100

    evaluation = _read("docs/EVALUATION.md")
    assert f"**{caught} caught ({pct:.1f}%)**" in evaluation, (
        f"docs/EVALUATION.md must quote {caught} caught ({pct:.1f}%) from {RESULTS.name}"
    )

    readme = _read("README.md")
    assert f"{caught} / {total} detected" in readme
    assert f"{pct:.2f}%" in readme


def test_benign_realistic_still_flagged_matches_artifact():
    benign = _results()["benign_realistic_corpus"]
    flagged = benign["still_flagged"]
    assert f"**{flagged} still flagged**" in _read("docs/EVALUATION.md")


def test_no_doc_quotes_a_stale_adversarial_figure():
    """Catch any `N/14` or `N caught` that disagrees with the artifact."""
    adv = _results()["adversarial_corpus"]
    caught, total = adv["caught"], adv["total_fixtures"]
    for relpath in (
        "README.md", "docs/EVALUATION.md", "bench/methodology.md", "TODO.txt",
        "CHANGELOG.md",
    ):
        text = _read(relpath)
        for found in re.findall(rf"(\d+)\s*/\s*{total}\b", text):
            assert int(found) == caught, (
                f"{relpath} quotes {found}/{total}; artifact says {caught}/{total}"
            )


def test_secret_pattern_count_matches_docs():
    from secchecker.patterns import PATTERNS

    rules = _read("docs/RULES.md")
    assert f"{len(PATTERNS)} patterns across" in rules, (
        f"docs/RULES.md must state {len(PATTERNS)} patterns"
    )
