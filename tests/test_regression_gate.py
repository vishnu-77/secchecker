"""T9 (docs/plans/llm-scanner-test-plan.md): CI gate on benchmark and evasion numbers.

Compares against bench/baseline.json. Getting worse fails. Getting better also fails, with a
message to update the baseline, so an improvement can't silently regress later.
"""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench"
BASE = json.loads((BENCH / "baseline.json").read_text(encoding="utf-8"))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, BENCH / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ratchet(label, now, base, higher_is_better=True):
    if now == base:
        return
    better = now > base if higher_is_better else now < base
    if better:
        raise AssertionError("{} improved {} -> {}: update bench/baseline.json".format(label, base, now))
    raise AssertionError("{} regressed {} -> {}".format(label, base, now))


def test_paired_corpus():
    run = _load("run")
    _, tp, fp, tn, fn = run.classify(BENCH / "fixtures")
    assert {"tp": tp, "fp": fp, "tn": tn, "fn": fn} == BASE["paired"]


def test_adversarial_and_benign_corpora():
    run = _load("run")
    adv = run.scan_only(sorted((BENCH / "fixtures" / "adversarial").rglob("*.py")))
    ben = run.scan_only(sorted((BENCH / "fixtures" / "benign_realistic").glob("*.py")))
    _ratchet("adversarial caught", sum(r["flagged"] for r in adv), BASE["adversarial_caught"])
    _ratchet("benign flagged", sum(r["flagged"] for r in ben), BASE["benign_flagged"], higher_is_better=False)


def test_mutation_survival():
    mutate = _load("mutate")
    rows, noise = mutate.run()
    for name, base in BASE["mutation_kept"].items():
        kept = sum(r["status"] == "kept" for r in rows if r["transform"] == name)
        _ratchet("mutation kept[{}]".format(name), kept, base)
    _ratchet("comment-noise flagged", sum(bool(n["flagged"]) for n in noise),
             BASE["comment_noise_flagged"], higher_is_better=False)
