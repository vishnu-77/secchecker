#!/usr/bin/env python3
"""Reproducible LLM/MCP/agentic security benchmark for secchecker.

Runs the LLM scanner (secchecker/llm_scanner.py - the module covering
prompt injection, RAG leakage, MCP tool poisoning, tool-output execution,
memory injection, and unsafe function-call handling) against every fixture
under bench/fixtures/, classifies each file as a true/false positive/negative
by whether it produced *any* finding, and reports precision/recall/F1.

See methodology.md for scoring rules, corpus construction, and limitations.

Usage:
    python bench/run.py                  # print summary, write results/<version>.json
    python bench/run.py --version 0.5.0  # label the results file explicitly
"""
import argparse
import json
import sys
import time
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
REPO_ROOT = BENCH_DIR.parent
sys.path.insert(0, str(REPO_ROOT))

from secchecker.llm_scanner import scan_file_llm  # noqa: E402
from secchecker import __version__ as SECCHECKER_VERSION  # noqa: E402


def classify(fixtures_dir):
    """Scan every fixture, return (rows, tp, fp, tn, fn)."""
    rows = []
    tp = fp = tn = fn = 0

    vulnerable = sorted((fixtures_dir / 'vulnerable').rglob('*.py'))
    safe = sorted((fixtures_dir / 'safe').glob('*.py'))

    for path in vulnerable:
        findings = scan_file_llm(str(path))
        flagged = bool(findings)
        if flagged:
            tp += 1
        else:
            fn += 1
        rows.append({
            'file': str(path.relative_to(BENCH_DIR)),
            'expected': 'vulnerable',
            'flagged': flagged,
            'categories': sorted(findings.keys()),
        })

    for path in safe:
        findings = scan_file_llm(str(path))
        flagged = bool(findings)
        if flagged:
            fp += 1
        else:
            tn += 1
        rows.append({
            'file': str(path.relative_to(BENCH_DIR)),
            'expected': 'safe',
            'flagged': flagged,
            'categories': sorted(findings.keys()),
        })

    return rows, tp, fp, tn, fn


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default=SECCHECKER_VERSION,
                         help='Label for the results file (default: installed secchecker version)')
    args = parser.parse_args()

    fixtures_dir = BENCH_DIR / 'fixtures'
    start = time.perf_counter()
    rows, tp, fp, tn, fn = classify(fixtures_dir)
    elapsed = time.perf_counter() - start

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    summary = {
        'secchecker_version': SECCHECKER_VERSION,
        'total_fixtures': len(rows),
        'true_positives': tp,
        'false_positives': fp,
        'true_negatives': tn,
        'false_negatives': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'execution_time_seconds': round(elapsed, 4),
        'files': rows,
    }

    out_path = BENCH_DIR / 'results' / '{}.json'.format(args.version)
    out_path.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')

    print('secchecker v{} - LLM/MCP/agentic benchmark'.format(SECCHECKER_VERSION))
    print('  fixtures: {} ({} vulnerable, {} safe)'.format(
        len(rows), tp + fn, fp + tn))
    print('  TP={} FP={} TN={} FN={}'.format(tp, fp, tn, fn))
    print('  precision={:.2f}  recall={:.2f}  f1={:.2f}'.format(precision, recall, f1))
    print('  scan time: {:.3f}s'.format(elapsed))
    print('  results written to {}'.format(out_path.relative_to(REPO_ROOT)))

    if fn or fp:
        print('\nMisses:')
        for row in rows:
            if row['expected'] == 'vulnerable' and not row['flagged']:
                print('  FN (missed):     {}'.format(row['file']))
            elif row['expected'] == 'safe' and row['flagged']:
                print('  FP (false alarm): {} -> {}'.format(row['file'], row['categories']))


if __name__ == '__main__':
    main()
