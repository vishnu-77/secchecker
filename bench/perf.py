#!/usr/bin/env python3
"""Scan-throughput benchmark for secchecker.

Generates a synthetic tree of files (mixed sizes, a few near the 10MB
skip-file guard) and times secchecker.core.scan_directory() over it at a few
sizes, checking that scan time scales roughly linearly with file count -
this catches an accidental O(n^2) regression (e.g. pattern-cache thrashing,
see the regex-precompilation fix in core.py) that a single-size timing
number wouldn't reveal.

Not an absolute-time CI gate (machine-dependent) - only the scaling ratio is
asserted. See bench/methodology.md.

Usage:
    python bench/perf.py [--sizes 100 400 1600]
"""
import argparse
import json
import random
import shutil
import sys
import tempfile
import time
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
REPO_ROOT = BENCH_DIR.parent
sys.path.insert(0, str(REPO_ROOT))

from secchecker.core import scan_directory  # noqa: E402
from secchecker import __version__ as SECCHECKER_VERSION  # noqa: E402

# A realistic mix: some clean lines, one planted secret-shaped line, a
# handful of comment/prose lines - not pathological, not empty.
_FILE_TEMPLATE = """\
# module {i}
import os
import json


def handler_{i}(request):
    data = json.loads(request.body)
    result = process(data)
    return result


API_KEY = "not-a-real-key-{i}"
CONFIG_VALUE = "plain-config-string-{i}"


class Worker{i}:
    def run(self):
        for item in range(100):
            self.process(item)

    def process(self, item):
        return item * 2
"""


def _make_tree(root, n_files):
    root.mkdir(parents=True, exist_ok=True)
    rng = random.Random(42)
    for i in range(n_files):
        subdir = root / "pkg{}".format(i % 20)
        subdir.mkdir(exist_ok=True)
        content = _FILE_TEMPLATE.format(i=i)
        if rng.random() < 0.02:
            # A few larger files, still well under the 10MB skip guard.
            content = content * 200
        (subdir / "mod_{}.py".format(i)).write_text(content, encoding='utf-8')


def _time_scan(n_files):
    tmp = Path(tempfile.mkdtemp(prefix="secchecker_perf_"))
    try:
        _make_tree(tmp, n_files)
        start = time.perf_counter()
        scan_directory(str(tmp))
        elapsed = time.perf_counter() - start
        return elapsed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sizes', type=int, nargs='+', default=[100, 400, 1600],
                         help='File counts to benchmark at (default: 100 400 1600)')
    parser.add_argument('--version', default=SECCHECKER_VERSION)
    args = parser.parse_args()

    results = []
    for n in args.sizes:
        elapsed = _time_scan(n)
        results.append({'files': n, 'seconds': round(elapsed, 4),
                         'files_per_second': round(n / elapsed, 1) if elapsed else None})
        print('{:>6} files: {:.4f}s ({:.0f} files/s)'.format(
            n, elapsed, n / elapsed if elapsed else 0))

    # Linearity check: doubling input size shouldn't more than ~3x the time
    # (generous slack for filesystem/OS noise on a small synthetic run - this
    # is a regression guard against O(n^2)-shaped blowups, not a tight bound).
    ratios = []
    for a, b in zip(results, results[1:]):
        if a['seconds'] > 0:
            size_ratio = b['files'] / a['files']
            time_ratio = b['seconds'] / a['seconds']
            ratios.append({'size_ratio': size_ratio, 'time_ratio': round(time_ratio, 2)})

    summary = {
        'secchecker_version': SECCHECKER_VERSION,
        'results': results,
        'scaling_ratios': ratios,
    }
    out_path = BENCH_DIR / 'results' / 'perf-{}.json'.format(args.version)
    out_path.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print('results written to {}'.format(out_path.relative_to(REPO_ROOT)))

    bad = [r for r in ratios if r['time_ratio'] > r['size_ratio'] * 3]
    if bad:
        print('\nWARNING: scan time grew much faster than input size - possible regression:')
        for r in bad:
            print('  {}x more files took {}x longer'.format(r['size_ratio'], r['time_ratio']))
        sys.exit(1)


if __name__ == '__main__':
    main()
