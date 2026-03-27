import argparse
import os
import sys
from .core import scan_directory, scan_file
from .reporter import to_json, to_markdown, to_xml

try:
    from .sarif_reporter import to_sarif
except ImportError:
    to_sarif = None

try:
    from .html_reporter import to_html
except ImportError:
    to_html = None

try:
    from .llm_scanner import scan_directory_llm, scan_file_llm
except ImportError:
    scan_directory_llm = None
    scan_file_llm = None

try:
    from .devsecops_scanner import scan_directory_devsecops, scan_file_devsecops
except ImportError:
    scan_directory_devsecops = None
    scan_file_devsecops = None

try:
    from .entropy import scan_file_entropy
except ImportError:
    scan_file_entropy = None

try:
    from .config import load_config
except ImportError:
    load_config = None

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _merge_results(base, extra):
    """Merge extra scan results into base dict."""
    for filepath, findings in extra.items():
        if filepath not in base:
            base[filepath] = {}
        base[filepath].update(findings)
    return base


def _filter_by_severity(results, threshold):
    """Remove findings below the severity threshold."""
    if threshold is None:
        return results
    min_level = SEVERITY_ORDER.get(threshold.upper(), 0)
    try:
        from .reporter import get_severity
    except ImportError:
        return results
    filtered = {}
    for filepath, findings in results.items():
        kept = {k: v for k, v in findings.items()
                if SEVERITY_ORDER.get(get_severity(k), 0) >= min_level}
        if kept:
            filtered[filepath] = kept
    return filtered


def _run_scan(path, scan_type, no_entropy, config):
    """Run the requested scan type(s) and return merged results."""
    import os as _os
    is_file = _os.path.isfile(path)

    results = {}

    if scan_type in ('secrets', 'all'):
        if is_file:
            r = scan_file(path)
            if r:
                results[path] = r
        else:
            results = _merge_results(results, scan_directory(path))

        if not no_entropy and scan_file_entropy is not None:
            entropy_cfg = config.get('entropy', {}) if config else {}
            if entropy_cfg.get('enabled', False):
                import os as _os2
                from pathlib import Path
                if is_file:
                    er = scan_file_entropy(path)
                    if er:
                        results.setdefault(path, {}).update(er)
                else:
                    for root, dirs, files in _os2.walk(path):
                        for fname in files:
                            fp = _os2.path.join(root, fname)
                            er = scan_file_entropy(fp)
                            if er:
                                results.setdefault(fp, {}).update(er)

    if scan_type in ('llm', 'all'):
        if scan_directory_llm is None:
            print('[!] LLM scanner not available', file=sys.stderr)
        else:
            if is_file:
                r = scan_file_llm(path)
                if r:
                    results.setdefault(path, {}).update(r)
            else:
                results = _merge_results(results, scan_directory_llm(path))

    if scan_type in ('devsecops', 'all'):
        if scan_directory_devsecops is None:
            print('[!] DevSecOps scanner not available', file=sys.stderr)
        else:
            if is_file:
                r = scan_file_devsecops(path)
                if r:
                    results.setdefault(path, {}).update(r)
            else:
                results = _merge_results(results, scan_directory_devsecops(path))

    return results


def main():
    """Main CLI entry point for secchecker."""
    parser = argparse.ArgumentParser(
        description='secchecker — security auditing for DevSecOps and AI systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secchecker .                               # Scan for secrets (default)
  secchecker . --type llm                    # Scan for LLM/AI vulnerabilities
  secchecker . --type devsecops             # Scan Dockerfiles, Terraform, K8s
  secchecker . --type all                    # Run all scanners
  secchecker . --format sarif --output report.sarif
  secchecker . --severity-threshold HIGH     # Only report HIGH and CRITICAL

Exit codes:
  0  No findings at or above the severity threshold
  1  One or more findings detected
  2  Runtime error
        """,
    )
    parser.add_argument('path', help='Path to scan (file or directory)')
    parser.add_argument(
        '--type',
        choices=['secrets', 'llm', 'devsecops', 'all'],
        default='secrets',
        dest='scan_type',
        help='Scan type (default: secrets)',
    )
    parser.add_argument(
        '--format',
        choices=['json', 'md', 'xml', 'sarif', 'html'],
        default=os.environ.get('SECHECKER_REPORT_FORMAT', 'md'),
        help='Output format (default: md)',
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: secchecker_report.<format>)',
    )
    parser.add_argument(
        '--severity-threshold',
        choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        default=None,
        metavar='LEVEL',
        help='Minimum severity to report (LOW/MEDIUM/HIGH/CRITICAL)',
    )
    parser.add_argument(
        '--config',
        metavar='FILE',
        help='Path to .secchecker.yml config file',
    )
    parser.add_argument(
        '--no-entropy',
        action='store_true',
        help='Disable entropy-based detection',
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output',
    )

    args = parser.parse_args()

    # Load config
    config = {}
    if load_config is not None:
        try:
            config = load_config(
                config_path=args.config,
                scan_root=args.path if not os.path.isfile(args.path) else None,
            )
        except Exception:
            config = {}

    # CLI --severity-threshold overrides config
    threshold = args.severity_threshold
    if threshold is None and config:
        threshold = config.get('severity_threshold')

    if args.verbose:
        print('[*] Scanning: {}'.format(args.path))
        print('[*] Scan type: {}'.format(args.scan_type))
        print('[*] Format: {}'.format(args.format))
        if threshold:
            print('[*] Severity threshold: {}'.format(threshold))

    try:
        results = _run_scan(args.path, args.scan_type, args.no_entropy, config)
        results = _filter_by_severity(results, threshold)
    except Exception as e:
        print('[!] Error during scan: {}'.format(e), file=sys.stderr)
        sys.exit(2)

    if not results:
        print('[+] No findings detected.')
        sys.exit(0)

    # Determine output file
    fmt = args.format
    output_file = args.output or 'secchecker_report.{}'.format(fmt)

    try:
        if fmt == 'json':
            report_file = to_json(results, output_file)
        elif fmt == 'md':
            report_file = to_markdown(results, output_file)
        elif fmt == 'xml':
            report_file = to_xml(results, output_file)
        elif fmt == 'sarif':
            if to_sarif is None:
                print('[!] SARIF reporter not available', file=sys.stderr)
                sys.exit(2)
            report_file = to_sarif(results, output_file)
        elif fmt == 'html':
            if to_html is None:
                print('[!] HTML reporter not available', file=sys.stderr)
                sys.exit(2)
            report_file = to_html(results, output_file, scan_type=args.scan_type)
    except Exception as e:
        print('[!] Error generating report: {}'.format(e), file=sys.stderr)
        sys.exit(2)

    total = sum(len(v) for v in results.values())
    if args.verbose:
        print('[*] {} finding(s) across {} file(s)'.format(total, len(results)))
    print('[+] Report: {}'.format(report_file))

    sys.exit(1)


if __name__ == '__main__':
    main()
