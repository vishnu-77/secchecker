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
    from .entropy import scan_file_entropy, scan_directory_entropy
except ImportError:
    scan_file_entropy = None
    scan_directory_entropy = None

try:
    from .config import load_config, is_path_excluded, is_pattern_excluded
except ImportError:
    load_config = None
    is_path_excluded = None
    is_pattern_excluded = None

try:
    from .ast_scanner import scan_directory_ast, scan_file_ast
except ImportError:
    scan_directory_ast = None
    scan_file_ast = None

try:
    from .patterns import PII_PATTERNS
except ImportError:
    PII_PATTERNS = {}

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


def _resolve_scan_types(cli_scan_type, config):
    """Resolve the effective scan type(s): CLI --type wins; else config
    scan_types; else the default {'secrets'}."""
    if cli_scan_type:
        return {cli_scan_type}
    cfg_types = (config or {}).get('scan_types') or []
    valid = {t for t in cfg_types if t in ('secrets', 'llm', 'devsecops', 'all')}
    return valid or {'secrets'}


def _run_scan(path, scan_type, no_entropy, config, extra_patterns=None):
    """Run the requested scan type(s) and return merged results.

    scan_type may be a single string ('secrets', 'llm', 'devsecops', 'all')
    or an iterable/set of those strings (as resolved by _resolve_scan_types).
    """
    import os as _os
    is_file = _os.path.isfile(path)

    types = {scan_type} if isinstance(scan_type, str) else set(scan_type)

    results = {}

    if types & {'secrets', 'all'}:
        if is_file:
            r = scan_file(path, extra_patterns=extra_patterns)
            if r:
                results[path] = r
        else:
            results = _merge_results(results, scan_directory(path, extra_patterns=extra_patterns))

        if not no_entropy and scan_file_entropy is not None:
            entropy_cfg = config.get('entropy', {}) if config else {}
            if entropy_cfg.get('enabled', False):
                thr = entropy_cfg.get('threshold', 4.5)
                mlen = entropy_cfg.get('min_length', 20)
                if is_file:
                    er = scan_file_entropy(path, threshold=thr, min_len=mlen)
                    if er:
                        results.setdefault(path, {}).update(er)
                elif scan_directory_entropy is not None:
                    results = _merge_results(
                        results, scan_directory_entropy(path, threshold=thr, min_len=mlen)
                    )

    if types & {'llm', 'all'}:
        if scan_directory_llm is None:
            print('[!] LLM scanner not available', file=sys.stderr)
        else:
            if is_file:
                r = scan_file_llm(path)
                if r:
                    results.setdefault(path, {}).update(r)
            else:
                results = _merge_results(results, scan_directory_llm(path))

    if types & {'devsecops', 'all'}:
        if scan_directory_devsecops is None:
            print('[!] DevSecOps scanner not available', file=sys.stderr)
        else:
            if is_file:
                r = scan_file_devsecops(path)
                if r:
                    results.setdefault(path, {}).update(r)
            else:
                results = _merge_results(results, scan_directory_devsecops(path))

    # AST scanner runs on Python files for secrets and all scan types
    if (types & {'secrets', 'all'}) and scan_directory_ast is not None:
        if is_file:
            r = scan_file_ast(path)
            if r:
                results.setdefault(path, {}).update(r)
        else:
            results = _merge_results(results, scan_directory_ast(path))

    # Drop findings in files matched by config exclude_paths. Applied after all
    # scanners so a single rule covers secrets, LLM, DevSecOps, AST, and entropy.
    exclude_paths = config.get('exclude_paths') if config else None
    if exclude_paths and is_path_excluded is not None:
        results = {fp: findings for fp, findings in results.items()
                   if not is_path_excluded(fp, exclude_paths)}

    # Drop finding categories (rule names) matched by config exclude_patterns.
    exclude_patterns = config.get('exclude_patterns') if config else None
    if exclude_patterns and is_pattern_excluded is not None:
        filtered = {}
        for fp, findings in results.items():
            kept = {k: v for k, v in findings.items()
                    if not is_pattern_excluded(k, exclude_patterns)}
            if kept:
                filtered[fp] = kept
        results = filtered

    return results


def main():
    """Main CLI entry point for secchecker."""
    parser = argparse.ArgumentParser(
        description='secchecker — static security scanner for AI agents, MCP tools, and LLM applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secchecker . --type llm          # Scan for LLM/AI/MCP vulnerabilities (recommended)
  secchecker . --type all          # Run all scanners: LLM + secrets + IaC
  secchecker . --type secrets      # Scan for hardcoded credentials only
  secchecker . --type devsecops    # Scan Dockerfiles, Terraform, K8s
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
        default=None,
        dest='scan_type',
        help='Scan type (default: secrets, or scan_types from .secchecker.yml)',
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
        '--pii',
        action='store_true',
        help='Include opt-in PII patterns (Email, Phone Number) in secrets scans',
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

    scan_types = _resolve_scan_types(args.scan_type, config)

    extra_patterns = {}
    custom = config.get('custom_patterns') if config else None
    if custom:
        extra_patterns.update(custom)
    if args.pii:
        extra_patterns.update(PII_PATTERNS)

    if args.verbose:
        print('[*] Scanning: {}'.format(args.path))
        print('[*] Scan type: {}'.format(','.join(sorted(scan_types))))
        print('[*] Format: {}'.format(args.format))
        if threshold:
            print('[*] Severity threshold: {}'.format(threshold))

    try:
        results = _run_scan(args.path, scan_types, args.no_entropy, config, extra_patterns=extra_patterns)
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
            report_file = to_html(results, output_file, scan_type=','.join(sorted(scan_types)))
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
