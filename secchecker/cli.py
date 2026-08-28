import argparse
import os
import re
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
    from .dependency_scanner import (
        scan_directory_dependency,
        scan_file_dependency,
        find_lifecycle_hooks,
        parse_lockfile,
        LOCKFILE_PARSERS,
    )
    from .dependency_policy import verdict_for, verdict_for_tree
    from .dependency_patterns import DEPENDENCY_PATTERNS as _DEP_PATTERNS, STRUCTURAL_CATEGORIES as _DEP_STRUCTURAL
except ImportError:
    scan_directory_dependency = None
    scan_file_dependency = None
    find_lifecycle_hooks = None
    parse_lockfile = None
    LOCKFILE_PARSERS = {}
    verdict_for = None
    verdict_for_tree = None
    _DEP_PATTERNS = {}
    _DEP_STRUCTURAL = frozenset()

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
    valid = {t for t in cfg_types if t in ('secrets', 'llm', 'devsecops', 'dependency', 'all')}
    return valid or {'secrets'}


def _run_scan(path, scan_type, no_entropy, config, extra_patterns=None):
    """Run the requested scan type(s) and return merged results.

    scan_type may be a single string ('secrets', 'llm', 'devsecops',
    'dependency', 'all') or an iterable/set of those strings (as resolved by
    _resolve_scan_types).
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

    if types & {'dependency', 'all'}:
        if scan_directory_dependency is None:
            print('[!] Dependency scanner not available', file=sys.stderr)
        else:
            if is_file:
                r = scan_file_dependency(path)
                if r:
                    results.setdefault(path, {}).update(r)
            else:
                results = _merge_results(results, scan_directory_dependency(path))

    # AST scanner runs on Python files for secrets and all scan types
    if (types & {'secrets', 'all'}) and scan_directory_ast is not None:
        if is_file:
            r = scan_file_ast(path)
            if r:
                results.setdefault(path, {}).update(r)
        else:
            results = _merge_results(results, scan_directory_ast(path))

    # Drop findings in files matched by config exclude_paths. Applied after all
    # scanners so a single rule covers secrets, LLM, DevSecOps, dependency, and AST/entropy.
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


def _add_scan_args(scan_parser):
    """Register the existing flat-scan arguments onto a subparser. Shared by
    the `scan` subcommand parser so its option surface is identical to the
    pre-subcommand CLI."""
    scan_parser.add_argument('path', help='Path to scan (file or directory)')
    scan_parser.add_argument(
        '--type',
        choices=['secrets', 'llm', 'devsecops', 'dependency', 'all'],
        default=None,
        dest='scan_type',
        help='Scan type (default: secrets, or scan_types from .secchecker.yml)',
    )
    scan_parser.add_argument(
        '--format',
        choices=['json', 'md', 'xml', 'sarif', 'html'],
        default=os.environ.get('SECHECKER_REPORT_FORMAT', 'md'),
        help='Output format (default: md)',
    )
    scan_parser.add_argument(
        '--output', '-o',
        help='Output file path (default: secchecker_report.<format>)',
    )
    scan_parser.add_argument(
        '--severity-threshold',
        choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        default=None,
        metavar='LEVEL',
        help='Minimum severity to report (LOW/MEDIUM/HIGH/CRITICAL)',
    )
    scan_parser.add_argument(
        '--config',
        metavar='FILE',
        help='Path to .secchecker.yml config file',
    )
    scan_parser.add_argument(
        '--no-entropy',
        action='store_true',
        help='Disable entropy-based detection',
    )
    scan_parser.add_argument(
        '--pii',
        action='store_true',
        help='Include opt-in PII patterns (Email, Phone Number) in secrets scans',
    )
    scan_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output',
    )


def _cmd_scan(args):
    """The original flat-CLI scan behavior, unchanged, now reached via the
    `scan` subcommand (or its argv-shimmed shorthand - see main())."""
    config = {}
    if load_config is not None:
        try:
            config = load_config(
                config_path=args.config,
                scan_root=args.path if not os.path.isfile(args.path) else None,
            )
        except Exception:
            config = {}

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


def _find_lockfiles(project_root):
    """Return {filename: path} for every recognised lockfile present at
    project_root's top level."""
    found = {}
    for name in LOCKFILE_PARSERS:
        candidate = os.path.join(project_root, name)
        if os.path.isfile(candidate):
            found[name] = candidate
    return found


def _cmd_package_inspect(args):
    """`secchecker package inspect <name>` - resolve one package from the
    project's lockfile, run static checks against node_modules/<name> if
    present, print its verdict. Fully offline unless --check-registry."""
    if scan_directory_dependency is None:
        print('[!] Dependency scanner not available', file=sys.stderr)
        sys.exit(2)

    project_root = args.path
    lockfiles = _find_lockfiles(project_root)
    resolved = None
    resolved_from = None
    for fname, fpath in lockfiles.items():
        entries = parse_lockfile(fpath)
        for key, meta in entries.items():
            if key.rsplit('@', 1)[0] == args.name:
                resolved = meta
                resolved_from = fname
                break
        if resolved:
            break

    if resolved:
        print('[*] {} resolved via {}: version {}'.format(
            args.name, resolved_from, resolved.get('version')))
    else:
        print('[*] {} not found in any lockfile at {} (checked: {})'.format(
            args.name, project_root, ', '.join(lockfiles) or 'none present'))

    if args.check_registry:
        print('[!] --check-registry is not implemented in this phase (see THREAT_MODEL.md) - '
              'no network call was made.', file=sys.stderr)

    pkg_dir = os.path.join(project_root, 'node_modules', args.name)
    if not os.path.isdir(pkg_dir):
        print('[*] {} not present in node_modules/ - static content/hook checks skipped '
              '(nothing installed to inspect yet).'.format(args.name))
        sys.exit(0)

    # Reuse the real dependency scanner (same content/hook/suspicious-binary
    # checks as `--type dependency`) instead of re-walking by hand, so this
    # command can't drift out of parity with it.
    findings = scan_directory_dependency(pkg_dir)

    if not findings:
        print('[+] No findings for {}. Verdict: ALLOW'.format(args.name))
        sys.exit(0)

    for fpath, f in findings.items():
        print('  {}'.format(fpath))
        for name, matches in f.items():
            print('    - {} ({})'.format(name, len(matches)))

    thresholds = None
    verdict = verdict_for_tree(findings, thresholds)
    print('[+] Verdict: {}'.format(verdict))
    sys.exit(0 if verdict in ('ALLOW', 'WARN') else 1)


def _cmd_scripts_review(args):
    """`secchecker scripts review [path]` - list every preinstall/install/
    postinstall/prepare hook across node_modules, with its static findings.
    Never executes anything."""
    if find_lifecycle_hooks is None:
        print('[!] Dependency scanner not available', file=sys.stderr)
        sys.exit(2)

    node_modules = os.path.join(args.path, 'node_modules')
    if not os.path.isdir(node_modules):
        print('[*] No node_modules/ found at {} - nothing to review.'.format(args.path))
        sys.exit(0)

    any_hooks = False
    for entry in sorted(os.listdir(node_modules)):
        pkg_dir = os.path.join(node_modules, entry)
        if not os.path.isdir(pkg_dir):
            continue
        hooks = find_lifecycle_hooks(pkg_dir)
        if not hooks:
            continue
        any_hooks = True
        print('{}:'.format(entry))
        for hook_name, cmd in hooks.items():
            print('  {}: {}'.format(hook_name, cmd))
            # Static-scan the hook command text itself for obvious red flags.
            for pname, pregex in _DEP_PATTERNS.items():
                if pname in _DEP_STRUCTURAL:
                    continue
                try:
                    if re.search(pregex, cmd):
                        print('      ! {}'.format(pname))
                except re.error:
                    continue

    if not any_hooks:
        print('[+] No lifecycle hooks found under node_modules/.')
    sys.exit(0)


def _cmd_verify(args):
    """`secchecker verify [path]` - lockfile-drift check only (fully
    offline): compares the working-tree lockfile against its last committed
    git version and reports any integrity-hash changes under an unchanged
    version. Does NOT monitor installed files/network/processes at runtime -
    see THREAT_MODEL.md for why that's out of scope this phase."""
    if parse_lockfile is None:
        print('[!] Dependency scanner not available', file=sys.stderr)
        sys.exit(2)

    lockfiles = _find_lockfiles(args.path)
    if not lockfiles:
        print('[*] No lockfile found at {}.'.format(args.path))
        sys.exit(0)

    import subprocess
    from .dependency_scanner import diff_lockfiles
    any_drift = False
    for fname, fpath in lockfiles.items():
        current = parse_lockfile(fpath)
        try:
            git_show = subprocess.run(
                ['git', 'show', 'HEAD:{}'.format(os.path.relpath(fpath, args.path).replace(os.sep, '/'))],
                cwd=args.path, capture_output=True, text=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            git_show = None

        if git_show is None or git_show.returncode != 0:
            print('[*] {}: not in git history (or not a git repo) - nothing to diff against.'.format(fname))
            continue

        import tempfile
        # parse_lockfile() dispatches on exact basename (e.g. 'package-lock.json'),
        # so the temp copy must keep that name -- a random-prefixed filename would
        # never match and silently parse as {} (no drift, always).
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = os.path.join(tmp_dir, fname)
            with open(tmp_path, 'w', encoding='utf-8') as tf:
                tf.write(git_show.stdout)
            previous = parse_lockfile(tmp_path)

        drift = diff_lockfiles(previous, current)
        if drift:
            any_drift = True
            print('[!] {}: {} integrity change(s) vs HEAD:'.format(fname, len(drift)))
            for line in drift:
                print('    - {}'.format(line))
        else:
            print('[+] {}: no drift vs HEAD.'.format(fname))

    sys.exit(1 if any_drift else 0)


def main():
    """Main CLI entry point for secchecker."""
    parser = argparse.ArgumentParser(
        prog='secchecker',
        description='secchecker - static security scanner for AI agents, MCP tools, and LLM applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secchecker . --type llm                    # Scan for LLM/AI/MCP vulnerabilities (recommended)
  secchecker . --type all                     # Run all scanners: LLM + secrets + IaC + dependency
  secchecker . --type secrets                 # Scan for hardcoded credentials only
  secchecker . --type devsecops               # Scan Dockerfiles, Terraform, K8s
  secchecker . --type dependency              # Scan node_modules for supply-chain risk
  secchecker package inspect left-pad         # Inspect one resolved dependency
  secchecker scripts review                   # List every install-time lifecycle hook, unexecuted
  secchecker verify                           # Check lockfile integrity drift vs git HEAD
  secchecker . --format sarif --output report.sarif
  secchecker . --severity-threshold HIGH      # Only report HIGH and CRITICAL

Exit codes:
  0  No findings at or above the severity threshold
  1  One or more findings detected
  2  Runtime error
        """,
    )
    subparsers = parser.add_subparsers(dest='command')

    scan_parser = subparsers.add_parser('scan', help='Scan a path for security findings (default command)')
    _add_scan_args(scan_parser)

    package_parser = subparsers.add_parser('package', help='Dependency package operations')
    package_sub = package_parser.add_subparsers(dest='package_command')
    inspect_parser = package_sub.add_parser('inspect', help='Inspect one resolved package, static-only')
    inspect_parser.add_argument('name', help='Package name to inspect')
    inspect_parser.add_argument('--path', default='.', help='Project root (default: current directory)')
    inspect_parser.add_argument('--check-registry', action='store_true',
                                 help='Also check package age/provenance via the npm registry '
                                      '(makes a network call - off by default, see THREAT_MODEL.md)')

    scripts_parser = subparsers.add_parser('scripts', help='Lifecycle-script operations')
    scripts_sub = scripts_parser.add_subparsers(dest='scripts_command')
    review_parser = scripts_sub.add_parser('review', help='List every install-time hook, without running any')
    review_parser.add_argument('path', nargs='?', default='.', help='Project root (default: current directory)')

    verify_parser = subparsers.add_parser('verify', help='Check lockfile integrity drift vs git HEAD (offline)')
    verify_parser.add_argument('path', nargs='?', default='.', help='Project root (default: current directory)')

    # Preserve `secchecker <path> --type ...` as shorthand for
    # `secchecker scan <path> --type ...` - inject the implicit subcommand
    # before parsing whenever the first token isn't a known subcommand name.
    # A real file/directory takes priority over the subcommand names even
    # when it happens to be spelled 'scan'/'package'/'scripts'/'verify'
    # (e.g. a `scripts/` folder), so those common names still scan correctly.
    known_commands = {'scan', 'package', 'scripts', 'verify'}
    argv = sys.argv[1:]
    if not argv or (argv[0] not in ('-h', '--help') and
                     (argv[0] not in known_commands or os.path.exists(argv[0]))):
        argv = ['scan'] + argv

    args = parser.parse_args(argv)

    if args.command == 'scan':
        _cmd_scan(args)
    elif args.command == 'package':
        if getattr(args, 'package_command', None) == 'inspect':
            _cmd_package_inspect(args)
        else:
            package_parser.print_help()
            sys.exit(2)
    elif args.command == 'scripts':
        if getattr(args, 'scripts_command', None) == 'review':
            _cmd_scripts_review(args)
        else:
            scripts_parser.print_help()
            sys.exit(2)
    elif args.command == 'verify':
        _cmd_verify(args)
    else:
        parser.print_help()
        sys.exit(2)


if __name__ == '__main__':
    main()
