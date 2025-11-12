import argparse
import os
from .core import scan_directory
from .reporter import to_json, to_markdown, to_xml

def main():
    """Main CLI entry point for secchecker."""
    # Configure default report format from environment variable
    default_format = os.environ.get('SECHECKER_REPORT_FORMAT', 'md')
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Secret Checker CLI - Scan for hardcoded secrets in repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secchecker .                     # Scan current directory with markdown report
  secchecker /path/to/project      # Scan specific path
  secchecker . --format json      # Generate JSON report
  secchecker . --format xml       # Generate XML report

Environment Variables:
  SECHECKER_REPORT_FORMAT         # Default report format (json, md, xml)
        """
    )
    parser.add_argument("path", help="Path to scan for secrets")
    parser.add_argument(
        "--format",
        choices=["json", "md", "xml"],
        default=default_format,
        help="Report format (default: %(default)s)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (optional, defaults to secchecker_report.{format})"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"[*] Scanning path: {args.path}")
        print(f"[*] Output format: {args.format}")
    
    try:
        # Scan the directory for secrets
        results = scan_directory(args.path)
        
        if not results:
            print("[+] No secrets found!")
            return
        
        # Determine output file
        if args.output:
            output_file = args.output
        else:
            output_file = f"secchecker_report.{args.format}"
        
        # Generate report based on format
        if args.format == "json":
            report_file = to_json(results, output_file)
        elif args.format == "md":
            report_file = to_markdown(results, output_file)
        elif args.format == "xml":
            report_file = to_xml(results, output_file)
        
        print(f"[+] Report generated: {report_file}")
        
        if args.verbose:
            print(f"[*] Found {sum(len(findings) for findings in results.values())} secret patterns across {len(results)} files")
            
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1

if __name__ == "__main__":
    main()