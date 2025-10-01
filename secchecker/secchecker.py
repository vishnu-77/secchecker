import argparse
import os
from .core import scan_directory
from .reporter import to_json, to_markdown, to_xml

def main():
    # Step 1: Configure default report format from environment variable
    default_format = os.environ.get('SECHECKER_REPORT_FORMAT', 'md')  # If SECHECKER_REPORT_FORMAT is set, use it; else default to 'md'

    # Step 2: Parse command-line arguments
    parser = argparse.ArgumentParser(description="Secret Checker CLI")
    parser.add_argument("path", help="Path to scan")  # Required positional argument
    parser.add_argument(
        "--format",
        choices=["json", "md", "xml"],  # Added 'xml' as an option
        default=default_format,
        help="Format for the generated report (json, md, or xml)"
    )
    args = parser.parse_args()

    # Step 3: Scan the directory for secrets
    results = scan_directory(args.path)

    # Step 4: Generate report based on chosen format
    if args.format == "json":
        report = to_json(results)
    elif args.format == "md":
        report = to_markdown(results)
    elif args.format == "xml":
        # Placeholder for XML reporting (not yet implemented)
        report = to_xml(results) # Assuming this function is defined in reporter.py
    else:
        report = "Invalid format"

    # Step 5: Print where the report was generated
    print(f"[+] Report generated: {report}")

# Entry point
if __name__ == "__main__":
    main()
