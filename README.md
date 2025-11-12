[![PyPI version](https://img.shields.io/pypi/v/secchecker.svg)](https://pypi.org/project/secchecker/)  
[![Python versions](https://img.shields.io/pypi/pyversions/secchecker.svg)](https://pypi.org/project/secchecker/)  
[![Build Status](https://github.com/vishnu-77/secchecker/actions/workflows/ci.yml/badge.svg)](https://github.com/vishnu-77/secchecker/actions)  
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)  

# secchecker  

`secchecker` is a comprehensive Python package + CLI tool designed to detect hardcoded secrets, sensitive information, and security vulnerabilities in code repositories. It helps developers maintain security best practices and keep their projects audit-ready.

## Features  

### Comprehensive Secret Detection
- **40+ Secret Patterns** covering major security categories:
  - **Database Connections**: PostgreSQL, MySQL, MongoDB, Redis
  - **Cloud Provider Keys**: AWS, Google Cloud, Azure
  - **Authentication Tokens**: JWT, Bearer tokens, Basic Auth
  - **Private Keys**: RSA, EC, DSA, PGP, SSH keys
  - **Version Control**: GitHub, GitLab tokens
  - **Communication**: Slack, Discord, Telegram bot tokens
  - **Cryptocurrency**: Bitcoin, Ethereum private keys
  - **Sensitive Data**: Credit cards, Social Security numbers
  - **URLs with Credentials**: HTTP/FTP with embedded auth

### Advanced Reporting
- **Multiple Output Formats**: JSON, Markdown, XML
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW levels
- **Rich Metadata**: Timestamps, statistics, tool version info
- **Professional Formatting**: Emojis, structured layout, detailed breakdowns

### Performance & Accuracy  
- **Smart File Filtering**: Automatically skips binary files and build directories
- **False Positive Detection**: Filters common test/example patterns
- **Multiple Encoding Support**: Handles international text files
- **Memory Efficient**: Optimized for large repositories

### Developer-Friendly CLI
- **Verbose Mode**: Detailed scanning information
- **Custom Output**: Specify output file paths
- **Environment Configuration**: Set default formats via environment variables
- **Comprehensive Help**: Detailed usage examples and options

## Installation  

### From PyPI (Recommended)
```bash
pip install secchecker
```

### From Source
```bash
git clone https://github.com/vishnu-77/secchecker.git
cd secchecker
pip install -e .
```

## Usage

### Basic Scanning
```bash
# Scan current directory with markdown report
secchecker .

# Scan specific path
secchecker /path/to/project

# Generate JSON report
secchecker . --format json

# Generate XML report with custom output
secchecker . --format xml --output security_audit.xml

# Verbose mode for detailed information
secchecker . --format md --verbose
```

### Environment Configuration
```bash
# Set default report format
export SECHECKER_REPORT_FORMAT=json
secchecker .  # Will use JSON format by default
```

### Command Line Options
```bash
secchecker --help
```

Options:
- `--format {json,md,xml}`: Report format (default: md)
- `--output`, `-o`: Custom output file path
- `--verbose`, `-v`: Enable verbose output
- `--help`, `-h`: Show help message

## Example Output

> **Note**: Check the [`sample-reports/`](sample-reports/) folder for complete example outputs in all formats.

### Markdown Report
```markdown
# Secret Scan Report

**Generated:** 2025-11-12T18:05:17.494792  
**Tool:** secchecker v0.2.0  

## Summary
- **Files Scanned:** 25
- **Secret Types Found:** 12
- **Total Matches:** 18

### Severity Breakdown
- **CRITICAL:** 3
- **HIGH:** 8
- **MEDIUM:** 5
- **LOW:** 2

## Detailed Findings
### `config/database.py`
- **RSA Private Key** (CRITICAL): 1 match(es)
- **AWS Access Key** (HIGH): 1 match(es)
```

### JSON Report Structure
```json
{
  "metadata": {
    "timestamp": "2025-11-12T18:05:17.494792",
    "version": "0.2.0",
    "tool": "secchecker"
  },
  "summary": {
    "total_files": 25,
    "total_secrets": 12,
    "total_matches": 18,
    "severity_counts": {"CRITICAL": 3, "HIGH": 8, "MEDIUM": 5, "LOW": 2}
  },
  "findings": {
    "config/database.py": {
      "AWS Access Key": {
        "matches": ["AKIAIOSFODNN7EXAMPLE"],
        "severity": "HIGH",
        "count": 1
      }
    }
  }
}
```

## API Usage

### Basic Scanning
```python
from secchecker import scan_directory, scan_file
from secchecker.reporter import generate_report

# Scan a directory
results = scan_directory("/path/to/project")

# Scan a single file
findings = scan_file("/path/to/file.py")

# Generate reports
json_report = generate_report(results, "json")
markdown_report = generate_report(results, "md")
xml_report = generate_report(results, "xml")
```

### Advanced Usage
```python
from secchecker.core import get_scan_stats
from secchecker.reporter import get_severity

# Get scan statistics
stats = get_scan_stats(results)
print(f"Found {stats['total_files']} files with secrets")

# Check severity of specific patterns
severity = get_severity("AWS Access Key")  # Returns "HIGH"
```

## Security Categories

| Category | Examples | Severity |
|----------|----------|----------|
| **Private Keys** | RSA, EC, DSA, PGP keys | CRITICAL |
| **Financial Data** | Credit cards, SSN | CRITICAL |
| **Cloud Keys** | AWS, Google, Azure secrets | HIGH |
| **Database URIs** | PostgreSQL, MySQL connections | HIGH |
| **API Tokens** | GitHub, GitLab, service tokens | HIGH |
| **Auth Tokens** | JWT, Bearer tokens | MEDIUM |
| **Config Passwords** | Application passwords | MEDIUM |
| **Contact Info** | Email addresses | LOW |

## Performance

- **Fast Scanning**: Optimized regex patterns and smart file filtering
- **Memory Efficient**: Processes large repositories without memory issues  
- **Accurate Detection**: Low false positive rate with pattern validation
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Testing

```bash
# Run the full test suite
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=secchecker --cov-report=html
```

## Integration

### CI/CD Pipeline Integration
```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    pip install secchecker
    secchecker . --format json --output security-report.json
    # Fail build if critical secrets found
```

### Pre-commit Hook
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secchecker
        name: Secret Checker
        entry: secchecker
        language: system
        args: ['.', '--format', 'md']
```

---

##  Disclaimer

`secchecker` is intended **only** for security auditing of repositories you own or have explicit permission to test.

*  Misuse of this tool to access, scan, or extract information from systems you do not own is **strictly prohibited** and may violate the law.
*  The author(s) assume **no liability** for misuse or damages caused by this software.
*  Use responsibly for legitimate security auditing purposes only.

---

##  Terms & Conditions

By using `secchecker`, you agree to the following:

1.  You will only use this tool on codebases you own or have explicit authorization to audit.
2.  You will not use this software for malicious purposes, including but not limited to unauthorized access, exploitation, or data theft.
3.  The software is provided **"as is," without warranty of any kind**, express or implied.
4.  The author(s) are not responsible for any damages, losses, or legal consequences arising from the use or misuse of this software.
5.  You accept full responsibility for ensuring that your use of this tool complies with applicable laws and regulations in your jurisdiction.

---

## Contributing

Contributions are welcome! Here's how you can help:

### 🐛 Bug Reports & Feature Requests
- Open an issue on GitHub with detailed information
- Include sample code or files that demonstrate the issue
- Specify your environment (OS, Python version, etc.)

### Development Setup
```bash
git clone https://github.com/vishnu-77/secchecker.git
cd secchecker
pip install -e ".[dev]"  # Install with development dependencies
```

### 🧪 Running Tests
```bash
pytest tests/ -v                    # Run tests
black secchecker/ tests/            # Format code
flake8 secchecker/ tests/           # Lint code
mypy secchecker/                    # Type checking
```

###  Adding New Patterns
1. Add patterns to `secchecker/patterns.py`
2. Add severity mapping in `secchecker/reporter.py`
3. Add tests in `tests/test_patterns.py`
4. Update documentation

###  Pull Request Process
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 🙏 Acknowledgments

- Inspired by security best practices from the DevSecOps community
- Thanks to all contributors and security researchers
- Built with dedication for the open-source community

## 📚 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [DevSecOps Best Practices](https://www.devsecops.org/)