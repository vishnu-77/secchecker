"""
secchecker — lightweight security auditing for DevSecOps and AI systems.

Detects secrets, LLM/AI vulnerabilities, and infrastructure misconfigurations.
"""

__version__ = "0.3.0"
__author__ = "Vishnu Prashanth"
__email__ = "vishnu7stanite@gmail.com"

from .core import scan_file, scan_directory, get_scan_stats
from .reporter import to_json, to_markdown, to_xml, generate_report
from . import patterns

try:
    from .llm_scanner import scan_file_llm, scan_directory_llm
except ImportError:
    pass

try:
    from .devsecops_scanner import scan_file_devsecops, scan_directory_devsecops
except ImportError:
    pass

try:
    from .entropy import scan_file_entropy
except ImportError:
    pass

try:
    from .sarif_reporter import to_sarif, generate_sarif_report
except ImportError:
    pass

try:
    from .html_reporter import to_html, generate_html_report
except ImportError:
    pass

__all__ = [
    'scan_file',
    'scan_directory',
    'get_scan_stats',
    'to_json',
    'to_markdown',
    'to_xml',
    'generate_report',
    'patterns',
    '__version__',
]
