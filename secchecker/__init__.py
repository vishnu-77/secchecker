"""
secchecker — static security scanner for AI agents, MCP tools, and LLM applications.

Finds prompt injection, MCP tool poisoning, agentic vulnerabilities, and hardcoded AI credentials
before deployment. Also covers secrets and infrastructure misconfigurations.
Zero runtime dependencies. OWASP LLM Top 10 (2025) tagged output.
"""

__version__ = "0.4.1"
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

try:
    from .ast_scanner import scan_file_ast, scan_directory_ast
except ImportError:
    pass

try:
    from .owasp import get_owasp
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
