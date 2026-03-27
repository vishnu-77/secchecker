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

__all__ = [
    'scan_file',
    'scan_directory', 
    'get_scan_stats',
    'to_json',
    'to_markdown', 
    'to_xml',
    'generate_report',
    'patterns'
]
