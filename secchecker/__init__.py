"""
Secchecker - A tool for detecting hardcoded secrets in repositories.

This package provides functionality to scan code repositories for various types
of hardcoded secrets including API keys, passwords, tokens, and other sensitive data.
"""

__version__ = "0.2.0"
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
