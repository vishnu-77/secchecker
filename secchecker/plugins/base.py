"""Base classes for the secchecker plugin system.

Usage::

    from secchecker.plugins import BaseCheck, Finding, Plugin

    class MyCheck(BaseCheck):
        id = "custom-001"
        description = "Detect hardcoded internal tokens"
        severity = "HIGH"

        def match(self, content, context=None):
            results = []
            for m in self.match_regex(content, r'myco_[a-zA-Z0-9]{32}'):
                results.append(Finding(
                    rule_id=self.id,
                    message=self.description,
                    severity=self.severity,
                    matched_text=m,
                ))
            return results

    class MyPlugin(Plugin):
        name = "my-org-checks"
        version = "1.0.0"
        description = "Internal security checks for my-org"

        def load_checks(self):
            return [MyCheck()]
"""
import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Finding:
    """A single security finding produced by a BaseCheck."""
    rule_id: str       # e.g. "custom-001"
    message: str       # human-readable description
    severity: str      # CRITICAL / HIGH / MEDIUM / LOW
    matched_text: str = ""
    file: Optional[str] = None
    line: Optional[int] = None

    def to_dict(self) -> dict:
        """Return a dict representation, omitting None-valued fields."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


class BaseCheck:
    """Abstract base for a single security check.

    Subclass this, set *id*, *description*, *severity*, and implement *match()*.
    """
    id: str = ""
    description: str = ""
    severity: str = "MEDIUM"

    def match(self, content: str, context: Optional[Dict] = None) -> List[Finding]:
        """Scan *content* and return a list of Finding objects.

        Must be overridden by subclasses.
        """
        raise NotImplementedError(
            "{}.match() must be implemented".format(type(self).__name__)
        )

    def match_regex(self, content: str, pattern: str) -> List[str]:
        """Return all regex matches of *pattern* in *content*.

        Returns an empty list if *pattern* is invalid rather than raising.
        """
        try:
            matches = re.findall(pattern, content)
            return [m if isinstance(m, str) else " ".join(m) for m in matches]
        except re.error:
            return []


class Plugin:
    """Container for a named set of BaseCheck instances.

    Subclass this and override *load_checks()* to return your checks.
    """
    name: str = ""
    version: str = "1.0.0"
    description: str = ""

    def load_checks(self) -> List[BaseCheck]:
        """Return the list of checks this plugin provides."""
        return []
