"""Data models for the secchecker LLM Firewall."""
from dataclasses import dataclass, field
from typing import List


@dataclass
class FirewallFinding:
    """A single pattern match found during firewall inspection."""
    pattern: str       # pattern name from LLM_SEVERITY_MAP
    severity: str      # CRITICAL / HIGH / MEDIUM / LOW
    matched: List[str] = field(default_factory=list)


@dataclass
class InspectionResult:
    """Result returned by InputGuard.inspect() / OutputGuard.inspect()."""
    allowed: bool
    modified_text: str                             # original or redacted text
    findings: List[FirewallFinding] = field(default_factory=list)
    blocked_reason: str = ""


class FirewallViolation(Exception):
    """Raised in active/strict mode when text must be blocked."""

    def __init__(self, findings: List[FirewallFinding]) -> None:
        self.findings = findings
        super().__init__("Firewall blocked: {} finding(s)".format(len(findings)))
