"""Shared guard logic for InputGuard and OutputGuard."""
from typing import Dict, List

from secchecker.llm_patterns import LLM_SEVERITY_MAP
from secchecker.llm_scanner import _scan_content

from .models import FirewallFinding, InspectionResult
from .policy import PolicyEngine


class _BaseGuard:
    """Internal base class — do not instantiate directly; use InputGuard or OutputGuard."""

    def __init__(self, mode: str = "passive") -> None:
        self._policy = PolicyEngine(mode)

    def _build_findings(self, scan_results: Dict[str, List[str]]) -> List[FirewallFinding]:
        findings = []
        for pattern_name, matches in scan_results.items():
            sev = LLM_SEVERITY_MAP.get(pattern_name, "LOW")
            findings.append(FirewallFinding(
                pattern=pattern_name,
                severity=sev,
                matched=matches,
            ))
        return findings

    def inspect(self, text: str) -> InspectionResult:
        """Scan *text* and apply the configured policy.

        Returns InspectionResult.
        Raises FirewallViolation when the policy mandates blocking.
        """
        raw = _scan_content(text)
        findings = self._build_findings(raw)
        return self._policy.apply(text, findings)
