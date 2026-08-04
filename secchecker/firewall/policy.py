"""PolicyEngine — applies passive / active / strict firewall policies."""
from typing import List, Optional

from .models import FirewallFinding, FirewallViolation, InspectionResult

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Per-mode thresholds: severity >= block_at → block; >= redact_at (but < block_at) → redact
_POLICY: dict = {
    "passive": {"block": None,       "redact": None},
    "active":  {"block": "CRITICAL", "redact": "HIGH"},
    "strict":  {"block": "HIGH",     "redact": "MEDIUM"},
}


class PolicyEngine:
    """Apply a named policy to a list of FirewallFindings.

    Modes
    -----
    passive  — log all findings, never block or redact
    active   — block CRITICAL; redact HIGH
    strict   — block HIGH+CRITICAL; redact MEDIUM
    """

    MODES = ("passive", "active", "strict")

    def __init__(self, mode: str = "passive") -> None:
        if mode not in self.MODES:
            raise ValueError(
                "Unknown firewall mode {!r}. Valid modes: {}".format(mode, self.MODES)
            )
        self.mode = mode
        policy = _POLICY[mode]
        self._block_min: int = (
            SEVERITY_ORDER.get(policy["block"], 99) if policy["block"] else 99
        )
        self._redact_min: int = (
            SEVERITY_ORDER.get(policy["redact"], 99) if policy["redact"] else 99
        )

    def apply(self, text: str, findings: List[FirewallFinding]) -> InspectionResult:
        """Apply policy to *text* given the pre-computed *findings*.

        Returns an InspectionResult, or raises FirewallViolation when the
        policy mandates blocking.
        """
        if not findings:
            return InspectionResult(allowed=True, modified_text=text)

        to_block = [
            f for f in findings
            if SEVERITY_ORDER.get(f.severity, 0) >= self._block_min
        ]
        to_redact = [
            f for f in findings
            if (
                SEVERITY_ORDER.get(f.severity, 0) >= self._redact_min
                and SEVERITY_ORDER.get(f.severity, 0) < self._block_min
            )
        ]

        if to_block:
            raise FirewallViolation(to_block)

        modified = text
        for f in to_redact:
            for match in f.matched:
                if match:
                    modified = modified.replace(match, "[REDACTED]")

        return InspectionResult(
            allowed=True,
            modified_text=modified,
            findings=findings,
        )
