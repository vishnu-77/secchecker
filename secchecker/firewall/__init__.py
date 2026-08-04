"""secchecker LLM Firewall — runtime input/output guard for LLM applications.

Quick start::

    from secchecker.firewall import InputGuard, OutputGuard, FirewallViolation

    # Guard user input before it reaches your LLM
    guard = InputGuard(mode="active")
    try:
        result = guard.inspect(user_message)
        prompt = build_prompt(result.modified_text)   # redacted if needed
    except FirewallViolation:
        return "Request blocked by security policy."

    # Guard LLM output before your app acts on it
    out_guard = OutputGuard(mode="strict")
    result = out_guard.inspect(llm_response)
    safe_output = result.modified_text

Modes
-----
passive  — log all findings, never block or redact (default)
active   — block CRITICAL; redact HIGH
strict   — block HIGH+CRITICAL; redact MEDIUM
"""
from .models import FirewallFinding, FirewallViolation, InspectionResult
from .policy import PolicyEngine
from .input_guard import InputGuard
from .output_guard import OutputGuard

__all__ = [
    "InputGuard",
    "OutputGuard",
    "PolicyEngine",
    "FirewallFinding",
    "InspectionResult",
    "FirewallViolation",
]
