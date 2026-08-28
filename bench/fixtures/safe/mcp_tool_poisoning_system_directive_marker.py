"""Safe counterpart to vulnerable/mcp_tool_poisoning/system_directive_marker.py:
a plain docstring with no embedded fake directive line."""


def refund_customer(order_id: str) -> str:
    """Process a refund for the given order, subject to standard approval rules."""
    return billing.refund(order_id)
