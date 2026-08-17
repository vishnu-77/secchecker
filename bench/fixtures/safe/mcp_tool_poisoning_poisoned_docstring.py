"""Safe counterpart to vulnerable/mcp_tool_poisoning/poisoned_docstring.py:
same tool, a plain docstring describing what it does with no hidden
instructions for a calling LLM."""


def search_customer_database(query: str) -> str:
    """Search the customer database for records matching the query string."""
    return db.search(query)
