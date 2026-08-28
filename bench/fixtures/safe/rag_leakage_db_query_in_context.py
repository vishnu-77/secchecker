"""Safe counterpart to vulnerable/rag_leakage/db_query_in_context.py:
retrieval goes through a vetted function against an explicit allowlist
instead of a raw query result landing directly in the context variable."""


def get_context(query):
    docs = retrieve_documents(query, allowlist=APPROVED_SOURCES)
    return sanitize(docs)
