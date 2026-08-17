"""Safe counterpart to vulnerable/memory_injection/raw_query_to_vector_store.py:
the query is validated before being written to the vector store."""


def store_query(query, vector_store):
    validated_query = validate_query(query)
    vector_store.insert(validated_query)
