"""Safe counterpart to vulnerable/rag_leakage/raw_file_read.py:
context comes from a verified document store lookup, not an unfiltered
raw file read."""


def load_context():
    docs = document_store.fetch_verified(source_id="kb-042")
    return docs
