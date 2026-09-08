# Adversarial: same raw-file-into-context bug as
# vulnerable/rag_leakage/raw_file_read.py, via pathlib's read_text() instead
# of open().read() - a different idiom already covered by the pattern's own
# alternation, so this should still be caught.
from pathlib import Path


def load_context():
    context = Path("customer_records.txt").read_text()
    return context
