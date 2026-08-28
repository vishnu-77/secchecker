"""Vulnerable: raw DB query result dropped straight into RAG context, unfiltered."""


def get_context(query, db):
    context = db.query("SELECT * FROM documents WHERE content LIKE '%{}%'".format(query))
    return context
