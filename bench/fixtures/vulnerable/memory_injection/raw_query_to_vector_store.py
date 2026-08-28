"""Vulnerable: raw query text inserted straight into the long-term vector store."""


def store_query(query, vector_store):
    vector_store.insert(query)
