"""Validate secchecker's SARIF output against the real, vendored SARIF 2.1.0
JSON Schema - the existing tests/test_sarif_reporter.py only asserts bespoke
properties of the hand-built dict, which would pass even if the document
were structurally invalid per spec (e.g. a wrong region shape or an invalid
`level` enum value)."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from secchecker.sarif_reporter import generate_sarif_report

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _validate(sarif_doc):
    jsonschema.validate(instance=sarif_doc, schema=SCHEMA)


def test_empty_scan_is_schema_valid():
    _validate(json.loads(generate_sarif_report({})))


def test_multi_file_multi_pattern_scan_is_schema_valid():
    results = {
        "src/config.py": {
            "AWS Access Key": ["AKIAIOSFODNN7EXAMPLE"],
            "Password in Config": ["password='test'"],
        },
        "src/main.py": {
            "LLM - Eval of LLM Output": ["eval(llm_response)"],
        },
    }
    _validate(json.loads(generate_sarif_report(results)))


def test_a_structurally_invalid_document_is_rejected_by_the_schema():
    # Sanity check that the schema itself actually catches something, so a
    # future regression to malformed SARIF wouldn't pass this file silently.
    bad = json.loads(generate_sarif_report({"f.py": {"AWS Access Key": ["x"]}}))
    bad["runs"][0]["results"][0]["level"] = "not-a-real-level"
    with pytest.raises(jsonschema.ValidationError):
        _validate(bad)
