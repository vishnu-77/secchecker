"""Contract: every finding category any scanner can emit must have an
explicit severity — get_severity() must never fall back to the LOW default
for a category we ship. That silent fallback caused audit bug G-2, where
--severity-threshold HIGH dropped real eval/exec and hardcoded-secret
findings and reported a dirty repo as clean.
"""
from secchecker.patterns import PATTERNS, PII_PATTERNS
from secchecker.llm_patterns import (
    LLM_PATTERNS, LLM_SEVERITY_MAP, CAT_POISONED_DOCSTRING, CAT_POISONED_DESCRIPTION,
)
from secchecker.devsecops_patterns import DEVSECOPS_PATTERNS, DEVSECOPS_SEVERITY_MAP
from secchecker.ast_scanner import AST_SEVERITY_MAP
from secchecker.reporter import SEVERITY_MAP, get_severity


def test_every_shipped_category_has_explicit_severity():
    emitted = (
        set(PATTERNS)
        | set(PII_PATTERNS)
        | set(LLM_PATTERNS)
        | set(DEVSECOPS_PATTERNS)
        | set(AST_SEVERITY_MAP)
        | {"High Entropy String", CAT_POISONED_DOCSTRING, CAT_POISONED_DESCRIPTION}
    )
    mapped = (
        set(SEVERITY_MAP)
        | set(LLM_SEVERITY_MAP)
        | set(DEVSECOPS_SEVERITY_MAP)
        | set(AST_SEVERITY_MAP)
    )
    missing = sorted(emitted - mapped)
    assert not missing, "Categories with no explicit severity (default LOW): {}".format(missing)


def test_severity_values_are_valid():
    all_names = (
        set(SEVERITY_MAP)
        | set(LLM_SEVERITY_MAP)
        | set(DEVSECOPS_SEVERITY_MAP)
        | set(AST_SEVERITY_MAP)
    )
    for name in all_names:
        assert get_severity(name) in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
