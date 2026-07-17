"""Tests for secchecker.owasp OWASP/CWE mapping."""
import pytest
from secchecker.owasp import get_owasp, OWASP_MAP


def test_aws_access_key_has_owasp():
    result = get_owasp("AWS Access Key")
    assert "A02:2021" in result["owasp"]
    assert "CWE-798" in result["cwe"]
    assert result["owasp_llm"] == []


def test_credit_card_has_multiple_owasp():
    result = get_owasp("Credit Card")
    assert "A02:2021" in result["owasp"]
    assert "A01:2021" in result["owasp"]


def test_jwt_token_mapping():
    result = get_owasp("JWT Token")
    assert "A07:2021" in result["owasp"]
    assert "CWE-384" in result["cwe"]


def test_llm_prompt_injection_has_llm_tag():
    result = get_owasp("LLM - Prompt Injection via f-string")
    assert "LLM01:2025" in result["owasp_llm"]
    assert "A03:2021" in result["owasp"]


def test_llm_eval_output_critical():
    result = get_owasp("LLM - Eval of LLM Output")
    assert "LLM05:2025" in result["owasp_llm"]
    assert "CWE-94" in result["cwe"]


def test_unknown_pattern_returns_empty_lists():
    result = get_owasp("This Pattern Does Not Exist")
    assert result["owasp"] == []
    assert result["cwe"] == []
    assert result["owasp_llm"] == []


def test_all_map_entries_have_required_keys():
    for name, entry in OWASP_MAP.items():
        assert "owasp" in entry, "Missing 'owasp' key for: {}".format(name)
        assert "cwe" in entry, "Missing 'cwe' key for: {}".format(name)
        assert "owasp_llm" in entry, "Missing 'owasp_llm' key for: {}".format(name)
        assert isinstance(entry["owasp"], list), name
        assert isinstance(entry["cwe"], list), name
        assert isinstance(entry["owasp_llm"], list), name


def test_k8s_privileged_maps_to_a05():
    result = get_owasp("K8s - Privileged container")
    assert "A05:2021" in result["owasp"]


def test_ci_unpinned_action_maps_to_a08():
    result = get_owasp("CI - Unpinned GitHub Action")
    assert "A08:2021" in result["owasp"]
    assert "CWE-829" in result["cwe"]


def test_terraform_open_sg_maps_to_a01():
    result = get_owasp("Terraform - Open security group ingress")
    assert "A01:2021" in result["owasp"]
    assert "CWE-732" in result["cwe"]


def test_new_mcp_and_agentic_owasp_mappings():
    assert "LLM01:2025" in OWASP_MAP["MCP - Unvalidated Tool Result in Prompt"]["owasp_llm"]
    assert "LLM05:2025" in OWASP_MAP["MCP - Tool Call Output Executed Directly"]["owasp_llm"]
    assert "LLM02:2025" in OWASP_MAP["Agentic - PII Passed to External Agent"]["owasp_llm"]
    assert "LLM06:2025" in OWASP_MAP["Agentic - Agent Loop Without Exit Condition"]["owasp_llm"]


def test_mcp_tool_output_execution_is_code_injection():
    result = get_owasp("MCP - Tool Call Output Executed Directly")
    assert "CWE-94" in result["cwe"]
    assert "LLM05:2025" in result["owasp_llm"]


def test_all_new_llm_patterns_have_owasp_entries():
    from secchecker.llm_patterns import LLM_PATTERNS
    for name in LLM_PATTERNS:
        assert name in OWASP_MAP, "Missing OWASP mapping for: {}".format(name)


def test_all_devsecops_patterns_have_owasp_entries():
    """Regression (planning discovery): OWASP_MAP DevSecOps keys previously
    didn't match DEVSECOPS_PATTERNS names, so every DevSecOps SARIF rule
    shipped with empty OWASP/CWE tags."""
    from secchecker.devsecops_patterns import DEVSECOPS_PATTERNS
    for name in DEVSECOPS_PATTERNS:
        result = get_owasp(name)
        assert result["owasp"], "Missing OWASP mapping for: {}".format(name)
        assert result["cwe"], "Missing CWE mapping for: {}".format(name)


def test_poisoned_tool_categories_map_to_llm01():
    for name in ("MCP - Poisoned Tool Docstring", "MCP - Poisoned Tool Description"):
        result = get_owasp(name)
        assert "LLM01:2025" in result["owasp_llm"]
        assert "CWE-20" in result["cwe"]


def test_ast_categories_have_owasp_entries():
    for name in (
        "AST - Hardcoded Secret Assignment",
        "AST - eval/exec Call",
        "AST - Tainted Input to Dangerous Sink",
    ):
        result = get_owasp(name)
        assert result["owasp"]
        assert result["cwe"]


def test_pii_categories_have_owasp_entries():
    for name in ("Email", "Phone Number"):
        result = get_owasp(name)
        assert "A01:2021" in result["owasp"]
