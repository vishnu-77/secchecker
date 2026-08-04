"""Tests for the secchecker plugin base classes."""
import pytest
from secchecker.plugins import BaseCheck, Finding, Plugin


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class TestFinding:
    def test_to_dict_omits_none_fields(self):
        f = Finding(rule_id="x-001", message="test", severity="HIGH")
        d = f.to_dict()
        assert "rule_id" in d
        assert "message" in d
        assert "severity" in d
        assert "file" not in d
        assert "line" not in d

    def test_to_dict_includes_optional_when_set(self):
        f = Finding(rule_id="x-001", message="test", severity="HIGH", file="app.py", line=42)
        d = f.to_dict()
        assert d["file"] == "app.py"
        assert d["line"] == 42

    def test_finding_equality(self):
        f1 = Finding(rule_id="x-001", message="m", severity="LOW", matched_text="tok")
        f2 = Finding(rule_id="x-001", message="m", severity="LOW", matched_text="tok")
        assert f1 == f2


# ---------------------------------------------------------------------------
# BaseCheck
# ---------------------------------------------------------------------------

class TestBaseCheck:
    def test_match_raises_not_implemented(self):
        check = BaseCheck()
        with pytest.raises(NotImplementedError):
            check.match("content")

    def test_match_regex_returns_matches(self):
        check = BaseCheck()
        results = check.match_regex("api_key = 'abc123'", r"api_key\s*=\s*'([^']+)'")
        assert results == ["abc123"]

    def test_match_regex_returns_empty_on_bad_pattern(self):
        check = BaseCheck()
        results = check.match_regex("some text", r"[invalid(")
        assert results == []

    def test_match_regex_returns_empty_when_no_match(self):
        check = BaseCheck()
        results = check.match_regex("nothing here", r"password\s*=")
        assert results == []


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class TestPlugin:
    def test_load_checks_returns_empty_by_default(self):
        plugin = Plugin()
        assert plugin.load_checks() == []

    def test_custom_plugin_subclass_works_end_to_end(self):
        class TokenCheck(BaseCheck):
            id = "custom-001"
            description = "Detect internal tokens"
            severity = "HIGH"

            def match(self, content, context=None):
                results = []
                for m in self.match_regex(content, r"myco_[a-zA-Z0-9]{6,}"):
                    results.append(Finding(
                        rule_id=self.id,
                        message=self.description,
                        severity=self.severity,
                        matched_text=m,
                    ))
                return results

        class MyPlugin(Plugin):
            name = "my-plugin"
            version = "1.0.0"

            def load_checks(self):
                return [TokenCheck()]

        plugin = MyPlugin()
        checks = plugin.load_checks()
        assert len(checks) == 1

        findings = checks[0].match("token = 'myco_abc123xyz'")
        assert len(findings) == 1
        assert findings[0].rule_id == "custom-001"
        assert findings[0].severity == "HIGH"
        assert "myco_" in findings[0].matched_text
