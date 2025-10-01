from secchecker import patterns

def test_patterns_exist():
    assert isinstance(patterns.PATTERNS, dict)
    assert "Postgres URI" in patterns.PATTERNS
