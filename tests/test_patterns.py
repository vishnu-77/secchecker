import pytest
from secchecker import patterns
from secchecker.patterns import is_likely_false_positive

def test_patterns_exist():
    """Test that patterns dictionary exists and has expected patterns."""
    assert isinstance(patterns.PATTERNS, dict)
    assert "Postgres URI" in patterns.PATTERNS
    assert "AWS Access Key" in patterns.PATTERNS
    assert "JWT Token" in patterns.PATTERNS

def test_pattern_count():
    """Test that we have a comprehensive set of patterns."""
    # We should have significantly more patterns than the original 10
    assert len(patterns.PATTERNS) > 25

def test_aws_patterns():
    """Test AWS-related patterns."""
    aws_patterns = [k for k in patterns.PATTERNS.keys() if "AWS" in k]
    assert len(aws_patterns) >= 3  # AWS Access Key, Secret Key, Session Token

def test_private_key_patterns():
    """Test private key patterns."""
    key_patterns = [k for k in patterns.PATTERNS.keys() if "Private Key" in k]
    assert len(key_patterns) >= 5  # RSA, EC, DSA, PGP, SSH, Generic

def test_database_patterns():
    """Test database connection patterns."""
    db_patterns = [k for k in patterns.PATTERNS.keys() if any(db in k for db in ["Postgres", "MySQL", "MongoDB", "Redis"])]
    assert len(db_patterns) >= 4

def test_api_token_patterns():
    """Test API token and service-specific patterns."""
    token_patterns = [k for k in patterns.PATTERNS.keys() if any(service in k for service in ["GitHub", "GitLab", "Slack", "Discord"])]
    assert len(token_patterns) >= 4

def test_severity_patterns():
    """Test that critical patterns are identified."""
    from secchecker.reporter import SEVERITY_MAP, get_severity
    
    # Test critical patterns
    assert get_severity("RSA Private Key") == "CRITICAL"
    assert get_severity("Credit Card") == "CRITICAL"
    
    # Test high severity patterns
    assert get_severity("AWS Access Key") == "HIGH"
    assert get_severity("GitHub Token") == "HIGH"
    
    # Test medium severity patterns
    assert get_severity("JWT Token") == "MEDIUM"
    assert get_severity("Password in Config") == "MEDIUM"

def test_false_positive_detection():
    """Test false positive detection."""
    # These should be detected as false positives
    assert is_likely_false_positive("password123")
    assert is_likely_false_positive("your_api_key_here")
    assert is_likely_false_positive("example.com")
    assert is_likely_false_positive("localhost:3306")
    
    # These should not be false positives
    assert not is_likely_false_positive("AKIAIOSFODNN7EXAMPLE")
    assert not is_likely_false_positive("eyJhbGciOiJIUzI1NiJ9.test.signature")
    assert not is_likely_false_positive("prod_database_password")

def test_pattern_categories():
    """Test that patterns cover all major categories."""
    pattern_names = list(patterns.PATTERNS.keys())
    
    # Database connections
    assert any("Postgres" in name for name in pattern_names)
    assert any("MySQL" in name for name in pattern_names)
    assert any("MongoDB" in name for name in pattern_names)
    
    # Cloud providers
    assert any("AWS" in name for name in pattern_names)
    assert any("Google" in name for name in pattern_names)
    assert any("Azure" in name for name in pattern_names)
    
    # Authentication
    assert any("JWT" in name for name in pattern_names)
    assert any("Bearer" in name for name in pattern_names)
    assert any("Basic" in name for name in pattern_names)
    
    # Version control
    assert any("GitHub" in name for name in pattern_names)
    assert any("GitLab" in name for name in pattern_names)
    
    # Cryptocurrency
    assert any("Bitcoin" in name for name in pattern_names)
    assert any("Ethereum" in name for name in pattern_names)
    
    # Sensitive data
    assert any("Credit Card" in name for name in pattern_names)
    assert any("Social Security" in name for name in pattern_names)
