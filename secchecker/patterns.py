# Enhanced patterns for secret detection
PATTERNS = {
    # Database Connection Strings
    "Postgres URI": r"postgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@[^:\s]+:\d+/[a-zA-Z0-9_]+",
    "MySQL URI": r"mysql://[a-zA-Z0-9_]+:[^@\s]+@[^:\s]+:\d+/[a-zA-Z0-9_]+",
    "MongoDB URI": r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+/[a-zA-Z0-9_-]+",
    "Redis URI": r"redis://[^:\s]*:[^@\s]+@[^:\s]+:\d+/?[0-9]*",
    
    # Cloud Provider Keys
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.*(secret|key)['\"\s:=]+[A-Za-z0-9/+=]{40}",
    "AWS Session Token": r"(?i)aws.*(session|token)['\"\s:=]+[A-Za-z0-9/+=]{16,}",
    "Google API Key": r"AIza[0-9A-Za-z_-]{35}",
    "Google Cloud Service Account": r"\"type\":\s*\"service_account\"",
    "Azure Client Secret": r"(?i)azure.*(client|secret)['\"\s:=]+[0-9a-zA-Z\.\-_]{32,}",
    "Azure Storage Key": r"(?i)azure.*(storage|account).*(key|secret)['\"\s:=]+[A-Za-z0-9+/=]{88}",
    
    # Authentication Tokens
    "JWT Token": r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    "Bearer Token": r"[Bb]earer\s+[a-zA-Z0-9_\-\.=]+",
    "Basic Auth": r"[Bb]asic\s+[A-Za-z0-9+/=]+",
    
    # Private Keys
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "DSA Private Key": r"-----BEGIN DSA PRIVATE KEY-----",
    "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "SSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "Generic Private Key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    
    # API Keys and Secrets
    "Generic API Key": r"(?i)api[_-]?key['\"\s:=]+[0-9a-zA-Z\.\-_]{16,}",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth": r"gho_[a-zA-Z0-9]{36}",
    "GitLab Token": r"glpat-[a-zA-Z0-9_\-]{20}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z\-]+",
    "Discord Bot Token": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
    "Telegram Bot Token": r"\d{10}:[A-Za-z0-9_-]{35}",
    
    # Configuration Passwords
    "Password in Config": r"(?i)(password|pwd|pass|secret)['\"\s]*[:=]['\"\s]*[^\s'\"]{4,}",
    "Database Password": r"(?i)db[_-]?(password|pwd|pass)['\"\s]*[:=]['\"\s]*[^\s'\"]{4,}",
    "Admin Password": r"(?i)admin[_-]?(password|pwd|pass)['\"\s]*[:=]['\"\s]*[^\s'\"]{4,}",
    
    # Connection Strings
    "SQL Server Connection": r"(?i)server=.*password=.*",
    "Oracle Connection": r"(?i)oracle.*password=.*",
    
    # Cryptocurrency
    "Bitcoin Private Key": r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}",
    "Ethereum Private Key": r"0x[a-fA-F0-9]{64}",
    
    # Other Sensitive Data
    "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    "Social Security Number": r"\b\d{3}-\d{2}-\d{4}\b",
    "Phone Number": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    
    # URLs with embedded credentials
    "HTTP URL with Credentials": r"https?://[^:\s]+:[^@\s]+@[^\s]+",
    "FTP URL with Credentials": r"ftp://[^:\s]+:[^@\s]+@[^\s]+",
    
    # Generic Secrets
    "Generic Secret": r"(?i)(secret|token|key|password)['\"\s]*[:=]['\"\s]*[a-zA-Z0-9+/=]{16,}",
    "Hex Encoded Secret": r"(?i)(secret|token|key)['\"\s]*[:=]['\"\s]*[a-fA-F0-9]{32,}",
    
    # Docker and Kubernetes Secrets
    "Docker Config": r"\.dockercfg",
    "Kubernetes Secret": r"(?i)kind:\s*secret",
    
    # Certificate Files
    "X509 Certificate": r"-----BEGIN CERTIFICATE-----",
    "PKCS12 Certificate": r"-----BEGIN PKCS12-----"
}

# Patterns that commonly produce false positives - used for filtering
FALSE_POSITIVE_PATTERNS = {
    "example.com",
    "localhost",
    "127.0.0.1",
    "password123",
    "secretkey",
    "your_api_key",
    "your_secret_key",
    "changeme",
    "admin",
    "root",
    "test",
    "demo",
    "sample"
}

def is_likely_false_positive(match: str) -> bool:
    """Check if a match is likely a false positive."""
    match_lower = match.lower()
    # Don't flag valid JWT tokens or other legitimate tokens as false positives
    if match.startswith("eyJ") and "." in match:  # JWT token structure
        return False
    return any(fp in match_lower for fp in FALSE_POSITIVE_PATTERNS)
