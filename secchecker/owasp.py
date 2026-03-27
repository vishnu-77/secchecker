"""OWASP Top 10 (2021) and OWASP LLM Top 10 (2025) mappings for secchecker patterns."""
from typing import Dict, List

# Each entry maps a pattern name to its OWASP/CWE classification.
# Keys present:
#   owasp     - OWASP Top 10 2021 category IDs  (may be empty list)
#   cwe       - CWE IDs as strings               (may be empty list)
#   owasp_llm - OWASP LLM Top 10 2025 IDs        (may be empty list for non-LLM patterns)

OWASP_MAP: Dict[str, Dict[str, List[str]]] = {
    # ------------------------------------------------------------------ #
    # Secrets / credentials  ->  A02:2021 Cryptographic Failures          #
    # ------------------------------------------------------------------ #
    "AWS Access Key":           {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "AWS Secret Key":           {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "AWS Session Token":        {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Google API Key":           {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Azure Client Secret":      {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Azure Storage Key":        {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "GitHub Token":             {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "GitHub OAuth":             {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "GitLab Token":             {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Slack Token":              {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Discord Bot Token":        {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Telegram Bot Token":       {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Stripe Secret Key":        {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Stripe Test Secret Key":   {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Stripe Publishable Key":   {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Stripe Restricted Key":    {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Twilio Account SID":       {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Twilio Auth Token":        {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "SendGrid API Key":         {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Datadog API Key":          {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "New Relic License Key":    {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "HashiCorp Vault Token":    {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "npm Access Token":         {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "PyPI API Token":           {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Bitcoin Private Key":      {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Ethereum Private Key":     {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},

    # Private / cryptographic keys
    "RSA Private Key":          {"owasp": ["A02:2021"], "cwe": ["CWE-321"], "owasp_llm": []},
    "EC Private Key":           {"owasp": ["A02:2021"], "cwe": ["CWE-321"], "owasp_llm": []},
    "DSA Private Key":          {"owasp": ["A02:2021"], "cwe": ["CWE-321"], "owasp_llm": []},
    "PGP Private Key":          {"owasp": ["A02:2021"], "cwe": ["CWE-321"], "owasp_llm": []},
    "SSH Private Key":          {"owasp": ["A02:2021"], "cwe": ["CWE-321"], "owasp_llm": []},
    "Generic Private Key":      {"owasp": ["A02:2021"], "cwe": ["CWE-321"], "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # Database URIs  ->  A02:2021 + A07:2021 (auth embedded in URI)       #
    # ------------------------------------------------------------------ #
    "Postgres URI":             {"owasp": ["A02:2021", "A07:2021"], "cwe": ["CWE-798", "CWE-257"], "owasp_llm": []},
    "MySQL URI":                {"owasp": ["A02:2021", "A07:2021"], "cwe": ["CWE-798", "CWE-257"], "owasp_llm": []},
    "MongoDB URI":              {"owasp": ["A02:2021", "A07:2021"], "cwe": ["CWE-798", "CWE-257"], "owasp_llm": []},
    "Redis URI":                {"owasp": ["A02:2021", "A07:2021"], "cwe": ["CWE-798", "CWE-257"], "owasp_llm": []},
    "SQL Server Connection":    {"owasp": ["A02:2021", "A07:2021"], "cwe": ["CWE-798", "CWE-257"], "owasp_llm": []},
    "Oracle Connection":        {"owasp": ["A02:2021", "A07:2021"], "cwe": ["CWE-798", "CWE-257"], "owasp_llm": []},
    "HTTP URL with Credentials":{"owasp": ["A02:2021", "A07:2021"], "cwe": ["CWE-522"],            "owasp_llm": []},
    "FTP URL with Credentials": {"owasp": ["A02:2021", "A07:2021"], "cwe": ["CWE-522"],            "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # Auth tokens  ->  A07:2021 Identification & Authentication Failures  #
    # ------------------------------------------------------------------ #
    "JWT Token":                {"owasp": ["A07:2021"], "cwe": ["CWE-384"], "owasp_llm": []},
    "Bearer Token":             {"owasp": ["A07:2021"], "cwe": ["CWE-384"], "owasp_llm": []},
    "Basic Auth":               {"owasp": ["A07:2021"], "cwe": ["CWE-522"], "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # PII / financial  ->  A02:2021 + A01:2021 (access control)          #
    # ------------------------------------------------------------------ #
    "Credit Card":              {"owasp": ["A02:2021", "A01:2021"], "cwe": ["CWE-200", "CWE-798"], "owasp_llm": []},
    "Social Security Number":   {"owasp": ["A02:2021", "A01:2021"], "cwe": ["CWE-200", "CWE-798"], "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # Passwords in config  ->  A02:2021                                   #
    # ------------------------------------------------------------------ #
    "Password in Config":       {"owasp": ["A02:2021"], "cwe": ["CWE-256"], "owasp_llm": []},
    "Database Password":        {"owasp": ["A02:2021"], "cwe": ["CWE-256"], "owasp_llm": []},
    "Admin Password":           {"owasp": ["A02:2021"], "cwe": ["CWE-256"], "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # DevSecOps — Dockerfile                                               #
    # ------------------------------------------------------------------ #
    "Docker - Latest Tag":              {"owasp": ["A06:2021"], "cwe": ["CWE-1104"], "owasp_llm": []},
    "Docker - Secret in ENV":           {"owasp": ["A02:2021"], "cwe": ["CWE-798"],  "owasp_llm": []},
    "Docker - Curl Pipe Bash":          {"owasp": ["A08:2021"], "cwe": ["CWE-829"],  "owasp_llm": []},
    "Docker - Copy All Files":          {"owasp": ["A05:2021"], "cwe": ["CWE-552"],  "owasp_llm": []},
    "Docker - Root User":               {"owasp": ["A05:2021"], "cwe": ["CWE-250"],  "owasp_llm": []},
    "Docker - Privileged":              {"owasp": ["A05:2021"], "cwe": ["CWE-250"],  "owasp_llm": []},
    "Docker - No Healthcheck":          {"owasp": ["A05:2021"], "cwe": ["CWE-778"],  "owasp_llm": []},
    "Docker - Hardcoded Secret ARG":    {"owasp": ["A02:2021"], "cwe": ["CWE-798"],  "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # DevSecOps — Kubernetes                                               #
    # ------------------------------------------------------------------ #
    "K8s - Privileged Container":       {"owasp": ["A05:2021"], "cwe": ["CWE-250"],  "owasp_llm": []},
    "K8s - Run As Root":                {"owasp": ["A05:2021"], "cwe": ["CWE-250"],  "owasp_llm": []},
    "K8s - Host Network":               {"owasp": ["A05:2021"], "cwe": ["CWE-441"],  "owasp_llm": []},
    "K8s - Host PID":                   {"owasp": ["A05:2021"], "cwe": ["CWE-441"],  "owasp_llm": []},
    "K8s - Allow Privilege Escalation": {"owasp": ["A05:2021"], "cwe": ["CWE-250"],  "owasp_llm": []},
    "K8s - No Resource Limits":         {"owasp": ["A05:2021"], "cwe": ["CWE-400"],  "owasp_llm": []},
    "K8s - Plaintext Secret":           {"owasp": ["A02:2021"], "cwe": ["CWE-312"],  "owasp_llm": []},
    "K8s - Default Namespace":          {"owasp": ["A05:2021"], "cwe": ["CWE-16"],   "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # DevSecOps — Terraform                                                #
    # ------------------------------------------------------------------ #
    "Terraform - Open Security Group":  {"owasp": ["A01:2021"], "cwe": ["CWE-732"],  "owasp_llm": []},
    "Terraform - Public S3 Bucket":     {"owasp": ["A01:2021"], "cwe": ["CWE-732"],  "owasp_llm": []},
    "Terraform - Hardcoded Secret":     {"owasp": ["A02:2021"], "cwe": ["CWE-798"],  "owasp_llm": []},
    "Terraform - Plaintext Password":   {"owasp": ["A02:2021"], "cwe": ["CWE-256"],  "owasp_llm": []},
    "Terraform - HTTP Backend":         {"owasp": ["A02:2021"], "cwe": ["CWE-319"],  "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # DevSecOps — CI/CD                                                    #
    # ------------------------------------------------------------------ #
    "CI - Secret in Log":               {"owasp": ["A09:2021"], "cwe": ["CWE-532"],  "owasp_llm": []},
    "CI - pull_request_target":         {"owasp": ["A01:2021"], "cwe": ["CWE-863"],  "owasp_llm": []},
    "CI - Unpinned Action":             {"owasp": ["A08:2021"], "cwe": ["CWE-829"],  "owasp_llm": []},
    "CI - Hardcoded Token":             {"owasp": ["A02:2021"], "cwe": ["CWE-798"],  "owasp_llm": []},
    "CI - Curl Pipe Bash":              {"owasp": ["A08:2021"], "cwe": ["CWE-829"],  "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # LLM / AI  ->  OWASP LLM Top 10 2025                                 #
    # ------------------------------------------------------------------ #
    "LLM - Prompt Injection via f-string":    {"owasp": ["A03:2021"], "cwe": ["CWE-20"],  "owasp_llm": ["LLM01:2025"]},
    "LLM - Prompt Injection via format()":    {"owasp": ["A03:2021"], "cwe": ["CWE-20"],  "owasp_llm": ["LLM01:2025"]},
    "LLM - Hardcoded Jailbreak Instruction":  {"owasp": ["A03:2021"], "cwe": ["CWE-20"],  "owasp_llm": ["LLM01:2025"]},
    "LLM - Role Override Instruction":        {"owasp": ["A03:2021"], "cwe": ["CWE-20"],  "owasp_llm": ["LLM01:2025"]},
    "LLM - Prompt Delimiter Injection":       {"owasp": ["A03:2021"], "cwe": ["CWE-20"],  "owasp_llm": ["LLM01:2025"]},
    "LLM - RAG DB Query in Context":          {"owasp": ["A01:2021"], "cwe": ["CWE-200"], "owasp_llm": ["LLM08:2025", "LLM02:2025"]},
    "LLM - RAG Raw File in Prompt":           {"owasp": ["A01:2021"], "cwe": ["CWE-200"], "owasp_llm": ["LLM08:2025", "LLM02:2025"]},
    "LLM - Env Var in LLM Context":           {"owasp": ["A02:2021"], "cwe": ["CWE-200"], "owasp_llm": ["LLM02:2025"]},
    "LLM - Eval of LLM Output":               {"owasp": ["A03:2021"], "cwe": ["CWE-94"],  "owasp_llm": ["LLM05:2025"]},
    "LLM - LangChain Unsafe Input":           {"owasp": ["A03:2021"], "cwe": ["CWE-20"],  "owasp_llm": ["LLM01:2025"]},
    "LLM - Secret Passed to LLM":             {"owasp": ["A02:2021"], "cwe": ["CWE-200"], "owasp_llm": ["LLM02:2025"]},
    "LLM - API Key in Log Statement":         {"owasp": ["A09:2021"], "cwe": ["CWE-532"], "owasp_llm": ["LLM02:2025"]},
    "LLM - OpenAI API Key":                   {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": ["LLM02:2025"]},
    "LLM - Anthropic API Key":                {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": ["LLM02:2025"]},
    "LLM - HuggingFace Token":                {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": ["LLM02:2025"]},
    "LLM - Pinecone API Key":                 {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": ["LLM02:2025"]},
    "LLM - Weaviate API Key":                 {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": ["LLM02:2025"]},
    "LLM - System Prompt Hardcoded":          {"owasp": ["A05:2021"], "cwe": ["CWE-312"], "owasp_llm": ["LLM07:2025"]},
}


def get_owasp(pattern_name):
    # type: (str) -> Dict[str, List[str]]
    """Return OWASP/CWE classification for a pattern, or empty lists if unknown."""
    return OWASP_MAP.get(pattern_name, {"owasp": [], "cwe": [], "owasp_llm": []})
