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
    # PII (opt-in --pii)  ->  A01:2021 Broken Access Control              #
    # ------------------------------------------------------------------ #
    "Email":                    {"owasp": ["A01:2021"], "cwe": ["CWE-200"], "owasp_llm": []},
    "Phone Number":             {"owasp": ["A01:2021"], "cwe": ["CWE-200"], "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # Entropy-based detection                                             #
    # ------------------------------------------------------------------ #
    "High Entropy String":      {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # AST scanner (structural analysis of Python source)                  #
    # ------------------------------------------------------------------ #
    "AST - Hardcoded Secret Assignment":     {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "AST - eval/exec Call":                  {"owasp": ["A03:2021"], "cwe": ["CWE-95"],  "owasp_llm": []},
    "AST - Tainted Input to Dangerous Sink": {"owasp": ["A03:2021"], "cwe": ["CWE-94"],  "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # DevSecOps — Dockerfile                                               #
    # (keys match secchecker.devsecops_patterns.DEVSECOPS_PATTERNS exactly;
    #  previously stale names here left every DevSecOps SARIF rule untagged)
    # ------------------------------------------------------------------ #
    "Dockerfile - FROM latest tag":       {"owasp": ["A06:2021"], "cwe": ["CWE-1104"], "owasp_llm": []},
    "Dockerfile - FROM without tag":      {"owasp": ["A06:2021"], "cwe": ["CWE-1104"], "owasp_llm": []},
    "Dockerfile - Explicit root USER":    {"owasp": ["A05:2021"], "cwe": ["CWE-250"],  "owasp_llm": []},
    "Dockerfile - ADD with remote URL":   {"owasp": ["A08:2021"], "cwe": ["CWE-829"],  "owasp_llm": []},
    "Dockerfile - Secret in ENV":         {"owasp": ["A02:2021"], "cwe": ["CWE-798"],  "owasp_llm": []},
    "Dockerfile - RUN with privileged flag": {"owasp": ["A05:2021"], "cwe": ["CWE-250"], "owasp_llm": []},
    "Dockerfile - COPY entire context":   {"owasp": ["A05:2021"], "cwe": ["CWE-552"],  "owasp_llm": []},
    "Dockerfile - curl pipe to shell":    {"owasp": ["A08:2021"], "cwe": ["CWE-829"],  "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # DevSecOps — Kubernetes                                               #
    # ------------------------------------------------------------------ #
    "K8s - Privileged container":         {"owasp": ["A05:2021"], "cwe": ["CWE-250"],  "owasp_llm": []},
    "K8s - allowPrivilegeEscalation":     {"owasp": ["A05:2021"], "cwe": ["CWE-250"],  "owasp_llm": []},
    "K8s - runAsUser root":               {"owasp": ["A05:2021"], "cwe": ["CWE-250"],  "owasp_llm": []},
    "K8s - hostNetwork enabled":          {"owasp": ["A05:2021"], "cwe": ["CWE-441"],  "owasp_llm": []},
    "K8s - hostPID enabled":              {"owasp": ["A05:2021"], "cwe": ["CWE-441"],  "owasp_llm": []},
    "K8s - automountServiceAccountToken": {"owasp": ["A05:2021"], "cwe": ["CWE-269"],  "owasp_llm": []},
    "K8s - Plaintext secret in stringData": {"owasp": ["A02:2021"], "cwe": ["CWE-312"], "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # DevSecOps — Terraform                                                #
    # ------------------------------------------------------------------ #
    "Terraform - Hardcoded AWS access key": {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Terraform - Hardcoded AWS secret key": {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},
    "Terraform - S3 bucket public ACL":     {"owasp": ["A01:2021"], "cwe": ["CWE-732"], "owasp_llm": []},
    "Terraform - Open security group ingress": {"owasp": ["A01:2021"], "cwe": ["CWE-732"], "owasp_llm": []},
    "Terraform - RDS publicly accessible":  {"owasp": ["A01:2021"], "cwe": ["CWE-732"], "owasp_llm": []},
    "Terraform - Hardcoded DB password":    {"owasp": ["A02:2021"], "cwe": ["CWE-256"], "owasp_llm": []},

    # ------------------------------------------------------------------ #
    # DevSecOps — CI/CD                                                    #
    # ------------------------------------------------------------------ #
    "CI - Secret echoed to log":          {"owasp": ["A09:2021"], "cwe": ["CWE-532"],  "owasp_llm": []},
    "CI - pull_request_target trigger":   {"owasp": ["A01:2021"], "cwe": ["CWE-863"],  "owasp_llm": []},
    "CI - Unpinned GitHub Action":        {"owasp": ["A08:2021"], "cwe": ["CWE-829"],  "owasp_llm": []},
    "Docker Compose - Secret in environment": {"owasp": ["A02:2021"], "cwe": ["CWE-798"], "owasp_llm": []},

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

    # ------------------------------------------------------------------ #
    # MCP (Model Context Protocol)  ->  OWASP LLM Top 10 2025             #
    # ------------------------------------------------------------------ #
    "MCP - Unvalidated Tool Result in Prompt":    {"owasp": ["A03:2021"], "cwe": ["CWE-20"],  "owasp_llm": ["LLM01:2025"]},
    "MCP - Tool Call Output Executed Directly":   {"owasp": ["A03:2021"], "cwe": ["CWE-94"],  "owasp_llm": ["LLM05:2025"]},
    "MCP - Hardcoded MCP Server URL":             {"owasp": ["A05:2021"], "cwe": ["CWE-200"], "owasp_llm": ["LLM02:2025"]},
    "MCP - Untrusted Tool Description in Prompt": {"owasp": ["A03:2021"], "cwe": ["CWE-20"],  "owasp_llm": ["LLM01:2025"]},
    "MCP - Poisoned Tool Docstring":               {"owasp": ["A03:2021"], "cwe": ["CWE-20"],  "owasp_llm": ["LLM01:2025"]},
    "MCP - Poisoned Tool Description":             {"owasp": ["A03:2021"], "cwe": ["CWE-20"],  "owasp_llm": ["LLM01:2025"]},

    # ------------------------------------------------------------------ #
    # Agentic AI  ->  OWASP LLM Top 10 2025                               #
    # ------------------------------------------------------------------ #
    "Agentic - Unsanitized Input to Agent Memory":  {"owasp": ["A03:2021"], "cwe": ["CWE-20"],  "owasp_llm": ["LLM01:2025"]},
    "Agentic - Agent Loop Without Exit Condition":  {"owasp": ["A04:2021"], "cwe": ["CWE-400"], "owasp_llm": ["LLM06:2025"]},
    "Agentic - Function Call Result Not Validated": {"owasp": ["A03:2021"], "cwe": ["CWE-20"],  "owasp_llm": ["LLM05:2025"]},
    "Agentic - Recursive Self-Invocation Risk":     {"owasp": ["A04:2021"], "cwe": ["CWE-674"], "owasp_llm": ["LLM06:2025"]},
    "Agentic - PII Passed to External Agent":       {"owasp": ["A01:2021"], "cwe": ["CWE-200"], "owasp_llm": ["LLM02:2025"]},
}


def get_owasp(pattern_name):
    # type: (str) -> Dict[str, List[str]]
    """Return OWASP/CWE classification for a pattern, or empty lists if unknown."""
    return OWASP_MAP.get(pattern_name, {"owasp": [], "cwe": [], "owasp_llm": []})
