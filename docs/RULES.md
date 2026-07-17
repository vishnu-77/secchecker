# Rule catalog

Full detection coverage across all scanners. Every finding is tagged with OWASP Top 10 (2021) and OWASP LLM Top 10 (2025) classifications in SARIF output — see [OWASP_MAPPING.md](OWASP_MAPPING.md).

## Coverage at a glance

| Scanner | What it detects | Patterns |
|---------|----------------|---------|
| MCP / Agentic AI | Tool poisoning, tool-output execution, memory injection, PII to external agents | 9 |
| LLM / AI | Prompt injection, RAG leakage, eval of model output, hardcoded AI API keys | 18+ |
| Secrets | Cloud keys, private keys, database URIs, payment credentials, service tokens | 52+ |
| DevSecOps | Dockerfile, Kubernetes, Terraform, CI/CD misconfigurations | 28+ |
| Entropy | Unknown secrets with high Shannon entropy — catches what regex misses | — |
| AST | Hardcoded secrets in Python assignments, eval/exec calls, tainted input to sinks | — |

## MCP / Agentic AI

| Risk | Example | OWASP | Severity |
|---|---|---|---|
| MCP tool poisoning | Tool result injected into prompt without sanitization | LLM01:2025 | HIGH |
| Tool output executed | `eval(tool_result)` / `os.system(function_result)` | LLM05:2025 | CRITICAL |
| Hardcoded MCP server URL | External MCP server URL in source | LLM02:2025 | HIGH |
| Memory injection | User input stored to agent memory unvalidated | LLM01:2025 | HIGH |
| PII passed to agent | SSN/credit card passed to external LLM agent | LLM02:2025 | CRITICAL |
| Function call not validated | LLM tool call result used without schema check | LLM05:2025 | CRITICAL |

## LLM / AI security

18+ patterns, tagged OWASP LLM Top 10 (2025):

| Risk | What it catches | OWASP LLM | Severity |
|------|----------------|-----------|----------|
| Prompt injection | User input concatenated directly into LLM prompt strings | LLM01:2025 | HIGH |
| Jailbreak literals | Hardcoded override instructions in source | LLM01:2025 | HIGH |
| RAG data leakage | Unfiltered database queries or file reads fed into model context | LLM08:2025 | HIGH |
| Insecure output handling | Model response passed directly to eval or exec | LLM05:2025 | CRITICAL |
| AI API key exposure | OpenAI, Anthropic, HuggingFace, Pinecone keys in source | LLM02:2025 | CRITICAL |
| Sensitive data in prompt | PII or financial data concatenated into prompt strings | LLM02:2025 | CRITICAL |
| System prompt disclosure | Hardcoded system prompts revealing application logic | LLM07:2025 | LOW |

## Secrets

52+ patterns across 15 credential categories:

| Category | Examples | Severity |
|----------|----------|----------|
| Private keys | RSA, EC, DSA, PGP, SSH | CRITICAL |
| Financial | Credit cards (Luhn-validated), SSN | CRITICAL |
| Vault tokens | HashiCorp Vault | CRITICAL |
| Cloud keys | AWS, Google Cloud, Azure | HIGH |
| Database URIs | PostgreSQL, MySQL, MongoDB, Redis | HIGH |
| Service tokens | Stripe, Twilio, SendGrid, Datadog | HIGH |
| VCS tokens | GitHub, GitLab | HIGH |
| Auth tokens | JWT (structure-validated), Bearer | MEDIUM |
| Config passwords | Common password assignment patterns | MEDIUM |

Matches are validated post-regex — credit cards pass the Luhn algorithm, JWT tokens are verified for structural integrity — to reduce false positives.

## DevSecOps

28+ patterns, tagged OWASP Top 10 (2021):

| Category | Risk examples | Severity |
|----------|--------------|----------|
| Dockerfile | Unpinned base images, secrets in ENV, curl-pipe-bash, root user | HIGH |
| Kubernetes | Privileged containers, hostNetwork, allow privilege escalation | CRITICAL |
| Terraform | Open security groups (0.0.0.0/0), public S3 buckets, plaintext credentials | HIGH |
| CI/CD | Secrets echoed to logs, pull_request_target misuse, unpinned actions | HIGH |

## Entropy and AST scanners

- **Entropy** (`entropy.py`) — Shannon-entropy detection of unknown secrets that no regex covers. Enabled by default; disable with `--no-entropy` or via `.secchecker.yml`.
- **AST** (`ast_scanner.py`) — Python structural analysis: hardcoded secrets in assignments, `eval`/`exec` calls, tainted input reaching dangerous sinks.

## Adding new rules

- **New secret pattern:** add the regex to `secchecker/patterns.py`, a severity entry to `SEVERITY_MAP` in `secchecker/reporter.py`, and OWASP/CWE mappings to `secchecker/owasp.py`. Include a test in `tests/test_patterns.py`.
- **New LLM check:** add the pattern to `secchecker/llm_patterns.py` and a severity entry to `LLM_SEVERITY_MAP`. Include a test in `tests/test_llm_scanner.py`.
