# OWASP mapping and severity pipeline

secchecker maps findings to OWASP Top 10 (2021) and OWASP LLM Top 10 (2025) categories for developer guidance only. **This does not imply OWASP certification, endorsement, or compliance.**

## What gets mapped

- Secrets and DevSecOps findings carry OWASP Top 10 (2021) categories and CWE IDs.
- LLM, MCP, and agentic findings carry OWASP LLM Top 10 (2025) categories (e.g. LLM01:2025 Prompt Injection, LLM05:2025 Improper Output Handling).
- All mappings live in `secchecker/owasp.py` and are attached to every rule in SARIF output — compatible with the GitHub Security tab without additional configuration.

## Severity pipeline

Every finding flows through a single severity pipeline regardless of which scanner produced it:

```
Pattern definition          SEVERITY_MAP / LLM_SEVERITY_MAP / DEVSECOPS_SEVERITY_MAP
        |                           |
        +-------- get_severity() ---+
                       |
               CLI --severity-threshold     <- filter here before reporting
                       |
               Reporter (color / SARIF level / HTML badge)
```

## SARIF level mapping

| secchecker severity | SARIF level |
|---------------------|-------------|
| CRITICAL, HIGH | `error` |
| MEDIUM | `warning` |
| LOW | `note` |
