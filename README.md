[![PyPI version](https://img.shields.io/pypi/v/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Python versions](https://img.shields.io/pypi/pyversions/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Downloads](https://img.shields.io/pypi/dm/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Build Status](https://github.com/vishnu-77/secchecker/actions/workflows/ci.yml/badge.svg)](https://github.com/vishnu-77/secchecker/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![codecov](https://codecov.io/gh/vishnu-77/secchecker/branch/main/graph/badge.svg)](https://codecov.io/gh/vishnu-77/secchecker)

# secchecker

**Static security checks for AI agents, MCP tools, and LLM applications.**

secchecker catches unsafe **context-to-action flows** before they ship: prompt injection sinks, MCP tool poisoning, unsafe agent memory writes, LLM output execution, exposed AI credentials, and deployment risks. Zero external dependencies — runs anywhere Python runs.

## Why this exists

AI-agent systems fail when untrusted context becomes trusted action:

```python
prompt += tool_result
eval(tool_result)
agent_memory.add(user_input)
subprocess.run(llm_output, shell=True)
```

secchecker scans for these patterns locally and in CI.

## What it checks

**Action boundaries**
- LLM or tool output passed to `eval`, `exec`, shell, or SQL
- Agent loops without clear exit conditions
- Function/tool call results used without validation

**Tool boundaries**
- MCP tool results injected into prompts unsanitized
- Hardcoded external MCP server URLs
- Untrusted tool descriptions loaded into prompts

**Memory and context boundaries**
- User input written directly to agent memory
- PII passed to external agents or LLMs
- Retrieved or external content treated as trusted context (RAG leakage)

**Supporting checks**
- AI provider credentials (OpenAI, Anthropic, HuggingFace, Pinecone) and 52+ hardcoded secret patterns
- Docker, Kubernetes, Terraform, and CI/CD misconfigurations
- Shannon-entropy detection for secrets no regex covers

Full rule catalog: [docs/RULES.md](docs/RULES.md)

## Quickstart

```bash
pip install secchecker

# Scan AI agent / LLM / MCP code
secchecker . --type llm

# Run all checks (AI, secrets, infra)
secchecker . --type all

# Generate SARIF for the GitHub Security tab
secchecker . --type all --format sarif --output secchecker.sarif
```

Requires Python 3.8+. No external dependencies. All flags: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)

## Example findings

```text
CRITICAL  MCP - Tool Call Output Executed Directly
CRITICAL  Agentic - PII Passed to External Agent
HIGH      MCP - Unvalidated Tool Result in Prompt
HIGH      Agentic - Unsanitized Input to Agent Memory
```

## Output formats

`json` · `markdown` · `sarif` · `html` · `xml`

SARIF output includes OWASP Top 10 (2021) and OWASP LLM Top 10 (2025) tags plus CWE IDs on every rule, ready for the GitHub Security tab. Details: [docs/REPORTING.md](docs/REPORTING.md)

## OWASP mapping

Findings are mapped to OWASP LLM Top 10 categories for developer guidance. This does not imply OWASP certification, endorsement, or compliance. Details: [docs/OWASP_MAPPING.md](docs/OWASP_MAPPING.md)

## How it differs

secchecker is not trying to replace Gitleaks, TruffleHog, Semgrep, or Checkov.

It focuses on AI-agent security boundaries: the places where prompts, tool outputs, memory, RAG context, and model responses become actions. Secrets and infrastructure checks are included so one pass covers the AI app, the source code, and the deployment configs around it.

## CI usage

```yaml
name: secchecker

on:
  pull_request:
  push:
    branches: [main]

jobs:
  secchecker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vishnu-77/secchecker@v0.4.1
        with:
          type: all
          format: sarif
```

SARIF results are uploaded to the GitHub Security tab automatically. Full Action inputs and pre-commit hooks: [docs/CI.md](docs/CI.md)

## Configuration

Drop a `.secchecker.yml` in your project root to set severity thresholds, exclude paths, and add custom patterns. Details: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)

## Docs

- Rule catalog: [docs/RULES.md](docs/RULES.md)
- OWASP mapping: [docs/OWASP_MAPPING.md](docs/OWASP_MAPPING.md)
- CI and pre-commit: [docs/CI.md](docs/CI.md)
- Output formats: [docs/REPORTING.md](docs/REPORTING.md)
- CLI flags and config file: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
- Architecture and library API: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Roadmap: [docs/ROADMAP.md](docs/ROADMAP.md)

## Contributing

```bash
git clone https://github.com/vishnu-77/secchecker.git
cd secchecker
pip install -e ".[dev]"
pytest tests/ -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and the rule-authoring guide in [docs/RULES.md](docs/RULES.md).

## Responsible use

secchecker is intended for security auditing of repositories you own or have explicit written permission to test. It is not a substitute for a full penetration test or security audit. Found a vulnerability in secchecker itself? See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
