# secchecker public launch

secchecker is a dependency-free static security scanner for AI agents, MCP servers, and LLM applications. It detects risky tool-output handling, memory injection patterns, prompt construction issues, exposed credentials, and deployment misconfigurations before release.

## Launch thesis

MCP and agent applications introduce new trust boundaries between prompts, tools, memory, model output, and infrastructure. secchecker provides a fast, local first pass over those boundaries and produces CI-friendly findings without sending source code to an external service.

## Primary demonstration

Show three intentionally vulnerable examples and the corresponding findings:

1. Unvalidated MCP tool output reaching `eval`, `exec`, or a shell sink.
2. Untrusted user content written directly into persistent agent memory.
3. Sensitive data or credentials included in model or tool context.

Record a terminal demonstration using:

```bash
pip install secchecker
secchecker examples/vulnerable-agent --type llm --format sarif --output secchecker.sarif
```

The demonstration should show the vulnerable line, rule identifier, severity, OWASP mapping, remediation guidance, and generated SARIF output.

## Public evidence required

Before broad promotion, verify that all public distribution paths expose the same release and capabilities:

- PyPI package version matches `pyproject.toml`.
- Git tag and GitHub Release exist for the same version.
- GitHub Action examples use an existing immutable release tag.
- Installation from PyPI reproduces the documented MCP and agent findings.
- Changelog, README, package metadata, and release notes use the same positioning.

## Benchmark asset

Create `secchecker-bench` with:

- vulnerable and safe MCP examples;
- expected rule IDs and severities;
- machine-readable expected results;
- precision and recall reporting;
- false-positive regression fixtures;
- one reproducible command;
- clearly documented limitations.

Do not claim exclusivity against other scanners without a reproducible comparison. Lead with the verified product properties: local, dependency-free, CI-ready, SARIF-compatible, and focused on agent and MCP code paths.

## Distribution sequence

1. Publish a synchronised release.
2. Publish the benchmark and demo recording.
3. Write a technical article explaining one real agent trust-boundary failure.
4. Share the release with MCP framework communities and AI security groups.
5. Ask users to submit missed patterns and false positives, not merely to star the repository.

## Success metrics

Track external repositories scanned, repeat users, package installs, externally reported detection gaps, accepted contributor PRs, and third-party references. Stars are a secondary signal.
