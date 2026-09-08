[![PyPI version](https://img.shields.io/pypi/v/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Python versions](https://img.shields.io/pypi/pyversions/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Build Status](https://github.com/vishnu-77/secchecker/actions/workflows/ci.yml/badge.svg)](https://github.com/vishnu-77/secchecker/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

# secchecker

Static checks for risky context-to-action flows in AI applications.

Prompts, RAG results, MCP tool output, and model responses often reach a
shell, an API call, a SQL query, or agent memory with no validation in
between. secchecker finds those transitions.

**A pattern reaching a sink is not the same as a safe one.** The same
function, one line different, is the whole difference between a finding
and a clean scan:

```python
# flagged — user input concatenated straight into the system prompt
system_prompt = f"You are a helpful assistant. User query: {user_input}"

# clean — same input, routed through a structured message instead
messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": user_input},
]
```

```text
$ secchecker vulnerable.py --type llm && secchecker safe.py --type llm
LLM - Prompt Injection via f-string (HIGH): 1 match(es)
  1. `system_prompt user_input`
[+] No findings detected.
```

Same input variable. Different sink. Different verdict — real output from
`bench/fixtures/` (see [Benchmarks](#benchmarks)).

## Architecture

```text
Prompt / User / RAG / MCP
          |
        Agent
          |
      secchecker
          |
Memory / Tool / Shell / SQL / API
```

secchecker examines the transitions where untrusted context can influence
actions — not a full dataflow analyzer, a static check on the specific
lines where that transition happens unchecked.

## Quickstart

```bash
pip install secchecker
secchecker . --type llm      # scan your project for AI-agent/LLM/MCP risks
cat secchecker_report.md
```

Requires Python 3.8+, no external dependencies.

## What it checks

- **Action boundaries** — LLM or tool output passed to `eval`, `exec`, shell, or SQL
- **Tool/MCP boundaries** — MCP tool results injected into prompts unsanitized, untrusted tool descriptions loaded into prompts
- **Memory boundaries** — user input written directly to agent memory
- **Prompt injection** — jailbreak/role-override strings, delimiter injection, hardcoded overrides
- **Supporting checks** — AI provider credentials, 56 hardcoded secret patterns, Docker/Kubernetes/Terraform misconfigurations, npm/pnpm/Yarn dependency risk

Full rule catalog: [docs/RULES.md](docs/RULES.md).

## Why a generic scanner isn't enough

```text
Generic SAST (Semgrep, CodeQL):  known-bad code patterns, any language
Secret scanners (Gitleaks):       credential-shaped strings in text
IaC scanners (Checkov):           misconfigured infrastructure resources

secchecker:  where does untrusted AI-application context
             (prompt / RAG / MCP result / model output) reach an action?
```

secchecker is not trying to replace any of those. It focuses on the
boundary that's specific to AI applications — prompts, tool outputs,
memory, RAG context, and model responses becoming actions — and bundles
secrets/IaC/dependency checks alongside so one pass covers the AI-specific
surface, the source code, and the deployment configs around it.

## The rule

Every check is one named pattern with a severity and a compliance tag —
the same shape whether it's a secret, an LLM-boundary check, or an IaC
misconfiguration:

```python
"LLM - Eval of LLM Output": (
    r'(?i)(eval|exec|subprocess\.run|os\.system)\s*\(\s*(llm_?response|completion|response\.text|output\.content)'
)
```

```text
severity: CRITICAL
owasp:    A03:2021 (Injection)
owasp-llm: LLM05:2025 (Improper Output Handling)
cwe:      CWE-94
```

Rules are plain regex (compiled once at import) plus an AST walker for
Python-specific checks (hardcoded assignments, `eval`/`exec` calls,
single-hop taint tracking, poisoned tool docstrings). A shared severity map
and OWASP/CWE lookup feed every output format. Rule-authoring guide:
[docs/RULES.md](docs/RULES.md); design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## One scanner, four categories, one interface

```text
secrets      56 credential/connection-string patterns
llm          27 prompt injection / RAG leakage / MCP poisoning / agentic patterns
devsecops    25 Docker / Kubernetes / Terraform / CI misconfigurations
dependency   npm/pnpm/Yarn: obfuscation, install hooks, lockfile drift
```

All four share one function shape (`scan_file(path) -> {rule_name:
[matches]}`) and feed the same five reporters —
`secchecker . --type all` runs every category in one pass;
`--type llm` runs only the AI-boundary checks.

## Output formats

`json` · `md` · `xml` · `sarif` · `html`. SARIF carries OWASP Top 10 /
OWASP LLM Top 10 tags and CWE IDs on every rule, validated against the
official SARIF 2.1.0 JSON Schema (`tests/test_sarif_schema.py`) — ready for
the GitHub Security tab:

```bash
secchecker . --type all --format sarif --output secchecker.sarif
```

Full flags and `.secchecker.yml` config: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## CI and pre-commit

```yaml
- uses: vishnu-77/secchecker@v0.5.0
  with:
    type: all
    format: sarif
```

SARIF results upload to the GitHub Security tab automatically. Pre-commit
hooks and full Action inputs: [docs/CI.md](docs/CI.md).

## Benchmarks

Reproducible, offline, no LLM judge — `python bench/run.py`:

| Corpus | Result | What it measures |
|---|---|---|
| Regression (23 vulnerable / 23 safe pairs) | 1.00 precision / 1.00 recall | Does this release still catch every case it was built to catch? |
| Adversarial (14 paraphrased/reshaped variants) | 4/14 caught (29%) | Does it generalize past the exact phrasing it was built to catch? |
| benign_realistic (4 plausible-FP shapes) | 2/4 still flagged | Known static-analysis limitation, not a bug |

The 1.00/1.00 regression number is not an accuracy claim — full
methodology and what would make it one: [bench/methodology.md](bench/methodology.md) /
[docs/EVALUATION.md](docs/EVALUATION.md). Scan-throughput benchmark:
`python bench/perf.py`.

## Security-sensitive behaviour covered by tests

213 tests, `pytest`. Not exhaustive — these are the correctness-relevant ones:

```text
✓ eval/exec/subprocess sink detection (raw and decoded/obfuscated input)
✓ single-hop taint tracking (os.environ -> eval)
✓ poisoned MCP tool docstrings/descriptions detected, mapped to LLM01:2025
✓ every shipped pattern (secrets/LLM/devsecops/dependency) has a severity
  and an OWASP/CWE mapping — enforced as a test, not a doc claim
✓ Luhn-validated credit cards, structurally-validated JWTs (placeholder/
  malformed values rejected as false positives)
✓ SARIF output validated against the real SARIF 2.1.0 JSON Schema
✓ lockfile integrity drift detected against git HEAD
✓ known false-positive patterns (placeholder secrets, example.com, localhost)
  correctly not reported
```

## Security model / what secchecker is not

secchecker is **not**:
- a dataflow-complete analyzer — it's static regex/AST, single-file,
  single-hop; expect both false positives and false negatives
- a replacement for Semgrep, CodeQL, Gitleaks, or Checkov
- a runtime monitor, WAF, or LLM red-teaming tool
- a guarantee that a flagged pattern is actually exploited, or that a
  clean scan means the code is safe
- an OWASP certification or compliance claim — the tags are guidance

secchecker detects patterns associated with unsafe context-to-action
flows in source, before deployment. Runtime-only risks (delegated
authority escalation, multi-hop consequence chains, mid-session privilege
changes) need runtime governance, not a static scanner — see
[THREAT_MODEL.md](THREAT_MODEL.md) for the full boundary.

## Limitations

- AST-based checks (hardcoded secrets in assignments, `eval`/`exec` calls,
  taint tracking, poisoned tool docstrings/descriptions) run on Python
  source only.
- Taint tracking is single-file and single-hop; it does not follow values
  across module or function boundaries (planned: v0.7.0).
- Entropy detection is heuristic and opt-in (`.secchecker.yml`).
- Dependency scanning is static and offline: no tarball-integrity check
  against `node_modules/` contents, no CVE matching, hook detection only
  works on already-installed packages.
- Not a substitute for secret rotation, code review, or a full security audit.

## Repository guide

- **[docs/RULES.md](docs/RULES.md)** — full rule catalog, rule-authoring guide
- **[docs/OWASP_MAPPING.md](docs/OWASP_MAPPING.md)** — OWASP Top 10 / LLM Top 10 mapping detail
- **[docs/CI.md](docs/CI.md)** — GitHub Action inputs, pre-commit hooks
- **[docs/REPORTING.md](docs/REPORTING.md)** — output format reference
- **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** — CLI flags, `.secchecker.yml`
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — module map, scanner interface, library API
- **[docs/EVALUATION.md](docs/EVALUATION.md)** / **[bench/methodology.md](bench/methodology.md)** — benchmark methodology and results in full
- **[THREAT_MODEL.md](THREAT_MODEL.md)** — what's in scope, what needs runtime governance instead
- **[SECURITY.md](SECURITY.md)** — reporting a vulnerability in secchecker itself
- **[docs/ROADMAP.md](docs/ROADMAP.md)** — staged plan, what's shipped vs. planned

## Contributing

```bash
git clone https://github.com/vishnu-77/secchecker.git
cd secchecker
pip install -e ".[dev]"
pytest tests/ -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and the rule-authoring guide in
[docs/RULES.md](docs/RULES.md).

## Responsible use

Intended for auditing repositories you own or have explicit written
permission to test. Not a substitute for a full penetration test or
security audit.

## License

MIT — see [LICENSE](LICENSE).
