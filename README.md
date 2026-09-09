[![PyPI version](https://img.shields.io/pypi/v/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Python versions](https://img.shields.io/pypi/pyversions/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Build Status](https://github.com/vishnu-77/secchecker/actions/workflows/ci.yml/badge.svg)](https://github.com/vishnu-77/secchecker/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-black.svg)](LICENSE)

# secchecker

**Static security analysis for AI trust boundaries.**

Find risky transitions where prompts, RAG content, MCP tools, model output, agent memory, or AI credentials can influence consequential actions.

```bash
pip install secchecker
secchecker . --type llm
```

Zero runtime dependencies. Local analysis. No LLM judge.

---

## 1. Hero

```text
UNTRUSTED CONTEXT                         CONSEQUENTIAL ACTION

● user input ─────────────┐
● retrieved content ──────┤
● MCP result ─────────────┤
● tool metadata ──────────┼────►  AGENT  ────► □ tool
● model output ───────────┤                  ├─ ■ shell
● external context ───────┤                  ├─ ■ API
● memory ─────────────────┘                  ├─ ■ SQL
                                             └─ ■ memory
                               ▲
                               │
                          secchecker
```

SecChecker focuses on the places where **AI-controlled or externally controlled context crosses into something more trusted or more consequential**.

It is not trying to be a general-purpose DevSecOps scanner.

---

## 2. The problem

AI applications introduce trust transitions that ordinary request-response applications often do not.

A prompt can become a tool call. A retrieved document can influence privileged model context. An MCP tool description can contain instructions the user never sees. Model-controlled output can reach a shell, SQL query, API, or another agent. User-controlled content can become persistent agent memory.

SecChecker statically inspects those boundaries before deployment.

```text
context  ─────────────►  decision  ─────────────►  action
                           ▲
                           │
                      trust boundary
```

---

## 3. 15-second demonstration

The same input can be safe or unsafe depending on the boundary it crosses.

### Flagged

```python
system_prompt = f"You are a helpful assistant. User query: {user_input}"
```

```text
$ secchecker vulnerable.py --type llm
LLM - Prompt Injection via f-string (HIGH): 1 match(es)
```

### Cleaner boundary

```python
messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": user_input},
]
```

```text
$ secchecker safe.py --type llm
[+] No findings detected.
```

Real vulnerable/safe fixtures live under [`bench/fixtures/`](bench/fixtures/).

---

## 4. What SecChecker detects

SecChecker is organised around **security surfaces**, not a marketing count of rules.

### Prompt & context integrity

- unsafe user-controlled data entering privileged prompts
- prompt delimiter manipulation
- instruction and role override patterns
- sensitive values entering model context
- unsafe system-prompt handling

### RAG boundaries

- raw file content entering model context
- database results entering RAG context
- environment-derived sensitive information entering prompts
- retrieved content crossing into trusted context without an appropriate boundary

### MCP & tool trust

- poisoned tool descriptions
- poisoned tool docstrings
- untrusted tool metadata
- tool results reintroduced into privileged context
- tool output passed to dangerous execution sinks
- selected remote MCP configuration risks

### Model output handling

```text
model output ──► eval / exec
model output ──► subprocess / shell
tool output  ──► consequential action
```

Model output is data, not authority. SecChecker looks for code paths that blur that distinction.

### Agent memory

- user-controlled input written directly to memory
- untrusted context persisted into long-term state
- selected unsafe vector-store writes

### Agent control flow

- unvalidated function/tool-call results
- recursive agent invocation patterns
- autonomous loops without clear exit conditions
- selected sensitive-data-to-agent flows

### AI credentials

Credential analysis is not limited to token-shaped regex matches.

For Python, SecChecker also uses AST structure and usage context to recognise cases such as:

```python
openai_api_key = "hardcoded-value"
client = OpenAI(api_key=openai_api_key)
```

and direct provider initialisation:

```python
client = Anthropic(api_key="hardcoded-value")
```

The scanner distinguishes those from an expected environment-loading shape:

```python
openai_api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=openai_api_key)
```

That means SecChecker can reason about **where credential material is declared and how it is used in an AI provider client**, rather than relying only on a credential prefix appearing somewhere in text.

This remains bounded static analysis, not full semantic program understanding.

---

## 5. Why this is different from generic SAST

SecChecker does not claim that Semgrep, CodeQL, or other mature static-analysis platforms cannot analyse AI applications. They can.

The distinction is **focus out of the box**.

| Capability | SecChecker |
|---|---|
| AI trust-boundary checks | Primary focus |
| Prompt/context security | Built in |
| MCP/tool trust checks | Built in |
| Agent-memory checks | Built in |
| Model-output execution checks | Built in |
| Context-aware AI credential use | Built in for selected Python provider shapes |
| Python structural analysis | Supported |
| Whole-program interprocedural analysis | No |
| Runtime enforcement | No |
| LLM judge required | No |
| External runtime dependencies | None |

SecChecker is designed to complement Semgrep, CodeQL, specialist secret scanners, runtime AI security controls, code review, and red-team testing.

---

## 6. How it works

```text
                         SOURCE TREE
                             │
                       file discovery
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
       pattern analysis              Python AST analysis
              │                             │
              │                    structure + limited taint
              │                    provider credential context
              │                             │
              └──────────────┬──────────────┘
                             ▼
                       NORMALISED FINDING
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
         severity           CWE          OWASP / LLM
            └────────────────┼────────────────┘
                             ▼
                JSON · SARIF · Markdown
                   HTML · XML · CLI
```

SecChecker combines deterministic pattern analysis with Python AST checks and limited taint tracking. Findings are normalised into a shared reporting model with severity and security taxonomy metadata where applicable.

Source code is not sent to an LLM or external analysis service by SecChecker itself.

---

## 7. Benchmark results

The benchmark is reproducible and offline:

```bash
python bench/run.py
```

Current v0.5.0 benchmark artifact:

| Evaluation | Result |
|---|---:|
| Known vulnerable regression fixtures | 23 / 23 detected |
| Paired safe regression fixtures | 23 / 23 clean |
| Regression precision | 1.00 |
| Regression recall | 1.00 |
| Adversarial variants | 4 / 14 detected |
| Adversarial recall | 28.57% |
| Benign-realistic examples still flagged | 2 / 4 |

Performance fixture:

| Files | Throughput |
|---:|---:|
| 100 | 97.4 files/sec |
| 400 | 113.2 files/sec |
| 1,600 | 127.5 files/sec |

**The regression result is not a claim of 100% real-world detection accuracy.** Those fixtures contain known cases against which the implementation is expected to regress correctly. The adversarial corpus exists specifically to expose where current deterministic analysis fails to generalise.

See [`bench/methodology.md`](bench/methodology.md), [`docs/EVALUATION.md`](docs/EVALUATION.md), and [`bench/results/`](bench/results/).

---

## 8. Quickstart

```bash
pip install secchecker
```

Scan AI/agent/LLM/MCP surfaces:

```bash
secchecker . --type llm
```

Generate SARIF:

```bash
secchecker . --type llm --format sarif --output secchecker.sarif
```

Output formats:

```text
json · md · xml · sarif · html
```

Configuration: [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

---

## 9. CI integration

```yaml
- uses: vishnu-77/secchecker@v0.5.0
  with:
    type: llm
    format: sarif
```

SecChecker supports GitHub Actions, SARIF-based code scanning, CLI-based CI, and pre-commit workflows.

Full integration guide: [`docs/CI.md`](docs/CI.md).

---

## 10. Supported patterns and ecosystems

This section intentionally avoids claiming blanket framework support.

| Surface / ecosystem | Current status |
|---|---|
| Python AI applications | Pattern + AST analysis |
| Generic LLM applications | Supported security patterns |
| MCP-style tools | Tool metadata, result, poisoning and execution-boundary checks |
| Agent memory / vector stores | Selected unsafe-write patterns |
| LangChain | Selected implemented code patterns |
| OpenAI | Generic AI patterns + contextual provider credential analysis |
| Anthropic | Generic AI patterns + contextual provider credential analysis |
| Groq | Selected contextual provider credential analysis |
| Azure OpenAI | Selected contextual provider credential analysis |
| Pinecone / Weaviate | Selected AI credential and integration patterns |

Planned deeper framework-specific analysis includes LangChain, LlamaIndex, CrewAI, AutoGen, OpenAI Agents SDK, and FastMCP. These are not presented as fully supported until the corresponding source/sink packs ship and are tested.

---

## 11. Limitations

SecChecker deliberately trades heavyweight whole-program analysis for fast, local, deterministic checks.

- AST-specific analysis is Python-focused.
- Taint tracking is limited rather than fully interprocedural.
- Values are not comprehensively followed across functions, modules, services, or runtime tool chains.
- Static patterns can produce false positives and false negatives.
- Equivalent vulnerable code can evade existing checks.
- Adversarial paraphrases can bypass text-oriented detections.
- Provider-aware credential analysis currently covers selected constructor and keyword shapes rather than every SDK.
- SecChecker does not observe runtime authority or live tool invocation.
- SecChecker is not an LLM red-team framework, WAF, or runtime policy engine.
- A finding does not prove exploitability.
- A clean scan does not mean an application is secure.

Runtime-only problems such as delegated authority escalation, multi-agent consequence chains, mid-session privilege changes, and cross-agent trust propagation require runtime controls.

See [`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## 12. Repository map

```text
secchecker/
│
├── secchecker/          scanner implementation
├── tests/               correctness and regression tests
├── bench/               evaluation and performance harness
├── demo/                intentionally vulnerable examples
├── docs/                architecture, rules and configuration
├── .github/             CI workflows
│
├── action.yml           GitHub Action
├── THREAT_MODEL.md      security boundaries
├── SECURITY.md          vulnerability disclosure
├── CONTRIBUTING.md      contribution guide
└── README.md
```

Useful documentation:

- [`docs/RULES.md`](docs/RULES.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/EVALUATION.md`](docs/EVALUATION.md)
- [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)
- [`docs/CI.md`](docs/CI.md)
- [`docs/REPORTING.md`](docs/REPORTING.md)
- [`docs/OWASP_MAPPING.md`](docs/OWASP_MAPPING.md)
- [`docs/ROADMAP.md`](docs/ROADMAP.md)

---

## 13. Contributing

```bash
git clone https://github.com/vishnu-77/secchecker.git
cd secchecker
pip install -e ".[dev]"
pytest tests/ -v
```

A useful detection contribution should ideally include:

```text
detection
   ├── explicit finding name
   ├── severity
   ├── CWE / OWASP mapping where appropriate
   ├── vulnerable fixture
   ├── safe counter-example
   ├── adversarial variant where useful
   └── regression test
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`docs/RULES.md`](docs/RULES.md).

---

## 14. Responsible use

SecChecker is intended for repositories you own or are authorised to assess.

A finding means SecChecker identified a code shape associated with a security-sensitive AI trust transition. It does not necessarily mean the application is exploitable.

```text
NO FINDINGS ≠ SECURE APPLICATION
```

Use static analysis alongside threat modelling, code review, dependency analysis, runtime controls, testing, and security assessment.

If SecChecker identifies real credential material, rotate and revoke it rather than publishing it in an issue or demonstration.

For vulnerabilities in SecChecker itself, see [`SECURITY.md`](SECURITY.md).

## License

MIT — see [`LICENSE`](LICENSE).
