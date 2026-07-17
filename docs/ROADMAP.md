# Roadmap

**Vision:** Be the #1 static security scanner for MCP servers and AI agents — the tool a coding agent reaches for, unprompted and trusted, when building AI systems.

## Guiding principles

| Principle | Rule |
|---|---|
| Trust is the product | A security tool that reports a false "clean" is worse than none. Accuracy and provenance gate every release. |
| Test-first | No feature merges without unit + fixture + regression tests. Every fixed bug becomes a permanent regression test. |
| Deterministic | Same input → same output. Versioned rules. Machine-parseable (SARIF/JSON). |
| Zero-friction | `uvx secchecker` with no config must do something useful. |
| Own the AI surface | Lead with MCP/agent/LLM. Secrets + IaC stay a supporting baseline, never the pitch. |
| Ship credible, then broad | Fix what's broken before adding scope. |

## Phase overview

| Phase | Version | Theme | Status |
|---|---|---|---|
| 0 | 0.4.2 | Credibility fixes + test foundation | **Delivered** |
| 1 | 0.5.0 | Agent-native: MCP server + `init` scaffolding | Planned |
| 2 | 0.6.0 | Deepen the moat: agentic taint + framework packs + prompt linter | Planned |
| 3 | 0.7.0+ | Discoverability & trust at scale | Planned |

Phases are sequential on the critical path; the **Testing foundation** and **Trust/supply-chain** tracks run in parallel from Phase 0.

---

## Phase 0 — 0.4.2 · Credibility fixes + test foundation (delivered)

An independent audit of an earlier release found the tool's default scan crashing on current Python versions, a severity-filtering bug that could report a dirty repo as clean, and several config options that were parsed but silently ignored. 0.4.2 closes all of it out and adds a regression test per fixed bug so none of these can silently reappear.

### Delivered
- **Fixed a crash in the default scan** on Python 3.14 — the AST scanner used a deprecated attribute that was removed upstream; `secchecker <path>` (the default `secrets` scan) and `--type all` now run clean on Python 3.8–3.14.
- **Fixed a false-"clean" bug** — several finding categories (AST-detected `eval`/`exec` calls, hardcoded secrets, tainted-sink findings, and others) had no explicit severity and silently defaulted to `LOW`, so `--severity-threshold HIGH` could drop real findings and report a dirty repo as clean. Every finding category now has an explicit severity, enforced by a permanent contract test.
- **Added MCP tool-poisoning detection for the canonical attack** — hidden instructions embedded in a tool's docstring or `description=` value (the way a poisoned tool actually hijacks a calling LLM), not just the code-shape heuristics that shipped before.
- **Wired up dead config keys** — `exclude_patterns` (rule-name exclusions), `custom_patterns` (merged into the secrets scan), and `scan_types` (default scan type when `--type` isn't passed) all now do what `.secchecker.yml` says they do.
- **Moved Email/Phone Number behind `--pii`** — off by default to cut alert fatigue on ordinary codebases; still available as an opt-in flag.
- **Fixed a validator bug that suppressed every bearer-scheme finding** — JWT structural validation was incorrectly applied to bearer-scheme values as well as JWTs.
- **Fixed inconsistent entropy scan keys** — entropy findings now key by the same relative path the other scanners use, and respect the same skip-directory rules, instead of appearing as separate absolute-path entries.
- **Extended CI to Python 3.8–3.14** with a regression test for every fixed bug, plus a severity contract test and an OWASP-mapping contract test.
- **Corrected documentation claims** — pattern counts, entropy's actual opt-in behavior, and other doc/behavior mismatches now match what the code does.

### Testing foundation (now in place)
- pytest suite with one regression test per fixed bug, named for what it guards against.
- `tests/test_severity_contract.py` — asserts every finding category any scanner can emit has an explicit severity (the guard against the false-"clean" class of bug).
- `tests/test_owasp.py` contract test — asserts every DevSecOps pattern name has a matching OWASP/CWE entry (guards against silently untagged SARIF rules).
- CI matrix across Python 3.8–3.14.

---

## Phase 1 — 0.5.0 · Agent-native adoption
**Goal:** any MCP-enabled coding agent can call secchecker natively, and any repo can self-instruct an agent to run it.

### 1a. `secchecker-mcp` server (highest-leverage feature)
- Expose MCP tools:
  - `scan_code(path, type)` → structured findings JSON
  - `scan_mcp_manifest(path)` → tool-poisoning / rug-pull findings
  - `check_snippet(code, language)` → inline scan of a code string (for agents mid-edit)
  - `explain_finding(id)` → OWASP mapping + remediation
- Transport: stdio (local) first; HTTP/SSE later.
- Self-referential positioning: "the MCP security scanner that is itself an MCP server."

**Acceptance:** an MCP client (Claude Desktop / Claude Code / any MCP host) lists and successfully calls each tool; results match the CLI for the same input.

**Test plan:**
- **Protocol conformance:** automated MCP handshake + `tools/list` + `tools/call` against the server using an MCP test client; assert schema-valid responses.
- **CLI/MCP parity:** golden test — same fixture through CLI and through `scan_code` must yield identical findings.
- **Fault handling:** malformed input, oversized files, non-existent paths → structured error, never a crash.

### 1b. `secchecker init` scaffolding
Writes, idempotently, into the target repo:
- `.pre-commit-config.yaml` hook entry
- `.github/workflows/secchecker.yml` (SARIF upload to code scanning)
- Agent rule block appended to `AGENTS.md` / `CLAUDE.md` / `.cursorrules`:
  > "When building or modifying an MCP tool server or AI agent, run `uvx secchecker . --type all` and resolve HIGH/CRITICAL findings before completing the task."
- `.secchecker.yml` starter config

**Acceptance:** `secchecker init` on a fresh repo produces working hooks/workflow; re-running is idempotent (no duplicate blocks).

**Test plan:**
- Idempotency test: run `init` twice, assert files identical after second run.
- Generated GitHub Action is linted (actionlint) and dry-run validated.
- Generated pre-commit config validated with `pre-commit validate-config`.

### 1c. CI ergonomics
- `--baseline` allowlist file so teams accept known findings and gate only on new ones.
- `uvx` / `pipx run` zero-install path documented and tested.

**Acceptance:** baseline suppresses accepted findings and flags new ones.

**Test plan:** baseline round-trip test (accept a finding, confirm it's suppressed; introduce a new one, confirm it's flagged).

---

## Phase 2 — 0.6.0 · Deepen the moat
**Goal:** detection that generic scanners structurally cannot replicate.

### Deliverables
- **Cross-function agentic taint** — extend the AST engine: user input → tool call → dangerous sink (`eval`/shell/SQL) across function boundaries (today's taint tracking is single-file and simplified).
- **Framework sink packs** — LangChain, LlamaIndex, CrewAI, AutoGen, OpenAI-Agents SDK, FastMCP.
- **Prompt-template linter** — scan `.jinja` / `.prompt` / system-prompt strings for injection-prone concatenation.
- **Rug-pull detection** — diff a tool's description across versions; flag silent changes.

### Acceptance criteria
- On the agentic-taint benchmark corpus: recall ≥ 0.85, precision ≥ 0.80.
- Each framework pack detects its known-bad fixtures and stays quiet on known-good ones.

### Test plan
- **Benchmark corpus** (see Testing Strategy) with labeled true/false positives; CI asserts precision/recall thresholds and **fails the build on regression**.
- **Property tests** on the taint engine (e.g., renaming a variable must not change the verdict).
- Per-framework fixture pairs (vulnerable + safe).

---

## Phase 3 — 0.7.0+ · Discoverability & trust at scale
**Goal:** agents reach for it unprompted; users trust it by default.

### Deliverables
| Track | Actions |
|---|---|
| **Supply-chain trust** | Sigstore/Cosign-signed releases, SBOM (CycloneDX), PyPI Trusted Publishing, reproducible builds |
| **Registry presence** | List `secchecker-mcp` on Anthropic MCP registry, mcp.so, Smithery, Glama, PulseMCP |
| **Corpus seeding** | Submit to awesome-mcp-servers, awesome-ai-security, OWASP LLM/MCP resource lists; launch posts; reference implementation of an "MCP Security Checklist" |
| **Standards** | Publish the MCP Security Checklist and map every rule to it + OWASP LLM Top 10 |

### Acceptance
- Releases verifiably signed; SBOM published per release.
- Listed on ≥3 MCP registries.
- Public precision/recall benchmark page updated per release.

---

## Testing Strategy (cross-cutting — the backbone of "trusted")

### Layers
| Layer | What | Gate |
|---|---|---|
| Unit | Each pattern, validator, severity map, config parser | ≥85% line coverage on core modules |
| Fixture corpus | Curated vulnerable + safe files per scanner (secrets/llm/mcp/devsecops) | Every pattern has ≥1 positive and ≥1 negative fixture |
| Golden-file | Report output (md/json/sarif) diffed against checked-in expected output | Byte-stable except timestamps |
| Regression | One test per fixed bug | Must fail on pre-fix code |
| Cross-Python | Full suite on 3.8 / 3.11 / 3.12 / 3.13 / 3.14 | All green |
| Precision/recall benchmark | Labeled corpus, measured per scanner | Thresholds enforced; build fails on regression |
| MCP protocol | Handshake + tool call conformance | Schema-valid, CLI parity |
| Property/fuzz | Taint engine invariants; malformed inputs never crash | No unhandled exceptions |
| Self-scan | secchecker scans its own repo in CI | No unresolved HIGH/CRITICAL |

### Rules
- **Bug → test:** every reported bug ships with a regression test in the same PR.
- **No unmapped severities:** a test enumerates all finding categories and asserts each has an explicit severity (the Phase 0 contract test — prevents recurrence of the false-"clean" class of bug).
- **SARIF validated** against the official schema in CI.
- **Coverage gate** in CI (fail under threshold).
- **Benchmark as a gate,** not a vanity metric — precision/recall drops fail the build.

### Fixture corpus layout
```
tests/fixtures/
  secrets/{positive,negative}/
  llm/{positive,negative}/
  mcp/{positive,negative}/        # incl. poisoned docstrings, rug-pull diffs
  devsecops/{positive,negative}/
  agentic/{positive,negative}/    # cross-function taint cases
tests/golden/                     # expected report outputs
tests/benchmark/labels.json       # ground-truth for precision/recall
```

---

## Discoverability & adoption plan (summary)

| Priority | Move | Phase |
|---|---|---|
| 1 | Fix credibility bugs | 0 (done) |
| 2 | MCP server + registry listings | 1 / 3 |
| 3 | `uvx`/`pipx` zero-install | 1 |
| 4 | `secchecker init` rule-files + pre-commit + Action | 1 |
| 5 | SARIF-first CI + JSON schema | 1 |
| 6 | Signed releases + SBOM + SECURITY.md | 3 |
| 7 | MCP Security Checklist (be the standard) | 3 |
| 8 | Corpus seeding (awesome-lists, OWASP, posts) | 3 |

**The honest constraint:** MCP server buys *immediate* adoption for MCP-enabled agents; corpus presence (stars, repos using it, references) is what makes future agents reach for it *unprompted* — that's a slower flywheel, seeded in Phase 3.

---

## Success metrics (KPIs)
- Correctness: 0 false-"clean" on the regression corpus; precision ≥0.80 / recall ≥0.85 on benchmarks.
- Adoption: MCP server installs, registry listings (≥3), repos with `secchecker` in CI/pre-commit.
- Trust: 100% of releases signed + SBOM; median issue-to-fix time.
- Reach: GitHub stars, inbound references in framework/OWASP docs.

## Risks & mitigations
| Risk | Mitigation |
|---|---|
| Regressions erode trust | Bug→test rule + CI matrix + self-scan gate |
| False positives cause abandonment | Benchmark precision gate; opt-in PII; baseline file |
| MCP server maintenance burden | Thin wrapper over the same core; CLI/MCP parity tests |
| Solo-maintainer bandwidth | Prioritise Phase 1 (highest leverage); automate CI/release |
| Registry/standard adoption is slow | Treat as flywheel, not a launch dependency |

---

## Next step
Phase 1 (0.5.0): the `secchecker-mcp` server and `secchecker init` scaffolding are the highest-leverage next steps — they turn secchecker from "a CLI you remember to run" into "a tool an agent reaches for on its own."
