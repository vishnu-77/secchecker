# Threat Model

secchecker is a **static analysis** tool. It reads source files and configuration — it never executes code, makes network requests, or connects to external services.

---

## Assets Being Protected

| Asset | Risk if compromised |
|---|---|
| Source code repositories | Committed secrets enable cloud account takeover, data breach, supply chain attack |
| AI / LLM applications | Prompt injection enables data exfiltration, privilege escalation, jailbreak |
| Infrastructure-as-code | Misconfigured Terraform/K8s opens cloud resources to the internet |

---

## Threat Actors

| Actor | Motivation | Attack path |
|---|---|---|
| External attacker | Financial, espionage | Leaked API key → cloud account takeover → data exfiltration |
| Insider / developer error | Accidental | Hardcoded credential committed to public repo |
| Adversarial user | Abuse AI system | Prompt injection via user input → model follows injected instructions |
| Supply chain attacker | Persistent access | Unpinned base image → malicious layer pulled on next build |

---

## Attack Surfaces Covered

| Surface | Attack vector | secchecker check | OWASP reference |
|---|---|---|---|
| Source code | Hardcoded API keys, private keys, DB URIs | 52+ regex patterns + Shannon entropy | A02:2021 Cryptographic Failures |
| Source code | Hardcoded passwords in assignments | AST structural analysis | A02:2021 |
| LLM application | User input concatenated into prompt string | f-string prompt injection detection | LLM01:2025 Prompt Injection |
| LLM application | `eval()` / `exec()` of model output | AST + regex pattern | LLM05:2025 Improper Output Handling |
| LLM application | Unfiltered DB query result in model context | RAG leakage pattern | LLM08:2025 Vector and Embedding Weaknesses |
| LLM application | AI service API key in source | OpenAI / Anthropic / HuggingFace key patterns | LLM02:2025 Sensitive Information Disclosure |
| LLM application | PII / financial data in prompt | Sensitive data concatenation pattern | LLM02:2025 |
| Dockerfile | Unpinned base image (`:latest`) | `FROM *:latest` detection | A06:2021 Vulnerable Components |
| Dockerfile | Secrets in `ENV` statements | ENV credential pattern | A02:2021 |
| Dockerfile | `curl \| bash` anti-pattern | Pipe-to-shell detection | A08:2021 Software Integrity Failures |
| Dockerfile | Running as root | Missing `USER` non-root | A05:2021 Security Misconfiguration |
| Kubernetes | Privileged container | `privileged: true` check | A05:2021 |
| Kubernetes | `allowPrivilegeEscalation: true` | Explicit privilege escalation check | A05:2021 |
| Kubernetes | `hostNetwork` / `hostPID` enabled | Host namespace sharing check | A05:2021 |
| Terraform | Open security group (`0.0.0.0/0`) | CIDR block check | A05:2021 |
| Terraform | Publicly accessible RDS | `publicly_accessible = true` check | A05:2021 |
| Terraform | Public S3 bucket ACL | `acl = "public-read"` check | A05:2021 |
| Terraform | Plaintext credentials in config | Password / key assignment check | A02:2021 |
| CI/CD | Secrets echoed to logs | `echo $SECRET` pattern | A09:2021 Logging Failures |
| CI/CD | `pull_request_target` misuse | Workflow trigger check | A08:2021 |
| CI/CD | Unpinned GitHub Actions | `uses: action@main` check | A06:2021 |
| Dependency (npm/pnpm/Yarn) | Obfuscated `eval(atob(...))`, `Function()` constructor | Content pattern scan | A03:2021 Injection |
| Dependency (npm/pnpm/Yarn) | Shell execution from a package (`child_process.exec`) | Content pattern scan | A03:2021 |
| Dependency (npm/pnpm/Yarn) | Bulk `process.env` read, SSH/cloud credential paths | Content pattern scan | A02:2021 |
| Dependency (npm/pnpm/Yarn) | Undisclosed `preinstall`/`install`/`postinstall`/`prepare` hooks | `package.json` `scripts` field read | A06:2021 Vulnerable Components |
| Dependency (npm/pnpm/Yarn) | Suspicious binaries shipped in a package (`.exe`/`.node`/`.dll`) | Filename/extension check | A06:2021 |
| Dependency (npm/pnpm/Yarn) | A locked package's integrity hash silently changed | Lockfile diff vs git history | A08:2021 Software Integrity Failures |

---

## Dependency scanning: exactly what it does and doesn't touch

Added in this release, and held to the **same static-only, offline promise** as
everything above — not an exception to it.

**What it does, all fully local and offline:**
- Parses `package-lock.json` (npm), `pnpm-lock.yaml`, and `yarn.lock` — pure file
  parsing, no `npm install`.
- Reads each already-installed package's own `package.json` for lifecycle hooks
  (`preinstall`/`install`/`postinstall`/`prepare`) — it lists what a hook *would*
  run, it never runs it.
- Runs the same static content-pattern scan used everywhere else in secchecker
  against `node_modules/**` (obfuscation, shell-exec, network-access, and
  credential-access patterns), plus a filename check for suspicious binaries.
- Diffs a lockfile's package integrity hashes against the version last committed
  to git (`secchecker verify`) — a local `git show` read, not a network call.

**What it explicitly does not do:**
- It does not run `npm install`, `pnpm install`, or `yarn install`.
- It does not execute any lifecycle script, sandboxed or otherwise.
- It does not monitor runtime file changes, process execution, or network
  connections during or after an install — there is no install step here to
  monitor.
- **It makes exactly one network call, and only if you explicitly ask for it:**
  `secchecker package inspect <name> --check-registry` would query the npm
  registry for package age/provenance metadata. This flag exists in the CLI
  surface but the registry check itself is **not implemented yet** — passing it
  today prints a notice and makes no network call at all. When it does ship, it
  will remain off by default (`dependency_scan.check_registry: false`), and
  read-only registry metadata is the only thing it will ever fetch.
- It does not do CVE/vulnerability-database matching — that's still `pip-audit`'s
  or `npm audit`'s job, not this tool's (see "Out of Scope" below).
- A **controlled, sandboxed install** (running lifecycle scripts under restricted
  filesystem/network/process access) and **post-install runtime verification**
  (monitoring what an install actually did) are deliberately **not built**. Both
  require secchecker to execute code, which is the one thing this tool promises
  never to do. If that capability is ever added, it will ship as a clearly
  separate, opt-in subsystem with its own threat-model section stating plainly
  that it executes code and touches the network — not folded silently into the
  static scanner's guarantees.

## Out of Scope

secchecker is a **pre-deployment static scanner**. It intentionally does not cover:

- **Runtime monitoring** — use a WAF, RASP, or runtime security agent for deployed systems
- **Dynamic LLM red-teaming** — use [NVIDIA GARAK](https://github.com/NVIDIA/garak) for fuzzing a running model
- **Network-level attacks** — use a network scanner (Nmap, Nessus) for infrastructure scanning
- **CVE / vulnerability-database matching** — secchecker's dependency scanner checks for suspicious
  *behavior* (obfuscation, shell-exec, hook scripts, lockfile drift), not known-CVE lookups; use
  `pip-audit`, `safety`, or `npm audit` for that
- **DAST / penetration testing** — use OWASP ZAP or Burp Suite for live application testing

---

## Known Limitations

| Limitation | Impact | Workaround |
|---|---|---|
| Static analysis cannot trace all data flows | Complex injection paths via function call chains may not be detected | Use deeper SAST tools (Semgrep) for critical services |
| Shannon entropy has false positives on base64 non-secret data | Some legitimate base64 strings flagged as high-entropy secrets | Use `--no-entropy` or tune threshold in `.secchecker.yml` |
| LLM patterns are heuristic | Adversarially crafted prompts using unusual encodings or string construction may evade regex | Defence-in-depth: also add runtime input validation |
| Regex-based secret detection has false negatives | Novel secret formats not covered by current patterns may be missed | Contribute new patterns via issue/PR |
| Taint tracking is best-effort | AST taint analysis tracks single-hop flows; multi-hop data flows are not fully traced | Planned improvement in v0.5.0 |

---

## Security of secchecker Itself

- **Zero runtime dependencies** — no transitive supply chain attack surface
- **No code execution** — secchecker reads files; it never `eval()`s or `exec()`s content
- **No network access** — all analysis is local and offline
- **PyPI Trusted Publishing** — releases use OIDC-based authentication, no static API tokens in CI
- **Responsible disclosure** — see [SECURITY.md](SECURITY.md) for the vulnerability reporting process

---

## OWASP References

- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [OWASP LLM Top 10 (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html)
