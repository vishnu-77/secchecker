# Legacy scanner transition

SecChecker is narrowing its public scope to **static security analysis for AI trust boundaries**.

Earlier releases also shipped generic DevSecOps checks for Docker, Kubernetes, Terraform, CI/CD, dependencies, and broad secret scanning. Those capabilities remain part of the v0.5.x history and are not being rewritten or hidden.

## Transition

| Release line | Direction |
|---|---|
| v0.5.x | Existing broad functionality remains available |
| v0.6.x | AI/LLM/MCP analysis becomes the public product focus; generic scanners are treated as legacy |
| v0.7.x | Investment moves to deeper AI source/sink, MCP, memory, framework, and control-flow analysis |
| v1.0 | Generic DevSecOps scanners may be removed from core or extracted if users still depend on them |

No new generic Docker, Kubernetes, Terraform, or CI/CD rule development is planned as part of the AI-first direction.

## Credentials

Credential analysis remains where it is relevant to AI systems. The direction is not to compete with comprehensive secret scanners.

SecChecker may inspect:

- AI provider credentials
- credentials used to construct model/provider clients
- credentials entering model or agent context
- credentials passed to external agents or tools
- selected MCP/tool authentication material

Python analysis can use AST structure and usage context in addition to token-shape matching. For example, a hardcoded value subsequently passed to `OpenAI(api_key=...)` can be treated differently from a value loaded through `os.getenv(...)`.

## Product boundary

```text
context ──────► trust transition ──────► consequential action
                       ▲
                       │
                  SECCHECKER
```

SecChecker should answer:

> Where can AI-controlled or externally controlled context cross into something more trusted or consequential?

It should not attempt to answer every software-security question in a repository.
