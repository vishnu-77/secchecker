# GAP-02 — The canonical MCP reference servers are 84% invisible by language alone

**Verdict:** Coverage gap.

**Repo:** `modelcontextprotocol/servers` @ `d73f99efbfd40c3aa1b61e88728b3d49fb52608f`
**Scope:** whole repo — **zero findings**, `--type llm`, all severities.

## The numbers

| Language | Files |
|---|---|
| TypeScript (`.ts`) | 76 |
| Python (`.py`) | 14 |

This is the **official** Model Context Protocol reference-server implementation repo —
the closest thing to a canonical corpus of real MCP tool servers (filesystem, git,
fetch, time, etc.) that exists. 84% of it is TypeScript. secchecker's AST-based taint
tracking (`secchecker/ast_scanner.py`) is Python-only by construction; the regex-based
LLM/agentic layer (`secchecker/llm_patterns.py`) applies to any text file in principle,
but produced zero matches in the `.ts` sources either — its patterns (f-strings,
`.format()`, `os.environ`, Python-shaped MCP client imports) don't have JS/TS
equivalents (template literals, `process.env`, `@modelcontextprotocol/sdk` imports),
so there's nothing for even the lexical layer to key on.

The 14 Python files that *were* scanned are mostly thin CLI wrappers
(`__main__.py`/`__init__.py`) plus real tool-call handlers (e.g.
`src/git/src/mcp_server_git/server.py:471` — `call_tool(name, arguments)` dispatching
on `arguments["repo_path"]`, `arguments["branch_name"]`, etc. into GitPython calls);
none triggered a finding, which is plausible here specifically since GitPython's `Repo`
API doesn't build shell strings from those arguments — but it means this file got a
clean bill with no cross-function trace confirming that, only "no keyword matched."

## Why it matters for AgentSecBench

secchecker's own README and roadmap lead with "the #1 static security scanner for
MCP servers" — but the actual population of MCP servers in the wild skews heavily
toward TypeScript/Node (the reference implementations themselves are proof), and
today's detection depth (real AST taint tracking, not just keyword regex) exists only
for Python. This isn't a bug to patch so much as a scope gap worth being explicit
about: claims of MCP-server coverage should be qualified by language until a
JS/TS-aware pass (even a shallow one — template-literal prompt construction,
`process.env`, `@modelcontextprotocol/sdk` tool-handler shapes) exists.
