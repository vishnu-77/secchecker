# FP-04 — Any `server_url` variable reads as an "MCP server URL"

**Verdict:** False positive.
**Status:** Fixed — `MCP - Hardcoded MCP Server URL` now requires an MCP marker
(`mcp`, `modelcontextprotocol`, `ClientSession`, `FastMCP`, `@mcp.tool`,
`StdioServerParameters`) present anywhere in the file (`_MCP_MARKER_RE` guard in
`secchecker/llm_scanner.py`). No fixture in `bench/fixtures` exercised this rule before
this change, so there was no regression risk; re-scanning this repo confirms
`firecrawl.py` no longer appears.

**Repo:** `assafelovic/gpt-researcher` @ `6f998577d547b1e54ec662dac63583aa11e3b84b`
**File:** `gpt_researcher/scraper/firecrawl/firecrawl.py:28-54`
**Rule:** `MCP - Hardcoded MCP Server URL` (HIGH)
**Matched text:** `server_url`

## The flow

```python
self.firecrawl = FirecrawlApp(api_key=self.get_api_key(), api_url=self.get_server_url())

def get_server_url(self) -> str:
    ...
    server_url = os.environ.get("FIRECRAWL_SERVER_URL", 'https://api.firecrawl.dev')
    return server_url
```

This is the base URL for the **Firecrawl web-scraping API** — a self-hosted-or-cloud
scraper backend, configurable via `FIRECRAWL_SERVER_URL`. It has nothing to do with
the Model Context Protocol; there's no `mcp` import, no MCP client/server object,
nowhere in this file.

## Root cause

The rule appears to trigger on the identifier `server_url` (or similarly-shaped
variable names) on its own, without verifying the surrounding code is actually
constructing an MCP client/transport (e.g. `mcp.client.sse`, `ClientSession`,
`StdioServerParameters`). "Server URL" is a generic enough name that any app talking to
any HTTP backend is liable to use it.

## Why it matters for AgentSecBench

Same shape as FP-03: an MCP-specific rule firing on generic code because the check is
keyed to a common English phrase/identifier rather than actual MCP protocol usage.
Gating MCP rules behind "does this file import an MCP SDK" (even a cheap textual check
for `mcp`, `modelcontextprotocol`, `FastMCP`, `ClientSession` etc. in the same file)
would remove this whole class of miss without needing real cross-file resolution.
