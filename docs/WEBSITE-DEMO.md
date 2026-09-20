# Recorded website scan

The product illustration replays a real SecChecker 0.5.1 CLI scan captured on
2026-09-20 against a maintainer-owned repository. It is not a browser scanner.

The scanner was loaded from website baseline `f2137be`. The command ran from
the target repository root with an absolute output path in a local capture
directory:

```text
secchecker . --type llm --format sarif --verbose --output <capture>/original.sarif
```

Only the output destination is normalized to `secchecker_report.sarif` in the
displayed command and transcript. The actual exit code was 1. Actual output:

```text
[*] Scanning: .
[*] Scan type: llm
[*] Format: sarif
[*] 4 finding(s) across 4 file(s)
[+] Report: secchecker_report.sarif
```

`website/assets/example-scan.sarif` is the captured report with each of its
four artifact paths replaced by a distinct neutral path. Rule IDs, messages,
severities, counts, tool version, reported line numbers and invocation data
are unchanged. The report contains three HIGH `LLM - Groq API Key` findings
and one MEDIUM `LLM - API Key in Log Statement` finding.

No source snippets, credential values, original file paths or repository
identity are published. The original report and path mapping stay outside
the repository. The selected finding's reported line was checked against
the original source without displaying the credential value.

These are scanner findings, not independently confirmed vulnerabilities.
No credential-validity checks were performed. Existing scanner limitations
remain: the logging finding reports line 1, and the report contains no
source-to-sink flow trace. The illustration preserves the emitted report
instead of inventing richer evidence or correcting its output silently.

The replay reads its command and lines from the static HTML. Reduced-motion
and no-JavaScript visitors receive the same transcript and selected result.
Run `python scripts/verify_website_demo.py` to check the published transcript,
selected finding and report agree. The Site Check workflow runs this check.
