# FP-05 — The credential-redaction code itself flagged as leaking credentials to the LLM

**Verdict:** False positive — and the most consequential one in the corpus, since it's
the exact inverse of the actual code's purpose.

**Repo:** `openai/openai-agents-python` @ `83c737fd0b8d9a53bd39fa2a0856070417bb0bd3`
**Files:** `src/agents/sandbox/_mount_security.py`, `src/agents/extensions/sandbox/blaxel/mounts.py`
**Rule:** `LLM - Secret Passed to LLM` (CRITICAL) — matched on `"message credential"`
**Status:** Fixed — `LLM - Secret Passed to LLM` now requires an actual LLM-call sink
(`.create(`, `.invoke(`, `messages.append(`, `Anthropic(`, `OpenAI(`, ...) present
somewhere in the file (`_LLM_CALL_SINK_RE` guard in `secchecker/llm_scanner.py`).
Neither file has one anywhere in ~2,200 lines. Re-scanning `openai-agents-python`
confirms it now scans clean (0 findings), where it previously had 5.

## What the file actually does

`_mount_security.py` is ~2,200 lines implementing the **security boundary** that keeps
cloud-storage credentials (S3/GCS/Azure/Box access keys, tokens, service-account files)
*out of* a model-controlled sandbox: functions like
`validate_mount_activation_credential_boundary`,
`_sanitize_raw_credential_file_sources`, `_mark_mount_error_data_safe`, and error
messages such as:

```python
"mount-scoped credentials cannot be exposed to a helper inside a "
"model-controlled sandbox by default; use a credentialless or "
"external/provider-native strategy, or explicitly acknowledge exposure..."
```

`mounts.py` writes credential material to a short-lived file *outside* the sandbox
mount, restricts its permissions, and removes it after use
(`_write_mount_credential_file` / `_remove_mount_credential_file`) — again, keeping
secrets away from the LLM-driven execution environment.

Neither file constructs an LLM prompt, message, or API call anywhere near the matched
text. There is no `messages=`, no `client.messages.create`, no prompt string at all in
the ~40 lines around each match.

## Root cause

The rule fired on lexical co-occurrence of "credential"-family words with "message"
(likely from words like `MountConfigError(message=...)` — an ordinary Python exception
constructor's `message` kwarg — not an LLM chat message) near "credential". There is no
check that a `messages=`/prompt-construction call site is actually present, so any
error-handling code that discusses credentials in its `message=` string reads the same
as a real secret-into-prompt data flow.

## Why it matters for AgentSecBench

This is the strongest evidence in the corpus that `LLM - Secret Passed to LLM` needs a
sink check, not just a source check: require an actual LLM call/message-construction
identifier (`.create(`, `messages.append`, `ChatCompletion`, an SDK client method) in
the matched window, not any `message=`-shaped keyword argument. Without that, the rule
will always be noisiest exactly on the security-hardened, well-audited code that
*talks about* credentials the most — the opposite of where attention is needed.
