# Visual system

An e-ink-inspired diagnostic language: monochrome, functional geometry, sparse dot-matrix texture, and explicit trust-boundary diagrams. The logo appears once in the README banner. The animations are catalogued here rather than embedded in the root README; they focus on code and findings.

## Message and motion

**Catch risky AI trust-boundary crossings before they ship.**

The 1200 × 520 opening GIF shows three transitions from the first frame: user content into system instructions, tool metadata into agent instructions, and tool results into shell commands. An inspection bracket moves over each row for three seconds; all three findings remain visible for the final three seconds. This depicts source inspection, not runtime interception or blocking.

Three 1200 × 720 walkthroughs follow **risky code → finding → safer boundary**, held for four, five, and six seconds. They omit logos, terminal scenes, and version banners. The execution example deliberately removes shell execution; logging the result is a different behavior. A clean scan is not proof of security.

These are illustrated walkthroughs, not screen recordings. The renderer verifies the actual finding names and severities against the local CLI. Displayed line references annotate the illustrated source. A selected finding is not necessarily the only finding in the report.

## Assets

| Visual | GIF | Static alternative | Editable motion SVG |
|---|---|---|---|
| Overview | [GIF](secchecker-hero.gif) | [PNG](secchecker-hero-static.png) | [SVG](secchecker-hero-animated.svg) |
| Prompt injection | [GIF](prompt-injection.gif) | [PNG](prompt-injection-static.png) | [SVG](prompt-injection-animated.svg) |
| MCP tool poisoning | [GIF](mcp-tool-poisoning.gif) | [PNG](mcp-tool-poisoning-static.png) | [SVG](mcp-tool-poisoning-animated.svg) |
| Tool-output execution | [GIF](tool-output-execution.gif) | [PNG](tool-output-execution-static.png) | [SVG](tool-output-execution-animated.svg) |

- `secchecker-mark.svg` — primary square mark.
- [Animated mark](secchecker-mark.gif) — a four-second loop with fixed brackets, gently converging dots, a faint scan line, and transparent corners. [Motion SVG](secchecker-mark-animated.svg) · [Static PNG](secchecker-mark-static.png).
- `secchecker-lockup.svg` — native logo and wordmark source.
- `secchecker-banner.png` — logo banner rendered at twice the SVG dimensions.
- Each walkthrough PNG stacks all three scenes at full reading resolution.

## Regenerate and verify

With Python 3.10+ from the repository root:

```bash
python -m pip install -r brand/requirements.txt
python brand/render_assets.py
```

Check existing assets without rewriting them:

```bash
python brand/render_assets.py --check
```

Regenerate the standalone animated mark from the original `secchecker-mark.svg`:

```bash
python brand/animate_mark.py
```

This preserves the original SVG and creates a 256 × 256 GIF, an animated SVG, and a static PNG. The animation uses 50 frames at 80 ms per frame. Its renderer verifies the loop duration, transparency, motion, and stationary brackets. The standalone mark is available separately; the README keeps its single logo banner.

The default command verifies all six illustrated source snippets with the local scanner CLI in isolated temporary folders, renders the assets, refreshes the three marked walkthrough blocks in the README, and checks the outputs. The examples are scanned as text, never executed. No scanner code, runtime dependencies, or self-scan configuration is changed.

Edit `scenarios.py` for source snippets, selected findings, fixture provenance, and captions. Edit `render_assets.py` for the shared layout, overview, or timing. Regenerate after editing: each animation SVG is editable on its own, but manual SVG edits are overwritten by regeneration. Change the logo in its native lockup SVG.

`verify_assets.py` checks CLI exit codes, finding names and severity, clean paired examples, GIF dimensions, stage durations, motion, infinite looping, static-image dimensions, XML validity, README links, and a combined GIF budget below 1.5 MiB. All GIFs use 10 frames per second and one palette per animation to avoid flicker. Identical held frames may be combined by the encoder without changing timing.

The renderer preserves code indentation. SVG font stacks use Arial/Helvetica for prose and Consolas/Liberation Mono for code. System fonts resolve the stacks; use the same fonts when exact cross-machine typography is required. Review the overview and every walkthrough scene at approximately 800 pixels wide after changing layout or copy.

## Visual principles

- Paper: `#F4F4EF`; ink: `#111111`; secondary text: `#62625E`.
- No gradients, neon glow, shields, padlocks, brains, robots, or hacker imagery.
- Motion communicates inspection and progression, with no flashing or decorative particles.
- All overview rows remain visible throughout the loop; only inspection and findings change.
- Runtime-only protection and universal detection are not implied.

The four corner brackets form a scan window. The dot field represents noisy or untrusted AI context; the dense central pixel represents the inspected trust boundary.

Use lowercase `secchecker` in the wordmark, with `TRUST BOUNDARIES FOR AI` beneath it. The supporting line in the overview appears once: `Local analysis · No LLM judge · Zero runtime dependencies`.
