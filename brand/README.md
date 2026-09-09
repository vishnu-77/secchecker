# SecChecker visual system

SecChecker uses an e-ink-inspired diagnostic language: monochrome, low-noise, functional geometry, sparse dot-matrix texture, and explicit trust-boundary diagrams.

## Core assets

- `secchecker-mark.svg` — primary square mark
- `secchecker-lockup.svg` — horizontal logo + wordmark
- `secchecker-hero-animated.svg` — source animation for web/docs use
- `secchecker-hero.gif` — rendered README animation fallback

## Visual principles

- paper: `#F4F4EF`
- ink: `#111111`
- mid: `#62625E`
- hairline: `#A7A7A0`
- no gradients
- no neon/cyber glow
- no shields, padlocks, brains, robots, or hacker imagery
- motion should communicate scanning, convergence, inspection, or state change
- animation should remain subtle and legible when reduced to a static frame

## Mark meaning

The four corner brackets form a scan window. The dot field represents noisy or untrusted AI context. The dense central pixel is the inspected trust boundary.

The mark is intentionally not a generic security symbol. It represents SecChecker's core idea: inspect where AI-controlled context crosses into something trusted or consequential.

## Wordmark

Use lowercase `secchecker`.

Supporting line:

`TRUST BOUNDARIES FOR AI`

Primary product statement:

`Static security analysis for AI trust boundaries.`

## Motion

The hero animation follows one sequence:

`context → convergence → scan → action`

It loops slowly and remains monochrome. Avoid decorative particles, glitch effects, rapid flashing, or continuous high-frequency movement.
