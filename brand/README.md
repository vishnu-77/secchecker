# Visual system

SecChecker uses a paper-first diagnostic language shared with the wider product family: warm e-ink paper, matte geometry, restrained motion, thin rules, and explicit trust-boundary diagrams.

The primary identity is the **origami paper lock**:

- asymmetric folded paper body = code and configuration under inspection
- dark keyhole shackle = controlled authority without generic cyber ornament
- status dot = yellow while checking, green when settled/clear
- lowercase `secchecker` wordmark = quiet, technical, developer-first

The mark intentionally avoids glossy surfaces, gradients, shields, hacker imagery, neon, glassmorphism, 3D chrome, and decorative AI motifs.

## Core assets

- `secchecker-mark.svg` — primary mark and favicon source.
- `secchecker-lockup.svg` — horizontal mark + lowercase wordmark + `TRUST BOUNDARIES FOR AI` descriptor.
- `secchecker-banner.png` — legacy raster banner; the native SVG lockup is the source of truth.
- `secchecker-mark.gif`, `secchecker-mark-animated.svg`, `secchecker-mark-static.png` — generated motion/static derivatives; regenerate when the motion pass changes.

## Product walkthrough assets

| Visual | GIF | Static alternative | Editable motion SVG |
|---|---|---|---|
| Overview | [GIF](secchecker-hero.gif) | [PNG](secchecker-hero-static.png) | [SVG](secchecker-hero-animated.svg) |
| Prompt injection | [GIF](prompt-injection.gif) | [PNG](prompt-injection-static.png) | [SVG](prompt-injection-animated.svg) |
| MCP tool poisoning | [GIF](mcp-tool-poisoning.gif) | [PNG](mcp-tool-poisoning-static.png) | [SVG](mcp-tool-poisoning-animated.svg) |
| Tool-output execution | [GIF](tool-output-execution.gif) | [PNG](tool-output-execution-static.png) | [SVG](tool-output-execution-animated.svg) |

These walkthroughs are illustrated source inspections, not runtime-interception claims.

## Palette

| Token | Value | Use |
|---|---|---|
| Paper | `#F4F4EF` | canvas/background |
| Ink | `#111111` | type, rules, primary geometry |
| Secondary | `#62625E` | metadata and explanatory copy |
| Fold light | `#F0EEE7` | paper face |
| Fold mid | `#D4D2CB` | secondary fold |
| Fold dark | `#BEBDB7` | depth through flat tonal contrast |
| Status yellow | `#D8A624` | checking / in-progress state |
| Status green | `#698960` | settled / clear state and static identity |

Yellow and green are state-bearing accents, not decorative washes. The static mark defaults to green. The hero may transition once from yellow to green to communicate a completed check.

## Geometry

- asymmetric portrait lock composition based on the approved origami mark
- thin 1px–1.5px rules for diagrams and layout
- zero or very small border radius in UI surfaces
- no drop shadows
- no simulated glass
- no gradients
- no glow
- no decorative blur
- fold depth is communicated by flat tonal changes, not lighting effects

## Motion principles

Motion must communicate product state rather than advertise “AI”.

Preferred motion vocabulary:

1. the approved lock settles into place once on entry
2. the status dot begins yellow and resolves to green
3. a path stops at a boundary, is checked, then continues or terminates
4. findings reveal through line/dot state changes

Avoid floating cards, particles, pulsing halos, bouncing icons, continuous parallax, or ambient motion with no analytical meaning.

For reduced-motion environments, every animation must degrade to the final static green state.

## Website language

The landing page under `website/` is the reference implementation for the current design language.

Core message:

**Catch risky AI trust-boundary crossings before they ship.**

The public website must remain accurate to shipped capability and must not expose implementation internals.

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

Regenerate the standalone animated mark:

```bash
python brand/animate_mark.py
```

The animation generator should use `secchecker-mark.svg` as the source of truth. When changing the identity, update the SVG first and regenerate derivatives rather than manually editing generated files.

## Usage rules

- Prefer SVG for README, web, docs and product surfaces.
- Keep the mark on paper/neutral backgrounds where possible.
- Do not recolour the whole lock; only the status dot carries yellow/green state.
- Do not add a shield, robot, brain, binary digits, glow, or decorative security motifs around the mark.
- Do not add texture that reduces favicon legibility.
- At very small sizes, simplify fold lines before removing the status dot.
- Keep `secchecker` lowercase in the primary wordmark.
