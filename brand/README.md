# Visual system

SecChecker uses a paper-first diagnostic language shared with the wider product family: warm e-ink paper, matte geometry, restrained motion, thin rules, and explicit trust-boundary diagrams.

The primary identity is the **origami paper lock**:

- folded paper body = code and configuration under inspection
- dark key-shaped shackle = controlled authority rather than generic “cyber” ornament
- single muted red dot = the point currently being inspected
- lowercase `secchecker` wordmark = quiet, technical, developer-first

The mark intentionally avoids glossy surfaces, gradients, shields, hacker imagery, neon, glassmorphism, 3D chrome, and decorative AI motifs.

## Core assets

- `secchecker-mark.svg` — primary square mark and favicon source.
- `secchecker-lockup.svg` — horizontal mark + lowercase wordmark + `TRUST BOUNDARIES FOR AI` descriptor.
- `secchecker-banner.png` — legacy raster banner; the native SVG lockup is now the source of truth and should replace raster use when possible.
- `secchecker-mark.gif`, `secchecker-mark-animated.svg`, `secchecker-mark-static.png` — generated motion/static derivatives. Regenerate after the origami motion pass is updated.

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
| Fold light | `#F1F0EA` | paper face |
| Fold mid | `#D8D7D1` | secondary fold |
| Fold dark | `#BDBCB6` | depth through flat tonal contrast |
| Inspection red | `#B84A3A` | current inspection / critical state only |

Red is not a decorative brand wash. It is a state-bearing accent and should normally occupy less than ~3% of a composition.

## Geometry

- square or near-square composition
- thin 1px–1.5px rules for diagrams and layout
- zero or very small border radius in UI surfaces
- no drop shadows
- no simulated glass
- no gradients
- no glow
- no decorative blur
- fold depth is communicated by flat tonal changes, not lighting effects

## Motion principles

Motion must explain inspection, not advertise “AI”.

Preferred motion vocabulary:

1. a paper fold opens or closes
2. the red inspection dot moves to the active boundary
3. a path stops at a boundary, is checked, then continues or terminates
4. findings reveal through line/dot state changes

Avoid floating cards, particles, pulsing halos, bouncing icons, continuous parallax, or ambient motion with no analytical meaning.

For reduced-motion environments, every animation must degrade to a readable static state.

## Website language

The landing page under `website/` is the reference implementation for the updated design language.

Core message:

**Inspect the trust boundary before AI becomes authority.**

Supporting line:

`Local analysis · No LLM judge · Zero runtime dependencies`

The website should remain accurate to shipped capability. Do not visually imply complete framework understanding, whole-program trust-flow reconstruction, or runtime enforcement until those features exist.

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
- Do not recolour the whole lock red; only the inspection dot carries the red accent.
- Do not add a shield, robot, brain, padlock keyhole overlay, or binary digits around the mark.
- Do not add texture that reduces favicon legibility.
- At very small sizes, simplify fold lines before removing the inspection dot.
- Keep `secchecker` lowercase in the primary wordmark.
