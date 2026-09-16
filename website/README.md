# SecChecker website

The public SecChecker landing page lives in this directory as a dependency-free static site.

## Public-surface rule

The website may describe the product, how to run it, what broad classes of AI-security issues it checks, how evaluation is approached at a high level, and where the tool fits in a development workflow.

Do not publish implementation internals here. Keep scanner architecture, rule mechanics, test/corpus construction, internal benchmark paths, triage notes, root-cause analysis, roadmap detail, and repository-internal terminology off the public website.

## Design language

- paper background: `#F4F4EF`
- near-black ink: `#111111`
- secondary text: `#62625E`
- muted inspection red: `#B84A3A`
- approved origami lock mark
- no gradients, glow, glass, shadows, or decorative AI imagery
- square geometry, thin rules, monospace metadata

## Run locally

```bash
cd website
python -m http.server 8080
```

Then open `http://localhost:8080`.

No build step or package installation is required.

## Claim rule

Website claims must describe shipped SecChecker behaviour. Do not market planned or experimental capabilities as current product functionality.
