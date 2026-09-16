# SecChecker website

Static landing page for SecChecker.

## Design language

- paper background: `#F4F4EF`
- near-black ink: `#111111`
- secondary text: `#62625E`
- muted inspection red: `#B84A3A`
- no gradients, glow, glass, shadows, or decorative AI imagery
- square geometry, thin rules, monospace metadata
- motion only when it communicates inspection or a trust crossing

## Run locally

```bash
cd website
python -m http.server 8080
```

Then open `http://localhost:8080`.

No build step or package installation is required.

## Content rule

Website claims must describe shipped SecChecker behaviour. Planned topology discovery, framework semantic packs, whole-program trust-flow reconstruction, and runtime enforcement should not be presented as current capability until implemented and evaluated.
