# secchecker demo

This directory contains an intentionally vulnerable application used to demonstrate what secchecker detects.

**Do not deploy any of this code.**

## What's in here

| File | Vulnerabilities |
|---|---|
| `app.py` | Hardcoded OpenAI API key, prompt injection, eval of LLM output, RAG data leakage |
| `Dockerfile` | Unpinned base image, secrets in ENV, curl-pipe-bash |
| `terraform/main.tf` | Open security group, public S3 bucket, hardcoded AWS credentials, public RDS |

## Run the demo

```bash
pip install secchecker

# Scan everything at once
secchecker demo/ --type all

# Scan only LLM/AI vulnerabilities
secchecker demo/ --type llm

# Scan only infrastructure misconfigs
secchecker demo/ --type devsecops

# Generate a SARIF report for GitHub Security tab
secchecker demo/ --type all --format sarif --output demo_report.sarif

# Generate a shareable HTML report
secchecker demo/ --type all --format html --output demo_report.html
```

## Record the terminal GIF

Install [asciinema](https://asciinema.org) and [svg-term-cli](https://github.com/marionebl/svg-term-cli):

```bash
pip install asciinema
npm install -g svg-term-cli

# Record
asciinema rec demo.cast --command "secchecker demo/ --type all"

# Convert to SVG (embeds in README without a CDN)
svg-term --in demo.cast --out demo.svg --window --width 90 --height 30

# Or convert to GIF
# Install agg: https://github.com/asciinema/agg
agg demo.cast demo.gif
```

Then add to README.md:
```markdown
![secchecker demo](demo/demo.gif)
```
