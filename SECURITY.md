# Security Policy

## Supported versions

| Version | Security fixes |
|---------|---------------|
| 0.3.x   | Yes — current release |
| 0.2.x   | No — upgrade to 0.3.x |
| < 0.2   | No |

## Reporting a vulnerability

If you discover a security vulnerability in secchecker, please **do not open a public GitHub issue**.

Report it privately by emailing: **vishnu7stanite@gmail.com**

Include in your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The secchecker version affected
- Any suggested fix, if you have one

You will receive an acknowledgement within 48 hours. If the vulnerability is confirmed, a fix will be released as a patch version and credited to you in the changelog (unless you prefer to remain anonymous).

## Scope

This policy covers the secchecker package itself. It does not cover:

- False negatives (patterns that secchecker fails to detect) — report these as regular issues
- Vulnerabilities in projects that secchecker scans — report those to the respective project maintainers
- Dependencies of secchecker's dev extras (pytest, coverage) — report those to the respective maintainers

## Responsible disclosure

We ask that you give us reasonable time to patch and release a fix before any public disclosure. We aim to resolve confirmed vulnerabilities within 14 days of a verified report.
