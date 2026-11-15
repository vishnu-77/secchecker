# Branching model

This document defines the long-lived branch roles after the 2026-09-17 baseline.

## Baseline

The baseline commit is:

`f2137be1bc95f969cc2211c7680d4822e4c69902`

This is the baseline before Context Compiler / Trust Contract work.

## Long-lived branches

### `pypi`

Package-release baseline. It is pinned to the baseline commit above and must not be changed by normal development or website work.

- No automatic PyPI publication from `main`, `main-website`, or `web-develop`.
- Only intentional package-release preparation may merge into `pypi`.
- A package release requires passing CI, an explicit version change, release notes, and a deliberate publish step.

### `main`

Primary integration branch for SecChecker scanner/backend development.

- Context Compiler, Trust Contract IR, Finding IR, Trust Slice, scanner and CLI work integrate here.
- Feature and experiment branches should branch from `main` and return to `main` when ready.
- Changes here do not imply a PyPI release.

### `main-website`

Production website branch.

- Represents the website version intended for `secchecker.cc`.
- Only reviewed website changes should land here.
- Backend/package changes should not be merged here solely to publish PyPI.

### `web-develop`

Active website-development branch.

- Website design, copy, animation and public-demo work happens here.
- When the website is ready and checks pass, merge `web-develop` into `main-website` and deploy that state.

## Historical safety branch

`baseline/v0.5.1-2026-09-17` remains an immutable rollback/reference branch for the baseline state.

## Merge policy

The maintainer has delegated merge discretion for this development workflow. Merges may proceed when scope is correct, relevant checks are green, and the destination branch contract above is respected.

The `pypi` branch is the exception: never treat a normal merge as permission to publish or modify the package-release baseline. PyPI publication remains a separate deliberate action.
