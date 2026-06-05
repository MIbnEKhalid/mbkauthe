# Documentation Style Guide

[Back to docs index](README.md) | [Back to project README](../README.md)

Use this guide when adding or changing documentation source.

## File Placement

- Put setup walkthroughs and operational how-to content in `guides/`.
- Put endpoint, middleware, type, and error-code details in `reference/`.
- Put long API sections under `reference/api/` and link them from `reference/api.md`.
- Put executable database SQL in `schema/`.
- Put Mermaid source in `diagrams/` and rendered outputs in `images/`.

## Markdown Structure

- Use one `#` title per file.
- Keep files focused on one job; split a file when it becomes hard to scan or review.
- Add a small navigation line under the title for files below `docs/`.
- Prefer descriptive links such as `[Configuration guide](guides/configuration.md)` over raw paths in prose.
- Keep table-of-contents blocks short; rely on smaller files instead of very deep TOCs.

## Code Blocks

- Always include a language tag when the language is known: `javascript`, `json`, `bash`, `sql`, `env`, or `typescript`.
- Keep examples copy-pasteable where possible.
- Use placeholders for secrets and tokens; never include real credentials.
- Keep endpoint examples close to the endpoint they describe.

## Cross-Links

- Links from `docs/README.md` are relative to `docs/`.
- Links from `docs/reference/api/*.md` need one extra `..` segment to reach the docs index.
- After moving docs, run a Markdown link check before committing.

## Generated Assets

- Mermaid source is authoritative.
- Rendered images in `images/` should be regenerated when the matching `.mmd` file changes.
- Keep package scripts aligned with the source paths in `diagrams/`.
