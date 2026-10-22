# Changelog

## 0.4.1

- Added `SECURITY.md` (private advisory reporting, scope, handling policy).
- Added a GitHub bug report issue template.
- `MANIFEST.json` now covers 43 files with SHA-256 integrity hashes.

## 0.4.0 — 22 October 2026

### Header redesigned (same text, new position)
- The horizontal top bar was replaced with a persistent left rail: vertical wordmark,
  stacked "How it works" / "Advisories" navigation, bottom-anchored "View example" CTA,
  and a signal footer ("Evidence first. Uncertainty included.").
- Content previously centered under the top bar now composes against the rail.
  Mobile keeps a compact single-row header with the same texts.
- `#nav-example` id preserved; app.js behavior unchanged.

### Repo hygiene
- Removed legacy editor/config references from the shipped tree: `.gitignore` now
  tracks only runtime-generated files; no test fixture lockfiles are shipped.
- Source contains zero third-party model references; verified by keyword audit across the tree.
