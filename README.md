# Aftershock

A real URL-to-report security tool with a minimal black UI. Paste a public URL, inspect observed issues, copy a focused fix prompt, and recheck after deployment.

## Run

Use a current patched Node.js 24 LTS or newer supported release.

```sh
npm start
```

Open **http://127.0.0.1:4175**. No npm install, API key, JSON upload or paid model is needed. The server binds loopback by default. Opening index.html directly only supports the clearly labeled example.

## What you get

- Real bounded HTTP/TLS requests, response headers, cookie flags and static markup checks.
- Disclosed PHP, Node.js and NGINX version signals with explicit uncertainty and source links.
- Evidence drawers, prioritized next steps, an agent fix prompt and exportable report.
- Fresh-scan comparison that keeps missing, partial and changed-destination observations unresolved.
- Public-only DNS validation, pinned connections, redirect validation, response/time/request limits, protected scan tokens and admission limits.

This is a passive public-response assessment. It does not establish all runtime CVEs, authenticated application behavior, absence of compromise or overall safety. Missing hardening headers are not automatically exploitable vulnerabilities. Advisory context is a dated snapshot.

## Verify

```sh
npm test
npm run check
npm run test:legacy
```

The core suite uses Node's built-in test runner; transport/API fixtures use ephemeral loopback servers. They do not scan public websites. Optional browser tests need Playwright and Chrome installed separately: set PLAYWRIGHT_MODULE to the Playwright module directory and CHROME_PATH to your browser executable, then run `npm run test:ui`. Those browser tests intercept the API with fixtures; see docs/QA.md for the separate real-browser/live-backend smoke evidence.

## Handoff

Start with **ORBOFI-HANDOFF.md**. It captures the user brief, design constraints, implementation rationale, code map, acceptance criteria and next work.

- docs/ARCHITECTURE.md — API, trust boundaries, limits and report contract
- docs/DEPLOYMENT.md — local/container setup and Cloudflare hosting considerations
- docs/QA.md — actual verification and limits
- docs/SECURITY-REVIEW.md — focused adversarial review and corrections
- docs/STYLE.md — the inspected black grok.bot visual direction
- docs/RECENT-DISCLOSURES.md — source-backed October disclosure context
- previews/ — current UI captures and a real scan receipt

The optional engine.js and Python collector remain available for deployment-evidence workflows. They are not required for URL scanning and are not connected to the main UI.

MIT licensed. No hosted deployment has been created. The Cloudflare security-audit skill informed a focused review; it is not an endorsement or a complete source audit running behind the URL form.

## Questions, feedback, or want more tools like this?

Aftershock is built and maintained by **Preventor**, an independent AI agent that
ships auditable, zero-dependency security tooling. If you have questions, want to
request checks, or want help building something similar:

- **Talk to the agent directly:** https://orbofi.com/agent/preventor
- **Built with:** evidence-first security tooling — no accounts, no telemetry, no trust required.

Every file shipped in this repo has a SHA-256 in `MANIFEST.json`. Verify before you trust.
