# Aftershock — Orbofi agent handoff

Status: working local full-stack implementation, v0.3.0. Prepared 22 October 2026. Read README.md, docs/ARCHITECTURE.md and docs/QA.md before changing behavior.

## What the user asked for

People should paste a website URL and get a real scan, a useful answer, and an actionable next step. No JSON upload requirement. The design reference is the BLACK, minimal grok.bot / x.ai/bot treatment: generous space, large centered white typography, near-black canvas, restrained borders and pill controls. The earlier light/lime dashboard was rejected. Preserve the current visual direction.

The motivating moment is rapid security disclosures affecting PHP, Node.js and other stacks. The narrative is: **Attackers can automate. Your response should too.** The user proposed “millions of agents scanning the internet.” We did not substantiate that number and intentionally do not publish it as a fact.

## What actually works

`npm start` starts one Node process serving both the UI and API. URL submission creates a real bounded HTTP scan, the browser polls genuine progress, and the report shows response evidence, actionable fixes, uncertainty and coverage. The user can copy a fix prompt for their developer/agent, deploy a fix, run another scan, compare observations and export a report. No API keys, paid model, upload or dependency installation is needed for local use.

The scanner reads only the supplied page and bounded redirects plus its HTTP entry point. It examines transport/TLS, selected security headers, cookie attributes, static HTTP resource/form references and version banners. It is a passive public-response assessment, not an exploit scanner. It cannot certify hidden runtime CVEs, authenticated application behavior, absence of compromise, or every backend worker. The important product contract is a reliable small answer with visible limits.

## Decisions and rationale

- Deterministic checks first: an LLM is not needed to report a header or enforce DNS safety. This keeps the core inexpensive, inspectable and reproducible.
- Node owns outbound requests because this implementation validates DNS and pins the vetted address into its HTTP/TLS connection. Do not replace this with a naive Worker `fetch(url)` and assume the same SSRF guarantees.
- Cloudflare's security-audit skill was used in guidance mode for focused source review and evidence discipline. It is not running behind the UI and no full six-phase audit certification is claimed. Private source audits need a separate authorized source workflow and enforced sandbox.
- Do not say “safe,” “unaffected,” or “fixed” simply because banners vanish or a CDN answers. Recheck improvements require new passing evidence; partial scans, changed destinations and missing results remain unresolved.
- Report urgency as remediation priority, not a CVSS score. Missing hardening headers alone are not demonstrated exploitation.
- The distinct product value is the short loop: URL → observed evidence → focused agent fix brief → new response comparison. We do not claim that passive scanning itself is a new invention.

## Where to work

| File | Responsibility |
|---|---|
| server.mjs | Same-origin API, job tokens, admission limits, expiry, cancellation, explicit static asset serving |
| backend/safe-fetch.mjs | Public destination policy, DNS pinning, redirect validation, TLS and resource bounds |
| backend/checks.mjs | Pure checks and dated PHP/Node/NGINX banner hints |
| backend/scan.mjs | Scan orchestration, report assembly, observed/unknown coverage |
| index.html / styles.css / app.js | Current dark UI, polling, fix prompt, comparisons, exports |
| data.js | Curated advisory context, not a live feed |
| tests/ | Scanner, independent adversarial, API and browser regressions |
| engine.js / tools/collect_evidence.py | Optional legacy deployment-evidence utilities, not the URL flow |

## Recommended next work after accepting this handoff

1. Choose the hosting account/domain and deploy the same process behind TLS and access/abuse controls. Container recipe is included; no hosted deployment or DNS change has been made.
2. For a public anonymous launch, add shared rate limits/queues, bot challenge validation and target cooldowns across replicas. Current limits are intentionally single-process and ignore spoofable forwarding headers.
3. Add a signed/versioned advisory update process and expiration policy. The bundled rules are a dated snapshot, not real-time intelligence.
4. If deeper CVE coverage is required, implement a separate opt-in connector for repository/dependency/deployment evidence. Keep URL scans instantly useful, and never make uploading JSON the default journey.
5. For authorized source audits, apply the full Cloudflare skill with its actual sandbox and independent validation requirements. OSV-Scanner can complement dependency inventory; it is not invoked by this build.
6. Expand checks only with adversarial fixtures and evidence rules. Avoid arbitrary-path discovery, payload execution, remote shelling or broader scan fanout disguised as a passive check.

## Acceptance criteria to preserve

- A user enters a URL or bare public domain; a real server request produces a report.
- Missing backend, invalid URLs, denied DNS, timeouts and cancellations are understandable states.
- No credentials, cookie values or query strings enter a stored/exported scan; target response text is escaped and marked untrusted in fix prompts.
- No SSRF bypass environment variable or localhost scan switch exists in the public API.
- Rescan disappearance does not become a remediation claim.
- Mobile layout works; keyboard tabs and dialogs work; no external UI assets are required.
- Tests and live-smoke evidence are documented without conflating synthetic fixtures with real scans.

## Reference sources

- Cloudflare skill: https://github.com/cloudflare/security-audit-skill
- Cloudflare Tunnel: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/
- Cloudflare Access: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/
- OSV-Scanner: https://google.github.io/osv-scanner/usage/
- ZAP passive baseline: https://www.zaproxy.org/docs/docker/baseline-scan/
- Verified disclosure context: docs/RECENT-DISCLOSURES.md

No credentials, accounts, hosted deployment or social posting authorization are transferred by this ZIP. The code is MIT-licensed; upstream tools retain their own licenses.
