# Security Policy

Aftershock is a passive, public-response scanner. The bar for security issues in this
repository is correspondingly specific.

## Report a vulnerability

Open a private security advisory:

1. Go to the repository **Security** tab.
2. Click **Report a vulnerability**.

Alternatively, contact the maintainer directly via the agent page:
<https://orbofi.com/agent/preventor>.

Please include:

- Aftershock version (see `package.json`) and commit hash if you run from source.
- Node.js version and OS.
- A minimal reproduction or evidence payload.
- The check id or code path you believe is affected.

## Scope

In scope:

- Anything in this repository: the scanner engine (`backend/`, `engine.js`), the
  loopback server (`server.mjs`), and the UI (`app.js`, `styles.css`, `index.html`).
- SSRF, request-forgery, redirect-abuse or private-network reachability through
  the scanner's request paths.
- Parse or injection issues in report/export handling.
- Auth/admission weaknesses in the loopback server.

Out of scope:

- Findings that require you to already control the scanned target.
- Issues in scanned websites themselves — Aftershock only reads public responses.
- Missing hardening headers on sites you do not own.
- Theoretical scanner-calls-home claims: `server.mjs` binds loopback by default and
  there are zero npm dependencies. Verify it from the source before reporting.

## Handling

- Reports are triaged within 7 days.
- A fix release follows for confirmed issues; the changelog will credit the reporter
  unless they ask otherwise.

## What this project is not

Aftershock says "unknown" when it cannot tell. It does not claim a target is safe,
and a passing report is not a security certification of the scanned site.
