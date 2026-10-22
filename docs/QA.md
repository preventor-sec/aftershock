# Verification record

Date: 22 October 2026. Environment: Windows, Node v24.13.0 provided by the workspace, Python 3.12, installed Chrome with Playwright. Deploy with a current patched supported Node release; the test environment's version is recorded for reproducibility, not recommended as a production security baseline.

## Passed

- **43 scanner/API tests** via `npm test`: public/reserved IP policy, numeric URL tricks, mixed DNS, rebinding and redirects, pinned-address selection, real loopback body caps, timeout and cancellation, honest findings, cookie privacy/stability, bounded static HTML, uncertainty, exact Host/Origin rules, explicit static assets, JSON/body limits, token checks, sanitized failures, lifecycle, concurrency, rate limits and TTL.
- **40 optional legacy evidence-engine checks** via `npm run test:legacy`.
- **4 optional Python collector tests** using mocked processes. No actual Docker container collection was performed.
- JavaScript syntax checks for server and frontend.
- Browser fixture assertions: labeled example makes no API request, bare domain normalization, API report rendering, evidence drawer, fix/export flows, cancellation token, API failures, keyboard-compatible tab state, mobile no overflow, and conservative comparisons for unknown/partial/changed-destination/error responses. A complete newer passing response at the same destination earns an observed improvement. Browser tests intercept API responses and do not prove live scanning by themselves.
- **Separate live browser-to-backend smoke test**: local real API serving the UI, submitted example.com, actual outbound HTTPS and HTTP requests, certificate verification with TLSv1.3, 2 target requests, 10 observations, exported report validated, fix plan rendered, desktop/mobile captures, no page errors, no mobile horizontal overflow.

The retained `previews/live-report.json` is a real example.com response receipt, clearly distinct from the UI's illustrative sample. Results describe that time and response only; future results can differ. Screenshots in previews/ show the current UI.

## Review loop

An independent reviewer examined the fetcher, checks, browser comparison and API boundaries. Issues were corrected and covered by fixtures; see SECURITY-REVIEW.md. A malformed-markup assertion initially expected a clean pass and was tightened to unknown with the parser change. The final 43-test suite is green.

## Test harness caveats

This desktop environment sometimes delayed shell startup and browser teardown. Browser assertions completed successfully. The browser fixture harness now uses an owned BrowserServer with bounded graceful-close and owned-process kill fallback. The live smoke used bounded screenshots and cleanup. No unrelated processes were terminated.

Browser download initiation and the exported JSON textarea were verified. This environment can cancel browser filesystem downloads, so copy/export fallback is included; no claim is made that every browser will save the requested file automatically.

## Not performed

No production/cloud deployment; Docker image not built; no multi-instance load test; no full Cloudflare six-phase source audit; no automated accessibility certification; no authenticated target tests; no exploit payloads; no hidden-file/endpoint enumeration; no installed OSV/ZAP integration; no live advisory refresh. The network scan did not execute website code.

## Reproduce

`npm test` runs local fixtures only. `npm run test:ui` needs Playwright and Chrome (see README). A manual live check: `npm start`, open the printed URL, enter a public URL you are authorized to assess, inspect Coverage & evidence, open the fix plan and export the report. Recheck after changing your own deployment.
