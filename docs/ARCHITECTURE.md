# Architecture and API contract

Browser → same-origin Node API → bounded job → public DNS validation → pinned HTTP/TLS connection → deterministic checks → report → browser comparison/export.

## API

`POST /api/scans`, Content-Type application/json, body `{"url":"https://example.com"}` creates a job. Only the `url` key is accepted; maximum request body is 2 KiB. Returns 201 `{id, token, status:"queued"}`. Use that random token only in the `X-Scan-Token` header.

`GET /api/scans/:id` returns `{id,status,stage,report?,error?}`. States are queued, running, complete and failed. A complete job can contain a partial scan report; those are different concepts. Tokens are never placed in URLs or persisted to disk.

`DELETE /api/scans/:id` aborts and removes the job. `GET /api/health` returns basic process readiness. Reports expire after ten minutes. Restarting the process clears all jobs. No database or third-party telemetry is used.

## Limits

| Boundary | Current limit |
|---|---|
| Target requests | 6 total, including redirect hops and HTTP entry-point probe |
| Redirect chain | 3 redirects per fetch chain |
| Response bytes | 1 MiB per response, enforced while streaming |
| Request time | 8 seconds including response body |
| Scan deadline | 25 seconds, including waiting for DNS |
| Server job deadline | 30 seconds |
| UI deadline | 45 seconds, cancels job |
| Concurrent jobs | 2 per process |
| Job retention | 100 records, 10 minutes |
| Client admission | 8 scans per 10 minutes by socket IP |
| Target admission | 4 scans per hostname per 10 minutes |
| Global admission | 50 scans per 10 minutes per process |
| Client limiter entries | 256 |

The counts are per process. A reverse proxy's address is shared by its users because forwarded IP headers are intentionally not trusted. A public service needs edge/distributed quotas before horizontal scaling.

## Outbound trust boundary

Only HTTP(S), DNS hostnames and standard scheme ports are accepted. Literal IPv4/IPv6, single-label/local names, credentials and query parameters are rejected; fragments are removed. Every redirect is parsed and checked again. HTTPS-to-HTTP downgrades are refused. Every DNS answer must be public; mixed public/private answer sets fail closed. The chosen vetted address is supplied to Node's lookup callback for the connection; the original hostname is retained for TLS identity checks. No second uncontrolled DNS lookup chooses the destination.

TLS verification is enabled. Requests carry no cookies, authorization or user headers. Accept-Encoding requests identity; unexpected encoded responses are not decompressed. Bodies are read within byte/time limits and never executed. No subresource, secret-file, admin-path, API enumeration or port scan is performed.

## Inbound trust boundary

The process binds loopback by default. Host is checked against exact configured authority including port, and browser Origin is checked against allowed origins. Cross-site API requests are rejected; there is no wildcard CORS or preflight allowance. JSON-only creation rejects simple-form submissions. Reports need a random 256-bit token, with timing-safe comparison. The static file list is explicit; source files, dotfiles, reports and tools cannot be fetched through the server.

## Report 2.0

Each report has id, target, finalUrl, timestamps, durationMs, complete/partial status, summary, findings, coverage, requests and optional TLS metadata. Each finding has a stable ID, title, category, action/pass/unknown status, priority, observed/inferred/unknown confidence, evidence strings, explanation, fix and optional source link.

Cookie identity uses a digest of name/domain/effective path; values are not retained, and duplicate identities cannot produce a reliable passing comparison. Headers are data, escaped in the UI. Copied fix prompts explicitly delimit all target evidence as untrusted. Do not treat that delimiter as a substitute for a consuming agent's own prompt-injection defenses.

`engine.js` uses a separate older 1.0 deployment evidence contract. It remains an optional utility and is not consulted by the URL scanner. Do not accidentally convert banner evidence into attested running-process evidence.

## Honest limitations

No patch/compromise certification, no browser execution, no authenticated routes, no exhaustive HTML parser, no live advisory feed, no direct source audit, no automatic code changes. The response may be a CDN/WAF/login page. Static markup checks inspect a bounded subset and can miss dynamic or malformed content; wording is scoped to the sampled markup. Token-bearing URL paths are possible even though query strings are prohibited, so submit only public pages.
