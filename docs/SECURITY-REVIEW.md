# Focused security review

Reviewed 22 October 2026. This is a focused review of our authored scanner/API and adversarial fixture testing, informed by the Cloudflare security-audit skill in **guidance mode**. It is not the skill's full six-phase audit, not an endorsement, and not an audit of any scanned third-party website. No target JavaScript or downloaded code was executed. Tests used our own bounded fixtures and a separately identified passive example.com smoke scan.

## Corrections made during independent review

| Area | Issue | Correction and verification |
|---|---|---|
| SSRF | Short IPv6 hextets could satisfy a textual public-prefix pattern | Numeric 2000::/3 boundary, reserved/transition exclusions; regression fixtures |
| Resource use | Malformed repeated HTML openings could cause excessive parser work | Monotonic bounded traversal, tag budget, unknown on incomplete parsing |
| Finding accuracy | Wildcard framing directives looked like effective restrictions | Report directive presence only; do not claim an effective embedding defense |
| Finding accuracy | Comments, canonical links and JS/attribute strings could look like active HTTP content | Skip comments/raw-text bodies, parse quoted attributes, scope reference claims; fixtures |
| Comparison | Positional cookie IDs could match different cookies after reordering | Stable value-free name/domain/path digest; duplicate identities unknown |
| Comparison | Changed/partial/error response could look improved | Require newer complete reports with same final destination and successful nonempty responses |
| Agent handoff | Header evidence might contain instructions | Escape UI text; explicit untrusted-data delimiters and no-follow instruction in copied prompt |
| API token | Non-ASCII token changed UTF-8 length | Strict token format and equal buffer lengths before timing-safe comparison |
| API body | Oversized chunked body could reset before a clean error | Bounded iterator with non-destroying return; close after 413 |

## Boundaries examined

Public DNS validation, selected-address pinning, redirect revalidation, HTTPS downgrade prevention, TLS trust, response limits, deadline/cancellation handling, malformed content, cookie privacy, banner uncertainty, Host/Origin checks, simple-request CSRF prevention, token-protected reports, static-file allowlist, job expiry, concurrency and single-process quotas.

No remaining bypass was identified in this focused source review. That is a coverage statement about the reviewed implementation, not a guarantee of absence. Public deployment needs its own edge, network, quota and operational review.

## Remaining limitations

- A CDN, bot challenge, login page or successful error page can differ from the origin. The tool reports the observed response and cannot always identify disguised responses.
- HTML inspection is deliberately bounded and partial; dynamic content, entity-obfuscated URLs and CSS are outside coverage. It is not a browser parser.
- DNS policy is conservative and may reject public services with unusual/special-purpose answer sets. Only one vetted address is attempted per request.
- Single-process limits are not sufficient for a scaled anonymous public service. Origin verification does not authenticate users.
- No persistent report storage, distributed queue, live advisory feed, authenticated scan or exploitation check is included.
- Prompt delimiters reduce ambiguity; a downstream agent must still enforce its own untrusted-data rules.

Upstream skill: https://github.com/cloudflare/security-audit-skill
