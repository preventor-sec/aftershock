# Evidence model

The primary contract is report schema 2.0 in ARCHITECTURE.md. Observed means the sampled response supports the exact statement. Inferred means a disclosed version suggests a relevant advisory but actual deployment/backports still need verification. Unknown means the scan did not establish the answer.

A passing check is narrow: e.g. an HTTPS connection was established or no explicit HTTP resource appeared in supported sampled markup. It is not an all-clear. A missing CSP header is a hardening observation, not evidence of an XSS exploit. The UI uses remediation priorities rather than claiming formal CVSS severity.

Reports distinguish complete versus partial collection. Browser comparisons require the same final URL, newer complete reports, and successful nonempty final responses before a new passing check can count as improvement. Missing/unknown results, changed destinations and partial responses do not count.

Cookie values and names are omitted; a value-free digest of cookie name/domain/path stabilizes comparison. Duplicate cookie identities cannot yield a reliable passing comparison. No remote bodies are persisted. URL paths can be sensitive; only public non-secret paths should be submitted, while query strings and embedded credentials are rejected.

Legacy engine.js schema 1.0 is an optional deployment-evidence utility from the earlier iteration. It is not the source of remote scan conclusions and its evidence must not be confused with public response banners.
