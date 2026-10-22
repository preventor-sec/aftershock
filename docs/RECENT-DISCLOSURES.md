# Recent disclosures beyond PHP and Node.js

Research snapshot: 22 October 2026. “Recent” here means disclosures/releases in October, not necessarily the date the underlying issue was discovered.

| Date | Item | What matters | Primary source |
| --- | --- | --- | --- |
| 14 Oct | NGINX protocol and memory-safety issues | Configuration-dependent alias/rewrite, HTTP/3, TLS session and AIO issues. NGINX rates these medium. Fixed releases include 1.30.6 and 1.31.7. | https://nginx.org/en/security_advisories.html and https://nginx.org/en/CHANGES |
| 14 Oct | Drupal Field UI RCE, CVE-2026-108097 | Core alone is not directly exploitable. Contributed/custom modules can expose paths, including an unauthenticated one. Fixes: 10.6.19, 11.3.19, 11.4.10; uninstalling Field UI is the documented interim mitigation. | https://www.drupal.org/sa-core-2026-014 |
| 21 Oct advisory | Go crypto/x509 trust update, CVE-2026-111943 | Adds a denylist for intermediate certificates no longer considered trustworthy, including cases not addressed by system trust updates alone. Fixed in 1.26.10 and 1.27.3. | https://pkg.go.dev/vuln/GO-2026-6809 |
| 6 Oct | WordPress 6.9.10 security release | Stored XSS, second-order SQL injection in WXR export, comment disclosure and other fixes. Older affected branches received courtesy backports. This is research context; no WordPress matching rule is implemented. | https://wordpress.org/documentation/wordpress-version/version-6-9-10/ |
| 19 Oct, updated 21 Oct | TeamUpdraft / UpdraftCentral breach | Connection keys were misused to create admins or install malicious plugins. UpdraftPlus 1.26.13 / 2.26.13 revoke those keys; owners still need to check their sites. This is a compromise/credential incident, not a clean version-floor problem. | https://teamupdraft.com/blog/security-incident-october-2026/ |
| 9 Oct | Hermes Agent session takeover and resource exhaustion | Login redirect parsing can expose an authorization code. Separate pre-auth memory/disk exhaustion advisories share fix 0.21.6. | https://www.tenable.com/security/research/tra-2026-65 and https://www.tenable.com/security/research/tra-2026-63 |
| 5 Oct | LangChain MongoDB chat-history injection, CVE-2026-106119 | Untrusted structured session IDs can affect MongoDB queries and expose other histories. `@langchain/mongodb` through 1.3.0; fix 1.3.1. | https://github.com/langchain-ai/langchainjs/security/advisories/GHSA-m6rx-h84q-8r95 |

These are selected relevant examples, not an exhaustive catalog. A vendor security release may contain several CVEs with different applicability conditions. The UI groups selected release floors and does not claim every listed CVE is exploitable on every affected-version deployment.
