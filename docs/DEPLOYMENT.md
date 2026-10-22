# Run and deploy

## Local

Install a current patched Node.js release in the 24 LTS line or a newer supported line, extract the archive, open a terminal in its folder, and run `npm start`. No npm install is required. Open http://127.0.0.1:4175. The browser and API share one origin. Opening index.html directly permits only the illustrative example and displays instructions for starting the backend.

PORT changes the listener port. HOST defaults to 127.0.0.1. Non-loopback binding requires an explicit PUBLIC_ORIGIN such as `https://scan.your-domain.com` with no trailing slash. PUBLIC_ORIGIN adds that exact public Host and Origin; it is not an authentication mechanism.

## Container

`docker build -t aftershock .`

`docker run --rm -p 127.0.0.1:4175:4175 -e HOST=0.0.0.0 -e PUBLIC_ORIGIN=https://scan.your-domain.com --read-only --cap-drop=ALL --security-opt=no-new-privileges --memory=256m --cpus=1 aftershock`

The image runs as the unprivileged node user. A current official Node 24 image is selected at build time. Resolve and pin a verified patched image digest in your production pipeline. The container recipe is included but was not built in this Windows workspace.

## Cloudflare where it fits

Keep the scanner in a Node/container service so its vetted-address connection policy remains intact. Cloudflare Tunnel can expose the loopback service without opening an inbound origin port; Cloudflare Access can restrict the preview to approved testers. Create the Access application/policy before sharing the hostname, and validate that bypass routes do not expose the origin. Keep tunnel credentials outside this repository.

Official setup: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/

Access for HTTP apps: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/

For a public anonymous release, use explicit edge bot/abuse controls and shared quotas. Current single-process token/rate limits are useful local defenses, not a multi-region abuse platform. Add operational monitoring that logs event IDs and counts, not target bodies, cookies or tokens. Define retention/privacy policy and a contact address before launch.

No Cloudflare account, deployment, DNS record, billing resource or hosted URL was created by this handoff. The provided Cloudflare audit skill influenced source review; that is independent of hosting.

## Production readiness remaining

Shared quotas and target cooldowns; maintained advisory feed with stale-data handling; monitoring and alerting; TLS/edge configuration; host and egress hardening; privacy/legal copy appropriate to the chosen service; independent deployment-specific security review. Add authentication for private team previews. Do not represent this local release as already validated for an unrestricted public launch.
