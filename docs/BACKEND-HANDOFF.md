# Backend handoff

The backend is now implemented. Start at ../ORBOFI-HANDOFF.md and ARCHITECTURE.md.

server.mjs serves the app and asynchronous scan API. backend/safe-fetch.mjs enforces public destination and transport boundaries; backend/checks.mjs creates deterministic observations; backend/scan.mjs orchestrates the scan and report.

This supersedes the earlier backend-only proposal. No JSON upload is required. Deeper repository/deployment evidence remains optional future functionality. Cloudflare integration is documented in DEPLOYMENT.md; no Worker or hosted deployment is silently implied.
