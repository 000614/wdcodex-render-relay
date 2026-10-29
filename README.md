# WDCodex Render relay

A dependency-free Node.js relay for one personally controlled WDCodex host. This repository contains relay code only: no engineering files, Codex authentication, passwords, conversation records, or deployment secrets.

Deploy a **Free Web Service** on Render. Build: `node --check server.mjs`; start: `node server.mjs`; health check: `/healthz`; runtime: Node 24. Set `UPSTREAM_ORIGIN` to the host's current HTTPS tunnel origin. Render supplies `RENDER_EXTERNAL_URL`; outside Render, also set `PUBLIC_ORIGIN` to the relay's HTTPS origin. Do not put either setting into source code. The upstream host retains its existing publicOrigin pointing to its tunnel.

The relay validates its own browser Origin and Host, then rebases the request Origin for the fixed upstream. It passes the existing WDCodex session cookie and CSRF token, preserves secure host-only login cookies, streams SSE/downloads without buffering, and blocks local control endpoints. It accepts no arbitrary proxy targets. HTTPS certificate verification stays enabled. This relay uses the existing host login; it does not possess an OpenAI key or run Codex in the cloud.

Run tests with `node --test test.mjs`. Test-only loopback HTTP support is available through the exported factory, not the production command-line entry point.

Render's free service can sleep after inactivity and lose its local filesystem on restarts. No persistent data is stored here. There is no keepalive job. Free usage quotas and platform suspension limits still apply; keep the free plan, review workspace spending settings, and do not enable paid add-ons. A sleeping relay may take about a minute to start. The home PC and its tunnel must stay on. Changing the tunnel URL requires updating UPSTREAM_ORIGIN in Render.

Only use this service where personal remote development is allowed. Availability from any particular corporate network is not guaranteed.
