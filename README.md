# ssl-cert-worker

Issues TLS certificates from Let's Encrypt (ACME v2, DNS-01 via the Cloudflare DNS
API) on Cloudflare Workers, stores them in R2, and distributes them to nodes that
pull periodically using per-node API keys (one key = one node).

- Single Worker deployment, single hostname (`ssl.example.com`).
- Admin panel: static SPA behind Cloudflare Access; admin API re-verifies the Access JWT.
- Node pull API: `ssl.example.com/v1/*`, Access bypass, bearer API keys, ETag/304.
- Renewal: daily cron creates Cloudflare Workflow instances for due domains.
- Requires the Workers **Paid** plan (free-tier CPU limits cannot perform issuance).

Status: implementation in progress — M0 (scaffold) + M1 (crypto core) complete.

## Local development

Prerequisites: Node.js >= 22 (Wrangler 4 requires it) and npm.

```sh
npm install
cp .dev.vars.example .dev.vars
npm run build:web          # placeholder SPA -> web/dist (required before wrangler dev / vitest)
npm run types              # regenerate worker-configuration.d.ts after changing wrangler.jsonc
npm run db:migrate:local   # apply migrations to the local D1 database (.wrangler/state)
npm test                   # workerd-pool tests (crypto + routing + schema)
npm run dev                # wrangler dev on http://localhost:8787
```

The admin API (`/api/*`) requires the `Cf-Access-Jwt-Assertion` header injected by
Cloudflare Access; without it, requests are rejected with 401 by design (M4 adds real
JWT verification and the handlers behind it).

Deployment placeholders: `wrangler.jsonc` currently carries placeholder D1/R2 IDs.
Replace them (`wrangler d1 create ssl-cert-worker`, `wrangler r2 bucket create
ssl-cert-artifacts`) before the first deploy.

Full design: [PLAN.md](./PLAN.md).
