# ssl-cert-worker

Issues TLS certificates from Let's Encrypt (ACME v2, DNS-01 via the Cloudflare DNS
API) on Cloudflare Workers, stores them in R2, and distributes them to nodes that
pull periodically using per-node API keys (one key = one node).

- Single Worker deployment, single hostname (`ssl.example.com`).
- Admin panel: static SPA behind Cloudflare Access; admin API re-verifies the Access JWT.
- Node pull API: `ssl.example.com/v1/*`, Access bypass, bearer API keys, ETag/304.
- Renewal: daily cron creates Cloudflare Workflow instances for due domains.
- Requires the Workers **Paid** plan (free-tier CPU limits cannot perform issuance).

Status: M0 + M1 complete. M2 ACME client and issuance script are implemented; live staging acceptance is pending. M3 persistence, Workflow pipeline, and internal manual trigger are implemented; offline workerd acceptance passes. M4 admin API, Access JWT verification, and the audit trail are implemented; certificate revocation, key last-use tracking, and the pull API follow in M6/M7.

## Local development

Prerequisites: Node.js >= 22 (Wrangler 4 requires it) and npm.

```sh
npm install
cp .dev.vars.example .dev.vars
npm run build:web          # placeholder SPA -> web/dist (required before wrangler dev / vitest)
npm run types              # regenerate worker-configuration.d.ts after changing wrangler.jsonc
npm run db:migrate:local   # apply migrations to the local D1 database (.wrangler/state)
npm test                   # workerd-pool unit tests
npm run dev                # wrangler dev on http://localhost:8787
```

The admin API (`/api/*`) requires the `Cf-Access-Jwt-Assertion` header injected by
Cloudflare Access; the Worker verifies its RS256 signature against the team JWKS
(`${ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`) plus `iss` and `aud`, rejecting
everything else with 401. Mutations are additionally same-origin and JSON-only.
Every admin mutation is recorded in the `audit_log` D1 table with the Access
email as the actor.

For local development behind `wrangler dev` (where no Access sits in front), set
`DEV_ACCESS_EMAIL` in `.dev.vars`: requests from loopback hosts then skip JWT
verification and use that email as the audit actor. The variable is empty in
`wrangler.jsonc`, so deployed Workers never run the bypass — it is also
unreachable on any non-loopback hostname.

Deployment placeholders: `wrangler.jsonc` currently carries placeholder D1/R2 IDs.
Replace them (`wrangler d1 create ssl-cert-worker`, `wrangler r2 bucket create
ssl-cert-artifacts`) before the first deploy.

## M2 staging issuance

Set `CF_DNS_API_TOKEN` in `.dev.vars` (or the process environment) with `Zone:Zone:Read`
and `Zone:DNS:Edit` on a dedicated test zone, then run:

```sh
npm run issue -- example.com                  # apex + wildcard by default
npm run issue -- '*.example.com'              # wildcard only
npm run issue -- example.com --no-wildcard    # apex only
```

The script defaults to Let's Encrypt staging, waits for DNS-01 propagation through
Cloudflare and Google DoH, and deletes its TXT records during cleanup. It stores the
staging account and downloaded artifacts under `.wrangler/acme/` (gitignored). The
local account and leaf private keys are plaintext development artifacts; do not copy
them into production storage. Any non-staging directory requires `--allow-production`.

The offline suite covers the ACME/Cloudflare DNS flows. The live staging run requires
a real test zone and DNS token and has not yet been performed in this workspace.

Full design: [PLAN.md](./PLAN.md).
