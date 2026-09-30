# ssl-cert-worker

Issues TLS certificates from Let's Encrypt (ACME v2, DNS-01 via the Cloudflare DNS
API) on Cloudflare Workers, stores them in R2, and distributes them to nodes that
pull periodically using per-node API keys (one key = one node).

- Single Worker deployment, single hostname (`ssl.example.com`).
- Admin panel: static SPA behind Cloudflare Access; admin API re-verifies the Access JWT.
- Node pull API: `ssl.example.com/v1/*`, Access bypass, bearer API keys, ETag/304.
- Renewal: daily cron creates Cloudflare Workflow instances for due domains.
- Requires the Workers **Paid** plan (free-tier CPU limits cannot perform issuance).

Status: planning complete, implementation not started.

Full design: [PLAN.md](./PLAN.md).
