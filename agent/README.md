# Node agent (reference)

Reference agent that pulls certificates from the certworker node pull API
(`/v1/*`) and installs them for nginx. It consists of three files plus the node's
API key:

| File | Installed to | Mode |
|---|---|---|
| `certworker-pull` | `/usr/local/bin/certworker-pull` | `755` |
| `certworker-pull.service` | `/etc/systemd/system/certworker-pull.service` | `644` |
| `certworker-pull.timer` | `/etc/systemd/system/certworker-pull.timer` | `644` |
| token (from the admin panel) | `/etc/certworker/token` | `600` |

Per run and domain the script requests `GET /v1/domains/<name>/cert`, stores the
manifest `ETag` under `/var/lib/certworker/` and installs:

```
/etc/nginx/ssl/<domain>.pem            fullchain (leaf + intermediate chain)
/etc/nginx/ssl/<domain>.key            private key, mode 600
/etc/nginx/ssl/wildcard.<domain>.pem   for a `*.example.com` row
```

Contract: a `304` is a no-op and never reloads; new material is staged as
`<file>.new`, checked with `openssl` (parses, and the key matches the
certificate) and only then moved into place; `nginx -t` and the reload run once
after all domains are processed; any failure is logged and exits non-zero (the
timer retries). Only a pair that parsed and whose key matches is installed, so a
failed run leaves the previous pair serving.

Requirements: Linux with systemd, nginx, and `curl`, `jq`, and `openssl`
installed. The service runs as root (it writes `/etc/nginx/ssl` and reloads
nginx). Environment overrides (`CERTWORKER_API`, `CERTWORKER_CONF_DIR`,
`CERTWORKER_STATE_DIR`, `CERTWORKER_OUT_DIR`) exist for non-default layouts.

## 1. Create the node key

In the admin panel open **Keys**, create a key with the node name as its label,
and copy the `cw_<id>.<secret>` token. It is shown **once**; only its hash is
stored server-side. Revoking or rotating the key takes effect on the next run.

## 2. Install

Copy the three files from a checkout of this repository to the node, then:

```sh
install -d -m 700 /etc/certworker
umask 077
printf '%s\n' 'cw_<id>.<secret>' > /etc/certworker/token
chmod 600 /etc/certworker/token

install -m 755 certworker-pull /usr/local/bin/certworker-pull
install -m 644 certworker-pull.service certworker-pull.timer /etc/systemd/system/
```

Verify the token before going further:

```sh
curl -sS -H "Authorization: Bearer $(cat /etc/certworker/token)" \
  https://ssl.example.com/v1/me
```

## 3. Configure the node

Edit `/etc/systemd/system/certworker-pull.service`: set `CERTWORKER_API` to the
Worker's pull API base URL and list the domain rows to pull in `ExecStart`.
Use the exact names from the admin Domains view (`example.com`, or
`*.example.com` for a wildcard-only row). A row with the wildcard toggle on
covers both `example.com` and `*.example.com` with one file pair.

```ini
Environment=CERTWORKER_API=https://ssl.example.com/v1
ExecStart=/usr/local/bin/certworker-pull example.com api.example.com
```

Then `systemctl daemon-reload`. Domains are passed as arguments (no config
file); systemd does not glob or shell-split them, so `*.example.com` is passed
literally.

## 4. First pull

Run the service once before pointing an nginx server block at the new files:

```sh
systemctl start certworker-pull.service
journalctl -u certworker-pull.service -n 50 --no-pager
ls -l /etc/nginx/ssl
```

Expected log lines: `certworker-pull: example.com updated (serial …)` followed by
`certworker-pull: nginx tested and reloaded`. The key file is mode `600`.

## 5. nginx

```nginx
server {
  listen 443 ssl;
  server_name example.com;

  ssl_certificate     /etc/nginx/ssl/example.com.pem;   # fullchain
  ssl_certificate_key /etc/nginx/ssl/example.com.key;
  # ...
}
```

For a `*.example.com` row the files are `wildcard.example.com.pem` and
`wildcard.example.com.key`. After this point the agent owns those paths; do not
edit them by hand.

## 6. Enable the timer

```sh
systemctl enable --now certworker-pull.timer
systemctl list-timers certworker-pull.timer
```

The timer runs every 15 minutes with up to 5 minutes of jitter and catches up
after downtime (`Persistent=true`).

## Operations

- **Logs**: `journalctl -u certworker-pull.service` (each run logs
  `unchanged`, `updated`, or a failure).
- **Force a refresh**: `rm -f /var/lib/certworker/<domain>.etag && systemctl start certworker-pull.service`
  (a `304` means the stored ETag still matches; the ETag is keyed by the
  on-disk name, so `*.example.com` uses `wildcard.example.com.etag`).
- **Rotate the key**: rotate in the admin Keys view, install the new token, run
  the service. The old key stops working immediately.
- **Renewals**: issued and renewed server-side; nodes pick the new pair up on
  the next timed run and reload nginx only if it changed.
- **Add or remove a domain**: edit `ExecStart`, `systemctl daemon-reload`, and
  run the service once. Removing a domain leaves its files in place; delete
  them manually if the vhost is gone too.
- **Uninstall**: `systemctl disable --now certworker-pull.timer`, remove the three
  files, the token, `/var/lib/certworker`, and revoke the key in the admin
  panel.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `HTTP 401` | Token revoked, mistyped, or the header is missing. Check `GET /v1/me`; create a new key if needed. |
| `HTTP 403` and an HTML hint in the log | Cloudflare Access is intercepting `/v1/*`. Access app B must be Bypass (or the node must send Service Auth credentials if that policy is enabled). |
| `HTTP 404 certificate_missing` | The domain has no current certificate yet; issue it from the admin panel. |
| `HTTP 404 not_found` | Domain name typo, or the domain row was deleted. |
| `HTTP 403 forbidden_domain` | The key is scoped to other domains. |
| `HTTP 429` | Per-key rate limit; the next timer run retries. |
| `HTTP 000` | The node cannot reach the Worker (DNS, firewall, TLS). |
| `certificate and private key do not match` | The pull raced a renewal flip; nothing was installed and the next run heals it. |
| `nginx failed to test/reload` | `nginx -t` output is in the log. The new files are already installed; fix the configuration and run `nginx -t` manually. |
| Nothing logged at all | Check `systemctl status certworker-pull.timer` and the unit's `CERTWORKER_API`/`ExecStart`. |
