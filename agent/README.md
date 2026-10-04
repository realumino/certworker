# Node Agent of CertWorker

## Introduction

`certworker-agent` is the reference node agent for CertWorker. It runs on each
node under a systemd timer, pulls the current certificate and private key for
the node's domains from the CertWorker pull API (`/v1/*`), and installs them
into an app-owned directory. It has **no web-server coupling**: when the
material actually changes, it runs an optional reload command you provide
(e.g. `nginx -t && nginx -s reload`), otherwise it does nothing.

The agent is three files from this directory plus an API key from the admin
panel — a shell script, a systemd service, and a systemd timer. There is no
build step, no daemon, and no configuration file: the domains to pull are
command-line arguments in the service unit. If the pull API is protected with
Cloudflare Access **Service Auth**, the node additionally needs a service token
(two more files; step 3). Requirements: Linux with systemd, `curl`, and
`openssl`. The service runs as root (it writes the private-key directory and
may need to reload a web server).

Behavior contract per run and domain:

- One conditional request to `GET /v1/domains/<name>/files/fullchain` with
  `If-None-Match`; a `304` means nothing changed — a no-op, and **never** triggers
  the reload command.
- On `200`, the key is fetched separately and both files are staged as
  `<file>.new`, validated with `openssl` (both parse, and the key matches the
  certificate), and only then moved into place. A failed validation installs
  nothing, so the previous pair keeps serving.
- `CERTWORKER_RELOAD_CMD`, if set, runs **once** after all domains have been
  processed and at least one pair changed.
- If the Access service-token files are present (`access-client-id`,
  `access-client-secret`), every request also carries `CF-Access-Client-Id` /
  `CF-Access-Client-Secret`; only one of the pair is a startup error.
- Any failure is logged and the run exits non-zero; the timer retries on the
  next tick. JSON is never parsed — the script needs only `curl` and `openssl`.

## Usage

This is a manual, copy-paste installation: copy the three files from this
directory to their locations on the node, put the API key in place, add the
service token if app B uses Service Auth, edit the service unit for this node,
and start the timer.

### 1. Create the node key

In the admin panel open **Keys**, create a key labelled with the node name, and
copy the `cw_<id>.<secret>` token. It is shown **once** (only its hash is stored
server-side); you will paste it into the token file in the next step. Use one
key per node — revoking or rotating a key takes effect on the next run.

### 2. Copy the files to the node

Copy the three files from this directory (or paste their contents) onto the
node:

```sh
install -d -m 700 /etc/certworker
install -d -m 755 /etc/certworker/certs
install -d -m 700 /etc/certworker/private
install -d -m 700 /var/lib/certworker

install -m 755 certworker-agent /usr/local/bin/certworker-agent
install -m 644 certworker-agent.service certworker-agent.timer /etc/systemd/system/

umask 077
printf '%s\n' 'cw_<id>.<secret>' > /etc/certworker/token
chmod 600 /etc/certworker/token
```

### 3. Only with Access Service Auth: install the service token

Skip this step if Access app B is set to **Bypass** (the default). If it uses
**Service Auth**, create a service token in the Cloudflare dashboard under
**Zero Trust** > **Access controls** > **Service credentials** > **Service
Tokens**, add it to app B's policy (action _Service Auth_, selector _Service
Token_), and install its Client ID and Client Secret on the node:

```sh
umask 077
printf '%s\n' '<CLIENT_ID>' > /etc/certworker/access-client-id
printf '%s\n' '<CLIENT_SECRET>' > /etc/certworker/access-client-secret
chmod 600 /etc/certworker/access-client-id /etc/certworker/access-client-secret
```

Both files must be present; the agent refuses to run with only one of them. Use
one token for the whole fleet, or one per node if you want to revoke access at
the edge for a single node. These files only satisfy Access — the per-node API
key from step 1 is still required.

### 4. Verify the credentials

Run one request by hand before going further. With a Bypass app B:

```sh
curl -sS -H "Authorization: Bearer $(cat /etc/certworker/token)" \
  https://certworker.example.org/v1/me
```

With a Service Auth app B, add the Access headers:

```sh
curl -sS -H "Authorization: Bearer $(cat /etc/certworker/token)" \
  -H "CF-Access-Client-Id: $(cat /etc/certworker/access-client-id)" \
  -H "CF-Access-Client-Secret: $(cat /etc/certworker/access-client-secret)" \
  https://certworker.example.org/v1/me
```

The response is the key id, label, and scoped domains. `401` means the API key
was rejected — or, under strict service token authentication, the Access token
was; a `302` or an HTML body means app B still has an `Allow` policy instead of
`Bypass` / `Service Auth`.

### 5. Edit the service unit

Edit `/etc/systemd/system/certworker-agent.service` for this node: the pull API
base URL, the domain rows to pull, and optionally a reload command:

```ini
Environment=CERTWORKER_API=https://certworker.example.org/v1
Environment=CERTWORKER_RELOAD_CMD=nginx -t && nginx -s reload
ExecStart=/usr/local/bin/certworker-agent example.com api.example.com
```

Use the exact domain names shown in the admin **Domains** view: `example.com`,
or `*.example.com` for a wildcard-only row (a wildcard-toggle row is just
`example.com` and covers both names with one file pair). Domains are plain
`ExecStart` arguments — systemd does not glob or shell-split them, so
`*.example.com` is passed literally. Omit `CERTWORKER_RELOAD_CMD` to install
files without reloading anything; set it to any command (HAProxy reload, a
systemd unit restart, …). Then:

```sh
systemctl daemon-reload
```

### 6. First run

Run the service once before pointing a web server at the new files:

```sh
systemctl start certworker-agent.service
journalctl -u certworker-agent.service -n 50 --no-pager
ls -l /etc/certworker/certs /etc/certworker/private
```

Expected log lines: `certworker-agent: example.com updated (serial …)`, followed
by `certworker-agent: reload command succeeded` (only if a reload command is
set). Subsequent runs log `unchanged` and reload nothing. A failure exits
non-zero and is described in the journal.

### 7. Enable the timer

```sh
systemctl enable --now certworker-agent.timer
systemctl list-timers certworker-agent.timer
```

The timer runs every 15 minutes with up to 5 minutes of jitter and catches up
after downtime (`Persistent=true`). Server-side renewals are picked up on one of
these runs; only a changed certificate triggers the reload command.

## What files are touched and changed

**Installed once, by you** (copy/paste in the Usage steps above):

| File | Installed to | Mode |
|---|---|---|
| `certworker-agent` | `/usr/local/bin/certworker-agent` | `755` |
| `certworker-agent.service` | `/etc/systemd/system/certworker-agent.service` | `644` |
| `certworker-agent.timer` | `/etc/systemd/system/certworker-agent.timer` | `644` |
| token (from the admin panel) | `/etc/certworker/token` | `600` |
| Access service token (only with Service Auth) | `/etc/certworker/access-client-id` · `/etc/certworker/access-client-secret` | `600` |

**Written by the agent** (its only footprint on the node):

| Path | Written when | Notes |
|---|---|---|
| `/etc/certworker/certs/<domain>.pem` | on a changed certificate | fullchain (leaf + intermediate chain), world-readable directory |
| `/etc/certworker/private/<domain>.key` | on a changed certificate | private key, mode `600`, directory `0700`/root-only |
| `/etc/certworker/certs/wildcard.<domain>.pem` · `/etc/certworker/private/wildcard.<domain>.key` | on a changed certificate | for a `*.example.com` row |
| `<file>.new` (in the cert/key dirs) | during a change | transient staging; validated then `mv`-ed into place, removed on failure |
| `/var/lib/certworker/<domain>.etag` | after a successful install | stores the response `ETag` so the next run can be a `304`; `wildcard.<domain>.etag` for wildcard rows. Delete it to force a refresh. |
| `/var/lib/certworker/<domain>.*.new` | during a change | transient response headers, removed at the end of the run |

The certificate and key live in separate directories so the key directory can
stay `0700`/root-only while the certificate is world-readable. Every path is an
environment override, so a node following a system convention can use another
layout entirely (e.g. `/etc/ssl/certs` + `/etc/ssl/private`):

| Variable | Default | Purpose |
|---|---|---|
| `CERTWORKER_API` | `https://certworker.example.org/v1` | pull API base URL |
| `CERTWORKER_CONF_DIR` | `/etc/certworker` | holds `token` and the optional Access `access-client-id` / `access-client-secret` (`0600`) |
| `CERTWORKER_STATE_DIR` | `/var/lib/certworker` | ETags and transient staging |
| `CERTWORKER_CERT_DIR` | `/etc/certworker/certs` | destination for `*.pem` fullchains |
| `CERTWORKER_KEY_DIR` | `/etc/certworker/private` | destination for `*.key` private keys |
| `CERTWORKER_RELOAD_CMD` | unset | command run once after a change |

Credentials are files, not variables: the Access `access-client-*` pair is read
from `CERTWORKER_CONF_DIR` only when both files exist.

**Never touched:** anything outside the paths above. The web-server
configuration is yours (point it at the installed paths, then reload); removing
a domain from `ExecStart` leaves its files in place for you to delete; upgrades
replace only the three installed files. Note that each run replaces the cert/key
pair atomically via `mv`, so do not edit installed files by hand — the agent owns
those paths.

## Troubleshooting

| Symptom in `journalctl -u certworker-agent.service` | Likely cause | Fix |
|---|---|---|
| `pull failed: HTTP 302 … (content-type: text/html)` | Access app B is missing, mis-scoped, or set to **Allow**, so the pull was redirected to a login page | Point app B at `/v1` with a **Bypass** or **Service Auth** policy |
| `HTTP 401` with a Bypass app B | Bad or revoked API key | Create a replacement in the admin **Keys** view and reinstall `/etc/certworker/token` |
| `HTTP 401` / `403` with a Service Auth app B | Missing, wrong, or expired `CF-Access-Client-Id` / `-Secret` — or a bad API key under strict service token authentication | Check `/etc/certworker/access-client-id` and `access-client-secret`; rotate the token if it expired |
| `HTTP 403 forbidden_domain` | The API key's domain scope does not include the domain | Update the key's `allowed_domains` in the admin panel |
| `HTTP 429` | Per-key rate limit (60 pulls/minute) | Nothing — the next timer run retries |
| `response is missing an ETag` | A proxy in front of the Worker is rewriting responses | Check Access and WAF rules for the hostname |

`pull_events` in the admin panel records every request that reached the Worker;
a pull rejected by Access never appears there.
