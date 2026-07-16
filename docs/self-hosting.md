# Self-hosting andvari

andvari is a zero-knowledge household password manager you can run yourself. The
server only ever stores ciphertext — your master password and vault contents never
leave your devices — so hosting it is mostly a matter of keeping one small container
and its data directory alive.

Every andvari client (Android app, desktop app, browser extension, web) works with
**any** andvari server: point it at yours under *Settings → Server*, or just open an
invite link from your server. Clients apply your instance's declared policy under one
hard rule — **a server can make a client safer, never laxer** (spec 03 §1.1) — so you
configure the *server's* stance here and the clients follow to the extent that's safe.

This page is bundled with every server at `<your-origin>/selfhost`, together with
downloadable copies of `docker-compose.yml`, `andvari.env.template`, and `bringup.sh`.

## What you need

- A Linux host (amd64 or arm64) with **Docker Engine + the compose v2 plugin**
  (`docker compose version` must work). ~512 MB RAM for the server is comfortable.
- A **DNS name** for the instance (e.g. `vault.example.org`) pointing at the host —
  or, for a LAN/dev setup, just the host's private IP.
- A **TLS story** (one of):
  1. **The caddy overlay** (`docker-compose.caddy.yml`) — zero-config automatic
     HTTPS via Let's Encrypt. Needs ports 80+443 reachable from the internet and
     DNS pointing at the host. `bringup.sh --caddy` arms it.
  2. **Your own front**: any reverse proxy, `cloudflared`, or `tailscale serve`
     pointed at `127.0.0.1:8080` (the app publishes on loopback only by default).
     Set `ANDVARI_TRUSTED_IP_HEADERS` (e.g. `X-Forwarded-For`) in `andvari.env` so
     rate limiting and the audit log see real client IPs — note the server honors
     forwarded headers **only when the connection's direct peer is loopback**
     (spec 03 §8). The caddy overlay satisfies that by sharing the app container's
     network namespace; a proxy that reaches the container over the Docker bridge
     does not, and per-client IP granularity degrades accordingly.
  3. **Plain http on a trusted LAN** (dev/home-lab only): choose an
     `http://<private-ip>:8080` origin at bring-up; the app then binds `0.0.0.0`.
     Clients will show a plain-http caution. Never expose this to the internet.
- A **printer** (or pen and paper) for the recovery sheet the bring-up ceremony
  produces. This is not optional decoration — it is the only way back into a lost
  account.

## Install

The distribution channel is the public container image
**`ghcr.io/silencelen/andvari`** — you **pull** it; building from source is not
required (the source repo is private; these docs + the image are the product).

```sh
mkdir andvari && cd andvari
# grab the deploy files from any running instance:
curl -fsSLO https://andvari.monahanhosting.com/selfhost/docker-compose.yml
curl -fsSLO https://andvari.monahanhosting.com/selfhost/docker-compose.caddy.yml   # only if using --caddy (auto-HTTPS)
curl -fsSLO https://andvari.monahanhosting.com/selfhost/andvari.env.template
curl -fsSLO https://andvari.monahanhosting.com/selfhost/bringup.sh
chmod +x bringup.sh

./bringup.sh                # interactive: asks for your origin + instance name
# or, non-interactive / with the auto-HTTPS sidecar:
./bringup.sh --origin https://vault.example.org --instance-name "example vault" \
             --admin-email you@example.org --caddy
```

`bringup.sh` is **idempotent** and **refuses to overwrite an existing
`andvari.env`**. It:

1. writes `andvari.env` (canonical origin, `invite-only` signup, TOTP not required,
   offline caches allowed, your instance name, `ANDVARI_STRICT_ENV=1`, and no
   break-glass hostname — single-origin is the default topology);
2. generates the anti-enumeration secret;
3. runs the **escrow ceremony** — `recovery-cli keygen` in a network-less container —
   shows you the recovery sheet to print, and pins the public key + fingerprint in
   the env (enrollment is refused until those pins exist, so bring-up cannot skip
   past a dead instance). *Print the sheet twice, copy the seed to a USB stick, store
   them separately, then clear your terminal scrollback.* If you prefer the
   by-the-book air-gapped ceremony, run
   `docker run --rm --network none ghcr.io/silencelen/andvari:latest recovery-cli keygen`
   on an offline machine and paste the two `ANDVARI_RECOVERY_*` values yourself;
4. mints a bootstrap token, starts the stack, waits for `/healthz`, smoke-checks that
   `GET /api/v1/client-policy` declares your configured policy, and prints the
   **first-admin enroll URL**.

Enroll yourself as the first admin (have the printed sheet at hand — enrollment
confirms the recovery fingerprint from it), then blank `ANDVARI_BOOTSTRAP_TOKEN` in
`andvari.env` and `docker compose up -d`.

From a **source checkout** (if you have repo access): `./deploy/bringup.sh --build`
builds the image locally (tag `:local`) instead of pulling. Everything else is
identical; pull remains the one default path.

## The policy variables — what your instance declares

Clients fetch `GET /api/v1/client-policy` before login and render/behave
accordingly. These are **operator** settings (env, not the in-app admin panel — a
compromised admin session must not be able to open your front door):

| Variable | Declares |
|---|---|
| `ANDVARI_CANONICAL_ORIGIN` | The instance's one true address — shown to clients as a diagnostic, embedded in emailed invites. Canonical form: lowercase `scheme://host[:non-default-port]`, no trailing slash. **https required for non-local hosts.** Replaces the deprecated `ANDVARI_INVITE_BASE_URL` (still accepted as a fallback alias, with a boot warning). |
| `ANDVARI_SIGNUP_MODE` | `closed` (sign-in only) \| `invite-only` (default — sign-in + invite-gated enroll) \| `landing` (invite-only + a stranger-facing "get an invite / self-host" landing) \| `open` (**reserved** — boot-coerces to `landing` with a warning until an open-register path exists). Enrollment is enforced server-side regardless: register always needs a valid invite. |
| `ANDVARI_TOTP_REQUIRED` | `true` ⇒ every account must enroll an authenticator: an account without one gets a **restricted session** at login until it enrolls. `false` (default) ⇒ password-only login is allowed — but an account that **has** enrolled TOTP is asked for it on **every** origin, always. |
| `ANDVARI_OFFLINE_CACHE_ALLOWED` | Operator **floor** for client durable offline caches, ANDed with the admin-settable policy knob. **Monotonicity note:** clients treat the resulting field as *forbid-only* — `false` forbids and wipes their local copy for your origin; `true` alone never forces caching onto a device (web and desktop still require an explicit per-device opt-in; Android defaults on, by recorded design — spec 05 T3/R11). |
| `ANDVARI_INSTANCE_NAME` | A display label. Decorative only — clients never render it as a verified identity; the raw origin is what users are asked to trust. |
| `ANDVARI_SELFHOST_DOCS_URL` | Where clients link "run your own server". Defaults to `<canonical-origin>/selfhost` — this very page, served by your own instance. |
| `ANDVARI_FORCE_HSTS` | `1` ⇒ send HSTS on every response. Set it once https works end-to-end. |
| `ANDVARI_LOGIN_RATE_PER_MIN` | Per-IP login attempts/min (default 5, flat on every origin). An email-keyed exponential backoff after repeated failures is always on. |
| `ANDVARI_STRICT_ENV` | `1` (bring-up default) ⇒ an unknown or invalid `ANDVARI_*` variable **kills boot** instead of logging a warning — typos fail loudly at the healthz wait. |
| `ANDVARI_PUBLIC_HOSTNAME` | **Leave unset** (single-origin, the default). Setting it arms the opt-in dual-origin *break-glass* régime: requests arriving under that exact hostname get an emergency hardened origin (TOTP mandatory, no register/refresh, `signupMode=closed`). Only for deployments that deliberately keep a separate primary + emergency topology. |

Timer-ish policy values an admin can set in-app (auto-lock, clipboard clear) are
**clamped on the client side** (auto-lock ≤ 15 min, clipboard ≤ 5 min) — a server,
including a hostile one, cannot disable a device's auto-lock. That is the trust
boundary working as intended.

## Backup

Everything lives in `./data` next to `docker-compose.yml`:

- `data/andvari.db` — the SQLite database (accounts, ciphertext items, audit log)
- `data/blobs/` — encrypted attachment blobs

Both are ciphertext (a stolen backup is as useless to a thief as the live server is —
spec 05 T7), but they are the *only* copy of your household's vaults. Back them up:

```sh
# consistent DB snapshot, safe against the live WAL (needs sqlite3 on the host):
sqlite3 ./data/andvari.db "VACUUM INTO './data/backup/andvari-nightly.db.tmp'"
sqlite3 ./data/backup/andvari-nightly.db.tmp "PRAGMA integrity_check;"   # expect: ok
mv -f ./data/backup/andvari-nightly.db.tmp ./data/backup/andvari-nightly.db
# then rsync/restic/borg the whole ./data directory off-host
```

Cron that nightly (it is a lift of the reference instance's
`ops/nightly-db-backup.sh`, which also shows the failure-alerting shape). Restore =
put `andvari.db` + `blobs/` back under `./data` and `docker compose up -d`.

Also part of your backup posture, but **never digital**: the printed recovery sheets
from the ceremony, and members' own `.andvari` export files if they make them.

## Invites & email

- Members join by **invite** (admin panel → invite): hand over the QR/link in person,
  or paste the token. Each invite chooses `required` (admin recovery backstop keeps
  working for that member) or `waived` (private even from you — losing both their
  master password and their personal recovery phrase means permanent loss).
- **Emailed invites** are optional and off until you configure a mail transport in
  `andvari.env` (SMTP `ANDVARI_SMTP_*`, or Microsoft Graph `ANDVARI_GRAPH_*`) — the
  emailed link embeds your canonical origin, is forced to a ≤ 60-minute single-use
  window, and defaults to `waived`. Treat inboxes accordingly (spec 05 R8: on a
  single-origin instance an emailed link *is* reachable by whoever reads the inbox —
  TTL, single-use, and https transport are the controls).

## Updates

```sh
docker compose pull && docker compose up -d
```

That is the whole update story. Watch the image's release tags; `:latest` follows the
newest release. (`bringup.sh --build` users: `git pull` and re-run with `--build`.)

**Explicit non-promise — the in-client update check is disabled by design** (design
2026-07-15 §9): the apps/extension do **not** phone anywhere to check for updates,
and they will not verify or nag about anything your `/downloads` page serves. Client
updates come from the app store / OS package channels (whose signing is the
load-bearing control) or as plain files you distribute yourself via
`ANDVARI_DOWNLOADS_DIR`. **Per-instance signed update feeds are future work**, not a
current feature — nothing you can set today makes your instance's `/downloads`
cryptographically verified by clients.

## Day-2 notes

- **Health:** `GET /healthz` (the compose healthcheck uses it). **Metrics:**
  `GET /metrics` is Prometheus-format, loopback-trust only — scrape from inside the
  network namespace or drop a sidecar; never expose it.
- **Recovery of a locked-out member** (admin backstop, `required` members): dump the
  escrow blob, run `recovery-cli recover` with the printed seed on an **offline**
  machine, upload the result in the admin panel — the full runbook ships in the spec
  (spec 04 §4). The recovery-cli in the image is the same tool:
  `docker run --rm -it --network none ghcr.io/silencelen/andvari:<ver> recovery-cli`.
- **Members' self-service recovery** works out of the box (`/recovery/self/*`): each
  member gets a personal recovery phrase at enrollment. These endpoints are
  internet-reachable on a single-origin instance — they are rate-limited per-IP with
  per-email backoff, and the phrase is a full-entropy key (spec 05 R9/R10), so this
  is a considered default, not an oversight.
- **Moving hosts:** copy `./data` + `andvari.env` (+ `.env`), `docker compose up -d`
  on the new host, repoint DNS. The origin is the identity members' devices trust —
  keep it stable; changing it means every device re-consents via the server-switch
  gate.
