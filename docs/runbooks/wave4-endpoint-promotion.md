# Runbook — Wave-4 endpoint promotion + release (owner-gated)

**Purpose:** promote the reference public origin `andvari.monahanhosting.com` from the break-glass
régime to full service, then release the clients that default to it. This is the single owner-gated
step the endpoint pivot (design `docs/design/2026-07-15-multi-tenant-endpoints.md` §6/§7) leaves for
you. Nothing in the committed tree ships until you run this.

**Why it's gated (§6.3):** the Wave-4 build swaps the native `DEFAULT_BASE_URL` to the public origin
and `migrateDefaultOnce` v2 rewrites existing installs from the old home/tailnet default to it. If a
client lands on the public origin **before** it serves full policy, members hit a server that refuses
refresh/recovery/sharing and demands TOTP. So: promote the origin first, verify with a live probe,
*then* release.

---

## 0. Preconditions (verify before touching anything)

- [ ] Local `main` carries Waves 1–4 (endpoint pivot), gate-green. `grep -rnE "taila2dff2|192\.168\.2\.122" app-android/src app-desktop/src extension/src web/src` returns **only** the two `LEGACY_` match-target constants (Session.kt, DesktopSession.kt).
- [ ] **CF tunnel token rotated** (secret-scan §4 #1 — independently overdue): CF Zero Trust → regenerate the andvari tunnel token → write to `/etc/andvari/cloudflared.env` (0600) on CT122 → `systemctl restart cloudflared-andvari` → confirm `andvari.monahanhosting.com` still serves. Do this whether or not you release today.
- [ ] Confirm the fleet: no member device on a pre-namespacing build depends on the tailnet front being the *only* front (it stays up regardless — see §5).

## 1. Flip the server env (§7.4) — one maintenance window on CT122

On the server (`server/deploy/env` or wherever `ANDVARI_*` is set), change:

```
# REMOVE (or leave unset) — this is what selects the break-glass/dual-origin régime:
#   ANDVARI_PUBLIC_HOSTNAME=...
ANDVARI_SIGNUP_MODE=landing
ANDVARI_CANONICAL_ORIGIN=https://andvari.monahanhosting.com
ANDVARI_INSTANCE_NAME="andvari (reference instance)"
ANDVARI_TOTP_REQUIRED=false
ANDVARI_FORCE_HSTS=1
```

Then restart the server. (Env names are the §2.1 canonical set — `ANDVARI_CANONICAL_ORIGIN`
supersedes the deprecated `ANDVARI_INVITE_BASE_URL` alias.)

## 2. Release gate — the live probe (BLOCKING, §6.3)

```
curl -s https://andvari.monahanhosting.com/api/v1/client-policy | jq
```

Must show the new fields with **`"signupMode": "landing"`** (not `closed`), a `canonicalOrigin` of
`https://andvari.monahanhosting.com`, and `totpRequired: false`. Then smoke the full surface against
the public origin: **register-with-invite, refresh, sharing, and recovery all work**, and an
enrolled-TOTP account is prompted on every origin. If any of these fail, STOP — do not release; the
origin is not fully promoted.

## 3. Release the clients (only after §2 is green)

The clients are already coded for the public default; releasing = bump + build + publish.

- [ ] Bump `ANDVARI_CLIENT_VERSION` (and the Gradle-side `versionName`/`packageVersion`, web
      `CLIENT_VERSION`, ext manifest/package versions) in lockstep — `scripts/verify.sh` asserts they match.
- [ ] Build + **string-scan every published artifact**: `strings <apk/deb/zip> | grep -E "ts\.net|192\.168\.2\.122"` → zero (the tailnet/LAN literals survive only as never-dialed migration match-targets in the binary, which is acceptable, but verify nothing is a *dialed* default).
- [ ] Publish per the artifact plan. **Reconcile F3 vs B2-4 first:** the trust-attestation strategy
      (`docs/design/2026-07-16-trust-attestation-strategy.md` F3) makes **GitHub Releases** canonical
      for client artifacts with `/downloads` a mirror; the pivot design (§8, B2-4) promoted `/downloads`.
      Pick one as canonical and make the other the mirror before publishing, so the web Devices card
      (manifest-driven) and the update/downloads copy agree.
- [ ] Web + server deploy to CT122 (byte-verify, as prior deploys).

## 4. Verify the migration on a real device

On a phone/desktop still on the old default, apply the update and confirm: the app now talks to
`andvari.monahanhosting.com`, and the offline copy / saved logins / quick-unlock are intact (the
`migrateDefaultOnce` v2 + §4.2 adoption carried them). A hand-set custom server address must be
untouched.

## 5. Tailnet front lifetime (§6.5 / B2-11 — do NOT retire early)

Keep the `tailscale serve` front for `andvari.taila2dff2.ts.net` **active ≥ 90 days AND until fleet
telemetry shows no pre-migration clients** (un-updated 0.17/0.18 natives + 0.14/0.15 ext point at it
forever). Retiring it is a *later, deliberate* owner step — never a side effect of this release.

## Rollback

If §2 fails or members break post-release: restore `ANDVARI_PUBLIC_HOSTNAME` (back to the break-glass
régime) and restart the server; un-updated clients are unaffected (they still use the tailnet front).
Updated clients that already migrated will retry the public origin — which, restored to break-glass,
still serves sign-in/read; hold the client release until the origin is re-promoted.
