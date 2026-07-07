# andvari — Roadmap

Where andvari is, what gates real-secret migration, and where it goes next. Living doc;
the SSOT for *state* is the memory file `andvari-password-manager-2026-07-05.md` + the
git history. This is the SSOT for *direction*.

## Where we are (2026-07-06, v0.4.0)

v1 is feature-complete and deployed (CT 122). **0.4.0 (same day, v4 cycle)** adds: spec 07
export/backup (`.andvari` container + CSV w/ totp round-trip + `backup-cli`), enforced
auto-lock + policy clipboard-clear, the spec 02 §3 unknown-field round-trip fix
(ExtrasOverlaySerializer + itemdoc.json vector; also fixed live favorite/passwordHistory/
multi-URI edit-loss bugs), web WS auto-reconnect + native foreground/5-min polls, delete
confirmations, user_lookup audit-PII fix, escrow upload validation + offline canary
`verify`, typed 426 surface + drill docs, and the Kuma healthz push monitor. The 0.3.0
line added, on top of the shipped P0–P4 core (ZK crypto, sync, attachments, server-TOTP,
admin, break-glass):

- **Hardening batch** — the 2026-07-06 self-audit's remaining LOW/INFO items: trusted-proxy
  client IP, per-user upload caps, WebSocket single-use ticket auth (no token-in-URL),
  audit-meta PII removal, prelogin params uniformity, CSP tightening. (Deployed.)
- **Family sharing** — shared vaults with `crypto_box_seal` member grants, owner-managed
  membership, out-of-band **seed-derived** fingerprint verification, web Sharing UI +
  native identity codes. Removal is revocation-only in v1 (see R7 below). (Deployed.)
- **Durable offline cache** (spec 02 §8) — native clients persist ciphertext envelopes +
  cursor + queue + accountKeys in per-account SQLite; offline unlock; crash-durable queue.
- **CSV import** (spec 06) — Chrome/Edge + Firefox, 100% client-side, idempotent retry.
- **Android autofill** (fill-only) — matching + classification are vector-tested `:core`;
  the AutofillService app ships with 0.3.0.

Every feature preserved the zero-knowledge invariant (the server still sees exactly the
spec 02 §5 table); each was adversarially reviewed before deploy.

## The gate to real secrets (owner + ops — BLOCKS migration)

The code is ready. These operational steps are not, and must complete **in order** before
importing any real password:

1. ~~**Air-gapped escrow-genesis ceremony**~~ **DONE 2026-07-07.** keygen ran air-gapped on
   prestige; canary make+verify PASSED from the printed sheet; CT122 pinned + restarted and
   now serves fingerprint `b26efdd3eafc9dad…` (TEST key `e3c0418f…` retired, backed up).
   Seed on 2 sheets + USB, offline only. Owner-verified canary at
   `/etc/andvari/escrow-canary.b64`. **TODO before soak:** purge the 1 pre-swap TEST account
   (0 items; its escrow is orphaned to the old key) so `recovery-cli verify` reads all-PASS.
2. **Enroll the first admin** (bootstrap token in andvari.env) + **enroll server-TOTP**
   immediately after (break-glass public login is impossible without it).
3. **Windows MSI rebuild** on the owner box (desktop 0.3.0 — the tailnet-default URL + version
   bump are in the tree; only the owner can run jpackage/WiX). See `ops/windows-build.md`.
4. **On-device smoke tests** — attachments + TOTP on the Fold + desktop; the autofill Fold-7
   checklist (design §6.4); a CSV dry-run with a synthetic export; a shared-vault invite
   round-trip web↔Fold with the printed-sheet fingerprint check.
5. ~~**Uptime-Kuma monitor** on `/healthz`~~ **DONE 2026-07-06** — gjallarhorn can't reach
   VLAN 2 (UDM default-deny), so it's a Kuma **push** monitor (`andvari-healthz`, id 13):
   heimdall checks `http://192.168.2.122:8080/healthz` every 2 min and pushes up/down
   (`andvari-kuma-push.{sh,service,timer}` on heimdall, mirrored in netplan
   `scripts/active/monitoring/`; token in `/etc/andvari-kuma-token`). Also dead-mans if
   heimdall itself dies (pushes stop → missed-heartbeat alert → Telegram).
6. **Drills:** PBS restore of CT122's DB + blobDir; **escrow-recovery drill** with the
   air-gapped key (recover a throwaway account end-to-end); **min-version-pin exercise**
   (bump `minVersion`, confirm all three clients block writes and show the upgrade path);
   **backup-verify drill** (export a `.andvari` → `backup-cli` verify/dump/extract —
   `docs/drills/backup-restore-drill.md`, then quarterly).
7. **30-day soak** with synthetic secrets across 3 devices (web + Fold + desktop).
8. **Migrate**, then keep the old manager **read-only for 60 days** before deleting it.

## P6 — next horizon (post-real-secrets)

Prioritized; each is additive and back-compatible.

- **Quick-unlock** (spec 01 §8) — Android Keystore-wrapped UVK + biometric; Windows Hello /
  DPAPI + PIN on desktop. The single integration point on Android is `AutofillUnlockActivity`
  (hook already noted). `androidx-biometric` is already catalogued.
- **Autofill save-flow** — SaveInfo/onSaveRequest (v1 is fill-only). Capture new logins the
  user types into an unrecognized form.
- **Browser extension** — reuses the `:core`/web `UriMatch` + `FieldClassifier` (already
  built + vector-tested for exactly this) and the same-origin API. Chromium + Firefox.
- **VK lazy rotation on member removal** (closes accepted risk R7) — the next online writer
  re-keys the vault and re-seals grants; removed members lose access to future ciphertext,
  not just server delivery. Needs a rotation protocol fenced against concurrent writers.
- **ItemDoc unknown-field round-trip** — decode to a JsonObject overlay so a future additive
  field (e.g. `neverAutofill`, `sensitive`) survives a mixed-fleet edit (spec 02 §3 already
  mandates preservation; the fixed data classes currently strip unknowns). Do this BEFORE
  adding any such field.
- **eTLD+1 / PSL matching** for autofill (v1's label-boundary rule is strictly safer but
  misses sibling-subdomain matches); **Digital Asset Links** for the native-app-with-web-creds
  case (v1 uses `androidapp://` exact + a browser allowlist).
- **iOS client** (KMP `:core` already targets it in principle; not wired) — assess.
- **Passkeys / WebAuthn** — evaluate as a credential type; large.

## Accepted risks (signed off; not P6 work unless revisited)

- **R7** removed shared-vault member keeps decryption capability for ciphertext they held
  until VK rotation (P6). **R3** the escrow key holder can decrypt every account (it *is* the
  recovery feature). **R1** JVM/JS can't guarantee secret zeroization. **R4** server sees
  traffic metadata + membership topology. **R5** single server (offline-first + PBS/shadow,
  not HA). **R6** TOTP seeds co-located with passwords. Full text: `spec/05-threat-model.md`.

## Operational cadence (once real secrets are in)

- **Backups:** daily PBS (02:00) covers CT122; nightly `VACUUM INTO` for a clean snapshot;
  skybox DR shadow 2122. Quarterly PBS-restore drill.
- **Escrow:** annual presence-verification of both printed sheets + the USB; re-ceremony +
  full re-escrow + item re-key on any suspected compromise (manual runbook, spec 04).
- **Monitoring:** Grafana `Andvari Alerts` (no-metrics, auth-fail burst, break-glass>24h) +
  the Kuma `/healthz` monitor; audit → Loki.
- **Security:** re-run the hardening self-audit before each major feature that touches the
  server or crypto; rotate the tailnet auth key on schedule.
- **Releases:** verify.sh + e2e.sh green → `ops/deploy.sh` (server+web) → `scripts/ship.sh`
  (Android → devstore) → owner MSI (desktop). Keep the 7 crypto vector files byte-identical;
  regenerate only the new one per feature.
