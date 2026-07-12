# andvari — Roadmap

Where andvari is, what gates real-secret migration, and where it goes next. Living doc;
the SSOT for *state* is the memory file `andvari-password-manager-2026-07-05.md` + the
git history. This is the SSOT for *direction*.

## v5 refinement cycle — batches B1–B8 SHIPPED (2026-07-07)

A 14-lens recon (168 raw → 84 deduped findings) drove eight reviewed batches, all shipped
same-day (each: gates → high-effort adversarial review → fix → deploy): web vault-chrome +
honest connectivity dot (owner gripe 4); the nightly-backup hotfix (silently dead since
night 2, verified fixed on CT122); **Android autofill resurrected** (four kill switches +
the Autofill Status diagnostic screen; owner protocol `docs/autofill-fold-debugging.md`);
web error-truthfulness; release/update-version truth (MSI rebuild now safe); the sole-admin
lockout guard + ZK-table/spec truth + vector-pinned derivations; **session & sync
integrity** (single-flight refresh — the device-revoking `refresh_reuse` race — lock
semantics, cross-tab lock, WS-down polling, tamper/rollback guards on web); **native
data-safety** (fold-proof editing, argon2 off the UI thread, FLAG_SECURE, clipboard
hygiene, locked-screen sign-out revocation, hand-typeable TOTP, reader-role gating, the
"N items need an app update" banner). Full narrative: CHANGELOG ~~"Unreleased"~~
"0.5.0-era refinement batches" section (the heading it now lives under).

**Cycle wrap (2026-07-08):** the **Skipti** shared-vault lifecycle **SHIPPED in 0.5.0**
(design `docs/design/2026-07-07-shared-vault-lifecycle-skipti.md`; schema v4 live on CT122
with a pre-migration snapshot). The finding tail is **triaged into `docs/v6-backlog.md`**
(9 already-fixed / 19 quick-wins / 8 fold-ins / 8 standalone / 1 won't-fix — the honest v6
work queue). Round-2 recon (live-WS, MSI wire-compat, attachments E2E, prod parity,
autofill, lifecycle cross-slice + persona walks, all findings adversarially verified) ran
2026-07-08 — report in `docs/recon/`. **Owner-actionable now:** update the Android app
(devstore vc 16260489) and run the Fold autofill protocol; rebuild the MSI (now safe —
fixes the 0.2.x edit-corruption); enroll server-TOTP (the v6-QW1 QR makes it a
camera-scan — do it right after the QW1 deploy).

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
   `/etc/andvari/escrow-canary.b64`. The pre-swap TEST account is already gone — CT122 reads
   `users=1, escrow=1` (owner only), so `recovery-cli verify` is all-PASS.
2. ~~**Enroll the first admin**~~ **DONE** (bootstrap token consumed + stripped; owner admin
   enrolled against the real key). **Still open: enroll server-TOTP** (web → Settings) —
   break-glass public login is impossible without it, and CT122 shows it not yet enrolled.
3. **Windows MSI rebuild** on the owner box (desktop ~~0.13.0~~ **0.14.2** in-tree as of 2026-07-11; fielded MSI still
   0.2.x — the tailnet-default URL + version bump are in the tree; only the owner can run
   jpackage/WiX). See `ops/windows-build.md`. (Batch B4 makes the update banner + 426 path
   honest first.)
4. **On-device smoke tests** — attachments + TOTP on the Fold + desktop; the autofill Fold-7
   checklist (design §6.4); a CSV dry-run with a synthetic export; a shared-vault invite
   round-trip web↔Fold with the printed-sheet fingerprint check.
5. ~~**Uptime-Kuma monitor** on `/healthz`~~ **DONE 2026-07-06** — gjallarhorn can't reach
   VLAN 2 (UDM default-deny), so it's a Kuma **push** monitor (`andvari-healthz`, id 13):
   heimdall checks `http://192.168.2.122:8080/healthz` every 2 min and pushes up/down
   (`andvari-kuma-push.{sh,service,timer}` on heimdall, mirrored in netplan
   `scripts/active/monitoring/`; token in `/etc/andvari-kuma-token`). Also dead-mans if
   heimdall itself dies (pushes stop → missed-heartbeat alert → Telegram).
6. **Drills:** PBS restore of CT122's DB + blobDir; ~~**escrow-recovery drill** with the
   air-gapped key (recover a throwaway account end-to-end)~~ **DONE** (0.6.0-era;
   `docs/drills/account-recovery-drill.md` + a passed drill); **min-version-pin exercise**
   (bump `minVersion`, confirm all three clients block writes and show the upgrade path);
   **backup-verify drill** (export a `.andvari` → `backup-cli` verify/dump/extract —
   `docs/drills/backup-restore-drill.md`, then quarterly).
7. **30-day soak** with synthetic secrets across 3 devices (web + Fold + desktop).
8. **Migrate**, then keep the old manager **read-only for 60 days** before deleting it.

## P6 — next horizon (post-real-secrets)

Prioritized; each is additive and back-compatible.

- **Quick-unlock** (spec 01 §8) — Android Keystore-wrapped UVK + biometric; Windows Hello /
  DPAPI + PIN on desktop. The single integration point on Android is `AutofillUnlockActivity`
  (hook already noted). `androidx-biometric` is already catalogued. **Android side DONE
  0.9.0 (F84); Windows/desktop DPAPI still deferred.**
- ~~**Autofill save-flow ("Save to andvari?")**~~ **DONE 0.7.0** (onSaveRequest +
  SaveConfirmActivity; web via extension) — *owner-requested 2026-07-07.* v1 is
  fill-only; add `SaveInfo` on the FillResponse + `onSaveRequest` so that when the user
  types credentials (or a card, below) andvari has no record for, it offers **"Save to
  andvari?"** and creates the item. Android first (SaveInfo/SaveCallback + a confirm
  activity that unlocks if needed); web save happens through the browser extension. Pairs
  naturally with the Autofill Status diagnostics already shipped (B2) and with cards.
- **Cards / wallet items + card autofill** — *owner-requested 2026-07-07.* **DESIGN GATE SETTLED
  2026-07-09** via a 4-design tournament × 12 breakers × judge: full contract in
  `docs/design/2026-07-09-cards-wallet.md`. Verdict: `ItemDoc + card: CardData?`, `type:"card"`,
  all ciphertext; **cards seal at formatVersion 2 (per-doc floor)** backstopped by a ~10-line
  **server monotonic-formatVersion guard** — NOT type-gate-at-fv1. Decisive code-verified reason:
  the fielded **0.2.x MSI is pre-ExtrasOverlay** and has an automatic pull-side conflict-rewrite
  that would silently strip an fv1 card with no user action; fv2 makes that a refused+audited
  `fv_downgrade` write instead of data loss. Autofill: 6 new `FieldKind`s, CVV demotion +
  token-bounded keywords (no substring "pan"/"exp"), per-frame-cluster card datasets, explicit
  trust gate. Extension: popup Cards + copy only this batch (in-page checkout fill deferred behind
  a frame-egress contract). **One owner decision** (rollout timing A/B) is in the design doc's last
  section; default A (card-create dark until the 0.2.x MSI is retired). Target release 0.7.0.
  **STATUS 2026-07-09: ALL PHASES COMPLETE — 0.7.0 CUT.** Phases 1-2 (`4ab5049`/`ed7b531`,
  server+web DEPLOYED CT122), 3+5 native UI (`106096f`), 4 Android autofill (`3255c1f`),
  6 extension (`f68abcb`), release cut (APK devstore, .deb + extension zips /downloads).
  Card-create DARK on every client per Option A — flip checklist in the design doc, fires
  when the 0.2.x MSI is retired. Owner steps: Windows MSI (`ops/windows-build.md`), Fold
  autofill re-run, extension load-unpacked. Deferred: in-page extension card fill (frame-
  egress contract), combined-expiry LIST dropdowns, Skipti honesty line placement on natives.
  **Owner dev-note 2026-07-10 (re-request): "support storing autofill creditcard and payment
  details."** Storage/UI/Android-autofill already shipped above but card-create is DARK
  (Option A) — so the visible to-dos are: (1) the Option-A unhide flip once the 0.2.x MSI
  retires (checklist in the cards design doc §build-order), (2) extension in-page card fill
  behind a breaker-passed frame-origin egress design, (3) scope decision on non-card payment
  types (IBAN / bank account) as a new template. Tracked in
  `docs/PLAN-autonomous-2026-07.md` §"Owner dev-notes queued".
- **Browser extension** — *owner-requested 2026-07-07 (reaffirmed).* Reuses the `:core`/web
  `UriMatch` + `FieldClassifier` (already built + vector-tested for exactly this) and the
  same-origin API; carries the web save-flow. Chromium + Firefox. Go/no-go spike:
  libsodium-WASM under an MV3 service-worker CSP + host_permissions vs. CORS. *(SHIPPED
  0.6.1/0.7.0 — the item below is the open follow-on.)*
- **Extension self-update / update-available signal** — *owner dev note 2026-07-10.* The
  self-hosted, load-unpacked extension has no store-update path, so a newer version on
  CT122 `/downloads` is invisible to an installed copy today. Two honest tiers: (1) **cheap,
  do first** — the SW periodically fetches `/downloads/manifest.json` (already carries the
  `browserExtension` version), compares to its own `MAX_ITEM_FORMAT_VERSION`-adjacent version
  const, and surfaces an "update available → download & reload" badge in the popup + Devices
  hub (no silent reinstall — Chrome forbids it for unpacked). (2) **real auto-update** — a
  signed Firefox `.xpi` with an `update_url` + `updates.json` on CT122 auto-updates natively;
  Chrome needs the Web Store or an enterprise `update_url` + CRX (owner call whether store
  distribution is wanted). Start with (1); it's ~a version-check + popup surface reusing the
  manifest the Devices hub already reads. **Tier 1 DONE (extension 0.8.0, `201428b`);
  tier 2 stays parked.**
- **Owner-signed grants** (Ed25519 signing identity) — closes F16 fully: grants and lifecycle
  ops carry a sender signature under a per-account signing key, so a malicious server can no
  longer inject vaults/credentials or forge a transfer even to a client that holds no VK. The
  0.5.0 lifecycle proofs (spec 03 §11) remove the *server* from the forgery set; this removes
  keyholders too. A new signing identity touches enrollment/escrow/every grant path — hence
  deferred here, not into v5.
- **VK lazy rotation on member removal** (closes accepted risk R7) — the next online writer
  re-keys the vault and re-seals grants; removed members lose access to future ciphertext,
  not just server delivery. Needs a rotation protocol fenced against concurrent writers.
  **Trigger extended (v5): also fire after an ownership transfer and after a restore whose
  vault had members removed before the delete.**
- ~~**ItemDoc unknown-field round-trip**~~ **DONE in 0.4.0** (ExtrasOverlaySerializer + the
  `itemdoc.json` vector) — a future additive field now survives a mixed-fleet edit, so new
  optional ItemDoc fields are safe to add.
- ~~**eTLD+1 / PSL matching** for autofill (v1's label-boundary rule is strictly safer but
  misses sibling-subdomain matches)~~ **DONE 0.10.0 (`5587d8c`)**; **Digital Asset Links**
  for the native-app-with-web-creds case (v1 uses `androidapp://` exact + a browser
  allowlist) — still open.
- **iOS client** (KMP `:core` already targets it in principle; not wired) — assessed
  2026-07-10 (`docs/assess/2026-07-ios.md`: defer native; PWA-polish default; trigger = a
  daily iPhone user hurting from no system autofill).
- **Passkeys / WebAuthn** — evaluate as a credential type; large — assessed 2026-07-10
  (`docs/assess/2026-07-passkeys.md`: defer-with-trigger; store-as-fv3 + Android
  CredentialProvider is the pre-agreed shape; trigger = a household site pushing
  passkey-first).

## Onboarding & reach (owner-requested 2026-07-07 — near-term product polish, mostly UI)

- ~~**TOTP enrollment QR code**~~ **SHIPPED 2026-07-08 (batch v6-QW1)** — Settings enrollment
  renders the otpauth URI as a scannable QR (vendored zero-dep `qrcode-generator@1.4.4` under
  `web/src/vendor/`, hashes pinned, decode-proven with a scratch jsqr round-trip; copy fields
  kept as fallback). Native parity still later (enrollment happens on web today).

- ~~**"Get andvari on your other devices" hub**~~ **SHIPPED 2026-07-08 (batch v6-QW1)** —
  Settings section: this browser, devstore Android (with install QR, tailnet-only labelled),
  Windows MSI via `/downloads/manifest.json` (honest "not published yet" until the owner
  publishes; no extension row until one exists). Hidden on the public break-glass origin
  (shared `isPrivateOrigin`). The batch also shipped the Skipti purge-visibility gauges
  (`andvari_vaults_deleted_pending` / `_purge_overdue`) — apply the ops alert per
  `ops/grafana-purge-stall-alert.md` after deploy.
- **Guided per-source importers** — replace the single generic "CSV upload" with named,
  instructioned flows: "Import from Chrome / Edge / Brave / Opera" (all export the *same*
  Chromium CSV the current importer already parses — so this slice is mostly a friendlier
  picker + per-source "how to export" steps, small), then "Import from Firefox / Bitwarden /
  1Password / LastPass" (each needs a new format adapter — medium each; the importer already
  has an `ImportFormat` seam). Cross-platform (web + natives). Eases the switch away from a
  previous manager — the natural companion to the vault-lifecycle work (people arrive, people
  leave). Do the Chromium-family UI first as a quick win; add adapters incrementally.
  **DONE 2026-07-09 — 0.8.0 release.** All 8 sources guided on web+Android+desktop (desktop
  gained the whole import flow); Bitwarden/1Password/LastPass adapters on both impls,
  vector-pinned (`import-foreign.json`); F75 vault-aware dedupe (personal-vault scope,
  zero-destruction, refuse-not-degrade); F56 measured at 10k + three server fixes applied
  (pull UNION-ALL rewrite, GC out of the DB lock, tombstone partial index — addendum doc).
  Deferred, recorded in the design doc: LastPass template parsing, 1pux adapter, pull
  paging (recommend-only), web list virtualization at >500 items.
  **Owner dev-note 2026-07-10 — import destination vault picker:** imports currently
  commit to the Personal vault only; the user should choose the destination vault
  (writable vaults, F18 picker semantics) at the confirm step, web + natives, per-import
  for v1. F75 dedupe scoping must follow the chosen vault. Tracked in
  `docs/PLAN-autonomous-2026-07.md` §"Owner dev-notes queued". **DONE (S2, 0.10.1,
  `c9a0d4d`).**
  **Superseded 0.14.1 (2026-07-11):** the per-source picker described above was folded into
  ONE universal import screen (`docs/design/2026-07-11-universal-importer.md`) — the parser
  always keyed off file headers, never the pick; only the per-source "how do I export?"
  help survives (core `ImportHelp` + its web twin). The adapters/dedupe/perf work stands.

- **Owner dev-note 2026-07-12 — "email this invite" checkbox on the invite-user flow.**
  Add an opt-in checkbox to the Admin invite form (`InviteForm`, `web/src/ui/Admin.tsx:284`,
  beside the existing `isAdmin` + QR options) that, when checked, ALSO emails the invitee their
  enroll link (`composeEnrollLink` — the same link the QR encodes) instead of the admin only
  handing the token over by hand. **Not a UI-only tweak — the real cost is net-new server email
  capability:** andvari has ZERO mail infra today (grep-confirmed; invites are deliberately
  hand-delivered out-of-band), so this needs an SMTP client + config + a credential in
  `andvari.env` + an email template on CT 122, plus a client→server flag on `createInvite`
  (`server/.../AdminService.kt:32`). Size **M–L** (server capability), not S.
  **Threat-model note (must be weighed before build):** emailing the enroll link widens the
  invite-delivery surface — the token lands in an inbox + the mail provider's hands, weakening
  today's out-of-band delivery (R3-adjacent). Mitigating facts: enrollment still requires typing
  the printed-sheet recovery fingerprint (spec 04 §2(3)), so an emailed link alone cannot
  complete enrollment; keep the checkbox **default-OFF** (secure-by-default), and consider a
  short invite TTL for emailed invites (the QR-invite precedent, `QR_INVITE_TTL_MINUTES`).
  Cross-check whether emailed invites should be limited to the private origin. Pitch-until-ratified
  (exploration/N7 lane); no build without the owner signing the mail-surface tradeoff.

- **Owner dev-note 2026-07-12 — collapse "Invite" + "Invite with QR" into ONE "Invite" button
  that shows the QR by default (with the token).** Today `InviteForm`
  (`web/src/ui/Admin.tsx:284,305`) has a `withQr` fork: a plain invite (72 h TTL) vs a QR invite;
  the result view shows the token, and the QR only when that path was chosen. Target: a single
  Invite action whose result always renders the enroll QR **and** the token/link together, so the
  admin can hand over whichever is convenient. Size **S** (mostly UI — merge the two buttons,
  always compose+render the QR in the result). **The one real decision — invite TTL:** QR invites
  currently get a SHORT TTL on purpose (`QR_INVITE_TTL_MINUTES`, `Admin.tsx:261`) because a
  photographed QR can't be revoked. If EVERY invite now shows a QR, every invite is photographable
  → the safe default is to give **all** invites the short TTL (or make TTL an explicit field), and
  the QR-can't-be-revoked warning copy should show on every invite. Decide the TTL policy before
  building. Pairs naturally with the "email this invite" note above (same form; if both land, the
  result offers token + QR + optional email in one flow).

- **Owner dev-note (BUG) 2026-07-12 — password-only re-auth autofill creates a DUPLICATE item.**
  Symptom (owner, live): on a site whose re-login form shows ONLY a password field, the owner
  autofills the password from an andvari suggestion and submits; andvari's save-offer then asks
  to "save this login?" as if it's new, and accepting creates a SECOND item (password-only)
  alongside the original (username+password) — two registrations for the same site. **Root-cause
  hypothesis:** the save-offer doesn't recognize the submitted password came FROM / matches an
  existing item for that origin, so a password-only submit (no username to match on) is
  classified as a new credential. **Fix direction:** before offering "save as new," dedup the
  submitted creds against existing items for the site — if the password matches an existing
  item's password (and/or the fill originated from an andvari autofill of that item), SUPPRESS
  the save-offer or offer **update** instead of create; treat username-absent password-only
  submits as an update to the matching item, never a new one. **Likely areas:** extension save
  detection (`content.ts` / `content-ui.ts showSaveBanner` + the background save path) AND Android
  autofill `SaveConfirmActivity` / save-offer logic — check both; the owner hit it via a browser
  fill. **Size S–M, P2 (data hygiene — silently clutters the vault with dupes).** Verify against
  the shipped save-flow before designing.

- **Owner dev-note (enhancement) 2026-07-12 — accelerate live cross-client sync via a change
  push.** Owner want: when a member changes an item, push an update notice to the OTHER remote
  clients on that vault so they pick it up quickly (use case: edit in the web app because it's
  easier to navigate → want the extension to reflect it without a manual refresh). **Current
  state to verify:** the server already has a WebSocket notify path (spec 03 §WS notify) that the
  web client uses for live updates; the **extension (MV3 service worker) most likely does NOT
  hold a live WS** (SW eviction makes a persistent socket hard) and refreshes on popup-open /
  poll instead. **Fix direction:** extend the live-notify to the extension — an MV3-safe WS that
  reconnects on SW wake (or a lighter push/alarm that triggers a sync) so a peer change lands
  fast; confirm the natives (Android/desktop core `SyncEngine`) also consume the WS notify vs
  poll. **Size M** (server notify infra exists; the MV3 SW WS lifecycle is the real work — pairs
  with the extension's existing WS-down-poll handling). No data-model change; pure freshness.

## Horizons & cycle doctrine (2026-07-08 brainstorm — the spine behind the queues)

**The organizing gate is the real-secrets migration.** Features are cheap before it and
risky after it, so the order of everything above is: (1) *before migration* — the recovery
path must be real and drilled (escrow re-seal F57, the F59 admin button + 2am drill doc,
native mustChangePassword F58), the public origin hardened (QW-1: F50/F52/F55), the
password floor raised (F60); (2) *during the 30-day soak* — features that convert mistakes
into trust: **item history & undelete on the existing `item_versions` data** (the v6
exploration tournament's 4-of-5-lens convergence; the server already archives every
overwrite and delete that no client can reach), plus the daily-delight queue
(cards+save-flow, importers — which are the migration tooling itself, quick-unlock);
(3) *after* — the compounding security milestones.

**Far horizons, in rough order of when they become real:**
- **Owner-signed grants** (already under P6) is the "security story complete" milestone —
  treat it as its own cycle with a Skipti-grade design tournament.
- **Emergency access / dead-man escrow** ("Arfi" tournament pitch): the 10-year household
  story. Honest blocker its breaker found: andvari has no out-of-band channel to deliver a
  veto-window notice — design that channel (likely via household ops, not the ZK server)
  before the feature.
- **Passkeys:** store-as-item + extension bridge is the realistic first slice; full
  WebAuthn custody stays "evaluate". Jumps the queue the moment household sites push
  passkeys hard.
- **Post-quantum, narrowly:** the escrow sheets are the decades-lived secret — a PQ-hybrid
  seal (X25519+ML-KEM) for escrow blobs is the one early PQ investment worth making;
  everything else waits for libsodium.
- **Steward panel / self-judging health** (tournament pitch): backup freshness, drill
  staleness, canary age as green/amber/red in Admin — the F38 lesson generalized.
  Companion: a generated, printed "household recovery booklet" (paper is the last-resort DR).
- **Explicit non-goals** (scope discipline): multi-household federation, cloud hosting, HA.
  One household, one home server, belt-and-suspenders backups — that constraint is why the
  ZK design stays auditable.

**Cycle doctrine (constitutional):** every cycle ships one *trust* feature, one
*daily-delight* feature, and one hardening/debt batch from `docs/v6-backlog.md`; wide
solution spaces get a design tournament; every diff gets the high-effort adversarial
review before deploy (5-for-5 catching data-loss past green gates); recon re-runs after
each cycle. Small reviewed batches, additive wire, docs true as you go.

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
