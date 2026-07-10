# andvari — changelog

## 0.7.0 cards phases 1–2 — fv2 foundation, server guard, web card items (2026-07-09, server+web deployed CT122)

The first two slices of cards/wallet items (design: `docs/design/2026-07-09-cards-wallet.md`,
tournament-settled). Additive: fielded 0.6.0 web/Android, the 0.2.x desktop MSI, and the 0.6.1
extension keep working untouched; **card creation ships dark** (`CARD_CREATE_ENABLED=false`,
the Option A rollout gate — flips when the 0.2.x MSI is retired). All version strings move to
0.7.0 (native artifacts build at their later phases).

- **formatVersion 2 with a per-doc floor (core + web).** Card-bearing docs seal at fv2;
  logins/notes stay fv1 (bit-compatible with the whole fielded fleet). Reseals are monotonic —
  `encryptItem` seals at `max(docFloor, the fv the item was decrypted at)` via a per-item map,
  and returns its fv so the wire field can never diverge from the AEAD AD. Web's five hardcoded
  `formatVersion: 1` sites now read the upload's own fv; `VaultItem` records the true stored fv
  (backup payloads now Android-parity even on the legacy-restore edge).
- **Server monotonic-fv guard (deployed).** A put/restore whose fv is below the stored row's is
  refused (`denied`, audited `push_denied/fv_downgrade`) with row + history untouched — the
  backstop that turns the 0.2.x desktop's automatic card-stripping conflict rewrite into a
  logged refusal instead of silent ciphertext loss. Provable no-op for all pre-card traffic;
  pinned end-to-end in e2e (forged fv1 downgrade over a real fv2 card row → denied, card intact).
- **Web card items (render/edit dark-launched).** Card editor (live IIN brand badge, Luhn
  warn-not-block, MM/YYYY selects preserving out-of-window stored years, digits-only + zero-pad
  + brand recompute at save — spread-only, unknown keys survive), detail view (brand + ••last4
  identity line, grouped reveal, copy-with-auto-clear, expired chip, masked CVV), list-row
  subtitles ("Visa ••4242"), and a calm fv-generic "N items … newer version" banner off the
  fail-closed undecryptable count (closes the web banner gap for every future format bump).
- **CardNormalize everywhere the same.** Pure TS port of core's CardNormalize (ASCII-only Luhn,
  IIN→brand, expiry adapters) consuming the same frozen `card.json` vectors; both ports now trim
  a pinned ASCII whitespace set (`trimAscii`) because platform `trim()`s disagree at the Unicode
  margins (JS strips U+FEFF, JVM strips U+001C–1F) — divergence vector-pinned in card.json.
- **CSV export honesty.** `CsvWarnings.cardItems` split out of the note catch-all; the export UI
  names skipped cards and points at `.andvari` backups (which carry cards as ordinary items).
  Spec 07 §1 updated; core's matching `cardItems` lands first thing in the Android phase.
- Autofill classifier groundwork (6 card `FieldKind`s, CVV demotion, token-bounded card keyword
  fallback firing only where the legacy verdict was NONE — card-free login verdicts bit-identical,
  204 card vectors) ships in core now; Android/desktop/extension consume it in phases 3–7.
- Adversarial review: phase 1 — 7 confirmed findings, all fixed; phase 2 — 7-lens review, 5 low
  findings confirmed → all fixed same-day, 2 refuted with traces.

## 0.6.0 — item history + undelete (2026-07-08, cross-platform release)

The "fat-finger seatbelt" release — the version bump (0.5.0 → 0.6.0) that gathers this cycle's
user-facing features into a coordinated release across web, Android, and desktop. Additive and
backward-compatible: the server's per-platform `minVersion` gate is unset, so older 0.5.0 clients
keep working. Web + server deployed to CT122; Android APK on devstore; Linux `.deb` published to
`/downloads`; Windows `.msi` follows (owner build). Every server-side piece was DB-snapshotted,
health-checked, and adversarially reviewed before ship.

- **Item history — roll back a fat-fingered password.** Every item's last 10 ciphertext versions
  (silently archived server-side since v1, previously unreachable — backlog F63) are now exposed
  via a grant-checked `GET /items/{id}/versions` and decrypted client-side under the held vault key.
  A per-item "Version history" panel (all three clients) reveals each past value and restores one
  with a tap. Honest bound: "up to the last 10 saves." Zero-knowledge intact — the server stores and
  learns nothing new. (Item AD binds `(vaultId, itemId, formatVersion)`, not rev, so an old version
  opens under the current key; history resets at a future vault-key rotation, by design.)
- **Undelete — a Trash to recover deleted items.** A grant-scoped `GET /items/deleted` lists
  tombstoned items (each named from its last archived version, since a tombstone carries no
  plaintext), and a dedicated `POST /items/{id}/restore` un-tombstones cleanly — a deliberate design
  choice over a plain put, which would flag an edit-over-tombstone conflict and spawn a spurious
  duplicate. A "Recently deleted" view on all three clients. (Attachments are not restored — their
  blobs are hard-unlinked at delete; passwords/notes/fields return. Trash retention is currently
  unbounded — a windowing decision, F49.)
- **Recovery hardening (earlier in the cycle, additive under 0.5.0).** F57 escrow re-seal across all
  three clients (a hostile server cannot redirect the UVK escrow — the new fingerprint is verified
  from the printed sheet), F59 admin escrow-download, a passed account-recovery drill, and the
  pre-migration integrity batch — together unblocking the real-secrets migration.

## v6-QW1 — TOTP-QR + devices hub + purge gauges (2026-07-08, deployed CT122)

Additive to 0.5.0 (no client-version bump — web+server only; Android/desktop unchanged at
0.5.0). Deployed to CT122 and verified (bundle sha matches repo dist, both new gauges live in
`/metrics`); adversarial review 7/7 confirmed → fixed/documented before ship.

- **Two-factor QR + a "get andvari on your devices" hub (v6-QW1, web + server).** Server-TOTP
  enrollment now renders the `otpauth://` URI as a scannable QR so a family member enrolls by
  camera instead of hand-copying a 32-character secret (a dependency-free vendored encoder,
  rendered entirely client-side — nothing new leaves the browser; the copy-URI / copy-secret
  fallbacks stay). A new Settings section points at every real client — this browser, the
  devstore Android install (with its own QR), and the Windows installer once the owner
  publishes it (it reads the `/downloads/manifest.json` the server already serves, showing an
  honest "not published yet" until then) — and hides those pointers on the public break-glass
  origin. Server-side, two additive `/metrics` gauges (`andvari_vaults_deleted_pending`,
  `andvari_vaults_purge_overdue`) expose the Skipti janitor's purge backlog so the
  design-mandated stalled-purge alert has a series to fire on.

## 0.5.0 — shared-vault lifecycle "Skipti" (2026-07-08)

Owner gripe 1 closed fleet-wide: shared vaults are no longer immortal. Server schema v4
(live on CT122, migrated with a pre-v4 snapshot), web UI deployed, Android APK
vc 16260489 on devstore; the desktop app inherits the client protections through the
shared engine (UI parity rides the future MSI rebuild). All wire changes additive —
fielded 0.4.0/0.2.x clients unaffected, no minVersion pin armed.

- **Delete a shared vault** (owner): type-the-exact-name confirm with an honest
  "what this does and doesn't erase" block, optional "Copy items to my Personal vault
  first…", 7-day grace, then a daily janitor purge that reduces items to permanent
  ciphertext-free tombstones and wipes every grant's key material.
- **Restore within grace** — Sharing → Recently deleted; brings the vault back for every
  member with everything in it, including members' parked offline edits (replayed with
  their original ids).
- **Leave a shared vault** (non-owner); owners are told to transfer or delete instead.
- **Transfer ownership** — two-phase: the owner offers (14-day expiry, one pending max),
  the recipient sees a consent screen that renders only after the offer proof verifies
  against the vault's own key, accepts by re-wrapping the vault key under their own
  account key. The old owner stays on as a writer.
- **Rename a shared vault** (owner) — name stays ciphertext to the server.
- **Move / Copy an item between vaults** — copy-leg-first with a positive server
  confirmation before the source is touched; attachments are re-encrypted under fresh
  file keys so ciphertext can't be linked across vaults.
- **Lifecycle proofs (ZK preserved):** every destructive action carries an HMAC minted
  under a key derived from the vault key, which the server never holds — clients verify
  removals/deletes/transfers as genuine owner actions; anything unverifiable lands in a
  local holding area with a warning instead of being silently dropped. The holding area
  is durable on phones (ciphertext-only at rest).
- Server hardening that rode along: uniform-403 guard order (no vault-existence oracle),
  idempotency by operation identity (a stale delete retry can never undo a restore),
  denied results never cached (parked edits re-apply after restore), removal proofs
  stored durably, the members list refused on the public break-glass origin, split
  destructive/recovery rate buckets so a delete spree can't block its own undo.

## 0.5.0-era refinement batches (v5 cycle, B1–B8 — all deployed)

Polish, fixes, and half-wired features across the shipped stack, landed as eight reviewed
batches over 2026-07-07 and carried to the whole fleet with the 0.5.0 release (the version
constant was pinned once, by batch B4).

- **Vault screen chrome (web).** The toolbar no longer overflows — the two export actions
  fold into an "Export ▾" menu (viewport-clamped, keyboard-navigable) so the search box
  keeps its width; the header survives phone widths with Lock always reachable; light-theme
  buttons and the item monogram are legible in both themes; the connectivity dot is honest
  (green only after a successful sync, grey on a sustained disconnect).
- **Android autofill resurrected.** Fixed the four reasons it produced zero suggestions on
  every browser: missing package-visibility (`<queries>`), a Chrome signing-cert pin
  truncated by one base64 character (now guarded by a core 32-byte-decode test),
  `supportsInlineSuggestions` never declared, and every failure collapsing into silence. New
  in-app **Autofill status** screen (service/vault state, last request with the "why nothing
  filled" reason and the caller's observed cert digest, and a self-expiring debug log that
  records only field types/counts/host names — never values), a **"Open andvari"** fallback
  row so a fill request is never dead-silent, and a post-unlock no-match message. Firefox and
  Samsung pins are captured on-device via the new screen (`docs/autofill-fold-debugging.md`).
- **Backups (ops).** The nightly clean-snapshot job no longer silently failed every night
  after the first (VACUUM INTO refused to overwrite — PBS/B2 had been carrying a frozen
  first-night copy); the snapshot is now `600` from creation and failures escalate to
  journald instead of unwatched cron mail.
- **Errors that tell the truth (web).** A VPN blip no longer reads as "Wrong master
  password"; a transient policy-fetch failure no longer claims the escrow ceremony isn't
  done (Retry with feedback instead); item deletes can't lie in either direction
  (permission vs connectivity vs server error, and a committed delete is never reported
  as "nothing was removed"); sharing errors drop raw wire codes; enrolling can't strand
  you on a consumed invite after a network hiccup.
- **Release & update truth.** One version constant now feeds the server, desktop, and the
  build gate (0.4.0 shipped with two modules still self-reporting 0.3.0); desktop
  identifies itself as `windows`/`linux` on the wire (it said `android`, so a desktop
  update-pin could never reach it); the "update available" banner shows above every
  desktop screen with the download link (it only showed on a screen signed-in users never
  see, and Linux compared itself against the Windows manifest); a 426 minVersion refusal
  is a real blocking "Update required" screen on desktop.
- **Safety rails.** The last active administrator can no longer be disabled (one
  unconfirmed click used to lock the whole instance, recoverable only by DB surgery) —
  refusals are audited; the admin Users list confirms before disabling; the spec's
  server-knowledge table now matches the real schema exactly; the conflict-copy and
  password-strength derivations are vector-pinned across both implementations; the
  annual escrow-drill reminder actually exists now (n8n `wf-escrowdrill-001`).
- **Session & sync integrity (web).** Token refresh is single-flighted per tab and
  coordinated across tabs (two concurrent refreshes used to trip the server's theft
  heuristic and revoke the whole device); a transient 502 during refresh no longer signs
  every tab out with a false "revoked" message; Lock and auto-lock keep the session and
  land on the lighter "Welcome back" unlock with a reason line (locking one tab locks
  them all); plain session expiry says so instead of claiming revocation; with the live
  socket down the vault polls over HTTP and offers a manual "Sync now" (it used to freeze
  silently); the client now enforces the spec's tamper checks (server identity-key
  cross-check at unlock, rollback/replay rejection, and a resync must be a full snapshot
  before local state is replaced).
- **Native data-safety.** Rotating or folding the phone mid-edit no longer wipes typed
  work (and a save finishing mid-fold closes the editor it should); unlock no longer
  freezes the UI for seconds (argon2 off the main thread); screens are excluded from
  Recents thumbnails/recordings (except the Autofill status screen, which stays
  screenshot-able on purpose); clipboard secrets are marked sensitive and cleared without
  ever clobbering something you copied later; sign-out revokes the device server-side
  even from the locked screen; a mispicked huge attachment can't crash the app; TOTP
  secrets can actually be typed by hand on all three clients (the field used to rewrite
  itself on the first keystroke); read-only members no longer see Edit/Delete buttons
  whose work the server would destroy; and items written by a future app version show as
  "N items need an app update" instead of silently vanishing from lists.

## 0.4.0 — backups & export, auto-lock, forward-compat, sync liveness

- **Back up vault** (all clients). One file, encrypted with a passphrase you choose
  (your master password is a fine choice — the backup is then exactly as protected as
  your vault). Full fidelity: every vault you can read, TOTP, password history,
  attachments (opt-in, capped), restorable years from now with nothing but the file,
  the passphrase, and the documented format (spec 07). `tools/backup-cli` verifies,
  dumps, and extracts backups offline. Restore flows in clients come next release —
  the file format is frozen and forward-safe now.
- **Export for another password manager** (all clients). Chrome-compatible CSV with a
  `totp` column (andvari's own importer round-trips it; other managers import the
  Chrome columns). The export screen names exactly what a CSV cannot carry.
- **Auto-lock enforced.** The org policy's `autoLockSeconds` now actually locks all
  three clients after inactivity (including the Android autofill path), and native
  clients honor the clipboard-clear policy instead of a hardcoded 30 s.
- **Forward compatibility fixed.** Editing an item written by a NEWER client version
  no longer silently strips fields it doesn't know (spec 02 §3 is now enforced and
  vector-tested in both implementations). This also fixes three live bugs: Android
  resetting `favorite` on every edit, both native editors wiping password history,
  and native edits truncating multi-URI logins to one URI.
- **Sync liveness.** Web reconnects its live-sync socket after drops (server deploys,
  laptop sleep) with fresh one-shot tickets; native clients sync on foreground and
  every 5 min while open, so revocations and policy changes actually arrive.
- **Safety rails.** Delete now asks for confirmation everywhere; deleting is still
  fleet-wide. New-client-version documents fail closed instead of being downgraded.
- **Ops.** `user_lookup` no longer writes the looked-up email into audit logs;
  escrow uploads are structurally validated; a typed 426 upgrade-path surfaced in the
  client API + an admin drill doc; recovery-cli gained an offline escrow-canary
  `verify` and a portable fat jar; Uptime-Kuma now watches `/healthz` via a
  heimdall-relayed push monitor (dead-mans if heimdall dies too).
- Fielded 0.3.0 clients keep working; no wire or schema changes require upgrade.

## 0.3.0 — family sharing, offline cache, CSV import, autofill

- **Family sharing.** Create shared vaults and add household members. Each member grant
  seals the vault key to that member's identity key (`crypto_box_seal`); before sending it
  you verify their short **identity code** out of band (in person / by phone) — that code is
  derived from a key the server can't forge. Web has a full Sharing screen (create, add by
  email with the fingerprint check, change role, remove); native apps open shared vaults and
  show your own identity code. Removing a member is revocation-only in v1 (they keep anything
  they already saw; key rotation is a later release).
- **Durable offline cache** (native). Android/desktop keep an encrypted on-device copy of the
  vault, so the app opens instantly and works **offline** (read + queue edits) until it
  reconnects. Only ciphertext is stored; the master password is still required to unlock.
- **CSV import.** Import from Chrome/Edge or Firefox password exports (web + native). Parsing
  is fully on-device; the file never leaves your machine. Handles quoting/dedupe/rename and
  warns that the export holds plaintext — delete it after. An interrupted import resumes
  without creating duplicates.
- **Android autofill** (fill-only). andvari can fill logins in Chrome and other apps. Matching
  is strict (exact host or a true subdomain — never a look-alike or a whole TLD) and honors a
  web domain only from a trusted browser. Locked → tap to unlock in place. Enable it in
  Settings → Passwords & autofill.
- **Security hardening.** Real client IPs behind the proxy for rate-limits/audit; per-user
  upload caps; WebSocket auth via a single-use ticket (no token in URLs); no emails in audit
  logs; tighter CSP. Desktop now defaults to the tailnet URL (auto-migrates once).
- Fielded 0.2.4 (Android) / 0.2.0 (desktop) clients keep working against the upgraded server.

## 0.2.4 — default to the tailnet server

- Default server URL is now https://andvari.taila2dff2.ts.net (reachable from any
  Tailscale device; the old .2.122 LAN IP isn't, from off-VLAN-2). Existing installs
  on the old default auto-migrate once. Changing the server now reloads the recovery
  key immediately (no restart).

## 0.2.3 — boot crash FIXED

- Fixed the ClassNotFoundException that crashed the app on launch since v0.1.0: the
  manifest referenced MainActivity/Application by relative name (resolved against the
  `com.silencelen.andvari` namespace) while the classes live in package
  `io.silencelen.andvari.app`. Now fully-qualified. The app launches to the Welcome
  screen (verified on-device). Crash reporter + ProfileInstaller changes from 0.2.1–0.2.2 kept.

## 0.2.2 (Android boot-crash diagnostic)

- Disable ProfileInstaller auto-init (a pre-Application startup step that can crash on
  some Android 15/OEM builds) — perf-only, safe to drop.
- Crash reporter now renders with a plain Android view (no Compose), so a crash in the
  Compose layer itself is still shown on the next launch to screenshot.

## 0.2.1 (Android diagnostic)

- On-screen crash reporter: if the app hits an unhandled error, the next launch shows
  the stack trace to screenshot (no adb needed). Diagnostic aid; no feature changes.

## 0.2.0

- Encrypted file attachments on items: attach from the editor, download+decrypt from
  the detail view. Per-file keys; the server only ever stores ciphertext chunks.
- Server-TOTP (Settings): enroll an authenticator as the second factor that
  break-glass/public logins require. Sign-in now prompts for a code when the server
  asks for one.
- Matches server/web 0.2.0 (admin console, password health, password change live in
  the web app).

## 0.1.0 (first release)

First Android client for the in-house andvari password manager.

- Sign in and enroll (invite + recovery-fingerprint confirmation) against the
  andvari server (default CT 122, `192.168.2.122`; configurable in the sign-in
  screen).
- Zero-knowledge: your master password derives all keys on-device; the server only
  ever sees ciphertext. A relaunch re-prompts for the master password (the vault key
  is never stored).
- Vault: search, logins and secure notes, per-item detail with copy-to-clipboard
  (auto-clears after 30s), live rolling TOTP codes, and a strong password generator.

**Note:** enrollment needs the server's escrow recovery key configured first (the
one-time offline ceremony). Until then the server disables new-account creation.
