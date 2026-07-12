# Cut 3 — Pre-migration hardening batch — 2026-07-12

> The quad-sweep's standalone code findings (`docs/assess/2026-07-11-quad-sweep.md`), re-verified
> STILL-LIVE at HEAD by the cut-3 investigator. This is the "responsible integrity + honesty +
> public-endpoint hardening" batch to land BEFORE real household secrets migrate — the backup/
> rollback and recovery surfaces must be honest, and the newly internet-facing server should bound
> request bodies. Full doctrine: design → breaker → parallel disjoint builds → find→refute → ship.

## SCOPING (2026-07-12) — cut 3 ships spec07-1 + desia-3/4 (WEB-ONLY); everything else → "3b"

**cut 3 ships `spec07-1` (export enumerates missing-VK items) + `desia-3/4` (web copy) — WEB-ONLY,
additive at 0.15.0** (`ops/deploy.sh` web bundle; no server code → **no vzdump**, cut-1 precedent).

**`spec03-01` (server body cap) DEFERRED → 3b** — the cut-3 breaker showed the naive design would
BREAK the flows it's meant to harden: (B1) the exempt predicate used `PUT` but the attachment upload
is `POST` (`App.kt:374`) → every >1 MiB attachment upload would 413 fleet-wide; (A4) there is **no
per-item blob byte cap** (`Service.kt:339` bounds only the 200-mutation *count*), so a note-heavy
200-item `POST /sync/push` exceeds 1 MiB → the **CSV migration import throws** — the exact flow this
cut protects. The correct fix needs a `/sync/push` (and `/items/{id}/restore`) body-size decision
that touches import chunking (core → a fleet rebuild) or an explicit per-route cap — its own design +
breaker in 3b, not a rushed exempt-list. **Also deferred → 3b:** `spec02-1` (metaV — core),
`spec06-03/04` (CsvImport — core), `spec04-2/3` (recovery-cli), `spec01-f61` (KDF parity). Per-item
fixes stay documented here.

## spec07-1 breaker amendments (BINDING — fold before build)

- **B2/A2 (double-count + heal):** at the top of the HELD path (once past the new `:435 !hasVault`
  block, before the try) unconditionally `missingVkById.delete(item.itemId)` — one line covers
  became-decryptable (`:451`), held-but-newer-fv (`:461`), and held-tombstone (`:438`); without it a
  `missing-VK → held-newer-fv` item lands in BOTH maps → double-counted in `undecryptable()`.
- **A3 (tombstone in the new block):** the `:435` replacement is
  `if (item.deleted) missingVkById.delete(id); else missingVkById.set(id,{...}); continue;` — a
  no-VK item's tombstone has `!hasVault` and never reaches `:438`.
- **A1 (resync):** add `missingVkById.clear()` to the resync-from-0 reset (`store.ts:358`, beside the
  `undecryptableById.clear()`); a lost-access-while-offline 410 otherwise strands stale entries.
- **grant-removal / vault-drop:** clear the vault's `missingVkById` in `hardDropLocal` (`:708`,
  beside the `undecryptableById` per-vault clear).
- **REASONED DEVIATION from B2's "clear at addGrant-open":** a grant that OPENS mid-session does NOT
  re-deliver its (unchanged) items, so web can't reload them mid-session (no persisted envelope,
  unlike Kotlin). B2 recommends clearing `missingVkById` at the addGrant site — but that yields a
  **silent omission** from the backup (item in neither map), which is the exact anti-pattern spec 07
  §2.4 forbids. Instead we **KEEP** the entry (over-report the just-opened vault's items as
  "skipped" until the next full sync reloads + `:435`-held-path-clears them). For a BACKUP,
  over-reporting ("not included in this export; here's its id") is HONEST and safe; silent omission
  risks data loss in migration. The app-list invisibility of a just-opened vault's items until
  reload is a pre-existing web-stateless limitation, not spec07-1's concern. Documented as a narrow,
  self-healing transient.
- Fix the misleading parity comment (`:250-252`) AND the "an itemId lives in exactly one of the two"
  comment (`:195-197`) — now three maps, still mutually exclusive.
- Tests: flip `store.test.ts:513-525` (the foreign no-VK item is now enumerated — capture its
  itemId, assert both it + the corrupt held-fail, sorted); add a missing-VK resync-clear case (A1).

## Scope (full batch listed; cut 3 = spec03-01 + spec07-1 + desia-3/4 only)

| Item | P | Surface | Fix (verified file:line in the investigator report) |
|---|---|---|---|
| **spec03-01** | P2 | server | No generic request-body size limit though spec 03 §5 claims >1 MiB rejected (except attachments). |
| **spec07-1** | P3 | web | Web export silently DROPS missing-VK items instead of enumerating them in `skipped.undecryptable`. |
| **spec02-1** | P3 | core+web | No client does the metaV regression "warn-and-keep-newer" check on delivery. |
| spec06-03 | P3 | core | `uriClass` BOM trim divergence (JVM `trim()` keeps U+FEFF, JS strips it). |
| spec06-04 | P3 | core | `nameFallback` port-strip: Kotlin `Char.isDigit()` (Unicode Nd) vs web ASCII-only. |
| spec04-2 | P3 | recovery-cli | CLI claims to refuse a server-URL arg but has no such check. |
| spec04-3 | P3 | recovery-cli | keygen printed sheet missing the generation date + the `recover` one-liner. |
| desia-3 | P3 | web | Sharing trash-icon aria/title "Recently deleted vaults" omits "removed" (P8 added the removed area). |
| desia-4 | P3 | web | web anomaly-notice omits the "(Sharing → the trash icon)" location pointer Android has. |

## Per-item fix

### spec03-01 — server request-body cap (P2, `server/.../App.kt` + `Main.kt`)
Add an early `intercept(ApplicationCallPipeline.Plugins)` (before any `call.receive`) reading
`call.request.contentLength()`; if `> 1_048_576` **and** the call is NOT the attachment upload,
throw the existing `PayloadTooLarge(...)` (StatusPages already renders it 413 + `ApiError`). Use a
distinct reason `request_too_large`. **Exempt** the only large-body route:
`call.request.httpMethod == Put && path.startsWith("/api/v1/attachments/")` (download routes carry
no request body; attachments keep their own streaming quota). **Known limits (document):**
Content-Length is null on chunked transfer-encoding (the guard covers all normal JSON clients that
send Content-Length; a chunked sender slips — full defense needs a byte-counting wrapper, out of
scope); a `POST /sync/push` batch near 1 MiB now 413s (spec-correct; the 200-mutation cap already
bounds it, so real batches fit). Server route test: oversize non-attachment PUT → 413; a 1 MiB
attachment PUT → accepted.

### spec07-1 — web export enumerates missing-VK items (P3, `web/src/vault/store.ts`)
The Kotlin reference persists every envelope ungated (`SyncEngine.kt:465`) and enumerates
missing-VK items in `ExportPlanner.kt:133` (no `hasVault` filter). Web drops them at `store.ts:435`
(`if (!this.account.hasVault(item.vaultId)) continue;`) and `undecryptable()` (`:254`) only holds
held-key decrypt failures. Fix: at `:435`, instead of `continue`, record
`{ itemId, vaultId, formatVersion }` (all plaintext wire fields) into a retained `missingVkById`
map; clear entries on tombstone (`:438`), when the vault becomes held (`:451`), on grant revoke,
and on vault-drop (`:707-714`); merge that set into `undecryptable()` (or a sibling the ExportPanel
reads at `ExportPanel.tsx:204`). Fix the misleading parity comment at `store.ts:250-252`.
**BLOCKER (build):** `store.test.ts:513-525` actively asserts the BUGGY behavior ("items of no-key
vaults are NOT ours to enumerate") — it MUST be flipped to assert enumeration; add a spec-07 §2.4
missing-VK case to the `:461` suite. Watch double-counting (an item that is missing-VK then becomes
held must not appear in both surfaces).

### spec02-1 — metaV regression check on delivery (P3, core + web)
metaV appears only on WRITE paths (`Account.kt:436`, `account.ts:382`); ingest blindly overwrites
(`SyncEngine.kt:437-438`, `store.ts:389-390`). The metaBlob AD excludes `rev` (spec 02 §4), so a
server can replay an OLD metaBlob (old name) at a new rev; metaV is the anti-replay counter. Fix:
add `Account.readMetaV(vaultId, metaBlob): Long?` (core + web twins — only `buildRenameMeta` parses
metaV today); at ingest, before overwriting a HELD vault's meta, decrypt the incoming metaV and
compare to the currently-held row's; if **incoming < held** → keep the held (higher-metaV) metaBlob
for the name while accepting the rest of the row (rev/lifecycle), and surface a warning notice.
Equal metaV = accept (idempotent redelivery). Only decidable when `hasVault`. Hook: `SyncEngine.kt`
ingest (serves both natives) + `store.ts` ingest. Extension: NO action (no rename/metaV surface).
Pin with client unit tests (web `store.test.ts`, a core `SyncEngineTest`), not a byte vector. **Keep
it surgical:** accept the incoming row's rev/lifecycle, retain only the higher-metaV metaBlob — do
NOT reject the whole row (that would stall lifecycle updates).

### spec06-03 / spec06-04 — CsvImport cross-impl determinism (P3, `core/.../CsvImport.kt`)
06-03: strip U+FEFF in the Kotlin `uriClass` trim (route both through a BOM-aware helper) so a
residual-BOM uri lands in the same equality class as web. 06-04: `nameFallback` port-strip
`s.substring(colon+1).all { it.isDigit() }` → `.all { it in '0'..'9' }` (ASCII, matching web —
same fix already vector-pinned in `UriMatch.isIpLiteral`). Add a BOM-in-uri-cell row and a
non-ASCII-digit-port row to the import CSV test vectors so the byte-for-byte guarantee
(`spec/06-import-formats.md:49`) is enforced.

### spec04-2 / spec04-3 — recovery-cli (P3, `tools/recovery-cli/.../Main.kt`)
04-2: add a top-of-`main` guard — any arg matching `://` → print a refusal and exit before dispatch
(spec 04 §5). Add a CLI test. 04-3: keygen's printed-sheet output gains a **generation date** line
and a **`recovery-cli recover` next-step** one-liner (spec 04 §1). NOTE: the genesis sheet is
already printed — these only help FUTURE sheets; call that out in the CHANGELOG.

### desia-3 / desia-4 — web copy (P3, `web/src/ui/Sharing.tsx`, `web/src/ui/Vault.tsx`)
desia-3: `Sharing.tsx:108-109` aria-label/title "Recently deleted vaults" → include "removed" (e.g.
"Recently deleted & removed vaults") — the disclosure reveals BOTH areas since P8. desia-4:
`Vault.tsx:657` append "(Sharing → the trash icon)" to the anomaly notice (Android has it).

## Parallel build partition (disjoint files, pinned contracts)

- **Builder S (server):** `server/.../App.kt`, `Main.kt` (spec03-01) + server test.
- **Builder C (core):** `core/.../CsvImport.kt` (06-03/04) + import vectors; `core/.../client/Account.kt`
  `readMetaV` + `SyncEngine.kt` ingest hook (spec02-1 core half) + `SyncEngineTest`.
- **Builder W (web):** `store.ts` (spec07-1 missing-VK map + `undecryptable` merge; spec02-1 web half:
  `account.ts` `readMetaV` + store ingest hook) + `store.test.ts` (flip the spec07-1 assertion, add
  metaV test); `Sharing.tsx`/`Vault.tsx` (desia-3/4).
- **Builder R (recovery-cli):** `tools/recovery-cli/.../Main.kt` (spec04-2/3) + CLI test.

**Pinned contract (the one cross-builder seam):** spec02-1's `readMetaV(vaultId, metaBlob) → Long?`
and the "incoming < held ⇒ keep held metaBlob, accept the rest, warn" rule — identical semantics in
core (C) and web (W). The orchestrator runs the combined gate. No other seam (files are disjoint).

## Ship (cut 3 = server+web additive, fleet stays 0.15.0)

- **No version bump** — additive server+web (spec03-01 is a server-internal guard; spec07-1/desia are
  client-internal), no client/server contract change (QW1 / cut-1 precedent). Fleet stays 0.15.0
  (extension already 0.12.0 from cut 2).
- **Server jar changes** (spec03-01) → **snapshot-first `VACUUM INTO` + vzdump** before deploy (the
  "jar changes" trigger; NO schema change — additive code only) → `ops/deploy.sh` (server+web) →
  byte-verify served web bundle sha == build + a fresh-jar boot with 0 errors + healthz. NO
  APK/deb/MSI (no core touch). CHANGELOG owner-voice. Telegram statement.
- Gate: `verify.sh` EXIT=0 (server route test + the flipped web `store.test` + 357+ web/tsc).

## (3b) Ship for the DEFERRED core/cli set — when built
Version → 0.16.0 (core lockstep) + APK + deb + MSI (owner) + recovery-cli in-tree; its own snapshot.

## DEFERRED → f61 follow-up (named, not dropped)

**spec01-f61 (KDF-upgrade silent re-key parity, web+desktop)** is deferred to its own cut: it needs a
TS port of core `KdfUpgrade.shouldUpgrade` + the re-key orchestration (Android's `KdfReKey` is
app-android-only, takes `SessionStore`), Argon2id **off the UI thread** on web + desktop, and gating
on a fresh-fetched policy + not `mustChangePassword`. It's the highest-complexity item (crypto on two
new clients) and deserves its own design + breaker + focused review — bundling it would bloat this
batch and dilute the review. Android already implements it; the gap is convergence-only (a policy KDF
bump reaches Android-unlocking accounts today), no data risk in deferring.

## Breaker seeds

1. spec03-01: the exempt predicate — can a non-attachment route with a huge legit body exist (sync
   push near 1 MiB)? Does the intercept run before auth (DoS a pre-auth body)? Is `PayloadTooLarge`
   the right existing exception + does StatusPages map it 413 with the reason? Chunked (null CL) —
   documented gap or must-fix?
2. spec07-1: the missing-VK map lifecycle — every clear path covered (tombstone, held, revoke, drop)?
   Double-count with `undecryptableById` when an item transitions missing-VK → held? Web's stateless
   full-pull-per-session model — does a fresh export still see all missing-VK items?
3. spec02-1: does "keep held metaBlob, accept the rest" ever strand a legit RENAME (a real newer name
   with a lower metaV can't happen — metaV monotonic per rename)? Equal-metaV idempotency? A
   missing-VK vault (can't readMetaV) — safe skip? Does the warning notice fire spuriously?
4. Cross-impl: do the core + web readMetaV + compare agree byte-for-byte (the seam)?
5. recovery-cli: the `://` guard — false-positive on a legit arg containing "://"? Does it run before
   ANY dispatch (including keygen/verify)?
