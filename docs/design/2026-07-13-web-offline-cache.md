# andvari — Web durable offline cache (encrypted IndexedDB)

**Status: BUILT S1-S5 (2026-07-14) — S6 (live e2e + docs polish) pending; NOT YET DEPLOYED.**
Roadmap item B (design review 2026-07-12 §B.5/§D.2: the owner model says *every* client holds a
usable local copy it can decrypt; today that is native-only by deliberate spec choice, `spec/02 §8`
closing note). This doc closes the gap for **web**. The breaker found **no BLOCKER**; two
near-blocker AMENDMENTs gate slice S4 (offline writes) and are folded into the body below —
verdict ledger in §I. S1–S3 (read-only offline) are clear to build as specced.

Scope guard: **NO web quick-unlock in this cut** (spec 01 §8 stays Android-normative; a web
quick-unlock story is explicitly out of scope — offline unlock is the full master password).
Attachments stay **online-only on every client** (unchanged; envelopes cache `attachmentIds` only).

References audited at HEAD `6e0d638`: native contract `spec/02 §8` + `VaultCache.kt` /
`SqliteVaultCache.kt` / `SyncEngine.kt` (`hydrate`, `applyPull`, `flushQueue`, `surfaceStagedDenials`);
web as-built `web/src/vault/store.ts` (`VaultStore.syncOnce`, `save`, `remove`, holding area),
`web/src/vault/account.ts` (`Account.unlock` / `unlockFromUvk`), `web/src/ui/session.ts` (what
persists today: tokens + metadata, never keys), `web/src/ui/App.tsx` (`andvari-lock`
BroadcastChannel, F27 storage listener), `web/src/ui/Welcome.tsx` (`Unlock.submit` — today
`client.accountKeys()` is a hard online dependency), `web/src/crypto/keys.ts`
(`assertServerKdfParams`, H1 floor), Android `Session.kt` (`cachedAccountKeys` +
`requireServerKdfParams` gate), `spec/05` T1/T3/T6/T8. The 2026-07-13 breaker pass re-verified
these plus `SqliteVaultCache.clear`, the `SyncEngine` epoch guard
(`pullStartCounter`/`freshestCompletedPullStart`), `store.parkOrRethrowDeniedEdit`, and
`web/src/ui/recovery-capture.ts` (`needsRecoveryCapture`/`confirmRegisteredRecovery`) — anchors
cited inline where a finding folded.

---

## A. What is cached — the native contract, mirrored

The cached set is **exactly the spec 02 §8 list**, field-for-field, so the normative sentence
carries over: *every persisted field is a subset of the §5 server-visible table — the client-at-rest
surface ⊆ the server-at-rest surface by construction.*

| # | Cached | Native twin | Web source |
|---|---|---|---|
| 1 | sync cursor (rev) + `lastSyncAt` | `kv('cursor')`; Session "vault as of last sync" stamp | `VaultStore.cursor` / `_lastSyncAt` (in-memory today) |
| 2 | item rows exactly as on the wire (ids, revs, timestamps, flags, fv, attachmentIds, `blob` AEAD ciphertext) | `items` table | `syncOnce` resp.items (today decrypt-and-discard-wire) |
| 3 | grant rows (vaultId, userId, role, `wrappedVk`/`sealedVk` ciphertext, rev) | `grants` table | `grantWireByVault` (in-memory today) |
| 4 | vault rows (vaultId, type, rev, `metaBlob` ciphertext, createdAt, + lifecycle wire fields) | `vaults` table | `vaultsById` |
| 5 | outbound mutation queue (mutationId, op, ids, baseItemRev, `ItemUpload` ciphertext) + staged-denied flag | `queue` table (`staged` column) | **none today** — web `save()` is push-or-throw |
| 6 | server `accountKeys` copy (kdfSalt, kdfParams, wrappedUvk, encryptedIdentitySeed, identityPub, escrowFingerprint, escrowStale?, recoverySetupNeeded?, recoveryConfirmed?) | Android `Session.cachedAccountKeys` / `DesktopSession` | `client.login()` / `client.accountKeys()` responses (discarded today) |
| 7 | lifecycle safety state: holding area (`HeldVaultRecord`-shape), consumedDeleteIds, lastVerifiedTransferSeq | `held` / `consumed_delete_ids` / `transfer_seq` tables (SQLite v2) | `holding` / `consumedDeleteIds` / `lastTransferSeqSeen` (in-memory today) |
| 8 | last-known `offlineCacheAllowed` + `autoLockSeconds` policy bits | Session persisted-policy fields | autoLock already in localStorage (`useAutoLock` fallback); cache bit new |

**Invariant A1 (durable-cursor rule, spec 03 §4 — MUST).** Rows 2–4 and the cursor live and die
together: a persisted cursor without the grant/vault/item rows applied up to it is corruption
(grant/vault rows never re-send once the cursor passes them). Any coherence doubt ⇒ discard the
**whole** cache and pull from 0. Never trust a partial cache.

**Invariant A2 (plaintext — NEVER).** Same list as spec 02 §8: no master password, MK, authKey,
UVK, VK, identity seed, decrypted `ItemDoc`s, decrypted vault names, attachment plaintext, or
fileKeys outside item ciphertext. Decryption is in-memory after the password; lock/reload drops all
key material. The held-vault snapshot is the **re-sealed ciphertext** `moveToHolding` already
builds — persist that record as-is (its `cachedName` is the one plaintext field in the in-memory
`HeldVault`; the persisted record MUST drop it, native `HeldVaultRecord` parity — the name is
re-derived from the retained grant on rehydrate, as core `peekVaultName` does).

**"Encrypted IndexedDB cache" means:** the payload is ciphertext **by construction** (the same AEAD
envelopes the server stores), not a new crypto layer. v1 adds **no extra whole-DB encryption**,
byte-for-byte the native posture ("the DB file gets no extra encryption in v1", spec 02 §8) — see
§E.1 for the honest metadata consequence and why a wrapper layer is rejected for v1.

**Enumerated divergences from the native contract** (everything else mirrors):

- **D1 — app shell.** There is **no service worker** (verified: none in `web/`). Natives cold-start
  offline; web offline works only in an already-loaded tab or an HTTP-cache-served load. A reload
  with cold HTTP cache while offline fails to load the SPA at all. v1 ships **without** an SW
  (an SW interacts with the 426 min-version pin and is its own update-security design); flagged as
  a follow-up decision, §F.4.
- **D2 — OS backup exclusion.** Natives exclude the cache from cloud/OS backup
  (`noBackupFilesDir` / `dataExtractionRules`). Web **cannot** exclude the browser profile from OS
  backup (Time Machine etc.). Accepted delta: backups then hold ciphertext ⊆ T7's already-accepted
  surface. (Browser *sync* does not replicate IndexedDB — profile sync carries no IDB data.)
- **D3 — eviction.** SQLite files persist until deleted; IndexedDB is **best-effort** storage the
  browser may evict under pressure. Mitigated by `navigator.storage.persist()` + the A1 discard
  rule (§B.4). For **server-derived** rows (items/grants/vaults/cursor/accountKeys) eviction =
  availability loss only, never integrity loss — resync-from-0 refetches everything. The
  **outbound queue is the exception** (breaker #1): queued offline edits exist ONLY locally until
  flushed, so whole-bucket eviction between enqueue and flush is silent USER-DATA loss with no
  recovery path (the server never saw them; the A1 discard cannot bring them back). Native has no
  analog — SQLite doesn't evict. Consequence: the offline-write QUEUED path (S4) is **gated on
  granted persistence** (§B.5/§D.3), never assumed.
- **D4 — queue improves web semantics.** Today a web `save()` retry mints a fresh `mutationId`
  (non-idempotent retry, noted in `store.save`). The durable queue enqueues ONCE and flushes with
  the SAME mutationId — retries converge on server dedup, core parity. (Behavioral change: an
  offline save returns "queued" instead of throwing — but ONLY while persistence is granted,
  §B.5/§D.3.)
- **D5 — accountKeys location.** Natives keep accountKeys in SharedPreferences/DesktopSession,
  separate from the vault DB. Web keeps them in the cache DB's `kv` store — one artifact, one wipe
  path. Same material, same lifecycle rules. Co-location changes one contract natives get for free
  (breaker #2): native `clear()` operates on a DB that doesn't CONTAIN accountKeys, so a 410 resync
  can't lose them; web's `clear()` therefore carries an enumerated contract (§D.1 — it resets
  `kv:cursor` ONLY). `wipe()` (deleteDatabase) is the only operation that removes accountKeys.

## B. Schema — IndexedDB

**B.1 Database.** One DB **per account**: `andvari-vault-<userId>` (native `vault-<userId>.db`
parity). Per-account isolation is structural: sign-out of account X deletes X's DB and cannot touch
Y's; the same-user guard problems `session.ts makeClient` solves for tokens don't arise for vault
rows. `DB_VERSION = 1`. All stores are created in version 1 — including `queue`/`held`/etc. even
though build slice S4 lands later (§H) — so no `onupgradeneeded` dance mid-rollout.

**B.2 Object stores** (names, keyPaths — mirroring `SqliteVaultCache.migrate` v2):

| store | keyPath | value | index |
|---|---|---|---|
| `kv` | `key` | `{key, value}` — `userId`, `cursor`, `lastSyncAt`, `accountKeys` (JSON), `policy` (`{offlineCacheAllowed}`), `createdAt` | — |
| `items` | `itemId` | the `WireItem` verbatim | `vaultId` (for dropVault) |
| `grants` | `vaultId` | the `WireGrant` verbatim | — |
| `vaults` | `vaultId` | the `WireVault` verbatim (incl. pendingTransfer/lastTransfer/restoreProof/deleteId wire fields) | — |
| `queue` | `seq` (autoIncrement) | `{seq, mutationId, vaultId, staged: 0|1, mutation}` | `mutationId` (unique), `vaultId` |
| `held` | `vaultId` | persisted `HeldVault` minus `cachedName` (A2), + `expungeAt` | — |
| `consumedDeleteIds` | `deleteId` | `{deleteId}` | — |
| `transferSeq` | `vaultId` | `{vaultId, seq}` | — |

**B.3 The module.** New `web/src/vault/idbcache.ts` exporting an interface that is the TypeScript
twin of core `VaultCache` (cursor/setCursor, upsertItem [wire only — no decrypted twin at rest],
envelopes, upsertGrant/grants, upsertVault/vaults, dropVault, clear (the §D.1 ENUMERATED contract —
resets `kv:cursor` only, preserves queue/holding/floors/accountKeys),
enqueue/pending/dequeue/dropPending/markStagedDenied/stagedDenied, putHeld/getHeld/heldVaults/
removeHeld, addConsumedDeleteId/isConsumedDeleteId, lastVerifiedTransferSeq/set…, plus web-only
`accountKeys()/setAccountKeys()`, `wipe()` = deleteDatabase, and `applyPull(fn)` = the one-tx commit
seam of §D.1). A `NullCache` no-op impl backs the opt-out/unsupported path — and the §D.1
stuck-cache demotion — so `store.ts` has ONE code shape (core `InMemoryVaultCache` parity).

**B.4 Open-time coherence check (MUST — the torn/evicted-cache story).**
On open, inside one tx: (i) `kv.userId` exists and equals the session's userId — mismatch ⇒ wipe
everything including the queue (foreign account; `SqliteVaultCache.init` parity); (ii) structural
sanity — every expected store exists (a missing store on an existing DB = a half-created v1 or a
future-version downgrade ⇒ wipe); (iii) **any** open-time error, quota error, or corruption
exception ⇒ `deleteDatabase` + proceed as cache-less cold start (RUNTIME commit failures get three
strikes before the same treatment — the §D.1 stuck-cache rule). Browsers evict IDB **per-origin,
whole-bucket** — partial row-level eviction is not a documented mode — but the A1 rule assumes
nothing: doubt ⇒ discard ⇒ `since=0` resync. The cache is a cache; the server is truth.

**B.5 Quota + persistence.** After first enable, call `navigator.storage.persist()` once (advisory;
result surfaced in the settings row as "protected from eviction: yes/best-effort"). Budget: a
household vault is thousands of envelopes × ~1–2 KB ⇒ single-digit MB, far under any origin quota;
`navigator.storage.estimate()` is displayed, never enforced. No attachment bytes are ever cached.
Feature-detect `indexedDB` (Firefox private windows may refuse) ⇒ `NullCache`, today's behavior.
Persistence is advisory for the READ cache but **load-bearing for offline writes** (breaker #1):
S4's success-as-QUEUED path is offered only while `navigator.storage.persisted()` reports true
(§D.3 — refuse-not-degrade). Denial is MOST likely exactly on the break-glass public origin
(E.3.3) where the cache is opt-in and offline edits would be most relied on — there, an offline
save keeps today's push-or-throw behavior, with copy saying why.

## C. Offline unlock

**C.1 Flow.** Unlock (existing session, `Welcome.Unlock.submit`) becomes **online-first with
offline fallback**:

1. Try `client.accountKeys()` as today. Success ⇒ unlock with the fresh payload, then
   `setAccountKeys(fresh)` (cache-refresh write point, §D.2).
2. **`NetworkError` only** (the `net()` tagger already distinguishes transport from server
   answers) ⇒ read cached `accountKeys`; if present, `Account.unlock(userId, password, cached)` —
   the function is already a pure function of `(password, keys)`; **zero crypto changes**.
3. A **server-answered** error NEVER falls back: a 401 after a refused refresh is a definitive
   rejection ⇒ wipe (§E.4); a 5xx keeps today's honest "server had a problem" copy.

Then `store.hydrate()` (§D.4) rebuilds the working set from envelopes with **no server call** —
the native `SyncEngine.hydrate` shape — and the first `sync()` is attempted but its failure is
non-fatal (the Vault's existing offline dot + F29 poll take over).

**C.2 kdfParams provenance.** Today web gets kdfParams from `prelogin` (sign-in) or the
`accountKeys` response (unlock). Offline unlock reads them from the cached accountKeys — which is
why row 6 of §A is in the cached set at all. **Fresh sign-in (no persisted session) remains
online-only** (prelogin/login/verifier are server round-trips by design) — native parity: offline
unlock presupposes a prior online login on this device.

**Invariant C3 (H1 floor on the cached path — MUST).** `assertServerKdfParams(cached.kdfParams)`
runs at cache-READ, exactly like the online fences in `client.ts` and exactly like Android's
`cachedAccountKeys()?.takeIf { requireServerKdfParams(...) }`. A cached weak-KDF payload refuses
offline unlock (fail closed, `KdfPolicyError` surfaces the same WEAK_KDF_MESSAGE). Without this, an
attacker with disk write access could plant weak params and halve the brute-force cost — the cache
must never be a floor bypass.

**Invariant C4 (identity hard-fail preserved — MUST).** Offline unlock routes through the SAME
`Account.unlock` → `unlockFromUvk` tail, so the seed-derived identityPub check fires against the
**cached** identityPub (server-sent at cache time). `IdentityMismatchError` on the cached path means
a tampered cache — same copy, do not soften to "wrong password".

**C5 (freshness posture = spec 05 T3, verbatim).** Offline unlock accepts the master password
current at the last online contact; remote revocation and password change take effect at next
connectivity. `mustChangePassword` (admin-recovery flag) is a login-response field, not an
accountKeys field — an offline unlock cannot see a flip that happened while offline. Accepted
narrowing, identical to natives (T3's "known-old master password reads the last-synced cache until
it reconnects").

**C6 (recoveryConfirmed offline — nag, never lock out; REVISED per breaker #4).** The §F.9
vault-entry capture gate needs `PUT /recovery/self-setup` + `POST /recovery/self/confirm` —
online-only, so the gate cannot be *satisfied* offline. The draft REFUSED offline unlock when
cached `recoveryConfirmed !== true`; the breaker showed that hard-locks a legitimate user:
`confirmRegisteredRecovery` is best-effort at its call site (`recovery-capture.ts` — "a failure
only re-nudges on the next unlock"), so a user whose confirm POST silently failed reaches the
vault, populates the cache, and carries `recoveryConfirmed=false` — refusing would then deny them
their own cached vault, with a valid password, because a background POST failed, while protecting
nothing (capture needs connectivity anyway; blocking cached READS does not reduce the loss risk
the flag guards). REVISED: offline unlock **PROCEEDS** with a **persistent in-vault banner**
("Finish setting up your recovery phrase next time you're online") that must never imply the vault
or account is broken. The ONLINE gate is unchanged — the next online unlock still hard-blocks
until capture completes, so the nag cannot be ridden indefinitely by any device that ever
reconnects. (The cached flag may also be stale-false after a confirm on another device — the
reminder-not-error copy covers exactly that case too.)

**C7 — NO quick-unlock.** Restated: the only offline unlock is the full master password → Argon2id
(≥64 MiB in-browser, as every login already does) → unwrap cached wrappedUvk. Nothing biometric,
nothing session-resumable, no derived-key persistence.

## D. Consistency

**D.1 Write point 1 — pull apply (one tx).** `VaultStore.syncOnce` keeps its exact order (F31
guards FIRST, then apply), but every cache write of one pull commits in **ONE IndexedDB
transaction** spanning all stores (IDB txs are multi-store within a DB): grants, vaults, items
(wire rows; tombstone ⇒ delete), holding-area moves, consumedDeleteIds, transferSeq, queue
re-enqueues of parked mutations, **cursor last**. This is `SyncEngine.applyPull`'s
`cache.atomically` twin with a simplification: web buffers ops and commits at the end, so a failed
commit leaves disk at the OLD cursor with OLD rows — coherent (A1).
**CORRECTED (S2 review, docs cut S5) — the draft's failed-commit heal was wrong.** The draft
claimed "the next pull re-delivers the same delta idempotently"; it does NOT: `sync()` →
`pullOnce()` pulls from the MEMORY cursor, and the strict-delta server sends `rev > since` exactly once, so a failed
commit's delta is never re-fetched for disk within the session. The heal AS BUILT is two-part:
(1) a **contiguity guard** — a later delta commit is REFUSED while `diskCursor < since` (disk
stays coherent-stale; it never stamps a cursor over a gap the server will not re-send); and
(2) **hydrate resumes from the DISK cursor**, so the next session's first pull re-fetches the
whole gap. In-memory-ahead-of-disk after a failed commit is therefore safe for the session
(memory applied the delta) and self-heals at the next hydrate; no `evictDecrypted+hydrate`
rollback dance needed.
**410 resync**: fetch-replacement-first (already in code), then ONE tx: clear items/grants/vaults +
reset cursor + apply the full snapshot. `clear()` is an ENUMERATED contract (breaker #2): it
deletes the `items`/`grants`/`vaults` stores and resets **`kv:cursor` only** — it MUST NOT touch
`queue`/`held`/`consumedDeleteIds`/`transferSeq` (spec 03 §4 / `VaultCache.clear` contract) **and
MUST NOT touch `kv:accountKeys`/`userId`/`policy`/`lastSyncAt`**. Native `SqliteVaultCache.clear()`
deletes only items/grants/vaults + resets the cursor; accountKeys live in SharedPreferences —
OUTSIDE that DB — so a native resync structurally cannot lose them. Web co-locates accountKeys in
the same DB (D5), so a naive `kv.clear()` would drop them and break offline unlock after any
mid-session resync-then-lock (online 410 clears keys → lock retains the cache but the keys are
gone → offline unlock fails, with no re-cache until the next ONLINE unlock). §G carries the
regression test.
**Stuck cache (breaker #6).** A PERSISTENTLY failing commit (quota/disk) would silently freeze
disk at an old cursor while the in-memory session advances — coherent (A1 holds; IDB multi-store
txs abort atomically) but stale on every future hydrate. Disk `lastSyncAt` freezes with it, so the
E.3.4 "last synced <t>" stamp stays honest — but do not run indefinitely against a frozen cache:
after **3 consecutive non-landing commits**, treat it as a §B.4 coherence failure — attempt
`wipe()`, demote to `NullCache` for the rest of the session, and show "offline copy unavailable —
storage error" in the settings row. **Non-landing, not just throwing (S2 as-built):** landing is
VERIFIED by reading the cursor back after the commit, so the demotion tally also counts the
SILENT failure shapes idbcache's own throw-counter never sees — a force-closed cache resolving
writes as caught no-ops (§D.2a), and a rejecting cursor read-back. A contiguity-guard REFUSE
(§D.1 correction above — disk behind but coherent) neither counts nor resets the streak.

**D.2 Write point 2 — post-push ack.** (a) `save()`'s local apply already holds the exact sealed
`ItemUpload` + `newItemRev` from the push response — persist that as a wire row in the same breath
as `itemsById.set` (the reconcile pull would also deliver it, but the committed-server-side rule in
`save` means the envelope must survive a crash before that pull lands). In S4 this same ack-persist
moves into `flushQueue`'s definitive-result step (§D.3 unification) — same rule, one code path.
This write can RACE a concurrent sign-out's `wipe()` (breaker #8, applies from S2 on): every cache
write goes through a guarded handle that resolves as a caught no-op once close/`versionchange` has
begun — never an uncaught rejection. Losing the race is harmless: the item is committed
server-side and re-syncs at next login. (b) Queue lifecycle:
enqueue-before-send, dequeue-on-definitive-result, `markStagedDenied` on denied — `flushQueue`
parity (§D.3). (c) accountKeys re-cache points: login response, unlock response, after
`changePassword` (fresh wrappedUvk/kdfSalt — a stale cached wrap under the OLD password is exactly
the T3 window; shrink it where we can), after recovery-capture confirm (flag flips true).
Write-time validation (breaker #5): `setAccountKeys` REFUSES to overwrite a good cached payload
with one that lacks or fails the kdfParams floor — `client.accountKeys()` only fences
`if (k?.kdfParams)` (client.ts), so an absent-params payload from a hostile or broken server is
otherwise cacheable and would refuse every later offline unlock at the C3 read check (an
offline-availability DoS; no new capability over a server that simply refuses service).
Keep-old-on-bad-write + C3's read-time reject = belt and suspenders.

**D.3 Offline writes (slice S4).** `save()`/`remove()` grow the native shape: enqueue durably →
attempt flush → on `NetworkError`, return success-as-QUEUED (UI: the item renders with a "pending
sync" affordance; the Editor stops claiming "nothing was changed" — copy TBD in build). The QUEUED
return is offered **only while persistence is granted** (`navigator.storage.persisted()` —
breaker #1, §B.5/D3): if the browser refuses durable storage, an offline save keeps today's
push-or-throw behavior with copy explaining why — refuse-not-degrade, because an evicted queue is
unrecoverable user data. Enqueue-before-send still runs on the ONLINE path regardless (D4's
idempotent-retry win — that exposure window is seconds, not days). On reconnect, `sync()` runs
`flushQueue → pull → surfaceStagedDenials` in that order (core `sync()` parity — flush BEFORE pull
so removedGrants arriving in the same cycle can park denials, F21).
**Denial unification (breaker #3 — REVISED from the draft's "two-sync review" hand-wave).** Web
today has a SECOND denial mechanism: online `save()` → `parkOrRethrowDeniedEdit` (store.ts), whose
deliberate double `sync()` exists precisely because its first `sync()` can JOIN an in-flight
`syncOnce` whose `api.sync` fetch STARTED before the denial was staged — a stale snapshot must
never classify a denial. Running both mechanisms would double-handle one denial (parked by one
path, thrown 403 by the other). S4 therefore ships ONE denial path: `save()`/`remove()` become
enqueue + `sync()`, and ALL denials — online saves and reconnect flushes alike — are staged
durably (`markStagedDenied`) inside `flushQueue` and classified only by `surfaceStagedDenials`,
carrying the core epoch guard over EXPLICITLY: web twins of
`pullStartCounter`/`freshestCompletedPullStart`, and a staged denial is classified ONLY against a
pull that STARTED after it was staged (`SyncEngine.surfaceStagedDenials` partition; genuine
denials still throw from `sync()`, so the Editor's failure UX is unchanged, and a too-fresh entry
stays durably staged for the next cycle — native semantics). Single-flight gives this invariant
for free ONLY when flush+pull+surface run inside the SAME `syncOnce`; the counters keep it true
even for a denial staged while a joined earlier pull is still in flight.
`parkOrRethrowDeniedEdit` and its ad-hoc double-sync are RETIRED in S4 (S1–S3 keep them unchanged
— no queue yet, nothing to unify). Conflicts on flush ride the EXISTING
`materializeConflictFromServerItem` path unchanged (offline edits that lose materialize copies —
LWW + copy, spec 03 §5; no new merge logic).
**Scope guard:** attachments make a save online-only in v1 — a doc with `newFiles` refuses to
queue (blob-before-item, spec 02 §6, and we don't cache attachment bytes). Imports likewise flush
live (they already chunk + are idempotent by plan).

**D.4 Hydrate.** New `VaultStore.hydrate()` (pre-first-sync, post-unlock): grants → `account.addGrant`
(role unconditional, key-open best-effort — F20 warnings recompute), vaults → `setPersonalVault` +
`vaultsById`, envelopes → decrypt into `itemsById` / `undecryptableById` / `missingVkById` (the
same tri-state `syncOnce` computes), holding → `holding` map (name re-derived via the retained
grant), consumedDeleteIds/transferSeq → their maps, stagedDenied → `preParkedByVault`. Undecryptable
envelopes are retried every hydrate (upgrade / later-opened grant — core comment carries over).
`_lastSyncAt` restores from kv so the export banner stays honest ("vault as of last sync <t>").

**D.5 Cross-tab.** Two tabs share one DB. Rules:
1. **Serialize cache commits** with `navigator.locks.request("andvari-cache-<userId>")` around each
   pull-apply commit and queue flush (the refresh path already uses Web Locks — F25). Within the
   commit tx, re-read the stored cursor: if it is already ≥ resp.rev (another tab applied newer)
   and this isn't a 410 resync, **skip the commit** (in-memory state trues up on this tab's next
   pull) — the durable twin of the F31 monotonic-cursor guard. A skipping tab keeps its OWN
   in-memory cursor at its resp.rev — it never fast-forwards in memory past rows it hasn't
   applied — so its next pull re-fetches the gap from that cursor and rows hidden by the skipped
   commit reappear; leaving `cursor = resp.rev` and re-pulling converges (breaker #7).
2. **Lock** (`andvari-lock` BroadcastChannel) — unchanged, and the cache is **retained** (§E.4).
   No new channel messages needed: locking is a key-drop, not a data event.
3. **Sign-out/revocation** — the `storage` event on `SESSION_STORAGE_KEY` removal already lands
   every tab on Welcome; the wiping tab calls `wipe()`. `deleteDatabase` blocks while siblings hold
   connections ⇒ every connection registers `onversionchange = close()` (and the storage listener
   closes this tab's handle before phase change), so the wipe completes promptly.

**D.6 Offline regression guards.** The F31 trio in `syncOnce` (410-partial, rev-below-cursor,
unsolicited-full) runs BEFORE the commit tx, so nothing rejected ever touches disk. New: the cursor
now SURVIVES restarts, so the guards finally protect across sessions (today a reload resets to 0
and a rollback-serving server gets a free pass) — a strict posture improvement worth a test. The
§D.1 contiguity guard is the durable half of the same posture: disk never stamps a cursor over
rows it did not apply, and hydrate-from-disk-cursor re-pulls any gap a failed commit left behind
(the corrected heal — see the §D.1 CORRECTION; the draft's "next pull re-delivers idempotently"
premise is retired).

## E. Threat-model deltas (argued, not waved at)

**E.1 At-rest ciphertext in the browser profile.** New artifact class on web: AEAD envelopes +
wrapped accountKeys in the profile directory — the SAME artifact natives already persist
(T3 explicitly accepts it). What is genuinely weaker on web: no OS-backup exclusion (D2), and the
profile is a fatter, better-known target than an app sandbox. What is unchanged: everything at rest
is ciphertext under keys derived from the master password at H1-floor Argon2id, or public. Metadata
(item COUNTS, ids, revs, vault topology, attachment ids) is cleartext in IDB exactly as in native
SQLite — A6-class, ⊆ what the server already sees. A whole-cache wrapper key was considered and
**rejected for v1**: any wrapper derivable pre-unlock adds no brute-force hardness beyond the
wrappedUvk that must be readable pre-unlock anyway; it only buys metadata hiding, at the cost of
breaking native byte-parity and complicating the coherence story. Revisit with native "whole-file
DB wrapping" (spec 02 §8 flags it future for BOTH).

**E.2 XSS — what the cache ADDS.** Baseline: a script running in an UNLOCKED session already owns
everything (reads memory, exfils plaintext, keylogs the password) — the cache adds nothing there.
The additions are exactly two:
1. **Persistent ciphertext exfil from a LOCKED/idle tab.** Today a locked web tab holds nothing;
   with the cache, same-origin script (T6 hostile-origin JS, or an injected one-shot) can read
   envelopes + wrappedUvk at any time. Consequence: offline brute-force of the master password
   against the exfiltrated wrap —
2. **an offline-cracking surface = T8**, floored by H1 (≥64 MiB / ops ≥3, now client-enforced and
   cache-read-enforced, C3). Weak master passwords remain the user's risk — T8's sentence,
   unchanged; the cache widens *where* that sentence applies (browser profile + any XSS), not its
   math.
   Honest framing: T6 is already an accepted gap ("page-load-time trust") — a hostile origin gets
   the PASSWORD at next unlock, which strictly dominates ciphertext theft. The cache mainly
   removes the "attacker must wait for an unlock" step for *ciphertext*. CSP self-only + no
   third-party origins remain the controls. spec 05 amendment: extend T6's paragraph + add the
   web cache to T3's at-rest sentence.
   One non-XSS residue for completeness (breaker #5): the cached grant ROLE is
   attacker-tamperable plaintext, and `addGrant` applies whatever role the grant row carries with
   no authority check (account.ts) — a tampered cache can locally "elevate" reader→owner for the
   OFFLINE view. Cosmetic only: every resulting write is server-denied on flush (the ZK server is
   the sole role authority, T1), so there is no escalation.

**E.3 Device theft / shared computers.** Theft of a personal device = T3 verbatim (ciphertext;
KDF; revocation lands at next connectivity). The genuinely new face is the **shared computer**:
a household member unlocking on a shared/borrowed machine would leave durable ciphertext + their
email in someone else's profile. Controls, layered:
1. **Org policy** `offlineCacheAllowed=false` force-wipes fleet-wide (already specced; web now
   honors it: re-evaluated on every successful policy fetch; last-known value persisted and honored
   on offline boot — Android `Session` parity).
2. **Per-device opt-out** — "Keep an offline copy on this device" toggle; turning it OFF wipes
   immediately (DB + accountKeys) and pins the `andvari.cacheOptOut` localStorage marker so
   the next unlock doesn't silently re-create it. (S5 as-built: the marker is per-DEVICE, not
   per-user — the toggle's sentence is about THIS device, and S3 shipped the gate reading the
   unsuffixed key; the public origin's symmetric opt-IN is `andvari.cacheOptIn`, and the
   last-known org bit is `andvari.orgCacheOff`.)
3. **RECOMMENDED DEFAULT: ON for the private tailnet origin, OFF (offer, not silent) for the
   break-glass public origin.** Reasoning: the owner model *wants* every client durable, and a
   tailnet-reachable browser is by construction an enrolled personal device; the public
   `andvari.monahanhosting.com` origin exists precisely for borrowed/emergency machines (already
   treated as hostile-adjacent: CF Access + TOTP) — defaulting the cache OFF there makes the risky
   path opt-in with one tap ("Remember this vault on this device?"), not a footgun. Mechanism:
   `location.origin` check at cache-enable time; surfaced, never hidden.
4. **Settings surface:** the account/settings flyout (2026-07-10 vault-settings-flyout) gains an
   "Offline copy" row: state (on/off), last-synced stamp, eviction-protection status (§B.5), size
   estimate, and the wipe-now action. The Unlock card gains one transparency line when a cache
   exists: "Offline copy on this device — last synced <t>".

**E.4 Wipe semantics — EXACT table (MUST implement to this):**

| Event | Cache DB (envelopes/queue/holding) | Cached accountKeys | Session (localStorage) |
|---|---|---|---|
| **Lock** (manual / auto / other-tab) | **retained** (T3 accepts ciphertext-at-rest; native "retained on lock") | retained | retained (today's F26) |
| **Sign-out** (user-initiated) | **wiped** (deleteDatabase) | wiped (same DB) | cleared (today) |
| **Revoked** (server WS frame) | **wiped** | wiped | cleared (today) |
| **Definitive 401** (refresh refused — `SessionEndKind` "expired") | **wiped** (spec 02 §8: "an invalid-session 401 that survives a refresh") | wiped | cleared (today) |
| **Policy `offlineCacheAllowed=false`** (any successful fetch) | **wiped** | wiped | retained (session itself is allowed) |
| **Opt-out toggled off** | **wiped** | wiped | retained |
| **Password change (this device)** | retained | **replaced** with the fresh payload | retained |
| **Cache-coherence failure / userId mismatch** (§B.4) | wiped | wiped | retained |

Consequence stated honestly: an ordinary token expiry (laptop asleep past refresh lifetime) wipes
the offline copy until the next ONLINE sign-in — native-parity fail-safe; offline-forever devices
never see a 401 so their copy survives (T3's design point). The queue is destroyed on every wipe
row above. **Sign-out with unsynced offline edits MUST BLOCK on an explicit confirm** ("N unsynced
changes will be lost" + destructive-action styling), not an advisory toast (breaker #9):
revocation may drop a queue silently (server-initiated; spec 03 §4 accepts losing a revoked
member's queue), but a user destroying their OWN pending edits gets a gate. A definitive-401 wipe
that finds a non-empty queue cannot be blocked (spec 02 §8 mandates the wipe) but MUST surface the
count ("N offline changes could not be synced — this session expired before reconnecting") so that
loss is never silent either.
**Wipe wiring (breaker #8).** The wipe hook lands in App's `signOut` callback (App.tsx) — the ONE
choke point that already handles user sign-out, `onRevoked`, and the definitive-401 session-end —
NOT in Welcome's copy path: today `Welcome` merely shows "Session expired — sign in again."
(Welcome.tsx) without wiping anything, so S3 must route the definitive-401 row through `signOut`
for this table to hold. In-flight cache writes racing the wipe resolve as caught no-ops (the D.2a
guarded close).

## F. Rollout

**F.1 Gating.** Ship GATED, not dark: ON by default on private origins (tailnet/LAN/localhost,
E.3.3), opt-in-only on the public break-glass origin (as built S3/S5: the computed
`webCacheEnabled()` predicate — org bit `andvari.orgCacheOff` > opt-out `andvari.cacheOptOut` >
origin default per E.3.3 > public-origin opt-in `andvari.cacheOptIn`; the draft's single
`andvari.webCache.enabled` flag was superseded) + the org policy bit. No server changes, no wire
changes, no spec-03 impact. Spec diffs in the docs cut (LANDED, S5 2026-07-14): `spec/02 §8`
(dropped "The web client keeps no at-rest cache in v1"; added the §8.1 web subsection pointing at
this doc), `spec/05` T3/T6/T8 amendments (E.1/E.2), `spec/01 §8.3` note clarified (still no web
quick-unlock — the cache is not one).

**F.2 Blocked-offline actions (enumerated — everything else works from the cache):** fresh sign-in
(C.2); recovery capture + all recovery flows (the capture itself is online-only — but an
unconfirmed flag no longer blocks offline unlock, C6 nag); password change / KDF upgrade;
attachment download/upload and any save carrying new files (D.3); item history + undelete + purge
(server archives); sharing/membership/admin/audit surfaces; vault lifecycle ops (delete/restore/
leave/transfer/rename — all proof+server round-trips); import (flush-live); WS bell (the F29 poll
already degrades). **Works offline:** unlock (including the C6 nag case), list/search/view/copy,
TOTP generation, export (banner reads the restored `lastSyncAt`), and — after S4 — item put/delete
edits, queued (persistence-granted devices only, §D.3).

**F.3 recoveryConfirmed / mustChangePassword interplay** — per C5/C6: an unconfirmed
`recoveryConfirmed` shows the persistent offline nag (never blocks; the ONLINE gate still blocks
until capture completes); `mustChangePassword` is a `SessionResponse` field, absent from
`AccountKeys` (types.ts), so an offline unlock genuinely CANNOT see a flip that happened while
offline — its banner already blocks writes in-vault when seen online, and an offline unlock during
the stale window is the accepted T3 narrowing.

**F.4 Follow-ups explicitly out of this cut:** service-worker app shell (D1 — needs its own
update/pinning threat design vs the 426 mechanism), web quick-unlock (out of scope by fiat),
whole-cache wrapper encryption (E.1), extension durable cache (separate surface, session-scoped
today by design).

## G. Test plan

- **Unit (vitest + `fake-indexeddb` dev-dep, `web/`):** idbcache CRUD parity suite (transliterate
  `SqliteVaultCacheTest` cases); userId-mismatch wipe; coherence-failure ⇒ full discard (delete one
  store, corrupt kv — assert cold-start, never partial trust); one-tx pull commit atomicity (abort
  mid-tx ⇒ zero rows moved, cursor unmoved); 410-resync tx preserves queue+holding **and
  `kv:accountKeys`/`userId`/`policy`** (breaker #2 regression: resync → lock → offline unlock
  still works); clear-preserves contract (enumerated, §D.1); stuck-cache demotion (3 consecutive
  commit failures ⇒ attempted wipe + NullCache, breaker #6); cursor-monotonic skip under a
  simulated concurrent tab; queue enqueue/flush/staged-denied/dropPending parity; setAccountKeys
  keep-old-on-bad-write (absent/sub-floor params never overwrite a good payload, breaker #5); E.4
  wipe table row-by-row.
- **Store integration (existing `store.test.ts` style, fake server):** hydrate tri-state
  (decryptable / held-key-fail / missing-VK) equals a fresh sync's classification; offline save ⇒
  queued ⇒ reconnect flush converges with SAME mutationId; offline save with persistence DENIED
  throws (no QUEUED return, breaker #1); denial epoch guard — a denial staged while a joined
  earlier pull is in flight is NOT classified by that pull, only by one that started after staging
  (breaker #3); sign-out-with-queue blocking confirm (count correct, breaker #9); F31 guards with
  a PERSISTED cursor across "restarts"; parked-mutation durability across restart + reinstate
  replay.
- **Unlock (Welcome/unit):** offline fallback triggers on NetworkError only (never on 4xx/5xx);
  C3 floor refusal on planted weak cached params; C4 IdentityMismatch on tampered cached
  identityPub; C6 nag — offline unlock PROCEEDS with the persistent banner while the online gate
  still blocks; wipe-then-offline-unlock fails to password-only cold state.
- **Live e2e (`live.e2e.test.ts` pattern):** login→sync→assert IDB populated (ciphertext-only:
  scan every stored value for known plaintext markers — the A2 tripwire); simulate offline
  (client base URL to a dead port) → new VaultStore + hydrate → items listable → offline unlock
  round-trip; torn-cache drill (delete `grants` store between sessions ⇒ resync-from-0, item set
  converges byte-identical).

## H. Effort + build order

| Slice | Contents | Size |
|---|---|---|
| **S1** | `idbcache.ts` + NullCache + coherence/wipe rules + unit suite | ~1 lane-session (largest single piece) |
| **S2** | `store.ts` cache-through: one-tx pull commit, hydrate, cross-tab lock, 410 tx, post-push envelope persist | ~1 lane-session |
| **S3** | offline unlock: accountKeys caching (incl. keep-old-on-bad-write) + Welcome fallback + C3/C4 gates + C6 nag + E.4 wipe wiring through `App.signOut` (sign-out/revoked/definitive-401/policy) | ~0.5 |
| **S4** | durable queue + offline writes: save/remove → enqueue+sync, flush-first order, durable staged-denied + epoch counters, RETIRE `parkOrRethrowDeniedEdit`, persist()-gate, sign-out confirm gate, "pending" UI affordance | ~1–1.5 |
| **S5** | settings surface + defaults (E.3) + `storage.persist()` + spec/docs cut | ~0.5 |
| **S6** | live e2e + torn-cache drills + threat-model spec diffs review | ~0.5 |

Build order S1→S2→S3 ships a useful read-only offline web (the owner-model gap closed for reads);
S4 completes native parity; S5/S6 harden and document. S1–S3 are one build session with parallel
lanes (S1 is dependency-free; S2/S3 touch disjoint files after S1's interface freezes).
**Ship gate (breaker verdict):** S1–S3 are clear on findings 5–8 as folded; **S4 must not ship
without findings 1 (persist()-gate) and 3 (denial unification) — both are load-bearing in
§B.5/§D.3 above.**

## I. Breaker verdicts and dispositions (2026-07-13)

The breaker verified the draft against `store.ts` / `account.ts` / `session.ts` / `keys.ts` /
`client.ts` / `App.tsx` / `Welcome.tsx` + core `SyncEngine.kt` / `SqliteVaultCache.kt` + Android
`Session.kt` at HEAD `6e0d638`. **No BLOCKER.** Two near-blocker AMENDMENTs gate S4; both are
folded. Every disposition is integrated into the body above (this section is the ledger, not the
fix). Nothing was refused.

1. **AMENDMENT (gates S4) — queue eviction is silent data loss, not "availability".** Queued
   offline edits exist only locally until flushed; whole-bucket eviction between enqueue and flush
   destroys them unrecoverably, and `persist()` is most likely denied exactly on the break-glass
   origin. **FOLDED** — D3 divergence rewritten to carve the queue out of the
   "availability-only" claim; §B.5+§D.3 gate the QUEUED-success path on granted persistence. Of
   the two offered remedies, the persist()-GATE (refuse-not-degrade) was chosen over
   warn-and-degrade: house posture is that silent-loss paths are refused, not disclaimed. Online
   enqueue-before-send stays ungated (seconds of exposure, and it buys D4's idempotent retry).
2. **AMENDMENT — 410-resync `clear()` must preserve `kv:accountKeys`/`userId`/`policy`.** Native
   `clear()` can't touch accountKeys (SharedPreferences, outside the DB); web co-locates them
   (D5), so a naive `kv.clear()` breaks offline unlock after any resync-then-lock. **FOLDED** —
   §D.1 now states the enumerated contract (resets `kv:cursor` ONLY); §A/D5 explains why web must
   write down what natives get structurally; §B.3 references it; §G carries the
   resync→lock→offline-unlock regression test.
3. **AMENDMENT — unify the two denial mechanisms; state the epoch invariant precisely.** Online
   `parkOrRethrowDeniedEdit` (double-sync) + S4 `flushQueue`/`surfaceStagedDenials` can
   double-handle one denial, and "single-flight ≈ two-sync review" was imprecise — the real
   invariant is core's `pullStartCounter`/`freshestCompletedPullStart` (classify a staged denial
   only against a pull that STARTED after staging). **FOLDED** — §D.3 rewritten: ONE denial path
   in S4 (all denials staged durably in `flushQueue`, classified by `surfaceStagedDenials` with
   explicit web epoch counters); `parkOrRethrowDeniedEdit` RETIRED in S4, unchanged through S3;
   §G epoch-misclassification test; §H S4 scope/size updated.
4. **AMENDMENT/NOTE — offline `recoveryConfirmed !== true` refusal can hard-lock a legitimate
   user.** `confirmRegisteredRecovery` is best-effort; a silently failed confirm POST leaves
   flag=false with a full cached vault and a valid password. **FOLDED (polarity flipped)** — §C6
   REVISED: offline unlock proceeds with a persistent in-vault nag whose copy reads as a reminder,
   never breakage; the ONLINE gate is unchanged, so the nag can't be ridden indefinitely.
   Rationale: the refusal protected nothing — capture needs connectivity anyway, and blocking
   cached READS doesn't reduce the loss risk the flag guards. §F.2/§F.3/§G/§H updated. (C6's other
   claim — stale `recoveryConfirmed=true` after admin-recovery — confirmed harmless: pure T3;
   `mustChangePassword` is a `SessionResponse` field, invisible to offline unlock, per C5/F.3.)
5. **NOTE — C3/C4 CONFIRMED sound; two residues.** (a) Cached grant role is tamperable plaintext
   → cosmetic offline "elevation", server-denied on flush. (b) `client.accountKeys()` fences only
   `if (k?.kdfParams)`, so an absent-params payload is cacheable → permanent offline-unlock
   refusal until a good refresh (availability DoS, no new capability). **FOLDED** — (a) one
   sentence in §E.2; (b) §D.2c keep-old-on-bad-write rule + §G test; C3's read-time reject stays
   as the belt.
6. **NOTE — A1 CONFIRMED (cursor cannot outlive rows); add a stuck-cache guard.** IDB multi-store
   txs abort atomically, but a persistently failing commit freezes disk at an old cursor while the
   session advances. **FOLDED** — §D.1 stuck-cache rule: 3 consecutive commit failures ⇒ §B.4
   treatment (attempt wipe, demote to NullCache for the session, settings-row notice); §B.4
   rescoped to open-time errors so the two rules don't contradict; §G test.
7. **NOTE — D.5 CONFIRMED sound; one build clarification.** A commit-skipping tab must re-pull
   from its own cursor so skipped rows reappear. **FOLDED** — §D.5 rule 1 now states the skipping
   tab keeps its own in-memory `cursor = resp.rev` and converges on its next pull.
8. **NOTE — sign-out racing an in-flight save's post-push envelope persist (S2+).** **FOLDED** —
   §D.2a guarded-close rule (caught no-op, never an uncaught rejection; the server-committed item
   re-syncs); §E.4 names `App.signOut` as the single wipe choke point — including the
   definitive-401 row, which today only shows copy in `Welcome` — §H S3 scope updated.
9. **NOTE — sign-out with an unsynced queue must BLOCK-with-confirm, not toast.** **FOLDED** —
   §E.4: user sign-out over a non-empty queue = blocking confirm with destructive styling;
   revocation stays silent-drop (server-initiated, spec 03 §4); a definitive-401 wipe can't be
   blocked (spec 02 §8) but must surface the lost-edit count. §G/§H updated.

---
*Breaker pass complete 2026-07-13 — verdicts and dispositions in §I. S1–S3 are clear to build;
S4 ships only with §I findings 1 and 3 folded (they are, in §B.5/§D.3). Next: owner review, then
build.*
