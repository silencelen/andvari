# andvari spec 03 — wire protocol

HTTPS JSON API under `/api/v1`. Base URL: `https://andvari.taila2dff2.ts.net`
(tailnet) or the break-glass public hostname. All binary fields base64url unpadded.
Server rejects requests > 1 MiB except attachment uploads (streamed, quota-checked).

## 1. Client identification & version pinning

Every request carries `X-Andvari-Client: <platform>/<semver>` with platform ∈
`android|windows|web|cli`. If policy pins `minVersion[platform]` above the caller,
the server answers **426** with the standard error shape (§8):
`{ "error": "upgrade_required", "message": "min <platform> <minVersion>" }` — clients
key on the BODY code, never the bare status (`message` is human-only; the actual pin
comes from `/client-policy`); they block writes and show the upgrade path
(devstore / /downloads / reload).
`GET /api/v1/client-policy` (unauthenticated) returns current pins + `serverTime`.

## 2. Auth & sessions

- `POST /auth/prelogin { email }` → `{ kdfSalt, kdfParams }` (rate-limited). Unknown
  emails get a fake-but-deterministic salt (spec 01 §3) + the **current org-default**
  kdfParams — never the compile-time default. Known accounts answer their real
  per-user params (clients need them pre-auth to derive the auth key); the residual
  params-divergence oracle after a policy bump is recorded in spec 05 R4 and heals
  when the account re-keys.
- `POST /auth/login { email, authKey, device: { platform, name } , totp? }` →
  `200 { userId, deviceId, accessToken, refreshToken, accountKeys }` where
  `accountKeys = { wrappedUvk, kdfParams, encryptedIdentitySeed, identityPub,
  escrowFingerprint }`. Failures are uniform `401 invalid_credentials` (no
  user/password distinction). Via the public origin, server-TOTP is mandatory
  (break-glass hardening): an account without it enrolled is refused outright
  (`403 public_login_requires_totp`); enrolled accounts must supply `totp`
  (missing → `401 totp_required`).
- Tokens are opaque 256-bit random, transported as base64url, stored server-side as
  `sha256(token)`. Access: 1 h. Refresh: 30 d, **rotating** — `POST /auth/refresh
  { refreshToken }` → new pair, old refresh token single-use; reuse of a consumed
  refresh token revokes the whole device session (theft signal, audited).
- `POST /auth/logout` revokes the device session. Admin device-revocation: §7.
- AuthN header: `Authorization: Bearer <accessToken>`.
- **Server-TOTP management** (authenticated): `GET /account/totp` → `{ enrolled,
  pendingSetup }`; `POST /account/totp/setup` → `{ secretBase32, otpauthUri }`
  (pending until confirmed); `POST /account/totp/confirm { code }`;
  `POST /account/totp/disable { code }`. Codes are RFC 6238 SHA-1/6-digit/30 s with a
  ±1-step window; an accepted step is single-use (replay-rejected), so a code that
  just confirmed enrollment cannot immediately re-authenticate — wait one step.

## 3. Account key material

- `GET /account/keys` → `accountKeys` (as in login).
- `PUT /account/password { currentAuthKey, newAuthKey, newKdfSalt, newKdfParams,
  newWrappedUvk }` — atomic; server verifies currentAuthKey, swaps verifier + salt +
  params + wrappedUvk, revokes all sessions except the calling one, audits. Used for
  both password change and KDF upgrade (spec 01 §7).
- `PUT /escrow/self { sealed, fingerprint }` — client (re)uploads its
  sealed UVK; server validates fingerprint equals the pinned org fingerprint.

## 4. Sync — pull

`GET /sync?since=<rev>` (since=0 → full) →

```jsonc
{
  "rev": 1042,                       // current global max
  "full": false,                     // true when the response is a full snapshot
  "vaults":  [ Vault… ],             // changed vaults (incl. metaBlob)
  "grants":  [ Grant… ],             // caller's grants only
  "items":   [ Item… ],              // changed items in granted vaults (incl. tombstones)
  "removedGrants": [ vaultId… ],     // caller lost access → client purges local copies
  "removedGrantsInfo": [ RemovedGrantInfo… ]  // additive (§11); companion detail, never the trigger
}
```

- Ordering: one **global monotonic rev** from the server's `changes` sequence; every
  create/update/delete of any object bumps it. Responses are consistent snapshots
  (single read transaction).
- **New-member / grant-change backfill:** a vault and its items are delivered when the
  object's rev **or the caller's grant rev on that vault** exceeds `since`. So a member
  added at a high rev whose cursor is already past the vault's/items' own revs still
  receives the vault row and all pre-existing items; a role change (which bumps the grant
  rev) likewise re-delivers that vault's items (idempotent client-side upsert). Without
  this, a new grant would sync as "exists" but be unusable.
- `removedGrants` client duty: purge that vault's items from the local cache, drop the VK,
  and discard any unsynced queued mutations targeting that vault (a revoked member's
  offline edits to the vault are lost — the push would be `denied` regardless).
- **`removedGrantsInfo`** (additive, spec 03 §11) is the companion detail for `removedGrants`
  (which remains the SOLE purge trigger for old clients): `{vaultId, reason:
  'removed'|'left'|'deleted', deletedAt?, purgeAt?, deleteId?, deleteProof?,
  restoreProof?, removeProof?, removeNonce?}` (no `transferred` reason: ownership
  transfer demotes the old owner to writer without revoking any grant, so it never
  produces a row here). `reason` derives from the caller's OWN grant's
  `revokedReason` (a member removed *before* a later vault delete sees `removed`, not
  `deleted`). 0.5.0+ client duties: verify the proof under the still-held `lifecycleKey`
  BEFORE any destructive local action; tri-state — *valid* → act with an attributed notice;
  *invalid, or bare revocation of a locally-held vault* → move to the holding area + warn;
  *unverifiable* (no VK / vault unknown locally) → silent no-op. Notices fire ONLY for
  vaults present locally before the pull (no ghost banners on fresh devices / `since=0`).
  A denied-mutation failure MUST NOT abort the pull that delivers `removedGrants` (F21);
  denied mutations for in-grace vaults SHOULD be parked and replayed on restore. Clients
  MUST ignore unknown response fields (pins the additivity contract).
- **Item history (feature: item history & restore):** `GET /items/{id}/versions` →
  `{ itemId, versions: [{ rev, blob, formatVersion, archivedAt }] }`, newest rev first — the
  archived ciphertext versions the server already keeps (spec 02 §7, last 10). Grant-checked
  against the item's own vault (unknown item and non-member both `403`-hidden, §8 — no
  existence oracle); serves a tombstoned item's versions too (the item row persists). The
  client decrypts each `blob` under the VK it holds (AD binds itemId+formatVersion, not rev)
  and restores a chosen version as an ordinary put over the live item. Additive: no schema
  bump, no formatVersion bump, no new server knowledge.
- **Durable cursor rule (spec 02 §8):** vaults/grants/items/removedGrants are all deltas
  over the same global rev, so a client that persists its cursor MUST also persist the
  grant rows, vault rows, and item envelopes it has applied (grant/vault rows never
  re-send once the cursor passes them) — otherwise it MUST discard the cursor and pull
  from 0. The offline queue survives a `410` resync and replays on top of the fresh
  snapshot; the resync MUST be transactional (the durable cache is replaced only once the
  full snapshot is in hand, never left empty by a failed re-pull).
- **Rev-regression rule (spec 05 T1):** a client MUST NOT apply a non-full response whose
  `rev` is below its cursor, nor an unsolicited `full` snapshot when it pulled with
  `since>0`; it surfaces a server-rollback warning and keeps local state (never deletes or
  overwrites local newer state). `rev` is not in item AD (spec 02 §2), so this is the
  client's defense against a server replaying old-but-AD-valid envelopes.
- `410 Gone` when `since` predates retained history (tombstone GC, spec 02 §7) →
  client discards cursor and re-pulls with `since=0`, then reconciles its offline
  queue on top.

## 5. Sync — push

`POST /sync/push`:

```jsonc
{ "mutations": [ {
    "mutationId": "uuid",            // client-generated, idempotency key
    "op": "put" | "delete",
    "itemId": "uuid", "vaultId": "uuid",
    "baseItemRev": 17,               // 0 = creating
    "item": { formatVersion, attachmentIds, blob }   // op=put only
} ] }
```

→ `200 { "rev": <newGlobalMax>, "results": [ { "mutationId", "status", "newItemRev",
"serverItem"? } ] }` with per-mutation status:

- `applied` — clean write (`baseItemRev` matched server state).
- `conflict` — divergence handled server-side, **write never rejected-and-dropped**:
  - put over newer put: applied; previous version archived to item_versions;
    `conflict=true`; `serverItem` = the displaced version (so the pusher can
    materialize the conflict copy immediately).
  - put over tombstone: item restored (edit beats delete), `conflict=true`.
  - delete over newer edit: delete NOT applied (edit beats delete); `serverItem` =
    current; client drops its local tombstone.
  - delete over tombstone: `applied` (idempotent).
- Idempotent replay — when a `mutationId` has been seen before for this device
  (dedup window ≥ 24 h / 1000 mutations), the server returns the ORIGINAL stored
  result **verbatim** (same `status`, same `newItemRev`) with no re-execution. A
  crash-retry therefore observes the identical outcome it would have on first
  success — the client's state converges the same way. (There is no distinct
  `duplicate` status code; the replayed status is whatever the original was.)
- `denied` — role violation (reader pushing to a shared vault), no grant, or an fv
  downgrade (`item.formatVersion` below the stored row's — the monotonic-fv guard; no
  fielded client legitimately downgrades, an invariant future clients MUST preserve;
  the same check 400s `fv_downgrade` on `POST /items/{id}/restore`); nothing written;
  audited.

Batch limit 200 mutations; server applies the batch in order inside ONE transaction:
a thrown validation failure (e.g. bad attachment refs) rolls back the WHOLE batch,
while per-mutation `denied` results are recorded without aborting the rest. Clients
maintain a durable outbound queue and MUST retry with the SAME mutationIds after
connectivity loss.

**Conflict-copy materialization (client duty):** on seeing `conflict=true` with a
decryptable displaced version, create a new item `{name: "<name> (conflict
YYYY-MM-DD)"}` carrying the losing content, then push it plus a flag-clearing rewrite of
the winner (both normal `put`s). The copy's itemId is derived **deterministically** from
`(itemId, conflictedRev)` — specifically a UUIDv4-shaped id from the first 16 bytes of
`sha256("conflict|" + itemId + "|" + conflictedRev)` with the version/variant nibbles
forced (vector-pinned, `spec/test-vectors/conflictcopy.json`) — so that if several members
materialize the same conflict concurrently they converge on one copy id (the server's idempotent existing-item path
absorbs the duplicates) rather than each creating their own. A **`reader`-role** member
MUST NOT materialize (its push would be `denied`); the flag waits for a writer/owner.

## 6. Events (WS)

`GET /api/v1/events` upgrades to WebSocket. **Auth:** browser clients first call
`POST /api/v1/events/ticket` (Bearer-authenticated) → `{ ticket, expiresInSeconds }`,
then connect as `GET /api/v1/events?ticket=…`. Tickets are 256-bit random, held
server-side as sha256 hashes **in memory only**, TTL 30 s, strictly single-use (a
restart drops pending tickets; clients re-mint). `Authorization: Bearer` on the
upgrade request remains valid for non-browser callers. **Raw access tokens in the
query are NOT accepted** — long-lived bearers must never ride URLs into edge logs.
A ticket authenticates the account at mint time; if the session is revoked within the
ticket's ≤30 s TTL, the already-minted ticket may still open the bell for that window
(accepted: the socket carries only rev/policy/revoked signalling, never vault data, and
the session's access token is rejected on its next `/sync`).
Server → client frames: `{"type":"rev","rev":N}` (something changed — pull if N >
local), `{"type":"policy"}`, `{"type":"revoked"}` (session killed — drop to lock
screen). Nothing else rides the socket; it is a dirty-bell, not a data plane.
**Liveness:** browser clients reconnect a dropped bell with exponential backoff (1 s
doubling to a 60 s cap, jittered), minting a fresh single-use ticket per attempt, and
pull `/sync` on every (re)open to recover bells missed while down (the notifier has no
replay); a tab becoming visible with a dead socket reconnects immediately, and a
401/403 at ticket mint (dead session) stops reconnection and drops to the lock screen.
Clients without WS poll `/sync` + refresh `/client-policy`: Android on every
foreground transition and every 5 min while foregrounded and unlocked; desktop on
window focus regained and every 5 min while unlocked. Server pings every 30 s; both
proxies in front (tailscale serve, cloudflared) pass WebSocket upgrades — verified in P1.

## 7. Admin (isAdmin only; every call audited)

- `GET/POST /admin/users` — list; create → invite `{ inviteToken (72 h), email }`.
  Registration is **invite-only, always** (even break-glass): `POST /auth/register
  { inviteToken, email, displayName, kdfSalt, kdfParams, authKey, wrappedUvk,
  identityPub, encryptedIdentitySeed, escrow: { sealed, fingerprint },
  personalVault: { vaultId, wrappedVk, metaBlob }, device: { platform, name } }` —
  one shot, atomic (user + escrow + personal vault + owner grant + first device +
  session; response = the login response). The enrolling client MUST have verified
  the recovery fingerprint (spec 04) before this call; the server rejects
  registration whose asserted escrow fingerprint ≠ pinned.
- `POST /admin/users/{id}/disable` — disables the account + revokes its sessions.
  Refuses with `400 last_admin` if the target is the only ACTIVE admin (an
  instance-wide lockout, recoverable only by DB surgery) and `400 no_such_user` for an
  unknown target; both refusals are audited (`user_disable_denied`). `POST
  /admin/devices/{id}/revoke`, `GET /admin/users/{id}/devices` — per-user device list
  (feeds the revocation UI).
- `POST /admin/recovery { userId, tempAuthKey, tempWrappedUvk, tempKdfSalt,
  tempKdfParams }` — uploads recovery-cli output (spec 04 §4); sets
  `mustChangePassword`; revokes all the user's sessions.
- `GET /admin/audit?since&type&userId` — filterable event log (also shipped to Loki
  via journald).
- `GET/PUT /admin/policy` — org policy JSON: `minVersion{platform}`, default
  kdfParams, autoLockSeconds, clipboardClearSeconds, offlineCacheAllowed, quotas,
  sessionTtls.
- `GET /admin/status` — server version, break-glass tunnel state (read-only),
  storage stats.

## 8. Misc

- `GET /api/v1/hibp/range/{5-hex-prefix}` — authenticated relay of the HIBP
  k-anonymity range API with a 7-day on-disk cache; response format identical to
  upstream (`SUFFIX:COUNT` lines). Client computes SHA-1 locally and compares
  suffixes locally; full hashes never leave the device.
- `GET /downloads` — web UI + manifest `{ windows: { version, url, sha256 } }`.
- `GET /healthz` (200 when the DB is readable — the probe is a read-only rev
  SELECT, so an unwritable-but-readable DB still answers 200) — Kuma target.
  `GET /metrics` — Prometheus, bound to localhost for Alloy only.
- Rate limits: prelogin/login are **per IP** 10/min (fixed window; per-account keys
  exist on vault-create, user-lookup and the §11 lifecycle buckets
  (`vault_destructive`/`vault_recovery`) — per-account login keys are a
  deferred hardening item);
  on the public origin (CF-Connecting-IP present + configured public hostname)
  **login** drops to 5/min (prelogin stays 10/min), TOTP is required, and
  register/refresh are hard-disabled (`403 register_public_disabled` /
  `public_refresh_disabled` — no policy flag enables them; break-glass sessions
  re-login with TOTP instead of refreshing).
- Client IP (rate keys + audit rows): derived from `CF-Connecting-IP`, else the
  **rightmost** `X-Forwarded-For` entry, **only when the direct TCP peer is
  loopback** (both front-ends terminate there). Any other peer uses the socket
  address and forwarded headers are ignored entirely (spoof-proof). The trusted
  header list is operator-configurable (`ANDVARI_TRUSTED_IP_HEADERS`); `/metrics`
  never trusts forwarded headers.
- Errors: `{ "error": "<machine_code>", "message": "<human>" }`; 401 uniform for
  auth, 403 role, 404 hidden-as-403 for cross-tenant probes, 409 never used for sync
  (conflicts are 200-with-status), 410 resync, 413 attachment/user/item quota,
  426 upgrade, 429 rate.

## 9. Attachments (data model: spec 02 §6)

- `POST /attachments/{attachmentId}?vaultId=…&itemId=…` — writer/owner grant
  required; ids are canonical UUIDs. Raw body = `header (24 B) || ciphertext chunks`
  exactly as stored. The server streams to disk under the quota caps (413 over
  policy `attachmentMaxBytes` / `userAttachmentsMaxBytes`), records
  `{ size, sha256(ciphertext), header }`, and never parses content. Idempotent per
  attachmentId: identical bytes → the stored meta; different bytes →
  `400 attachment_id_taken`.
- Uploads are additionally bounded per user by a concurrent-upload cap (429 when
  exceeded) and by in-flight `.part` bytes counted toward `userAttachmentsMaxBytes`
  mid-stream (413); the commit-time quota check remains authoritative.
- `GET /attachments/{attachmentId}` — any grant on the owning vault; raw body
  identical to the upload shape. Unknown/foreign ids answer 403 (hidden-as-403, §8).
- Item pushes referencing `attachmentIds` are validated: every id must exist and be
  bound to that exact (itemId, vaultId) (`400 unknown_attachment` /
  `400 attachment_mismatch`), and the referenced total must fit
  `itemAttachmentsMaxBytes` (413). A validation failure fails the whole push batch.
- Tombstoning an item deletes its blobs immediately; uploads never referenced by a
  live item are GC'd after 24 h (spec 02 §6).

## 10. Shared vaults (family sharing)

All authenticated + version-checked; membership management is owner-only. These routes
are **refused on the public break-glass origin** (sharing administration is a
sit-at-home operation). Every call is audited (ids/roles only, never names).

- `POST /api/v1/vaults { vaultId, metaBlob, wrappedVk }` → `201 { rev }`. Creates a
  `type=shared` vault and the caller's `owner` grant (`wrappedVk` under the caller's UVK,
  `sealedVk` empty). Client-chosen UUID `vaultId`. `metaBlob` ≤ 4 KiB and `wrappedVk` ≤ 1
  KiB base64url; vault creation rate-limited (5/hour/account). Audited `vault_create`.
- `POST /api/v1/users/lookup { email }` → `{ userId, displayName, identityPub }` or
  `404 no_such_user`. Deliberately confirms account existence **to authenticated,
  invited household members** so an owner can find whom to share with; rate-limited
  20/min/account, audited `user_lookup` (meta = target **userId**, never the email — 0.4.0 PII fix). The unauthenticated
  anti-enumeration guarantees of §2 are unchanged — this is an authed-only path.
- `GET /api/v1/vaults/{vaultId}/members` → `[{ userId, email, displayName, role,
  identityPub, addedAt, status? }]` (active grants only). Any active member may call
  (transparency: every member can re-verify who holds the VK). Foreign vaultId → 403
  (hidden-as-403). **Refused on the public break-glass origin** (§11 closed a drift where
  this alone leaked household emails/identity keys from the internet). `status` (additive)
  surfaces a disabled account (feeds the transfer target picker).
- `POST /api/v1/vaults/{vaultId}/members { userId, role: "writer"|"reader", sealedVk }` →
  `201`. Owner only; target must be an `active` user, not self, with no active grant (a
  previously-revoked grant row is resurrected). `sealedVk` opaque to the server, validated
  only as base64url ≤ 1 KiB. Audited `vault_member_add`.
- `PUT /api/v1/vaults/{vaultId}/members/{userId} { role }` → `200`. Owner only; not self.
  Bumps the grant rev (re-delivers the grant so clients update the role). Audited
  `vault_member_role`.
- `DELETE /api/v1/vaults/{vaultId}/members/{userId}` → `200`. Owner only; not self. Sets
  `revokedAt`, `revokedReason='member_remove'`, bumps the grant rev → the victim's next pull
  carries `removedGrants`; sync/push/attachment access stops immediately. **No VK rotation
  in v1** (spec 01 §6 / spec 05 R7). Gains an **optional** body `{proof, nonce}` (removal
  proof, §11) delivered to the victim via `removedGrantsInfo` so a 0.5.0 client can verify
  the removal was a real owner action. Removing (or role-changing) the **pending transfer
  target** clears the pending offer. Audited `vault_member_remove`.
- All five ring the WS dirty-bell for every affected member.

## 11. Vault lifecycle (delete / restore / leave / transfer / rename)

Owner gripe 1: a created shared vault was immortal. Full design + adversarial breaks:
`docs/design/2026-07-07-shared-vault-lifecycle-skipti.md`. Target: server schema v4 (spec
02 §4) + client 0.5.0. **All wire changes are additive; fielded 0.4.0 and 0.2.x clients
require zero changes and cannot 404 mid-sync** (sync is grant-driven; the only vault-scoped
calls — members GET, attachments — already 403-handle non-fatally; no minVersion pin is
armed). *Update 2026-07-10 (N2 §5):* the sync-cursor 410 (`resync_required`) is **live** —
the janitor now advances `oldestRetainedRev` on its 30-day fence (spec 02 §7) — and the
fielded-client guarantee still holds for the reason it always did: every client since 0.2.0
auto-resyncs on 410 (cache clear + `sync(0)`, offline queue preserved), so an aged-out
cursor is one clean full pull, never a wedge.

**Common rules.** All lifecycle routes are authenticated + `enforceVersion` + **refused on
the public break-glass origin** + audited ids-only. **Guard order: resolve the caller's
grant FIRST** (including revoked rows) → an outsider gets a uniform `403 not_vault_owner` /
`no_grant` regardless of vault existence (no tombstone existence oracle). Deleted-vault
special-case errors are returned only to grant-holders. Lifecycle ops are foreground REST
and are **never queued durably offline**. Rate buckets: `vault_destructive:{userId}` 10/h
(delete, transfer offer, rename); `vault_recovery:{userId}` 30/h (restore, cancel, accept,
leave) — restore is never blocked by the delete spree it undoes. Idempotency is by
**operation identity** (deleteId / offerId), not by row state. Grace/expiry:
`ANDVARI_VAULT_GRACE_DAYS=7`, `ANDVARI_TRANSFER_TTL_DAYS=14` (env, not schema).

**Proofs** (spec 01 §6, vectors `spec/test-vectors/lifecycleproof.json`): `lifecycleKey =
HKDF-SHA-256(VK, "andvari/v1|lifecycle")`; the server STORES and RELAYS proofs but cannot
mint or verify them (no VK) — verification is a CLIENT duty. Domain strings (base64url
HMAC-SHA-256 value; `|`-joined UTF-8; integers decimal):
- delete/restore: `andvari/v1|lifecycle|{delete,restore}|{vaultId}|{deleteId}`
- offer: `andvari/v1|lifecycle|transfer|{vaultId}|{offerId}|{toUserId}|{expiresAt}|{seq}`
- accept: `andvari/v1|lifecycle|transfer-accept|{vaultId}|{offerId}|{newOwnerUserId}|{seq}|{hexLower(sha256(utf8(wrappedVk)))}`
- remove: `andvari/v1|lifecycle|remove|{vaultId}|{targetUserId}|{nonce}`

**Routes:**
- `POST /vaults/{id}/delete {deleteId, proof}` → `200 {rev, purgeAt}`. Owner of a shared
  vault, unlocked. One tx: capture active `memberIds` BEFORE revoking; clear any pending
  transfer; revoke every active grant (`revokedReason='vault_delete'`, keeping key wraps for
  restore); set `deletedAt/purgeAt=now+GRACE/deletedBy/deleteId/deleteProof`, `restoreProof=NULL`,
  bump vault rev. Idempotent by `deleteId` (mismatched deleteId on an already-deleted vault
  → `409 vault_state_changed`, never a fresh delete). Bell the captured members.
- `POST /vaults/{id}/restore {deleteId, proof}` → `200 {rev}`. Deleting owner (via revoked
  owner grant), `purgedAt IS NULL`, `deleteId` matches (else `vault_gone` / `vault_state_changed`).
  Un-revoke ONLY grants `revokedReason='vault_delete' AND revokedAt=deletedAt` (members
  removed before the delete stay removed), clear lifecycle fields, store `restoreProof`
  (consumes the deleteId — a later tombstone bearing it is stale/forged), bump revs.
- `GET /vaults/deleted` → `200 [DeletedVaultSummary{vaultId, metaBlob, wrappedVk, deletedAt,
  purgeAt, deleteId}]` — the caller's own in-grace vaults (ciphertext they already owned).
- `POST /vaults/{id}/leave {}` → `200 {rev}`. Any non-owner active member;
  `owner → 400 owner_must_transfer_or_delete`. `revokedReason='member_leave'`; if caller ==
  `pendingOwnerId`, clear the pending offer. Idempotent by reason.
- `POST /vaults/{id}/transfer {toUserId, offerId, expiresAt, proof}` → `201 {rev, expiresAt}`.
  Owner; target = an existing **active** member with an active grant, status active, ≠ self;
  one pending max (overwrite audits a cancel). `seq = transferSeq+1`. Stores pending fields +
  bumps vault rev → `WireVault.pendingTransfer` re-delivers to every member.
- `DELETE /vaults/{id}/transfer` → `200 {rev}`. Owner cancel or target decline.
- `POST /vaults/{id}/transfer/accept {offerId, wrappedVk, proof}` → `200 {rev}`. The
  `pendingOwnerId` only, on a 0.5.0+ client that verified the offer proof and round-trip-
  verified its own minted `wrappedVk` before posting; `acceptProof` binds `sha256(wrappedVk)`.
  Tx re-checks pending/expiry/grant-predates-offer; old owner → `writer` (wrappedVk kept),
  new owner → `owner` with posted `wrappedVk` **and retained `sealedVk`** (fallback key
  material — spec 01's exactly-one rule is relaxed here; both wiped together at purge);
  `transferSeq=seq`. Idempotent when the caller is already owner for this `offerId`.
- `PUT /vaults/{id}/meta {metaBlob, baseVaultRev?}` → `200 {rev}`. Owner; shared vaults;
  not deleted; `≤4 KiB` b64. `baseVaultRev < vaults.rev → 409 stale_meta`. Rename only
  (name is ciphertext — server audits ids). Personal-vault rename deferred.

**Errors:** `vault_deleted, vault_gone, vault_state_changed, owner_must_transfer_or_delete,
transfer_not_pending, not_transfer_target, stale_meta, no_grant, not_vault_owner,
user_inactive`. **Audit types** (ids only): `vault_delete, vault_restore, vault_purge,
vault_member_leave, vault_transfer_{offer,accept,cancel,expire}, vault_rename`; `push_denied`
gains a `deleted:` meta prefix for tombstoned vaults (excludes routine lifecycle fallout
from intrusion review). **Janitor** (daily 04:30 + delayed on-boot; log-only dry-run its
first armed week): purge vaults past grace (spec 02 §7) and expire transfer offers past
`expiresAt`; a Grafana/Loki alert fires on any vault with `purgeAt < now-2d AND purgedAt IS
NULL`. **Admin succession: no admin lifecycle route exists BY DESIGN** (a server route that
reassigns owner rows *is* the F16 forgery class) — a lost/disabled owner is recovered via
spec 04 §4 escrow recovery, then acts as owner (`ops/runbooks/vault-succession.md`).
