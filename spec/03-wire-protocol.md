# andvari spec 03 — wire protocol

HTTPS JSON API under `/api/v1`. Base URL: `https://andvari.taila2dff2.ts.net`
(tailnet) or the break-glass public hostname. All binary fields base64url unpadded.
Server rejects requests > 1 MiB except attachment uploads (streamed, quota-checked).

## 1. Client identification & version pinning

Every request carries `X-Andvari-Client: <platform>/<semver>` with platform ∈
`android|windows|web|cli`. If policy pins `minVersion[platform]` above the caller,
the server answers **426** `{ "error": "upgrade_required", "minVersion": "…" }`;
clients block writes and show the upgrade path (devstore / /downloads / reload).
`GET /api/v1/client-policy` (unauthenticated) returns current pins + `serverTime`.

## 2. Auth & sessions

- `POST /auth/prelogin { email }` → `{ kdfSalt, kdfParams }` (rate-limited). Unknown
  emails get a fake-but-deterministic salt (spec 01 §3) + the **current org-default**
  kdfParams — never the compile-time default. Known accounts answer their real
  per-user params (clients need them pre-auth to derive the auth key); the residual
  params-divergence oracle after a policy bump is recorded in spec 05 R4 and heals
  when the account re-keys.
- `POST /auth/login { email, authKey, device: { platform, name } , totp? }` →
  `201 { userId, deviceId, accessToken, refreshToken, accountKeys }` where
  `accountKeys = { wrappedUvk, kdfParams, encryptedIdentitySeed, identityPub,
  escrowFingerprint }`. Failures are uniform `401 invalid_credentials` (no
  user/password distinction). If the account has server-TOTP enrolled and the request
  arrives via the public origin, `totp` is REQUIRED (spec: break-glass hardening).
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
- `PUT /escrow/self { sealed, recoveryKeyFingerprint }` — client (re)uploads its
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
  "removedGrants": [ vaultId… ]      // caller lost access → client purges local copies
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
- `denied` — role violation (reader pushing to a shared vault) or no grant; nothing
  written; audited.

Batch limit 200 mutations; server applies the batch in order, atomically per
mutation (not per batch). Clients maintain a durable outbound queue and MUST retry
with the SAME mutationIds after connectivity loss.

**Conflict-copy materialization (client duty):** on seeing `conflict=true` with a
decryptable displaced version, create a new item `{name: "<name> (conflict
YYYY-MM-DD)"}` carrying the losing content, then push it plus a flag-clearing rewrite of
the winner (both normal `put`s). The copy's itemId is derived **deterministically** from
`(itemId, conflictedRev)` so that if several members materialize the same conflict
concurrently they converge on one copy id (the server's idempotent existing-item path
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
- `POST /admin/users/{id}/disable`, `POST /admin/devices/{id}/revoke`,
  `GET /admin/users/{id}/devices` — per-user device list (feeds the revocation UI).
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
- `GET /healthz` (200 when DB writable) — Kuma target. `GET /metrics` — Prometheus,
  bound to localhost for Alloy only.
- Rate limits (per IP + per account): prelogin/login 10/min then backoff;
  public-origin (CF-Connecting-IP present + configured public hostname): 5/min,
  TOTP required, register/refresh disabled unless policy explicitly enables.
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
  20/min/account, audited `user_lookup` (target email in meta). The unauthenticated
  anti-enumeration guarantees of §2 are unchanged — this is an authed-only path.
- `GET /api/v1/vaults/{vaultId}/members` → `[{ userId, email, displayName, role,
  identityPub, addedAt }]` (active grants only). Any active member may call (transparency:
  every member can re-verify who holds the VK). Foreign vaultId → 403 (hidden-as-403).
- `POST /api/v1/vaults/{vaultId}/members { userId, role: "writer"|"reader", sealedVk }` →
  `201`. Owner only; target must be an `active` user, not self, with no active grant (a
  previously-revoked grant row is resurrected). `sealedVk` opaque to the server, validated
  only as base64url ≤ 1 KiB. Audited `vault_member_add`.
- `PUT /api/v1/vaults/{vaultId}/members/{userId} { role }` → `200`. Owner only; not self.
  Bumps the grant rev (re-delivers the grant so clients update the role). Audited
  `vault_member_role`.
- `DELETE /api/v1/vaults/{vaultId}/members/{userId}` → `200`. Owner only; not self. Sets
  `revokedAt`, bumps the grant rev → the victim's next pull carries `removedGrants`;
  sync/push/attachment access stops immediately. **No VK rotation in v1** (spec 01 §6 /
  spec 05 R7). Audited `vault_member_remove`.
- All five ring the WS dirty-bell for every affected member.
