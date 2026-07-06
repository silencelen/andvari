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

- `POST /auth/prelogin { email }` → `{ kdfSalt, kdfParams }` (fake-but-deterministic
  for unknown emails, spec 01 §3; rate-limited).
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
- `duplicate` — `mutationId` seen before (per-device dedup window ≥ 24 h /
  1000 mutations): the ORIGINAL result is replayed verbatim; no re-execution.
- `denied` — role violation (reader pushing to a shared vault) or no grant; nothing
  written; audited.

Batch limit 200 mutations; server applies the batch in order, atomically per
mutation (not per batch). Clients maintain a durable outbound queue and MUST retry
with the SAME mutationIds after connectivity loss.

**Conflict-copy materialization (client duty):** on seeing `conflict=true` with a
decryptable displaced version, create a new item `{name: "<name> (conflict
YYYY-MM-DD)"}` with a fresh itemId carrying the losing content, then push it plus a
flag-clearing rewrite of the winner (both normal `put`s). Exactly-one materializer:
whoever holds the displaced version from `serverItem` or item_versions does it; the
flag-clear makes later syncers skip.

## 6. Events (WS)

`GET /api/v1/events` upgrades to WebSocket (same Bearer auth). Server → client
frames: `{"type":"rev","rev":N}` (something changed — pull if N > local),
`{"type":"policy"}`, `{"type":"revoked"}` (session killed — drop to lock screen).
Nothing else rides the socket; it is a dirty-bell, not a data plane. Clients without
WS poll `/sync` on foreground + every 5 min. Server pings every 30 s; both proxies in
front (tailscale serve, cloudflared) pass WebSocket upgrades — verified in P1.

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
- `POST /admin/users/{id}/disable`, `POST /admin/devices/{id}/revoke`.
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
- Errors: `{ "error": "<machine_code>", "message": "<human>" }`; 401 uniform for
  auth, 403 role, 404 hidden-as-403 for cross-tenant probes, 409 never used for sync
  (conflicts are 200-with-status), 410 resync, 426 upgrade, 429 rate.
