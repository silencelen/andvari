# andvari spec 02 — vault format

## 1. Item model

An **item** is one encrypted record in one vault. Server-side row (see §5 for the
full plaintext contract):

```
Item {
  id            uuid          # client-generated at creation
  vaultId       uuid
  rev           int64         # server-assigned, from the global changes sequence
  createdAt     int64         # server clock, unix millis
  updatedAt     int64         # server clock, unix millis
  deleted       bool          # tombstone
  conflict      bool          # set by server on conflicting write; cleared by client push
  formatVersion int           # plaintext schema version, = 1
  attachmentIds string[]      # plaintext by necessity (blob GC + quotas), ids+sizes only
  blob          base64url     # AEAD envelope (§2) over the plaintext document (§3)
}
```

Client caches store the same shape plus local dirty/queue state. Client-observed
times (e.g. "password last changed") live INSIDE the encrypted document; `createdAt`/
`updatedAt` are server bookkeeping and untrusted for security decisions.

## 2. AEAD envelope

Binary layout, transported as unpadded base64url:

```
offset 0    version   1 byte   = 0x01
offset 1    alg       1 byte   = 0x01  (XChaCha20-Poly1305-IETF)
offset 2    nonce     24 bytes (random per encryption, never reused with a key)
offset 26   ct        ciphertext || 16-byte Poly1305 tag
```

Parsers MUST reject unknown version/alg bytes and envelopes shorter than 42 bytes.

**Associated data** binds every ciphertext to its identity so the server cannot swap
blobs between items, vaults, or purposes (`|`-joined UTF-8, spec 00 conventions):

| Use | Key | AD |
|---|---|---|
| Item blob | VK(vaultId) | `andvari/v1|item|{vaultId}|{itemId}|{formatVersion}` |
| UVK wrap | wrapKey | `andvari/v1|uvk|{userId}` |
| Identity seed | UVK | `andvari/v1|idkey|{userId}` |
| Personal-vault VK wrap | UVK | `andvari/v1|vk|{vaultId}|{userId}` |
| Vault metadata (§4) | VK(vaultId) | `andvari/v1|vaultmeta|{vaultId}` |

`rev` is deliberately NOT in AD (the server assigns it after encryption). Sealed
boxes (escrow, shared-vault grants) have no AD; their payloads are self-describing
and receivers MUST validate the internal ids against the row they arrived on.

## 3. Item plaintext document (formatVersion 1)

JSON (not canonical — round-trips freely), `type` inside the ciphertext:

```jsonc
{
  "type": "login" | "note",
  "name": "GitHub",
  "notes": "free text",                  // optional, all types
  "favorite": false,                     // optional
  "login": {                             // when type=login
    "username": "jacob",
    "password": "…",
    "uris": ["https://github.com/login"],
    "totp": "otpauth://totp/…?secret=BASE32&…",   // optional, full otpauth URI
    "passwordHistory": [ { "password": "…", "retiredAt": 1751700000000 } ]  // client-maintained, capped 10
  },
  "attachments": [                       // mirrors attachmentIds; holds the SECRET half
    { "id": "uuid", "name": "scan.pdf", "size": 12345, "fileKey": "base64url(32B)" }
  ]
}
```

Unknown fields MUST be preserved on rewrite (forward compatibility within a
formatVersion). TOTP presentation: RFC 6238, SHA-1, 6 digits, 30 s step unless the
otpauth URI overrides.

## 4. Vaults

```
Vault { id uuid, type "personal"|"shared", rev, createdAt, metaBlob base64url }
```
`metaBlob` = envelope under VK with AD `andvari/v1|vaultmeta|{vaultId}`, plaintext
`{"name":"Family","icon":"…"}` — vault display names are ciphertext; the server
knows vaults only as ids. Grants (per member): `{ vaultId, userId, role
"owner"|"writer"|"reader", wrappedVk-or-sealedVk }` per spec 01 §6. Roles are
**server-enforced only** (crypto cannot stop a reader who has VK from encrypting; the
server rejects writes without writer role).

## 5. Server-visible plaintext — the zero-knowledge contract

The server stores/sees EXACTLY this and nothing more; the hardening gate audits
against this table. Anything not listed here appearing server-side in plaintext is a
spec violation.

| Surface | Fields |
|---|---|
| users | userId, email, displayName, kdfSalt, kdfParams, verifier(argon2id str), identityPub, isAdmin, status, createdAt |
| devices | deviceId, userId, platform, clientVersion, createdAt, lastSeenAt, revokedAt |
| sessions | hashed tokens, deviceId, expiry |
| vaults | vaultId, type, rev, createdAt (names/icons are ciphertext) |
| grants | vaultId, userId, role, wrapped/sealed VK ciphertext |
| items | the Item row of §1 — ids, rev, server timestamps, flags, formatVersion, attachmentIds, ciphertext blob, ciphertext byte size |
| item_versions | itemId, rev, blob (bounded history, §7) |
| attachments | attachmentId, itemId, vaultId, ciphertext size, sha256(ciphertext), header, createdAt (filenames + file keys are inside item ciphertext) |
| escrow | userId, sealed blob, recoveryKeyFingerprint, updatedAt |
| audit | event type, userId, deviceId, ip, timestamp, coarse metadata (never names, URIs, or any decrypted content) |
| policies | org policy JSON (min versions, KDF policy, lock timeouts…) |

Traffic analysis (who syncs when, item counts, sizes) is visible to the server by
nature and accepted (spec 05).

## 6. Attachments

- Per-file random 32-byte `fileKey` (lives inside item ciphertext, §3).
- Content encrypted with `crypto_secretstream_xchacha20poly1305`, plaintext chunked
  at **64 KiB** (last chunk 1..65536 bytes, tag FINAL; all others tag MESSAGE).
  Stored as `header (24B)` + ordered ciphertext chunks (each chunk + 17-byte ABYTES);
  the server persists header and chunks and never sees content or filename.
- Decrypters MUST fail hard on: any chunk MAC failure, FINAL before last chunk,
  missing FINAL at end (truncation), or extra data after FINAL.
- Upload: blob first (`POST /attachments`), then the item update referencing it;
  orphaned blobs are GC'd after 24 h. Server enforces per-item and per-user quota
  from policy (v1 defaults: 25 MiB/attachment, 100 MiB/item, 1 GiB/user).

## 7. Tombstones, versions, conflicts

- **Delete** = tombstone (`deleted=true`, blob dropped, attachments GC'd). Tombstones
  are GC'd after **90 days**; a client whose cursor predates the oldest retained
  change receives `410 Gone` on sync and MUST full-resync (prevents deletion
  resurrection by stale caches).
- **item_versions**: on every overwrite the server archives the previous `{rev,
  blob}` for the item, keeping the most recent **10** versions. AD stays valid
  (same itemId). This is the no-silent-loss backstop and powers client-side
  "password history repair" after conflicts.
- **Conflict flow** (authoritative rules in spec 03 §5): the server never merges and
  never re-encrypts; it applies the newest write, archives the loser, and sets
  `conflict=true`. The next syncing client that can decrypt materializes a visible
  "(conflict copy)" item — new itemId, fresh envelope — then clears the flag with a
  normal push.
