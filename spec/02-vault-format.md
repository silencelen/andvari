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
  formatVersion int           # plaintext schema version, = 1–2 (§3)
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
| Member-recovery UVK wrap (spec 04 §per-member) | recoveryWrapKey | `andvari/v1|recovery-uvk|{userId}` |
| Identity seed | UVK | `andvari/v1|idkey|{userId}` |
| Personal-vault VK wrap | UVK | `andvari/v1|vk|{vaultId}|{userId}` |
| Vault metadata (§4) | VK(vaultId) | `andvari/v1|vaultmeta|{vaultId}` |

`rev` is deliberately NOT in AD (the server assigns it after encryption). Sealed
boxes (escrow, shared-vault grants) have no AD; their payloads are self-describing
and receivers MUST validate the internal ids against the row they arrived on.

## 3. Item plaintext document (formatVersions 1–2)

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

**formatVersion 2 — cards (0.7.0).** fv2 adds `type` value `"card"` and one optional
top-level object `card`: `{ cardholderName?, number? (digits-only), expMonth?
("01".."12"), expYear? (4-digit), securityCode? (3–4 digits; storing it is a per-card
choice), brand? (derived from the IIN at save, display-only) }` — all strings, all
inside the ciphertext; the server row gains nothing (`formatVersion` is the existing
§1 plaintext integer, and `card` gets the same every-level unknown-field preservation
as `login`). Clients ≥ 0.7.0 MUST seal card-bearing docs (`card != null` OR
`type == "card"`) at formatVersion ≥ 2; logins/notes keep sealing at 1 (per-doc
floor), and an existing item re-seals at max(floor, the fv it was decrypted at). The
server enforces **per-item monotonic formatVersion** — a put/restore declaring a lower
fv than the stored row's is refused (`denied`, audited `fv_downgrade`) — which turns a
pre-fv2 client's card-stripping rewrite into a refused write instead of silent
ciphertext loss. Readers accept a `card` field at ANY fv they can open (e.g. an fv1
doc whose `card` rode the unknown-field overlay through a legacy backup restore): the
floor binds writers, not readers, and such an item re-floors to ≥ 2 on its next
0.7.0 edit. The top-level key space doubles as the doc-level extension registry —
`card` is CLAIMED (fv2); future top-level fields MUST pick unclaimed keys and stay
additive within fv2 unless they change the meaning of existing fields.

Unknown fields MUST be preserved on rewrite (forward compatibility within a
formatVersion), at every level of the document: the top-level object, `login`, each
`login.passwordHistory[]` entry, and each `attachments[]` entry. Preservation rules:

- **Typed fields win.** If a field is known to this client version, its typed value is
  authoritative on encode; a stale unknown-field copy of the same name MUST NOT shadow it.
- **Scoped within a formatVersion.** A client MUST fail closed on any `formatVersion`
  greater than it implements — treat the item as undecryptable (keep the envelope, retry
  after upgrade), never edit it, since a rewrite would silently downgrade the version.
- **Numbers.** JavaScript clients parse JSON numbers as IEEE-754 doubles, so unknown
  numeric values outside the exactly-representable range (|n| > 2^53) are NOT
  preservation-guaranteed. Writers of future fields MUST encode 64-bit integers as
  JSON strings.
- **Partial editors.** A client that exposes only the first `login.uris` entry MUST
  preserve the tail on edit; clearing the field removes only the first entry.

TOTP presentation: RFC 6238, SHA-1, 6 digits, 30 s step unless the
otpauth URI overrides.

### 3.1 login.uris — semantics & client match rules (autofill / browser fill)

`login.uris` entries are either web URIs (scheme optional, default `https`) or the
native-app convention **`androidapp://<packageName>`** (Bitwarden-compatible).

**Normalization** (both impls, identical): lowercase the host; strip one leading
`www.`; strip a trailing dot; **path, query, fragment, userinfo, and port are ignored
for matching** (Android's `ViewNode.getWebDomain()` exposes only the domain — two
services on one host are indistinguishable, so give services distinct hostnames).

**Match rules (normative; amended 2026-07-10 — one addition + two tightenings, design
`docs/design/2026-07-10-etld1-psl-matching.md`).** Hosts with an **empty label** after
normalization (`.example.com`, `a..example.com`) are unparseable and never match (the
trailing-dot strip still applies first). Clients resolve each side against the vendored
PSL snapshot (`spec/psl/`, explicit rules only — the PSL's implicit `*` fallback is NOT
applied) into one of REGISTRABLE(domain) / PUBLIC-SUFFIX / UNKNOWN, where PUBLIC-SUFFIX
covers exact, wildcard-derived, and exception-derived suffixes alike. A page host matches
a saved host iff, in order:
- **exact equality**, OR else
- **[tightening] never when either side is a bare PUBLIC-SUFFIX** — saved `github.io`
  fills no tenant under it; a page at `b.kawasaki.jp` gets no `kawasaki.jp` item;
- **[addition] both sides REGISTRABLE → registrable-domain equality** decides. Saved
  `login.example.co.uk` now matches `example.co.uk` and `accounts.example.co.uk`; saved
  `foo.github.io` never matches `bar.github.io`; **[tightening]** known-but-unequal
  registrables refuse even when the old suffix relation holds (saved
  `compute.amazonaws.com` no longer fills `ec2-x.us-east-1.compute.amazonaws.com`);
- **either side UNKNOWN → the pre-amendment rule, bit-for-bit:** the saved host has
  **≥ 2 labels** AND the page host ends with `"." + savedHost` (label-boundary subdomain
  suffix). Intranet hosts (`pihole.lan`, `nas.local`) keep today's behavior; a
  **single-label** saved host (`com`, `router`, `localhost`) stays **exact-only**.
- **IP-literal** hosts match exact-only. `androidapp://<pkg>` matches by exact package
  string. An unparseable / empty saved URI never matches. Staleness: a suffix the snapshot
  doesn't know **at TLD level** resolves UNKNOWN and degrades to the old rules
  (under-match). The one residual over-breadth is a multi-tenant hosting domain missing
  from the **private section** under a known TLD (`foo.newpaas.app` ↔ `bar.newpaas.app`
  both resolve REGISTRABLE `newpaas.app` and R-EQ matches them) — identical to
  Bitwarden/1Password base-domain behavior; bounded by the refresh posture in
  `spec/psl/README.md`, not eliminated by it.

> **Conformance note (2026-07-10).** eTLD+1 matching is **client-version-gated** — there
> is NO formatVersion change and no wire change. Carrying the amended rules: web (deploy
> 2026-07-10, reports 0.10.0) and extension ≥ 0.8.1. Pre-dating them (old rules, including
> the bare-suffix and known-unequal fills the amendment forbids): Android ≤ 0.9.0,
> desktop ≤ 0.9.0, and the 0.2.x MSI, until the next native cut — which ships as
> **≥ 0.10.0** (the in-tree versions were bumped with this amendment so no rebuild can
> ever field a second, behaviorally-different "0.9.0"; desktop is inside that gate — no
> deb rebuilds before the cut). Until then a phone may decline a match the PC fills (and
> vice-versa for bare-suffix junk); this note is the recorded exception.

**webDomain trust.** A fill request's web domain is honored ONLY when the requesting
package is an allowlisted trusted browser; otherwise clients match by package name
only (any app can populate its own structure with an attacker-chosen `webDomain`).
A structure carrying **more than one distinct web domain** (cross-origin iframes) is
treated per-field: a dataset is built only over fields whose own frame domain matches
the saved item, and a form mixing domains yields no fill rather than filling a
credential into a foreign-origin field. (Client-side only; the spec 02 §5 server
plaintext table is unchanged — matching reads the existing `login.uris` ciphertext.)

## 4. Vaults

```
Vault { id uuid, type "personal"|"shared", rev, createdAt, metaBlob base64url }
```
`metaBlob` = envelope under VK with AD `andvari/v1|vaultmeta|{vaultId}`, plaintext
`{"name":"Family","icon":"…","metaV":N}` — vault display names are ciphertext; the server
knows vaults only as ids. `metaBlob` is **owner-rewritable** (rename, spec 03 §11) under the
same VK/AD; its plaintext carries a monotonic `metaV` counter (clients warn-and-keep-newer
when a delivered metaBlob's counter regresses); the AD deliberately excludes `rev`. Grants
(per member): `{ vaultId, userId, role "owner"|"writer"|"reader", rev, revokedAt,
revokedReason, wrappedVk XOR sealedVk }` per spec 01 §6 — normally exactly one of
`wrappedVk` (owner/personal, under UVK) or `sealedVk` (member, `crypto_box_seal` to the
member identityPub) is set; the other is empty (a post-transfer owner grant MAY carry both).
`revokedReason ∈ member_remove|member_leave|vault_delete` (NULL, pre-v4, reads as
`member_remove`); vault RESTORE resurrects only `vault_delete` revocations made at the
matching `deletedAt`. Vault rows also carry lifecycle state:
`deletedAt/purgeAt/purgedAt/deletedBy/deleteId/deleteProof/restoreProof` (soft-delete +
grace + purge — vault rows are NEVER hard-deleted; `vaultId` is never recycled, normative)
and `transferSeq/pendingOwnerId/pendingOfferId/pendingOfferProof/pendingOfferExpiresAt/
pendingOfferSetAt/lastTransferOfferId/lastTransferAcceptProof`. Roles are
**server-enforced only** (crypto cannot stop a reader who has VK from encrypting; the
server rejects writes without writer role). Membership (which userId holds which role on
which vaultId) is server-visible via the grants row; membership-management audit events
record only ids and roles, never names or decrypted content.

## 5. Server-visible plaintext — the zero-knowledge contract

The server stores/sees EXACTLY this and nothing more; the hardening gate audits
against this table. Anything not listed here appearing server-side in plaintext is a
spec violation.

| Surface | Fields |
|---|---|
| users | userId, email, displayName, kdfSalt, kdfParams, verifier(argon2id str), **wrappedUvk** (UVK ciphertext under the master key — opaque to the server, stored so a fresh device can unlock), identityPub, **encryptedIdentitySeed** (identity-seed ciphertext under the UVK — same story), isAdmin, status, mustChangePassword, **recoveryConfirmed** (boolean flag, plaintext metadata — the durable, cross-device capture-confirmation signal, design §F.9; not a secret; 0 until the user confirms saving their recovery phrase), **escrowPolicy** ('required'\|'waived'\|NULL pre-v8 — the member's enforced recovery posture, persisted from the invite at register; plaintext metadata for admin reconciliation, design §F.4), createdAt, server-TOTP columns (totpSecret, totpPendingSecret, totpEnrolledAt, totpLastStep — a server-side authenticator secret by design, never vault data; spec 03 §2) |
| invites | tokenHash, **invitee email in plaintext** (a person who may not have an account yet — accepted: invites are short-lived and admin-created), isAdmin, createdAt, expiresAt, usedAt, **escrowPolicy** ('required'\|'waived' — the admin's per-invite recovery posture, plaintext metadata; read server-side at register, design §F.4) |
| devices | deviceId, userId, platform, **name (user-chosen device label, plaintext)**, clientVersion, createdAt, lastSeenAt, revokedAt |
| sessions | sessionId, userId, deviceId, hashed access+refresh tokens, access/refresh expiries, refreshConsumedAt, createdAt, revokedAt |
| vaults | vaultId, type, rev, createdAt (names/icons are ciphertext); **lifecycle** — deletedAt/purgeAt/purgedAt/deletedBy/deleteId, transferSeq, pendingOwnerId/pendingOfferId/pendingOfferExpiresAt/pendingOfferSetAt/lastTransferOfferId (ids + epoch times), and opaque VK-derived MACs deleteProof/restoreProof/pendingOfferProof/lastTransferAcceptProof (PRF outputs — reveal nothing about VK) |
| grants | vaultId, userId, role, addedAt (join time, epoch ms; NULL on pre-v3 rows, COALESCEd to 0 in summaries), wrapped/sealed VK ciphertext, rev, revokedAt, revokedReason (revoked rows are retained — the server sees WHEN and WHY a member lost access: remove / leave / vault-delete), and removeProof/removeNonce (opaque VK-derived MAC + nonce, stored on a removal for durable relay to the victim — reveal nothing about VK) |
| items | the Item row of §1 — ids, rev, server timestamps, flags, formatVersion, attachmentIds, ciphertext blob, ciphertext byte size |
| item_versions | itemId, rev, blob, formatVersion, archivedAt (bounded to the newest 10 per item, §7) |
| changes | rev, kind, entityId, vaultId, at — the global sync feed (pure metadata; reveals per-vault write timing/volume) |
| mutations | (deviceId, mutationId) → resultJson, createdAt — idempotency replay cache; resultJson holds per-mutation status/rev, no vault content |
| attachments | attachmentId, itemId, vaultId, ciphertext size, sha256(ciphertext), header, createdAt (filenames + file keys are inside item ciphertext) |
| escrow | userId, sealed blob, fingerprint (of the recovery key), updatedAt |
| member_recovery | userId, **recoveryWrappedUvk** (the UVK sealed under the member's recovery-secret-derived wrap key — ciphertext, opaque; AD `andvari/v1\|recovery-uvk\|{userId}`, §2), **recoveryVerifier** (one-way `crypto_pwhash_str(recoveryAuthKey)` — a DB leak is not a replayable recovery, exactly as the login verifier), **pieceId** (opaque random id of the current piece — rotation/confirm binding, spec 03 §12; not a secret), **setupDeviceId** (which device committed it — legacy-confirm scoping), updatedAt — the per-member self-service recovery row (spec 04 §per-member / design §F); ZK-clean, the symmetric counterpart to `escrow` |
| audit | event type, userId, deviceId, ip, timestamp, coarse metadata (never names, URIs, emails of existing users, or any decrypted content) |
| policies | org policy JSON (min versions, KDF policy, lock timeouts…) |
| hibp_cache | sha1-prefix → upstream HIBP range body + fetchedAt (public breach data, no user linkage stored) |
| meta | key/value operational markers (schemaVersion, lastPublicRequestAt…) |

Traffic analysis (who syncs when, item counts, sizes) is visible to the server by
nature and accepted (spec 05). This table describes **schema v8 exactly** — adding any
table or plaintext column requires updating it in the same change. (v6 = design 2026-07-12
§F: the `member_recovery` table + the `invites.escrowPolicy` column. v7 = design 2026-07-12
§F.9: the `users.recoveryConfirmed` capture-confirmation flag. v8 = design 2026-07-13:
`users.escrowPolicy` (admin posture reconciliation) + `member_recovery.pieceId`/`setupDeviceId`
(confirm piece-binding).)

## 6. Attachments

- Per-file random 32-byte `fileKey` (lives inside item ciphertext, §3).
- Content encrypted with `crypto_secretstream_xchacha20poly1305`, plaintext chunked
  at **64 KiB** (last chunk 1..65536 bytes, tag FINAL; all others tag MESSAGE).
  Stored as `header (24B)` + ordered ciphertext chunks (each chunk + 17-byte ABYTES);
  the server persists header and chunks and never sees content or filename.
- Decrypters MUST fail hard on: any chunk MAC failure, FINAL before last chunk,
  missing FINAL at end (truncation), or extra data after FINAL.
- Upload: blob first (`POST /attachments/{id}`), then the item update referencing it;
  orphaned blobs are GC'd after 24 h. Server enforces per-item and per-user quota
  from policy (v1 defaults: 25 MiB/attachment, 100 MiB/item, 1 GiB/user).

## 7. Tombstones, versions, conflicts

> **Status note (v5; caution satisfied 2026-07-10):** two kinds of pruning must not be
> confused. **item_versions IS capped live** — every overwrite keeps only the newest 10
> versions per item and hard-deletes the rest (`Repo.archiveVersion`), so an 11th-oldest
> version is already unrecoverable. The *tombstone/oldestRetainedRev* GC and its
> 410-resync trigger — dormant when this note was written — are **now ACTIVE** (n2
> residue hardening, design 2026-07-10 §5): item tombstones purge at 30 days and the
> daily janitor advances `oldestRetainedRev` behind a fence keyed to that same horizon.
> The shared-vault lifecycle design (docs/design/2026-07-07-shared-vault-lifecycle-skipti.md)
> recorded the (a)–(d) preconditions any activation had to satisfy; the activation
> record below states how each is met.

**Vault deletion (spec 03 §11):** a soft-delete with a 7-day grace
(`ANDVARI_VAULT_GRACE_DAYS`) — all rows stay intact and every grant is revoked
(`revokedReason='vault_delete'`); RESTORE within grace un-revokes exactly those grants and
re-opens the vault. After the grace the daily **janitor** purges (per-vault tx that
re-checks `deletedAt/purgeAt` inside every destructive statement): `item_versions` and
attachment rows/files are deleted, item rows are reduced to ciphertext-free
**skeletal tombstones** (`deleted=1, blob=NULL`, no rev bump, `updatedAt` restamped to the
purge instant — they keep the `vault_mismatch` teleport fence alive, 0.2.x MSI included,
for the full 30-day tombstone horizon from purge, then age out with the ordinary tombstone
GC below; the edit-over-tombstone fence is grant-gated and never reads them post-purge),
`metaBlob` is blanked, and **every** grant's key material is wiped
(`wrappedVk=''` — the `NOT NULL` sentinel — and `sealedVk=NULL`, active and
previously-revoked alike). Vault tombstone rows and all grant rows are retained
indefinitely and `vaultId` is never recycled — that pair is what keeps a push against the
purged vault itself denied forever. Skeletal item rows are **not** retained indefinitely:
by the time one ages out, every cursor is vault-absent by one of two legs — (1) a cursor
predating the DELETE has sat behind the `oldestRetainedRev` fence for at least the full
grace window (410 → full resync → vault absent); (2) a cursor minted DURING the grace
window was minted by a pull that already delivered the revoked grant (`removedGrantsInfo`,
the `g.rev > since` arm), so the vault is absent locally by delivery — such a cursor may
never 410 at all on an idle server (the MAX(rev) fence floor + strict `since < fence`).
Either way a post-horizon teleport re-push degrades into the accepted re-add class (a clean INSERT
of the pusher's own re-encrypted copy into their own vault; pinned in `JanitorTest`, same
class as the >180d mutation replay). The janitor's v1 scope was **vault purge
+ transfer-offer expiry ONLY** — the general retention machinery had to stay dormant until
it could satisfy the (a)–(d) invariants of that note plus a quiet-server integration test
(delete → idle past retention → full janitor cycle → all client generations converge
without 409/410 loops). **Activation record (2026-07-10, n2 residue hardening §5): that
caution is satisfied, not repealed.** The daily janitor now prunes `changes` and advances
`oldestRetainedRev` in the SAME transaction, with the fence **keyed to the 30-day
item-tombstone horizon** — one shared constant (`Janitor.ITEM_TOMBSTONE_RETENTION_MS`), so
any cursor old enough to have missed a purged tombstone 410s into a full resync (this
closes the 30–89-day deletion-resurrection window a longer fence would have left).
Invariant (a) is implemented as a **MAX(rev) floor**: the horizon rev is
`min(oldest rev inside the window, MAX(rev))`, so on an idle server every stale row below
the newest is pruned but the MAX(rev) row is always retained and `currentRev` never
regresses; (b) holds by the same-transaction fence advance; (c) the mutation-dedup journal
retains 180 days; and (d)'s quiet-server test exists —
`JanitorTest.quietServer_convergence_afterFullSweep` (delete → idle past the fence → full
sweep → up-to-date cursor no-ops, stale cursor 410s then converges via `since=0`,
`currentRev` never regresses).

- **Delete** = tombstone (`deleted=true`, blob dropped, attachments GC'd). Tombstones
  are GC'd after **30 days** — the same horizon the `oldestRetainedRev` fence is keyed
  to (above); a client whose cursor predates the oldest retained
  change receives `410 Gone` on sync and MUST full-resync (prevents deletion
  resurrection by stale caches).
- **item_versions**: on every overwrite (and before every delete) the server archives
  the previous `{rev, blob, formatVersion}` for the item, keeping the most recent **10**
  versions. AD stays valid (bound to itemId+formatVersion, **not** rev), so an old version
  decrypts under the item's current VK with no crypto change. This is the no-silent-loss
  backstop and powers client-side "password history repair" after conflicts. **Exposed
  (item history & restore feature):** `GET /items/{id}/versions` (spec 03) serves them
  grant-checked; the client decrypts each blob under the VK it holds and can restore one as
  an ordinary put. Two bounds the UI MUST state honestly: (1) at most the last **10**
  versions ("up to the last 10", never "nothing is ever lost"); (2) **history resets at VK
  rotation** — the archive is ciphertext under the *current* VK, so the queued lazy VK
  rotation (ROADMAP — "VK lazy rotation on member removal") either prunes
  item_versions for the rotated vault or re-seals it
  (design decision handed to the rotation work; see docs/design/2026-07-08-item-history-and-restore.md).
- **Conflict flow** (authoritative rules in spec 03 §5): the server never merges and
  never re-encrypts; it applies the newest write, archives the loser, and sets
  `conflict=true`. The next syncing client that can decrypt materializes a visible
  "(conflict copy)" item — new itemId, fresh envelope — then clears the flag with a
  normal push.

## 8. Client offline cache

Native clients (Android/desktop) MAY persist, per account, in a local SQLite DB
(`vault-<userId>.db`), so the working set + sync cursor + outbound queue survive
process death. The web client MAY persist the same set in IndexedDB — the deltas are
enumerated in §8.1 (2026-07-14 amendment; this section previously closed with "the
web client keeps no at-rest cache in v1"). **Every persisted field is a subset of
the §5 server-visible table — the client-at-rest surface is ⊆ the server-at-rest
surface by construction:**

- the sync cursor (a rev number);
- item rows exactly as received on the wire (ids, revs, timestamps, flags,
  formatVersion, attachmentIds, `blob` AEAD ciphertext);
- grant rows (vaultId, userId, role, `wrappedVk`/`sealedVk` ciphertext, rev);
- vault rows (vaultId, type, rev, `metaBlob` ciphertext, createdAt);
- the outbound mutation queue (mutationId, op, ids, baseItemRev, `ItemUpload`
  ciphertext);
- for offline unlock, a copy of the server's `accountKeys` payload (kdfSalt,
  kdfParams, wrappedUvk, encryptedIdentitySeed, identityPub, escrowFingerprint).

Clients MUST NOT persist: the master password, MK, authKey, UVK, VK, identity seed,
decrypted `ItemDoc`s, attachment plaintext, or fileKeys outside item ciphertext.
Decryption happens only in memory after the user supplies the master password; lock
and relaunch drop all key material.

- The DB file gets no extra encryption in v1 (envelopes are already AEAD). Note:
  quick unlock (spec 01 §8) wraps the **UVK**, not this DB — whole-file DB wrapping
  remains a possible future hardening, independent of quick unlock.
- Clients MUST honor `ClientPolicy.offlineCacheAllowed`: when false, no durable cache
  is created and any existing cache file for the account is deleted (re-evaluated on
  every successful policy fetch).
- The cache is deleted on **sign-out** and on any **definitive server rejection**
  (device revoked, or an invalid-session 401 that survives a refresh) — the latter
  also drops the cached `accountKeys`. It is **retained on lock** (spec 05 T3 already
  accepts ciphertext-at-rest on a stolen locked device).
- **Offline unlock** accepts the master password that was current at the last online
  contact; a remote revocation or password change only takes effect at next
  connectivity (spec 05 T3).
- Native cache files SHOULD be excluded from OS cloud backup (Android
  `dataExtractionRules`/`fullBackupContent`) so no cloud copy of the ciphertext DB or
  token store exists. (The web client cannot make this exclusion — §8.1.)

### 8.1 Web client (IndexedDB — 2026-07-14 amendment)

The web client MAY persist the SAME per-account set (the list above verbatim, plus
the `lastSyncAt` stamp, the spec 03 §4 lifecycle safety state — holding area,
consumed delete-ids, verified transfer floors — and the last-known policy bits) in a
per-account IndexedDB database (`andvari-vault-<userId>`); as built, the policy bits
live device-locally in localStorage (see the origin-gated bullet below) — the DB's
`kv:policy` slot is reserved, with no production writer yet. Design, schema, and
consistency rules: `docs/design/2026-07-13-web-offline-cache.md`. The MUST NOT
list, the `offlineCacheAllowed` rule, the sign-out/definitive-rejection wipe rule,
retained-on-lock, the no-extra-encryption-in-v1 posture, and the offline-unlock
freshness posture above apply to the web cache **verbatim**. Web-specific deltas:

- **accountKeys co-location.** The cached `accountKeys` live in the SAME DB as the
  envelopes (natives keep them beside, not inside, the vault DB) — one artifact, one
  wipe. Consequence: the 410-resync `clear()` is an ENUMERATED contract that resets
  the items/grants/vaults stores and the cursor ONLY, and MUST preserve
  accountKeys/queue/holding/floors (design §D.1) — a naive clear would break offline
  unlock after any resync-then-lock.
- **Eviction + durable writes.** IndexedDB is best-effort storage the browser may
  evict. The client requests `navigator.storage.persist()` once at first enable, and
  the offline-WRITE queued-success path is offered ONLY while
  `navigator.storage.persisted()` is true (refuse-not-degrade: an evicted queue is
  unrecoverable user data; server-derived rows are refetchable, so their eviction is
  availability loss only).
- **No OS-backup exclusion.** The browser profile cannot be excluded from OS backup
  (no web analog of `dataExtractionRules`); OS backups may then hold the ciphertext
  DB — ⊆ the spec 05 T7 backup-theft surface, accepted.
- **Origin-gated default + per-device controls.** The cache defaults ON on private
  origins (tailnet/LAN/localhost), OFF on the public break-glass origin (explicit
  per-device opt-in only). A per-device settings toggle ("Keep an offline copy on
  this device") opts out — turning it off wipes immediately; the Unlock screen shows
  a transparency line whenever a durable copy exists on the device. The last-known
  `offlineCacheAllowed` policy bit is persisted device-locally and honored on
  OFFLINE boot (native persisted-policy parity), so a device that last saw `false`
  refuses to re-create a cache until a later successful fetch says otherwise.
- **No quick unlock** (spec 01 §8.3 unchanged): the cache stores ciphertext + wire
  metadata only and never changes what a reload demands — the full master password.
