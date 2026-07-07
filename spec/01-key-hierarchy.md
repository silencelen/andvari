# andvari spec 01 — key hierarchy

All primitives are libsodium constructions except HKDF-SHA-256, HMAC-SHA-1/SHA-256,
and SHA-1/SHA-256, which use platform crypto (javax.crypto on JVM/Android, WebCrypto
on web). No hand-rolled primitives anywhere.

## 1. Master key derivation

```
MK = Argon2id_v1.3(password = UTF-8(master password, as typed — no normalization v1),
                   salt     = kdfSalt (16 bytes, random per user, server-stored),
                   outLen   = 32,
                   opsLimit = kdfParams.ops,
                   memLimit = kdfParams.memBytes)
```

- libsodium `crypto_pwhash` with `crypto_pwhash_ALG_ARGON2ID13`. libsodium fixes
  Argon2 parallelism at **p = 1**; this is deliberate (browser WASM is
  single-threaded — native and web cost the same).
- **kdfParams v1 default: `{ "v": 1, "alg": "argon2id13", "ops": 3, "memBytes": 67108864 }`**
  (t=3, m=64 MiB). Params are per-user, stored server-side and returned by prelogin;
  they also ride inside `wrappedUvk` (§4) so an offline cache can unlock without the
  server. P0 benchmarks may revise the default **before first real account**; after
  that, changes go through the KDF-upgrade flow (§7). ~1 s on the slowest supported
  platform is the target.
- Unicode normalization is deliberately NOT applied in v1 (libsodium/Bitwarden
  behavior). Clients SHOULD warn when a master password contains non-ASCII.

## 2. Purpose split (HKDF)

```
authKey = HKDF-SHA-256(ikm = MK, salt = empty, info = "andvari/v1/auth", L = 32)
wrapKey = HKDF-SHA-256(ikm = MK, salt = empty, info = "andvari/v1/wrap", L = 32)   # the KEK
```

RFC 5869, full extract-then-expand. `salt = empty` means the RFC's default
(HashLen zero bytes). Info strings are the literal ASCII bytes shown. MK never leaves
the KDF step; authKey and wrapKey MUST NOT be persisted (only re-derived), except as
covered by quick-unlock (§8).

## 3. Login verifier

- Client → server at login: `authKey` (base64url) over TLS. The server never sees the
  master password or wrapKey; authKey cannot decrypt anything.
- Server stores `verifier = crypto_pwhash_str(authKey, ops = 2, memBytes = 16777216)`
  (libsodium's argon2id string format) and verifies with
  `crypto_pwhash_str_verify`. A leaked server DB therefore does not allow login
  replay. Server-side only — not vector-pinned across implementations.
- `POST /auth/prelogin { email }` returns `{ kdfSalt, kdfParams }`. For unknown
  emails it MUST return a deterministic fake salt
  `HMAC-SHA-256(serverEnumSecret, lowercase(email))[0..15]` with current default
  params (anti-enumeration), and the endpoint is rate-limited.

## 4. User Vault Key (UVK)

- `UVK` = 32 random bytes, generated at enrollment, **never rotated by password
  change** (invariant: escrow blobs and vault-key wraps stay valid for the account's
  lifetime; rotation of UVK is a full-account re-key, out of scope v1).
- Stored server-side as `wrappedUvk = Envelope(key = wrapKey, plaintext = UVK,
  ad = "andvari/v1|uvk|{userId}")` (envelope format: spec 02 §2), alongside a copy of
  the kdfParams used, so `{kdfSalt, kdfParams, wrappedUvk}` is sufficient to unlock
  offline from a client cache.

## 5. Identity keypair (X25519)

- `identitySeed` = 32 random bytes at enrollment;
  `(identityPub, identityPriv) = crypto_box_seed_keypair(identitySeed)`.
- Server stores `identityPub` in plaintext (it is public) and
  `encryptedIdentitySeed = Envelope(key = UVK, plaintext = identitySeed,
  ad = "andvari/v1|idkey|{userId}")`.
- Used to receive shared-vault key grants (§6) and nothing else in v1.
- **Identity fingerprint** = lowercase-hex `SHA-256(identityPub)` (same construction as
  the recovery fingerprint, spec 04 §1); short form = first 16 hex chars, displayed
  grouped `xxxx xxxx xxxx xxxx`. It MUST be computed over the **seed-derived** public key
  (`boxKeypairFromSeed(identitySeed).publicKey`), NEVER over the `identityPub` the server
  returns in account keys. The server cannot forge `identitySeed` (it is UVK-sealed), so a
  client unlocking MUST derive the pubkey from the decrypted seed and treat a mismatch
  against the server-sent `identityPub` as a security fault. Displaying a hash of the
  server-supplied value would let a malicious server pass an out-of-band check while
  substituting a key it controls.
- **Out-of-band verification (sharing, P5):** before an owner seals a shared VK to a
  member, the member reads their short fingerprint from their own client and the owner
  confirms it over an out-of-band channel (in person / phone). This closes the
  pubkey-substitution attack; it is only sound because the fingerprint is seed-derived.

## 6. Vault keys — everything is a vault

- Every item lives in exactly one vault; every vault `vaultId` has a random 32-byte
  Vault Key `VK`. Items encrypt under VK (spec 02), never directly under UVK.
- **Personal vault** (`type=personal`, one per user, created at enrollment):
  `wrappedVk = Envelope(key = UVK, plaintext = VK, ad = "andvari/v1|vk|{vaultId}|{userId}")`.
- **Shared vault** (`type=shared`): the creator generates `vaultId`, `VK`, `metaBlob`.
  - The **creator's own grant** uses `wrappedVk = Envelope(key = UVK, plaintext = VK,
    ad = "andvari/v1|vk|{vaultId}|{userId}")` — identical to the personal-vault wrap. The
    creator already holds their UVK, so there is no reason to seal to self, and it keeps
    already-deployed clients able to open vaults they create.
  - **Member grants** use `sealedVk = crypto_box_seal(recipient = member identityPub,
    plaintext = canonical-JSON {"v":1,"vaultId":"{vaultId}","vk":"{base64url(VK)}"})`.
    Sealed boxes carry no AD; context lives inside the payload, and the recipient MUST
    verify the payload's `vaultId` matches the grant row it arrived on.
  - A grant carries **exactly one** of `wrappedVk` / `sealedVk`.
  - Roles: `owner` (creator, immutable, exactly one per vault in v1), `writer`, `reader`;
    only the owner manages membership. Roles are server-enforced (spec 02 §4).
- **Member removal (v1)** is server-side revocation only — the server stops serving the
  vault and its items to the removed user. **Accepted risk (spec 05 R7):** a removed
  member who copied the VK or ciphertext while granted can still decrypt ciphertext they
  already hold (and any future leak of *unchanged* items). VK rotation + lazy
  re-encryption by the next online writer is the forward path, deferred to **P6**.

## 7. Password change and KDF upgrade

- **Password change** (client, atomic server call `PUT /account/password`):
  derive MK′/authKey′/wrapKey′ from the new password (fresh 16-byte salt), re-wrap
  UVK → wrappedUvk′, send `{newSalt, newKdfParams, newAuthKey, newWrappedUvk}` with
  the CURRENT authKey as proof. UVK, identity keys, vault keys, items: unchanged.
  Server revokes all other sessions on success.
- **KDF upgrade**: if prelogin's kdfParams are weaker than current policy, the client
  (after a successful unlock) re-derives with policy params and performs the same
  atomic update with the password unchanged. `kdfParams.v` gates format changes.

## 8. Quick unlock (platform-local, never server-visible)

Quick unlock wraps the **UVK** (not the password, not MK) in platform hardware:
- **Android:** UVK encrypted by an AES-GCM key in Android Keystore with
  `setUserAuthenticationRequired(true)` (biometric/credential-gated), stored in app
  storage. Invalidate on biometric enrollment change.
- **Windows:** UVK wrapped by DPAPI (user scope) XOR-combined with a key derived from
  a short app PIN — Argon2id(PIN, deviceSalt, ops=3, mem=64 MiB) — so neither DPAPI
  alone nor the PIN alone suffices. Windows Hello proper is P5.
- **Web:** none in v1. Session-memory only; a reload re-prompts for the master
  password.
Quick unlock never weakens the server story: the server still only ever sees authKey.

## 9. Benchmarks (P0 gate)

Measured 2026-07-05 on huginn (LXC 117 on E5-2640v4 @ 2.4 GHz — deliberately
slow-core hardware; treat as the floor). Median of 5 after warm-up, `--bench` mode
of tools/vector-gen (JVM) and node/V8 (WASM, Chrome-class engine):

| Platform | ops=3 m=64MiB | ops=2 m=64MiB | Notes |
|---|---|---|---|
| JVM native lazysodium (huginn) | **130 ms** | 101 ms | Android/desktop/server class |
| V8 WASM sumo (huginn, node 22) | **~380–500 ms** | ~195 ms | browser class; modern phones/desktops ≥2× faster |
| Android Chrome (phone, WASM) | pending | — | measure at P2 rollout; expected < huginn WASM |
| Android app (native lazysodium) | pending | — | measure at P2; expected ≈ JVM row |

**Decision (P0): keep the default `{ops:3, memBytes:64 MiB}`** — worst measured
platform (huginn-class WASM) sits at ~0.5 s, well under the ~1.5 s ceiling; phone
rows get confirmed at P2 before family rollout. Never go below 64 MiB memory.
