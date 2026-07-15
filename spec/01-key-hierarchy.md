# andvari spec 01 — key hierarchy

All primitives are libsodium constructions except HKDF-SHA-256, HMAC-SHA-1/SHA-256,
and SHA-1/SHA-256, which use platform crypto (javax.crypto on JVM/Android, WebCrypto
on web). The one whole-stack exception is the MV3 extension: its service-worker CSP
rules out WASM, so it implements the entire hierarchy (Argon2id, HKDF,
XChaCha20-Poly1305, X25519 sealed boxes, BLAKE2b) in pure-JS @noble + tweetnacl —
byte-parity with libsodium proven against the shared test vectors
(web/src/crypto/noble-extension-poc.test.ts). No hand-rolled primitives anywhere.

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
the KDF step; authKey and wrapKey MUST NOT be persisted (only re-derived) — with no
exception: quick-unlock (§8) persists a hardware-wrapped UVK, never these.

### 2.1 Per-member recovery secret split (spec 04 §6)

Per-member self-service recovery (full flow + trust model: spec 04 §6; endpoints: spec
03 §12) is backed by a **second, independent** purpose split whose IKM is **not** the
MK — it is a freshly generated high-entropy secret, never derived from the master
password and never typed:

```
recoverySecret  = randomBytes(32)                                                       # 256-bit CSPRNG (≥128 required, 256 recommended)
recoveryWrapKey = HKDF-SHA-256(ikm = recoverySecret, salt = empty, info = "andvari/v1/recovery-wrap", L = 32)   # the KEK
recoveryAuthKey = HKDF-SHA-256(ikm = recoverySecret, salt = empty, info = "andvari/v1/recovery-auth", L = 32)   # login-proof analogue
```

- `recoverySecret` = `CryptoProvider.randomBytes(32)` (libsodium `randombytes_buf`) —
  **NEVER `Math.random`, never user-influenced or typed.** base64url of the raw 32
  CSPRNG bytes is unbiased, so no rejection sampling is needed (only a
  restricted-alphabet / BIP39 encoding — deferred — would require it).
- Same empty-salt extract-then-expand as §2. The two infos `andvari/v1/recovery-wrap`
  and `andvari/v1/recovery-auth` are literal ASCII and **distinct** from
  `andvari/v1/auth` / `andvari/v1/wrap`, so the two hierarchies never collide.
- **No Argon2id on this path.** ≥128 generated bits are computationally unreachable, so
  HKDF alone suffices — unlike the human-chosen master password (§1), which must be
  Argon2id-stretched. This makes the recovery piece **stronger** than the master
  password and improves the weakest-link posture — **but only while the "generated,
  never typed" invariant holds.** A user-influenced/typed recovery secret would remove
  the entropy floor and (with no Argon2id) become the weakest link, offline-crackable
  from a leaked `recoveryVerifier` (spec 05 T8). The invariant is load-bearing.
- **UVK wrap:** `recoveryWrappedUvk = Envelope(key = recoveryWrapKey, plaintext = UVK,
  ad = "andvari/v1|recovery-uvk|{userId}")` (envelope format: spec 02 §2). This AD is a
  new domain string, **distinct** from the `andvari/v1|uvk|{userId}` MK-wrap AD (§4), so
  a recovery blob and a UVK-wrap blob can never be cross-substituted between slots.
- `recoveryAuthKey` is the login-verifier analogue: the server stores only
  `recoveryVerifier = crypto_pwhash_str(recoveryAuthKey)` (one-way, exactly like the §3
  login verifier), never the raw key — so the `member_recovery` row is zero-knowledge
  (ciphertext + a one-way hash; spec 02 §5).

## 3. Login verifier

- Client → server at login: `authKey` (base64url) over TLS. The server never sees the
  master password or wrapKey; authKey cannot decrypt anything.
- Server stores `verifier = crypto_pwhash_str(authKey, ops = 2, memBytes = 67108864)`
  (libsodium `OPSLIMIT_INTERACTIVE`/`MEMLIMIT_INTERACTIVE` = 2 ops / 64 MiB)
  (libsodium's argon2id string format) and verifies with
  `crypto_pwhash_str_verify`. A leaked server DB therefore does not allow login
  replay. Server-side only — not vector-pinned across implementations.
- `POST /auth/prelogin { email }` returns `{ kdfSalt, kdfParams }`. For unknown
  emails it MUST return a deterministic fake salt
  `HMAC-SHA-256(serverEnumSecret, lowercase(email))[0..15]` with current default
  params (anti-enumeration), and the endpoint is rate-limited.

## 4. User Vault Key (UVK)

- `UVK` = 32 random bytes, generated at enrollment, **never rotated by password
  change** (invariant: escrow blobs, per-member recovery blobs (§2.1, spec 04 §6), and
  vault-key wraps stay valid for the account's lifetime; rotation of UVK is a
  full-account re-key, out of scope v1).
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
  - A grant normally carries **exactly one** of `wrappedVk` / `sealedVk`; after an
    ownership transfer (spec 03 §11) the new owner's grant MAY carry both (`wrappedVk`
    current, `sealedVk` retained as fallback key material until vault purge).
  - Roles: `owner` (exactly one per vault at every instant; reassignable ONLY via the
    two-phase offer/accept transfer of spec 03 §11, in which the new owner's client
    re-wraps VK under its own UVK and the old owner demotes to `writer`, retaining VK —
    R7 applies), `writer`, `reader`; only the owner manages membership. Roles are
    server-enforced (spec 02 §4). Non-owner members may self-revoke (**leave**, spec 03
    §11); the owner may NOT leave — only transfer or delete.
- **Member removal (v1)** is server-side revocation only — the server stops serving the
  vault and its items to the removed user. **Accepted risk (spec 05 R7):** a removed
  member who copied the VK or ciphertext while granted can still decrypt ciphertext they
  already hold (and any future leak of *unchanged* items). VK rotation + lazy
  re-encryption by the next online writer is the forward path, deferred to **P6**.
- **Vault deletion** (spec 03 §11) is revocation of every grant plus server-side
  destruction of the vault's ciphertext after a grace window (spec 02 §7); it is NOT
  cryptographic erasure toward anyone who held VK (R7).
- **Lifecycle proofs** (spec 03 §11): destructive shared-vault ops carry an
  `HMAC-SHA-256` under `lifecycleKey = HKDF-SHA-256(ikm = VK, info = "andvari/v1|lifecycle",
  32)` — domain-separated from the AEAD key, and material the server never holds. A member's
  0.5.0 client verifies the proof under its held VK before treating a delete/transfer/remove
  as a genuine owner action. Proofs are MACs, not signatures — any current VK holder can
  mint one, so they remove only the *server* from the forgery set (server-side owner authz
  stays the real gate). Vectors: `spec/test-vectors/lifecycleproof.json`.

## 7. Password change and KDF upgrade

- **Password change** (client, atomic server call `PUT /account/password`):
  derive MK′/authKey′/wrapKey′ from the new password (fresh 16-byte salt), re-wrap
  UVK → wrappedUvk′, send `{newSalt, newKdfParams, newAuthKey, newWrappedUvk}` with
  the CURRENT authKey as proof. UVK, identity keys, vault keys, items: unchanged.
  Server revokes all other sessions on success.
- **KDF upgrade (F61, normative)**: after every successful **full-master-password**
  unlock with server connectivity, the client compares the account's stored
  `kdfParams` against the current org policy's `kdfParams`
  (`GET /client-policy`) and, when an upgrade is due, **silently re-keys with the
  password it just verified**: re-derive MK′/authKey′/wrapKey′ under the policy
  params (fresh 16-byte salt), re-wrap UVK, and perform the same atomic
  `PUT /account/password` — the password itself is unchanged and the user is not
  prompted. Rules:
  - **Upgrade-only, never sideways or down.** An upgrade is due iff policy params
    are ≥ the account's on **both** cost axes (`ops`, `memBytes`) and > on at least
    one, with `policy.v ≥ account.v`. Policy params that are lower or mixed
    (one axis up, one down) MUST NOT trigger a re-key — the policy JSON comes from
    the server, and a compromised server must not be able to talk a client into
    weakening its own KDF (spec 05 T1).
  - **Client-side sanity bounds.** Regardless of policy, a client MUST refuse to
    re-key to `memBytes < 67108864` (64 MiB — the §9 floor) or `ops < 3`, and
    SHOULD refuse absurd cost inflation (`ops > 10` or `memBytes > 1 GiB`) — a
    hostile policy must be able to neither weaken the KDF nor turn every unlock
    into a memory-exhaustion DoS.
  - **Full-password unlocks only.** A quick-unlock (§8) unlock CANNOT upgrade —
    the client never has the password in hand — and MUST NOT count as a
    full-password unlock for any §7/§8 purpose. The §8 periodic-full-password rule
    is what guarantees a biometric-happy user still types the master password at
    least every 30 days, which bounds fleet KDF-upgrade latency after a policy
    bump to ~one period.
  - **Offline full unlocks skip silently** (the PUT needs the server) and the
    check simply re-runs at the next online full-password unlock. Latency-critical
    unlock paths (the Android autofill unlock overlay) MAY defer the re-key to the
    next main-app unlock; interactive app unlocks SHOULD perform it inline.
  - **Known costs (accepted):** the atomic update revokes all *other* sessions
    (§3 wire semantics — no wire change for F61), so a policy bump signs the
    user's other devices out once as each device re-keys first; re-keying costs
    two extra Argon2id derivations at unlock. A failed re-key (race with another
    device, network drop) is non-fatal: the unlock already succeeded, and the
    upgrade retries next time.
  - The quick-unlock wrapped UVK (§8) survives a KDF upgrade untouched — the UVK
    itself never changes (§4).
  - Side effect: converging on policy params also heals that account's
    prelogin-divergence oracle (spec 05 R4).

## 8. Quick unlock (platform-local, never server-visible)

Quick unlock wraps the **UVK** — never the master password, MK, or a derived
authKey/wrapKey — in platform hardware. It is strictly device-local: the server is
never told quick-unlock exists, never sees the wrapped blob, and the wire protocol
is unchanged. Quick unlock never weakens the server story: the server still only
ever sees authKey. A quick unlock yields exactly the capability a full-password
unlock yields **except** knowledge of the password itself — so it can never perform
the §7 password change / KDF upgrade, and it MUST NOT count as a full-password
unlock anywhere the spec distinguishes the two.

### 8.1 Android (NORMATIVE, v1)

**Eligibility & enrollment.** Quick unlock is per-device, per-account **opt-in**,
offered only while the vault is unlocked (the UVK is in memory). It REQUIRES:

- org policy `offlineCacheAllowed == true` (spec 03 §7). The wrapped UVK is durable
  vault-opening secret material at rest; an org that forbids the (ciphertext-only!)
  offline cache has asked for *nothing durable on the device that helps open the
  vault*, and the honest reading gates the strictly-more-sensitive quick-unlock
  secret under the same bit. When a policy fetch shows `offlineCacheAllowed=false`,
  the client MUST delete the wrapped blob and its Keystore key (same re-evaluation
  points as the cache purge, spec 02 §8).
- `BiometricManager.canAuthenticate(BIOMETRIC_STRONG) == BIOMETRIC_SUCCESS`.
  Class-3 (strong) biometrics ONLY; `DEVICE_CREDENTIAL` MUST NOT be an accepted
  authenticator — a 4-digit screen PIN is routinely weaker than the master password
  and shoulder-surfed far more often.

**Construction.** A dedicated AES-256-GCM key is generated inside Android Keystore
(alias `andvari-qu-<userId>`) with:

- purposes ENCRYPT|DECRYPT, GCM, no padding, 256-bit;
- `setUserAuthenticationRequired(true)` with **auth-per-use** binding
  (API 30+: `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`;
  API 29: `setUserAuthenticationValidityDurationSeconds(-1)`, which is
  biometric-only auth-per-use) — every decrypt (and the enrollment encrypt)
  requires a fresh `BiometricPrompt` with the cipher as its `CryptoObject`;
- `setInvalidatedByBiometricEnrollment(true)` (explicit, though it is the default
  for auth-per-use keys): adding a new fingerprint/face permanently invalidates
  the key;
- `setUnlockedDeviceRequired(true)`: the key is unusable while the device is
  locked or before first unlock after boot;
- StrongBox attempted (`setIsStrongBoxBacked(true)`), falling back to the TEE on
  `StrongBoxUnavailableException` — TEE-backed is acceptable; software-only
  Keystore is not a supported target (minSdk 29 devices ship a TEE).

The UVK is sealed as `ct = AES-GCM(key, iv = Keystore-generated, aad =
UTF-8("andvari/v1|quick-unlock|{userId}"), plaintext = UVK)`. The AAD binds the
blob to the account so a blob copied between profiles/users cannot open (and a
tampered file fails the tag). The blob lives in a versioned JSON file
`quick-unlock-<userId>.json` under **`noBackupFilesDir`** (same posture as the
offline cache DB): `{ "v": 1, "alias", "iv", "ct", "createdAt" }` — all base64url
where binary. The `lastFullPasswordUnlockAt` stamp (plus its monotonic
elapsed/boot-ref companions) lives OUTSIDE the blob, in app SharedPreferences
(`qu_stampWall_<userId>` etc.), so it survives blob wipes and cannot be edited via
the blob; it is cleared on sign-out/revocation. The app already sets
`android:allowBackup="false"`; `noBackupFilesDir` is belt-and-suspenders so no
future backup-config change can exfiltrate the blob via `adb backup`/cloud backup.

**Use.** Unlock screens (main app + the autofill unlock overlay) that find an
eligible, fresh (see the periodic rule) blob MAY offer/auto-show a
`BiometricPrompt` (negative button = "Use master password"). On success the client
decrypts the UVK and unlocks via the UVK path (core `Account.unlockWithUvk`),
which MUST perform the same seed-derived `identityPub` verification as the
password path (§5) — a mismatch is a security fault and hard-fails, never falls
back silently. Vault keys are then obtained exactly as after a password unlock
(grants opened under UVK / identity key, from cache or sync).

**Failed / invalidated key — fail to the password, never weaken.** Any of the
following MUST fall back to the full master-password prompt, and where marked
*wipe* MUST first delete both the blob file and the Keystore key:

| Event | Action |
|---|---|
| `KeyPermanentlyInvalidatedException` (biometric enrollment changed) | *wipe*; notify "biometrics changed"; re-enroll only after a successful full-password unlock |
| Keystore key missing / unrecoverable, blob file missing/corrupt/unknown `v` | *wipe* remnants; password prompt |
| AES-GCM open fails (tag/AAD mismatch) | *wipe*; password prompt |
| `encryptedIdentitySeed` fails to open under the recovered UVK | *wipe* (stale/foreign UVK); password prompt |
| Seed-derived identityPub ≠ server identityPub | HARD FAIL (§5 security fault — same as the password path; do NOT retry, do NOT wipe evidence) |
| `BiometricPrompt` temporary lockout (`ERROR_LOCKOUT`) | password prompt this time; blob retained |
| `BiometricPrompt` lockout, temporary or permanent (`ERROR_LOCKOUT[_PERMANENT]`) | password prompt; **blob KEPT** (a lockout is attacker-/child-triggerable and the key is already auth-gated — destroying enrollment buys nothing) |
| User cancels the prompt | password prompt; blob retained |

There is deliberately **no app-level failed-attempt counter**: `BiometricPrompt` +
Keystore already rate-limit and lock out biometric attempts system-wide, and an
app-side counter stored next to the blob would be trivially resettable by exactly
the attacker it pretends to stop.

**Periodic full-password rule (normative).** Quick unlock MAY serve unlocks for at
most **30 days** since the last successful full-master-password unlock on that
device (`lastFullPasswordUnlockAt`, stamped by every full-password unlock,
including offline ones and the autofill overlay's). Past the window the client
MUST require the master password (the blob is retained; a successful full unlock
re-stamps the window).

**Clock-tamper safety (normative).** The window MUST NOT be evaluated on a clock the
device holder can set. A stamp in the future fails closed (stale). Within one boot the
monotonic clock (`elapsedRealtime`) is authoritative and its delta MUST also be under the
window. **Across a reboot** the client MUST evaluate the window against a *server-attested*
time anchor recorded after the stamp (`ClientPolicy.serverTime`, persisted monotonically);
with no such anchor the elapsed duration is unknowable and the client MUST fail closed and
require the master password. A device-clock high-water mark MAY be kept as an additional
one-way ratchet, but MUST NOT be the sole guard: it only advances while the app observes
it, so a dormant device freezes it. Why 30 and why time- rather than use-based: the rule exists
(a) so users do not lose master-password muscle memory — the classic quick-unlock
failure mode is "enabled biometrics in March, forgot the password by June", which
for a ZK design with only org-escrow recovery is an availability incident (A5);
and (b) to bound §7 KDF-upgrade latency for biometric-only users. Both pressures
are calendar-shaped, not count-shaped — a use-count cap (M unlocks) punishes
heavy autofill users hundreds of times faster than light users for zero
threat-model gain (the at-rest exposure window is temporal), so M is deliberately
unbounded. 30 days is long enough to be unobtrusive (~12 password entries/year)
and short enough that a forgotten password is caught while escrow recovery and the
user's own memory are still warm. The timestamp is advisory plaintext (not
integrity-bound): an attacker who can rewrite app-private files to stretch the
window is already past the app sandbox (spec 05 T5, out of scope) and still
cannot use the Keystore key without the biometric.

**What clears the quick-unlock secret** (blob + Keystore key), beyond the failure
table above:

- **Sign-out** — always, alongside the cache purge (spec 02 §8).
- **Definitive server rejection** (device revoked; invalid-session 401 that
  survives refresh) — same purge path as the cached `accountKeys`.
- **Policy flip** `offlineCacheAllowed → false` — on the next policy fetch.
- **User disable** in Settings (no password required to *disable* — reducing
  standing secret material must never be gated).
- **Password change: does NOT clear it.** The UVK survives a password change by
  §7/§4 invariant, so the wrapped blob stays **cryptographically valid** — this is
  explicit and intended (changing the password on the web does not silently break
  the phone's biometric unlock). Device-side hygiene still applies: a password
  change made *elsewhere* revokes this device's session (§7), and the resulting
  definitive 401 purges the blob with the rest of the offline material until the
  next sign-in + re-enroll. A KDF upgrade (§7) likewise leaves the blob valid.
- **UVK-invalidating events** are covered by the failure table (the seed no longer
  opens → wipe): none exist in v1 (UVK never rotates), so this is future-proofing,
  not a live path.

### 8.2 Windows (design sketch — DEFERRED, not normative)

Deferred past the 0.7.0 MSI refresh (backlog). The standing sketch — UVK wrapped
by DPAPI (user scope) XOR-combined with a key derived from a short app PIN,
Argon2id(PIN, deviceSalt, ops=3, mem=64 MiB), so neither DPAPI alone nor the PIN
alone suffices; Windows Hello proper later — is a starting point only and gets its
own design + breaker pass when scheduled. Until then the desktop client has no
quick unlock: master password only. The §8.1 policy gating
(`offlineCacheAllowed`), periodic full-password rule, and clearing events apply to
ANY future platform quick-unlock as written.

### 8.3 Web

None in v1 (unchanged): keys are session-memory only, and a reload always
re-prompts for the full master password. (The durable web offline cache — spec 02
§8.1, 2026-07-14 — persists ciphertext + wire metadata only; it stores nothing that
opens the vault without the master password and is NOT a quick unlock.)

### Auto-lock (policy `autoLockSeconds`)

All three clients enforce an **inactivity auto-lock** driven by the org policy's
`autoLockSeconds` (spec 03 §7; `0` or absent = disabled). Clients use the most
recently fetched policy — refreshed at start, at unlock (web), and on the spec 03 §6
sync cadence (natives) — and the natives persist the last-known value so an offline
cold start still enforces it.

- **Activity** = direct user interaction with the client (pointer, key, or touch),
  coarsened to ≥1 s granularity. Background syncs, WS bell frames, and Android
  autofill fills do **not** extend the window — a device left untouched locks even
  while the app keeps syncing or filling.
- **Expiry** drops the in-memory keys via exactly the manual lock path of that
  platform (web `onLock`/session clear, Android `VaultSession.lock()`, desktop
  `DesktopState.lock()`) and shows the normal unlock screen. The native durable
  offline queue (spec 02 §8) survives a lock that lands mid-push; the mutation
  replays after the next unlock. Clients may **defer** (never skip) the lock while a
  user-initiated operation is in flight rather than yank the engine mid-write — the
  1 s check re-fires.
- The window is **wall-clock**: time suspended/backgrounded counts, so a client
  returning from sleep or background past the window locks on return, before content
  is readable. Android additionally gates the autofill entry points on the same
  expiry check (an idle-expired vault re-prompts for the master password before any
  fill).
- The timer **resets on unlock**.
- Clipboard: vault-secret copies auto-clear after `clipboardClearSeconds`, clamped
  to a minimum of 1 s on every client (a policy of 0 still clears — never "keep
  forever" for secrets; non-secret setup material is exempt).

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
