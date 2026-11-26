# andvari spec 01 — key hierarchy

All primitives are libsodium constructions except HKDF-SHA-256, HMAC-SHA-1/SHA-256,
and SHA-1/SHA-256, which use platform crypto (javax.crypto on JVM/Android, WebCrypto
on web). The one whole-stack exception is the MV3 extension: its service-worker CSP
rules out WASM, so it implements the entire hierarchy (Argon2id, HKDF,
XChaCha20-Poly1305, X25519 sealed boxes, BLAKE2b) in pure-JS @noble + tweetnacl —
byte-parity with libsodium proven against the shared test vectors by the extension's own
gated vector run (`extension/src/crypto.vectors.test.ts`; the older
`web/src/crypto/noble-extension-poc.test.ts` is an opt-in spike that no default gate runs).
No hand-rolled primitives anywhere.

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
- **`memBytes` MUST be a multiple of 1024 (a whole number of KiB)** — normative for every
  producer of `kdfParams`: the operator policy (`PUT /admin/policy`, spec 03 §7.2), registration,
  password change / KDF upgrade (§7) and both recovery commits (spec 03 §12, §18.5). Argon2 takes its
  memory cost in KiB; libsodium converts `memLimit` bytes with integer division
  (`memlimit / 1024`, silently flooring), while an engine that takes KiB directly (the
  extension's Argon2id twin) must compute the same `⌊memBytes / 1024⌋` — a non-integer
  KiB value is not a cost, it is an error. The rule exists so that no in-range value can
  make two conformant engines derive different master keys from the same password
  (audit H16: a policy of `100000000` — "100 MB" — enrolled every libsodium
  client and locked the extension out until its twin floored). Servers MUST reject a
  policy or account `kdfParams` whose `memBytes % 1024 != 0` with
  `400 kdf_mem_not_kib_multiple` (distinct from `kdf_too_weak`: the shape, not the
  strength) on every path that sets it — the operator policy, registration, password change,
  and the kit and assisted recovery commits — and MUST serve an already-persisted
  non-KiB policy floored to whole KiB rather than refusing the clients that adopt it;
  clients MUST floor when converting to KiB, never round. The shared KDF vectors
  (`spec/test-vectors/kdf.json`) carry a non-KiB-multiple case so every engine is graded on
  the floor.
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
exception: quick-unlock (§8) persists a wrapped **UVK** — **(Android) hardware-wrapped**
(§8.1) or **(extension) PIN-wrapped, session-scoped** (§8.4) — never authKey/wrapKey/MK.

**Zeroization.** MK, authKey, wrapKey and the identity seed (§5) are zeroed (`fill(0)`)
once their consumers return, on all platforms — the same rule spec 07 §2.3 states for
MKx, exportKey and the export payload buffer, and for the same reason: these are the
shortest-lived and highest-value buffers in the system, they exist only to derive or
unwrap something else, and a process that keeps them alive turns a memory disclosure or
a core dump into a full account compromise rather than a session one. The **UVK and
vault keys an unlocked session owns are deliberately NOT wiped** — they are the working
set, and wiping them would be wiping the unlocked vault; what a lock does with them is
§8 "Keys in memory and the lock". This is best-effort hygiene, not
a guarantee: a managed runtime may have copied a buffer during GC and immutable string
types (passphrases) are explicitly out of scope, exactly as spec 07 §2.3 says. It is
still normative, because "we tried" is the difference between one derivation buffer left
in memory and every derivation buffer left in memory (audit H80).
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
- **Unlock failure classification (NORMATIVE; audit H67, extended 2026-09-13 by R38 to the
  sibling account-key blob).** A client unlocking with a password MUST separate the two ways
  an ACCOUNT-KEY envelope open can fail. This applies to **both** server-supplied account-key
  blobs — `wrappedUvk` (this section) and `encryptedIdentitySeed` (§5) — because they live in
  the same account row and are damaged by the same events (a partial DB restore, a newer
  server serving an envelope version an older client does not implement):
  - **Structural refusals** — the value is not decodable base64url, or the decoded
    envelope is shorter than the minimum, or carries an envelope version or AEAD alg the
    client does not implement (spec 02 §2). These are decided from the blob's public
    header **before** the wrap key is applied, so no password can affect them. A client
    MUST NOT report them as wrong credentials, and MUST NOT invite a retry (the same
    stored value fails identically forever); it MUST surface a distinct terminal
    condition meaning "this account's stored key material is unreadable by this client".
  - **AEAD tag failure** — the only outcome that is genuinely indistinguishable from a
    wrong master password, and the only one a client may report as such.
  Rationale: a corrupt account row (a partial DB restore) or a future envelope version
  served to an older client otherwise reads as a forgotten password on every device, and
  the member resets a working password and then spends their recovery secret.

  On the **quick-unlock / UVK** path the same split holds and costs nothing: a wrong or
  stale UVK can only ever produce the AEAD tag failure, which those clients already treat
  as "this quick-unlock secret is invalid" (§8.1's failure table) — a structural refusal
  there is likewise a damaged row, never a bad secret, and MUST be reported as such.

## 5. Identity keypair (X25519)

- The `encryptedIdentitySeed` envelope is an account-key blob: §4's **unlock failure
  classification** rule applies to it verbatim (structural refusal ⇒ the damaged-keys
  terminal, never "wrong master password"; AEAD tag failure ⇒ the ordinary bad-secret
  outcome).
- `identitySeed` = 32 random bytes at enrollment;
  `(identityPub, identityPriv) = crypto_box_seed_keypair(identitySeed)`.
- Server stores `identityPub` in plaintext (it is public) and
  `encryptedIdentitySeed = Envelope(key = UVK, plaintext = identitySeed,
  ad = "andvari/v1|idkey|{userId}")`.
- Used to receive shared-vault key grants (§6.3) and, through the joint key below, to sign the
  account's statements (§5.1).
- **Joint signing key (security review 2026-10, root cause A; owner decision: joint, not a
  separate HKDF key).** `(signPub, signSecret) = crypto_sign_seed_keypair(identitySeed)`, the
  same seed. Both libsodium functions take the clamped low half of SHA-512(seed) as the scalar,
  so `crypto_sign_ed25519_pk_to_curve25519(signPub) == identityPub` for every account, existing
  ones included. **No identity fingerprint changes and the server stores no new key**: the
  fingerprint over `identityPub` authenticates `signPub` too, through that mapping. The signing
  secret is derived at unlock from the UVK-sealed seed, the seed is wiped right after, and the
  secret is held for the session like `identityPriv` and never persisted. Its only use is signing the
  statements of §5.1, each through its own flow.
- **Identity fingerprint** = lowercase-hex `SHA-256(identityPub)` (same construction as
  the recovery fingerprint, spec 04 §1); short form = first **32 hex chars (128 bits)**,
  displayed as 8 groups of 4 on two lines `xxxx xxxx xxxx xxxx / xxxx xxxx xxxx xxxx`
  (security review 2026-10: a 64-bit/16-hex prefix is a grindable truncated second
  preimage). It MUST be computed over the **seed-derived** public key
  (`boxKeypairFromSeed(identitySeed).publicKey`), NEVER over the `identityPub` the server
  returns in account keys. The server cannot forge `identitySeed` (it is UVK-sealed), so a
  client unlocking MUST derive the pubkey from the decrypted seed and treat a mismatch
  against the server-sent `identityPub` as a security fault. Displaying a hash of the
  server-supplied value would let a malicious server pass an out-of-band check while
  substituting a key it controls.
- **Self-identity backstop (security review 2026-10, root cause A §2.4).** Every device that
  unlocked an account keeps the seed-derived `identityPub` it saw (native: per origin + userId
  beside the cached account keys; web: per origin in local storage) and passes it to every later
  unlock; if the seed then derives a DIFFERENT key, unlock hard-fails with the same security-fault
  copy as the server-`identityPub` mismatch. The record is public data and MUST survive sign-out,
  session revocation and offline-cache wipes (a recovery revokes every session first); it is
  written once from an unlock that passed and never overwritten from a server value. It stops a
  forged recovery (which must change the identity seed) on every device that knew the real key.
  **Bound to the typed email (branch A11):** the userId is the server's choice (the login response),
  so the record is ALSO kept per (origin, the email the user typed, trimmed and lowercased) as the
  (userId, identityPub) of the first passing unlock. An unlock whose server userId differs from the
  one bound to the typed email hard-fails with the same security-fault copy: a changed userId for the
  same email is a mismatch, never a fresh pin. Consequence: an account deleted and re-registered under the same
  email on the same origin is refused on a device that unlocked the old one, until that device's
  record is removed by hand. **Amended for account deletion (spec 03 §13, 2026-11-10):** the device
  that RAN the deletion removes its own records when the server confirms it — the userId-keyed pin,
  and the email binding only where it names the deleted userId — so the address can register again
  there; every OTHER device that unlocked the old account keeps refusing an account re-registered
  under that email until its record is removed by the person's own decision on that device
  ("Forget the earlier account on this device", decided on 2026-11-17, §7 and design §4.4; the
  shared code has the call since 2026-11-18 and hands it to the screens since 2026-11-19, both
  apps draw it since 2026-11-19, and the web client has its own since 2026-11-19; the offer is for
  another account only, never for the same account under another key, and the forgetting keeps
  the record of the earlier account's identity key, §7). A device link whose account goes by an
  address this device knows at that server under another account id stops with that address (at
  the approval, before the pickup, and at the take), so that the earlier account can be forgotten
  there as at a sign-in; the shared code keeps this since 2026-11-19 and offers the forgetting at a
  link's end only where its stop names the address. Both apps draw that offer at a link's end,
  by the same code as at a sign-in, since 2026-11-19. The forgetting also removes a session record the device cannot read, where it
  names the earlier account or does not read at all. That refusal is the backstop working: no
  device can tell a new account at the same address from a server that swapped the account, so the
  residual is accepted (spec 05 R19(c)), never relaxed.
- **Out-of-band verification is the link's job.** People pin each other's identity keys only
  through a link one of them made (spec 03 §15), confirmed by the committed comparison code (§5.5);
  nobody compares raw fingerprints. The short fingerprint is shown as the **account ID** on the
  recovery kit and in every notice except the mails about a recovery request (design 2026-11-15
  §11.2), and as the operator key's short form in the Trust Gate (§5.3).

### 5.1 Signed statements (`SignedStatement`, format v2)

A signed statement is a frame:

```
offset  len  field
0       4    magic        61 76 73 02   ("avs" + version 0x02)
4       1    purposeCode  (table below)
5       32   signerPub    Ed25519 public key (the signer's joint key, or a recovery-key signing key)
37      64   signature    Ed25519 detached signature over M
101     N    statement    canonical JSON, printable ASCII, 2 <= N <= 1024

M = "andvari/v2|signed-statement" || 0x00 || bytes[0..5) || signerPub || statement
```

Domain separation comes from the purpose byte inside `M`. The statement's `"purpose"` literal MUST
match the code. The **frame hash** `H(frame)` is the lowercase hex SHA-256 of the whole frame (magic
through statement); no prefix is added.

| Code | Purpose literal | Carried as | Signed by | Rules |
|---|---|---|---|---|
| 0x01 | `vault-grant` | `crypto_box_seal` to the member's identity key | the vault's owner | §6.3 |
| 0x02 | `escrow-uvk` | `crypto_box_seal` to the instance recovery key | the account | spec 04 §3 |
| 0x03 | `vault-log` | in the clear | the entry's actor | spec 02 §10 |
| 0x04 | `instance-card` | in the clear | the previous card's operator key | §5.2 |
| 0x05 | `account-genesis` | in the clear | the account | §5.4 |
| 0x06 | `link-offer` | envelope under the link's offer key | the link's creator | spec 03 §15 |
| 0x07 | `link-answer` | envelope under the link's answer key | the answering account | spec 03 §15 |
| 0x08 | `recovery-rotation` | in the clear, served with the card chain | the outgoing recovery-key signing key | spec 04 §5 |
| 0x09 | `assisted-recovery` | `crypto_box_seal` to the request key | the recovery-key signing key | spec 04 §7 |
| 0x0A | `recovery-veto` | in the clear, posted to the server | the account | spec 04 §7 |
| others | — | — | — | reserved: `bad_frame` |

**Value grammar.** Every value comes from a closed grammar that never needs escaping:

| Type | Grammar |
|---|---|
| `uuid` | lowercase `8-4-4-4-12` hex |
| `b64_16`, `b64_32` | unpadded base64url of exactly 22 / 43 chars that decodes to 16 / 32 bytes and re-encodes identically |
| `hex64` | 64 lowercase hex |
| `hex64n` | a `hex64`, or the literal `"none"` |
| `ms` | a decimal integer `1 <= x < 2^53` with no sign and no leading zero |
| `int` | a decimal integer `0 <= x < 2^53`: `0`, or `[1-9][0-9]*` |
| `role` | `"writer"` or `"reader"` |
| `origin` | `https://` + host + optional `:port`, all lowercase. The host is a DNS name of at least two labels, each `[a-z0-9]([a-z0-9-]*[a-z0-9])?` and 1–63 characters long, joined by `.` with no trailing dot; the whole host is at most 253 characters. Internationalised names appear only in A-label (`xn--`) form, and an `xn--` label is an ordinary label under this grammar: compared byte for byte, never decoded or checked as punycode. IP literals are not allowed: a host whose **last label is all digits**, or is `0x` followed only by hex digits, is refused (URL parsers read it as an IPv4 address: `1.2.3`, `999.1.1.1` and `example.123` are all refused); a last label that is exactly `0x`, with no hex digit after it, is refused too (URL parsers read it as 0); and bracketed IPv6 fails the label grammar. The port is `1..65535` without leading zeros, and never the scheme's default (`443` for https, `80` for http). The only plain-http forms are `http://localhost[:port]` and `http://127.0.0.1[:port]`, for development only (the one place a digit-only last label is allowed). Path, query, fragment and userinfo are never allowed. **This grammar is the single source for every origin a client stores, dials or shows**: `OriginCanon`, the Trust Gate and `andvari setup` refuse any origin it cannot carry, with "andvari needs an https address with a domain name for this server." |
| `name` | unpadded base64url of UTF-8 bytes, decoded length 1..64, re-encoding identically. The decoded text is valid UTF-8 and contains none of U+0000–U+001F, U+007F–U+009F, U+00AD, U+061C, U+180E, U+200B–U+200F, U+2028–U+202E, U+2060–U+2064, U+2066–U+206F, U+FEFF, U+FFF9–U+FFFB, and no leading or trailing U+0020. The list is explicit so that no engine's Unicode tables decide the outcome. No normalisation is applied; clients render it only as plain text. |
| `email_b64n` | unpadded base64url of the ASCII bytes of an `emailNorm` (§5.5), decoded 3..254 bytes and re-encoding identically; or the literal `"none"`. The decoded bytes must already be normal: `emailNorm` of them must equal them exactly, so an uppercase letter or a surrounding space inside is `non_canonical` |
| `email_b64` | the `email_b64n` grammar without the literal `"none"`: always an address (spec 04 §3, §7). It keeps `email_b64n`'s bound of 3..254 decoded bytes; the lower bound is never reached, since an `emailNorm` has at least 5 octets (`l@d.d`) |
| `v` | the `int` type; step 6 below then requires `v == 2`, or `v == 3` for the two version-3 templates. So `-1`, `02`, `2.0` and `"2"` are `non_canonical`, and `1` or `3` is `bad_statement` under a version-2 template |
| enumerated literals | where a template lists literals (the log's `kind`, the card's and the setup offer's `"public"\|"private"`, the link offer's `"connect"\|"register"`), they are a type of their own: any other value is `non_canonical` |

A JSON value that fails its type is `non_canonical`. A template whose fields are well formed but
violate a rule of the section that owns it is `bad_statement`.

**Templates** (one line each; keys in exactly this order, every key present exactly once, no optional
keys):

```
vault-grant:        {"v":2,"purpose":"vault-grant","from":<uuid>,"to":<uuid>,"toKey":<b64_32>,"vaultId":<uuid>,"grantId":<b64_16>,"issuedAt":<ms>,"vk":<b64_32>}
escrow-uvk:         {"v":2,"purpose":"escrow-uvk","userId":<uuid>,"identityKey":<b64_32>,"recoveryFp":<hex64>,"issuedAt":<ms>,"key":<b64_32>}
vault-log:          {"v":2,"purpose":"vault-log","vaultId":<uuid>,"seq":<int>,"prev":<hex64>,"kind":<kind>,"actor":<uuid>,"at":<ms>, …kind fields (spec 02 §10.1)}
instance-card:      {"v":2,"purpose":"instance-card","instanceId":<uuid>,"seq":<int>,"prev":<hex64>,"origin":<origin>,"name":<name>,"kind":"public"|"private","operator":<uuid>,"operatorSignKey":<b64_32>,"recoveryFp":<hex64n>,"issuedAt":<ms>}
account-genesis:    {"v":2,"purpose":"account-genesis","userId":<uuid>,"identityKey":<b64_32>,"instanceId":<uuid>,"personalVaultId":<uuid>,"createdAt":<ms>}
link-offer:         {"v":2,"purpose":"link-offer","linkId":<b64_16>,"kind":"connect"|"register","origin":<origin>,"instanceId":<uuid>,"cardHash":<hex64>,"from":<uuid>,"fromKey":<b64_32>,"name":<name>,"commit":<hex64>,"expiresAt":<ms>,"issuedAt":<ms>}
link-answer:        {"v":2,"purpose":"link-answer","linkId":<b64_16>,"offerHash":<hex64>,"to":<uuid>,"toKey":<b64_32>,"from":<uuid>,"fromKey":<b64_32>,"name":<name>,"nonce":<b64_32>,"issuedAt":<ms>}
recovery-rotation:  {"v":2,"purpose":"recovery-rotation","instanceId":<uuid>,"fromFp":<hex64>,"toFp":<hex64>,"issuedAt":<ms>}
assisted-recovery:  {"v":2,"purpose":"assisted-recovery","instanceId":<uuid>,"userId":<uuid>,"requestId":<b64_16>,"requestKey":<b64_32>,"uvk":<b64_32>,"issuedAt":<ms>}
recovery-veto:      {"v":2,"purpose":"recovery-veto","requestId":<b64_16>,"userId":<uuid>,"issuedAt":<ms>}
```

**Version-3 templates** (2026-11-16). Two purposes have a second template, version
3, which carries the account's address and is the only one a client produces (spec 04 §3, §7):

```
escrow-uvk v3:        {"v":3,"purpose":"escrow-uvk","userId":<uuid>,"email":<email_b64>,"identityKey":<b64_32>,"recoveryFp":<hex64>,"issuedAt":<ms>,"key":<b64_32>}
assisted-recovery v3: {"v":3,"purpose":"assisted-recovery","instanceId":<uuid>,"userId":<uuid>,"email":<email_b64>,"requestId":<b64_16>,"requestKey":<b64_32>,"commit":<b64_32>,"uvk":<b64_32>,"issuedAt":<ms>}
```

The frame is unchanged (magic `avs\x02`, the same purpose codes). Which templates a reader accepts is
the owning section's rule: spec 04 §4's opener of a recovery copy accepts both templates of 0x02, each
under its own `v`; the device's opener of an answer (spec 04 §7 step 4) accepts only the version-3
template of 0x09, and a statement canonical under the version-2 template is `bad_statement` there.
A reader of 0x02 or 0x09 tries both templates of the purpose: the key set picks one (a statement with
`email` against the version-3 template, one without against the version-2 template), steps 2 to 5
below match it against that template (`non_canonical` when it is not canonical there), and step 6
then requires that template's own `v`. A version its owning section does not accept is `bad_statement`,
so a version-2 key set marked 3, and a version-3 key set marked 2, are both `bad_statement`.

**Host-minted offers** (setup and enrol links, spec 03 §15) have no signer: there is no account key to
sign them. They are canonical JSON under the same grammar, strict parse and re-encode rules (steps
2–6 below, on the JSON alone), authenticated only by the link's AEAD envelope:

```
setup-offer:  {"v":2,"purpose":"setup-offer","linkId":<b64_16>,"origin":<origin>,"instanceId":<uuid>,"name":<name>,"kind":"public"|"private","recoveryFp":<hex64n>,"expiresAt":<ms>}
enrol-offer:  {"v":2,"purpose":"enrol-offer","linkId":<b64_16>,"origin":<origin>,"instanceId":<uuid>,"cardHash":<hex64>,"email":<email_b64n>,"expiresAt":<ms>}
```

**Recognising a host offer.** Before the template's own steps, the plaintext must be printable ASCII
and a JSON object with a string `purpose`, else `non_canonical`. "A JSON object" means RFC 8259
exactly: a bare token as a value, `NaN`, a trailing comma or trailing bytes are `non_canonical`, and
so are a key that appears twice at the top level (a repeated `purpose` included, whichever value
comes last) and nesting deeper than 32 open containers. The depth is decided on the bytes, or by a
parser that stops at the limit, before any general JSON parser sees the text: an offer of a thousand
open brackets must be `non_canonical`, never a stack overflow. Engines must not lean on a lenient library
parser here: one that reads a bare token as a value would answer `unknown_format` where the others
answer `non_canonical`. Only then is a `purpose` other than `setup-offer` and `enrol-offer`
`unknown_format`; then the template's own steps.

**Expiry is exclusive everywhere:** a link, an offer, a code or a ticket is valid while
`now < expiresAt` and has expired at `now = expiresAt`.

**Strict parse (every engine, in this order; the first failure decides the verdict).**

1. The frame, in this order: shorter than 4 bytes → `bad_frame`; wrong magic, including another
   version byte → `unknown_format`; total length outside `103..1125`, a reserved purpose code, or a
   purpose other than the one the caller expects → `bad_frame`. The magic is checked before the length,
   so a 50-byte frame with version byte `0x03` is `unknown_format`.
2. Every statement byte is printable ASCII (`0x20..0x7E`), or `non_canonical`. A statement is one flat
   object: a `[` anywhere, or a second `{`, is `non_canonical` too, and an implementation refuses it
   here, **before** the text reaches any general JSON parser (a parser that recurses once per level
   can be made to overflow its stack by a statement of a thousand brackets, and that is a crash, not a
   verdict).
3. The platform JSON parser yields an object with exactly the purpose's key set, or `non_canonical`.
4. Every value is in its grammar, or `non_canonical`.
5. Re-encode the parsed values through the template and byte-compare with the input, or
   `non_canonical`. This step shuts out parser differences between engines: whitespace, key order,
   duplicate keys, escapes and number forms all fail here.
6. `v == 2` (`v == 3` under a version-3 template) and the purpose literal matches the purpose code, or
   `bad_statement`; then each owning section's own template rules (for example a grant's `from != to`),
   also `bad_statement`. A statement is closed: a future field set means a new magic, or, as for 0x02
   and 0x09 above, a new statement version with a template of its own that the owning section names.

**Signer binding.** A verifier is handed the key the context says must have signed, never a key read
from the statement itself, in one of two forms:

- **an X25519 key**: the verifier requires `ed25519_pk_to_curve25519(signerPub) ==` that key (a key
  with no curve image fails too);
- **an Ed25519 key** (the instance card's `operatorSignKey`, and the account genesis on every device
  of the account, which derives its own signing key from the identity seed):
  the verifier requires `signerPub ==` that key, byte for byte.

Either way `crypto_sign_verify_detached` over `M` follows. When the signer does not map to the key,
a per-purpose helper returns `signer_not_pinned_key`; a bad signature is `bad_signature`. The vault
log (0x03), the card (0x04) and grants (0x01) return `not_authorized` instead, because their rules
also check the acting account (spec 02 §10.3, §5.2, §6.3). The key each helper is handed:

| Purpose | Key the helper is handed |
|---|---|
| 0x05 genesis | the account's own seed-derived **Ed25519** signing key, compared byte for byte, on every client; the server, which holds no seed, checks the signer against `identityPub` through its X25519 image and stores `signerPub` |
| 0x06 link offer | the offer's `fromKey`, once it has passed the link's `F` (`creator_mismatch` otherwise) |
| 0x07 link answer | the answer's own `fromKey`: proof of possession, which the comparison code authenticates later |
| 0x08 rotation | the recovery key of the verifier's current fingerprint (its consent, or the card's); a `fromFp` that is not that fingerprint is `fp_mismatch`, checked right after the parse (the fingerprint is inside the statement) and before the signer |
| 0x09 assisted recovery | the recovery key that the pinned card's `recoveryFp` names |
| 0x0A veto | the account's stored identity key (the server verifies it) |

`A` and `−A` have the same Montgomery image, so the mapping alone proves nothing; the signature
check that follows it does. **Each purpose has its own verify helper**, which cannot be called without its expected key, and
each flow owns its own builder: there is no "sign any statement" API on an account. Field checks that
depend on the caller come after the helper returns. `spec/test-vectors/statement-v2.json` and
`signedstatement.json` pin the layout, the grammar and every rejection rule.

**Escrow statements bind to the anchor, not to themselves.** The generic helper REFUSES purpose
`0x02`. An escrow statement verifies only through the escrow-specific helper
(`SignedStatement.verifyEscrow` / `verifyEscrowStatement`), which cannot be called without the
caller's out-of-band anchor: the expected `userId`, the anchored identity key, and the fingerprint of
the recovery key that opened the seal. The pin is that anchored key, never the statement's own
`identityKey`; the unverified `userId`/`recoveryFp` may be compared first only to refuse precisely
(`user_mismatch`, `recovery_fp_mismatch`); after the signature, the statement's `userId`,
`identityKey` and `recoveryFp` MUST EQUAL the anchor (`identity_mismatch` for a validly signed
statement naming another identity). Spec 04 §3 gives the full order.

**Typed separation.** A strict parse returns an UNVERIFIED type that is neither a statement nor a
verified statement and exposes only routing fields, never key material; only the verify helpers mint
a verified statement, and its byte fields are handed out as copies (read-only).

### 5.2 The instance card (purpose 0x04)

An instance names itself with a chain of cards, each signed by the operator key of the card before
it.

- `instanceId` is constant along the chain. `origin` is the instance's canonical origin. `name` is
  the display name. `kind` is `ANDVARI_INSTANCE_KIND`: it selects the copy and defaults that differ
  between a public instance and a private (family) instance, and grants nothing. `recoveryFp` is
  `hexLower(SHA-256(instance recovery public key))`, or `none` when the instance offers no operator
  recovery (spec 04 §1).
- `operator` and `operatorSignKey` name the operator account and its **Ed25519 joint key** (§5). The
  card names the Ed25519 form so that a verifier without a Montgomery map (the extension) can check the
  chain byte for byte. The server requires `operatorSignKey` to be byte-equal to the Ed25519
  key that signed the operator account's genesis (its `signerPub`, spec 03 §17.2). Among clients only
  the operator's own devices check it, against the Ed25519 key derived from their own identity seed
  (`operator_key_mismatch`). The comparison is on the Ed25519 key itself, never through its X25519
  image: a key and its negation share an image, and a card naming the negation would lock the real key
  out of every later card; other clients hold no
  trustworthy copy of that key, so they do not check it, and nothing rests on it: every card is still
  signed by the previous card's key. The operator's short fingerprint, wherever shown, is the usual
  identity fingerprint over that X25519 key.
- **Chain.** Card 0 has `seq = 0`, `prev` = 64 `0`s, and `signerPub` equal to its own
  `operatorSignKey`. Card n has `seq = n`, `prev = H(card n−1)`, and `signerPub` equal to **card n−1's
  `operatorSignKey`**. Any field except `instanceId` may change at n: a move (`origin`), a rename, an
  operator handover (`operator`, `operatorSignKey`), a `kind` change, or a recovery-key change
  (`recoveryFp`). **Verdicts, in order:** the parse verdicts (§5.1); `instance_mismatch` (an
  `instanceId` other than card 0's of the same chain, or, on the server, than its own; expectations
  from outside the chain belong to the pin verdicts below and are checked after the chain verifies);
  `bad_seq`; `bad_prev`;
  `not_authorized` (the signer is not byte-equal to the previous card's `operatorSignKey`, or card 0's
  own); `bad_signature`; then, only on the operator's own devices, `operator_key_mismatch`. Cards have
  no `precondition`.
- **Pin record.** A client keeps, per origin namespace, a pinned card record that outlives sign-out
  and cache wipes: `{ instanceId, card0Hash, seq, hash, origin, name, kind, operator, operatorSignKey,
  recoveryFp, root, account? }`, where `card0Hash` is the hash of the chain's card 0 (every root knows
  it when it makes the first pin), `root` is how the first pin was made (§5.3) and `account` the
  account a kit or setup pin is scoped to. A device keeps at most one pin record per origin. Rules
  for the pin store, for every client that keeps pins: (1) a root never replaces an existing pin: when
  the origin already has a pin, a root that turns up later first compares the served chain with that
  pin and stops on anything but `ok`; it may add its anchor or raise the root, never swap the chain;
  (2) a card that changes both `origin` and `kind` is a `kind` change, never a move alone; (3) "store
  builds never follow a move or a `kind` change of the baked instance" is keyed on the instance (a pin
  whose `card0Hash` is the baked one or whose origin is the baked origin), however the pin was made;
  (4) a move never replaces a pin that already exists for the new origin (`pin_conflict`); (5) a fork
  is durable: stored with the pin, surviving restarts, and until "Forget this server" nothing from that
  origin is trusted and the password rule refuses; (6) a device link's `pin_mismatch` removes only the
  pin that link made; (7) a pin record that fails to decode is `damaged` and blocks the origin.
- **On every policy probe or sync** the client fetches the chain (`GET /instance`, spec 03 §17) when
  its ETag changed, and verifies forward from the pinned card:
  - **Checkpoint comparison.** Comparing a served chain with a held head is one pure function, shared
    with the vault log (spec 02 §10.5), that returns `ok`, `withheld` (the chain ends below the head) or
    `fork` (another hash at the head's `seq`).
  - **Fork.** A chain that does not contain the pinned hash at the pinned `seq` makes the client
    **stop using the instance**: no sign-in, sync or writes. It says: "This server's identity changed
    in a way andvari can't verify. Don't continue. If you trust the operator, ask them what happened."
    The only way on is "Forget this server", which removes the namespace's pin and data.
  - **Withheld.** A chain that ends below the pinned `seq`, or no chain at all, does not stop
    anything. The client keeps its newer pinned card, shows "This server is showing an older version
    of its identity card", and retries on the next probe.
  - **Move.** When the newest verified card's `origin` differs from the namespace's, the app shows
    "*name* (*old origin*) moved to *new origin*, signed by its operator", and one tap moves the
    namespace, with no Trust Gate. **Store builds never follow a card-driven move of the baked public
    instance**: they show "This server says it moved. Update andvari." After following a move the app
    asks the person to make a new recovery kit, because the kit names the address it was made for.
    An address the chain has ever named must stay the operator's: the chain is public, so whoever
    later controls an old address can serve the genuine chain cut off before the move, and no client
    check can tell a cut-off chain from a current one (spec 05 R36).
  - **`kind` change.** A verified card that changes `kind` is never followed silently: store builds
    never follow one for the baked public instance ("This server says it changed. Update andvari."),
    and for any other instance the client shows the Trust Gate again naming the change. Until the
    person confirms, the client keeps using the old `kind`. A card that changes both `origin` and
    `kind` is a `kind` change first: on confirmation the pin records the accepted `kind` and stays at
    its card, and the changed origin is then offered as a move in its own right. A pin whose `origin`
    is not the origin it is stored under is `damaged`.
  - **A fork stops traffic, not reading.** What the device already holds stays readable: a vault it
    has a copy of can still be unlocked from that copy, read, copied from, filled from and exported,
    with the warning in view; nothing is sent to the origin, nothing from it is accepted, nothing is
    written. "Forget this server" says that it deletes this copy. A `damaged` pin stays blocked.
  - **Trust records.** Everything the device keeps per origin for deciding what to trust (account-state
    high-water marks, vault records and checkpoints, the device record) moves with the pin when a move
    is followed; a move never resets a mark, and its target is checked before either pin is touched. A
    trust record that cannot be read is "unknown", never empty: what it guards stays closed and it is
    not written back from what the server serves.
- **Display.** Wherever a card's name is shown, its origin is shown beside it, and a typed-address pin
  marks the name "(as the server names itself)".
- **Losing the operator.** A card advances only with the operator's signing key. If the operator
  account is lost, `andvari admin reset-instance-identity` starts a new chain with the same
  `instanceId` (spec 03 §17.5). Every device that pinned the old chain sees the new card 0 as a fork
  and stops; while no card is served it treats the empty chain as withheld. Each person uses "Forget
  this server" and reconnects, and makes a new kit (kits name the old `card0Hash`). Store builds bake
  `card0Hash` and need a new release. Operator recovery is never offered to the operator account
  itself.
- Vectors: `spec/test-vectors/instancecard.json`.

### 5.3 Trust roots and the password rule

The first pin of an origin comes from exactly one of five roots. A device link only **confirms** a
pin made by another root:

| Root (`root`) | When | Rule |
|---|---|---|
| **Baked** (`baked`) | the store apps' "Create an account on andvari", and any connection to `PUBLIC_INSTANCE.origin` | card 0 of the served chain must hash to `PUBLIC_INSTANCE.card0Hash`, and `instanceId` must match (`spec/public-instance.json`) |
| **Link offer** (`link_offer`) | opening a connect or register link | the served chain must contain a card with `H = offer.cardHash` and `instanceId = offer.instanceId`; the newest verified card is pinned |
| **Setup** (`setup`) | the first operator, through a setup link | the app signs card 0 itself and pins it |
| **Kit** (`kit`) | recovering with a recovery kit, **only** on Sign in → Forgot your master password? → Scan your recovery kit | card 0 of the served chain must hash to the kit's `card0Hash`. A kit made before an operator reset does not match: the client falls back to the Trust Gate with "This server's identity changed since your kit was made. Continue only if you know why" |
| **Typed address** (`trust_gate`) | "Use your own server" with a hand-typed origin | trust on first use behind the **Trust Gate**: it shows the origin, "It calls itself “*name*” — nobody you know has vouched for it", and the operator key's 32-hex short form; connecting pins the newest card |
| Device link (confirms only) | a device added by a device link (spec 03 §16) | the bundle's card checkpoint must agree with the pin the new device made before it claimed, or the device signs out |

**Pin verdicts, in order:** `origin_mismatch` (the newest verified card's `origin` is not the origin
the client dialed; cards are public, so any server can serve another instance's genuine chain, and
under an existing pin a changed origin is a move instead; after a move a device with no pin that
dials the old address gets this verdict too and may offer to dial the origin the newest card names,
where every check runs again from the start); `card0_mismatch` (card 0 does not hash to the baked or the kit's
`card0Hash`); `instance_mismatch` (the baked `instanceId`); `card_not_in_chain` (a link offer's
`cardHash` is not in the served chain); `fork` (card 0 does not hash to the pin's `card0Hash`, or
another hash stands at the pinned `seq`); `withheld` (the same chain ends below the pin: a state, not a
stop). In that order, so: a baked root whose card 0 hash and `instanceId` both differ is
`card0_mismatch`; a baked or kit root against an empty chain is `withheld`; an offer whose `cardHash`
is in the chain under another `instanceId` than the offer's is `instance_mismatch`; a pinned card
against a chain of another `instanceId` is a `fork`, because its card 0 differs. A replaced chain is
therefore a fork as soon as its card 0 is served, however short it is. Two more names come from the
pin store's rules (§5.2), not from this comparison: `pin_conflict` (a move toward an origin that
already has a pin is refused) and `damaged` (a pin record that fails to decode blocks the origin and is
never read as "no pin").

**An enrol link is not a root.** Its offer is minted by the host, so it passes the typed-address
Trust Gate, and the pin it leaves records root `enrol`. At the baked origin it takes the baked root
instead (next paragraph). If this device already pins a card for an origin, any new chain must extend
that pin.

**At the baked origin the baked root always comes first.** On a build that bakes a public instance, a
first pin at `PUBLIC_INSTANCE.origin` is made through the baked root whatever started the connection: a
typed sign-in, the first screen's "andvari" choice, or a link of any kind. The baked checks run first,
in the verdict order above (`origin_mismatch`, `card0_mismatch`, `instance_mismatch`; an empty chain is
`withheld`), and the pin records root `baked`, which is a password pin: the build, not the link,
vouches for the instance. A link then adds its own check on top: a connect or register link, that the
chain also contains the offer's `cardHash` under its `instanceId` (`card_not_in_chain`,
`instance_mismatch`); an enrol link, nothing more (no Trust Gate, and the pin's root is `baked`, not
`enrol`); a setup link is refused (`withheld` on an empty chain, so nothing is signed, and
`already_set_up` on a served one that passes the baked checks: a build that bakes an instance never
signs that instance's card 0). A link to any other origin is unaffected by what the build bakes. Under
an existing pin at the baked origin the pin is compared first; the baked checks then run on the same
chain, a pass makes the pin's root `baked`, and a pinned chain whose card 0 is not the baked one is
`card0_mismatch` (the instance is not used until the person forgets the server).

**Password rule.** A client sends a value derived from an account's secrets — prelogin for its email,
`authKey` or `currentAuthKey`, `recoveryAuthKey`, a TOTP code — only to:

- the origin of a session this device already holds **for that account** (re-authentication, password
  change, recovery settings); or
- for signing in, linking a device or recovering, an origin with a **password pin** for that purpose:
  - a pin this device made through the **baked** root or the **Trust Gate** counts for any account;
  - a **kit** pin counts only for recovering the kit's own account (the email in the kit), and a
    **setup** pin only for the operator account this device enrolled. Signing in to any other account
    there, or linking a device there, shows the Trust Gate first. A kit pin is for the recovery
    alone: a later sign-in through it, even to the kit's own account, also shows the Trust Gate. The kit
    vouches that this is the instance it was made on, for that one act; entering the master password at
    a server is a separate decision made at the gate. A setup
    pin allows signing in to the operator account it enrolled and recovering that account with its
    kit. Creating an account (`register`) proceeds with any pin for the origin, a kit or setup pin
    included. Assisted recovery through a kit or a setup pin shows the Trust Gate. A re-authentication
    with no session for that account at that origin is refused at the entry.

A pin that came only from a **link offer** or an **enrol link** is enough to *create* an account on
that instance, never to sign in to an existing one: signing in through it shows the Trust Gate first,
after which it is a password pin. Every screen that asks for an existing account's master password
names the account and the instance: "Master password for *email* on *name* (*origin*)".

The rule is one pure core function (`PasswordGate`), used by every native client and the CLI, with a
TypeScript twin in the web client. The web client pins one origin only, the one that serves it, in the
browser's storage and under the same pin-store rules as every client: the baked root for the public
instance, otherwise the Trust Gate once per browser, in its typed-address wording (the person typed
the address into the browser). It needs that pin for the genesis check (§5.4), and the pin lets it
notice a fork or a rollback on a later visit. It cannot follow a move, because another origin serves
its own web client: it reports "This server says it moved to *origin*" and keeps its pin. In the CLI
the Trust Gate is the printed origin,
name and operator key with a confirmation, or `--trust-card <card0Hash>` for scripts.
`spec/test-vectors/passwordgate.json` pins its decisions, including which entry screen may start which
flow (a `/d` link only on "Link from your other device", a kit only on the kit-recovery screen).

### 5.4 The account genesis record (purpose 0x05)

- The registering client signs exactly one genesis, at registration, and sends it in the register
  body (spec 03 §14.3). No client API can mint a second one.
- The server checks that the signer maps to `identityPub`, that `identityKey` is `identityPub`, that
  `userId` and `personalVaultId` equal the body's and that `instanceId` is its own; it stores the
  frame and serves it as `AccountKeys.genesis`.
- **At every unlock**, after deriving the identity key from the seed, a client runs these checks, each
  with its own verdict, in order: the parse verdicts (§5.1); the signer maps to the seed-derived key
  (the extension: `signerPub` equals its own Ed25519 key) — `signer_not_pinned_key`; the signature —
  `bad_signature`; `identityKey` equals the seed-derived X25519 key — `identity_mismatch`; `userId`
  equals the session's — `user_mismatch`; `instanceId` equals the pinned card's —
  `instance_mismatch`; the served `personalWrap.vaultId` equals `personalVaultId` when a wrap is
  served — `personal_vault_mismatch`. Every one shows the same identity security fault (the
  `IDENTITY_MISMATCH` copy), as the seed-derived key mismatch above does.
- **Offline unlock** runs the same checks against the genesis cached with the AccountKeys (spec 02 §8).
  A cached AccountKeys without a genesis is refused as damaged key material.
- `personalVaultId` names the account's one personal vault forever (§6.1).
- Vectors: `spec/test-vectors/accountgenesis.json`.

### 5.5 Domain strings and encodings

All new labels live in the `andvari/v2|` namespace. Every HKDF is HKDF-SHA-256 with an empty salt
(RFC 5869 default). Every AD is `|`-joined UTF-8 (spec 00). `b64url` is unpadded base64url.

| Use | Construction |
|---|---|
| Vault-key commitment | `hexLower(HKDF(ikm = VK, info = "andvari/v2\|vk-commit\|" + vaultId, L = 32))` |
| Shared-vault UVK wrap AD (owner wrap and member self-wrap) | `andvari/v2\|vk-shared\|{vaultId}\|{userId}\|{genesisHash}`, where `genesisHash = H(genesis frame of the vault's log)` |
| Link id | `b64url(HKDF(ikm = s, info = "andvari/v2\|link\|id", L = 16))` |
| Link offer key | `HKDF(ikm = s, info = "andvari/v2\|link\|offer", L = 32)`; envelope AD `andvari/v2\|link-offer\|{linkId}` |
| Link answer key | `HKDF(ikm = s, info = "andvari/v2\|link\|answer", L = 32)`; envelope AD `andvari/v2\|link-answer\|{linkId}` |
| Link register token | `token = b64url(HKDF(ikm = s, info = "andvari/v2\|link\|register", L = 32))`; the server stores `tokenHash = b64url(SHA-256(ASCII(token)))` |
| Code commitment (both kinds of link) | `commit = hexLower(SHA-256("andvari/v2\|code-commit\|" + b64url(nonce)))`, `nonce` 32 CSPRNG bytes kept by the committing side until it reveals it |
| Link comparison code | `u32be(SHA-256("andvari/v2\|link\|code\|" + side + "\|" + linkId + "\|" + offerHash + "\|" + answerHash + "\|" + b64url(nonceA) + "\|" + b64url(nonceB))[0..4]) mod 10^6`, zero-padded to 6 digits, where `side` is the literal `creator` or `answerer`. **There are two codes, one per side:** the link's creator shows the `creator` code and the answerer shows the `answerer` code, and each app accepts as typed input only the OTHER side's code. |
| Link creator fingerprint | `F = b64url(SHA-256(raw 32 bytes of the creator's identityPub)[0..16])` |
| Device-link id | `b64url(HKDF(ikm = s, info = "andvari/v2\|device-link\|id", L = 16))` |
| Device-link MAC key | `HKDF(ikm = s, info = "andvari/v2\|device-link\|mac", L = 32)`; MAC inputs in spec 03 §16.1 |
| Device-link comparison code | `u32be(SHA-256("andvari/v2\|device-link\|code\|" + linkId + "\|" + nPub + "\|" + b64url(nonceN) + "\|" + b64url(nonceE))[0..4]) mod 10^6` |
| Device-link bundle key | `HKDF(ikm = UVK, info = "andvari/v2\|device-link\|bundle\|" + linkId, L = 32)`; envelope AD `andvari/v2\|device-link-bundle\|{linkId}` |
| Sign-up code check | `HMAC-SHA-256(signupSecret, "andvari/v2\|signup-code\|" + emailNorm + "\|" + code)` |
| Sign-up proof of work | `SHA-256("andvari/v2\|signup-pow\|" + emailNorm + "\|" + utcDate + "\|" + nonce)` |
| Recovery-key signing key | `crypto_sign_seed_keypair(recovery seed)`: the seed that yields the instance recovery X25519 key (spec 04 §1), held only offline in `recovery-cli` |
| Recovery request code | `hexLower(SHA-256("andvari/v2\|recovery-request\|code\|" + b64url(rPub)))[0..24]`, shown as six groups of four (96 bits) |
| Assisted-recovery commit hash | `commitHash = hexLower(SHA-256("andvari/v2\|recovery-request\|commit\|" + b64url(commit)))`, `commit` 32 CSPRNG bytes the offline tool puts in the answer (spec 04 §7 step 3) |

**Encoding rules for every input above:**

- Every HKDF info, MAC and hash input is the UTF-8 encoding of the string shown, and every component
  is ASCII.
- Ids (`vaultId`, `linkId`, `requestId`, `userId`) appear as their canonical text.
- Keys and other byte values inside an input appear as unpadded base64url text (for example `nPub`,
  the 43-character base64url of the 32-byte key).
- Digests inside an input are lowercase hex (`offerHash`, `answerHash`).
- MAC outputs travel as unpadded base64url of the 32 bytes.
- `platform` is one of `android`, `ios`, `windows`, `macos`, `linux`, `web`, `cli`, `extension`.
- Proof of work: `utcDate` is `YYYY-MM-DD` (UTC); `nonce` is a decimal integer `0 <= n < 2^53`
  with no leading zeros; leading zero bits are counted from the most significant bit of digest byte 0,
  then byte 1, and so on.
- **`emailNorm`**: strip ASCII white space (space, tab, CR, LF) from both ends; lowercase ASCII `A–Z`
  only, with no Unicode case folding and no locale. Refuse (verdict `invalid_email`) any address that,
  **after the strip**, is shorter than 3 or longer than 254 octets, contains any byte outside
  `0x21–0x7E`, or does not have exactly one `@` with non-empty parts. So an interior space, a tab, any
  control character, DEL (`0x7F`) and any non-ASCII byte are all refused. After these steps the
  address must be `local@domain` with exactly one `@`: `local` is 1 to 64 characters of letters,
  digits and ``!#$%&'*+/=?^_`{|}~-`` with single dots between non-empty parts (a dot-atom: no quotes,
  no comments, no angle brackets, no spaces); `domain` is two or more labels under the host grammar
  of the `origin` type. Anything else has no `emailNorm`.

The AEAD envelope format is spec 02 §2. Vectors: `spec/test-vectors/encodings.json`, `links.json`,
`devicelink.json`.

## 6. Vault keys — everything is a vault

- Every item lives in exactly one vault; every vault `vaultId` has a random 32-byte Vault Key `VK`.
  Items encrypt under VK (spec 02), never directly under UVK.
- A **personal vault** (`type = personal`) is the account's one vault named by its genesis; it never
  has members and has no log (spec 02 §4). A **shared vault** (`type = shared`) has a signed log
  (spec 02 §10) from its first moment, even before it has a second member.

### 6.1 Wraps under the UVK

| Wrap | Construction | Where it lives |
|---|---|---|
| Personal vault, owner grant | `Envelope(key = UVK, plaintext = VK, ad = "andvari/v1\|vk\|{vaultId}\|{userId}")` | the personal vault's owner grant row |
| **Personal wrap** | `Envelope(key = UVK, plaintext = VK_personal, ad = "andvari/v1\|vk-personal\|{vaultId}\|{userId}")` | `AccountKeys.personalWrap` |
| Shared vault, owner wrap and member self-wrap | `Envelope(key = UVK, plaintext = VK, ad = "andvari/v2\|vk-shared\|{vaultId}\|{userId}\|{genesisHash}")` | the owner's grant row (posted with `genesis` or `accept`); a member's grant row (`PUT /vaults/{id}/grant/self-wrap`) |

- **The personal wrap.** Which vault is personal is decided by the genesis (`personalVaultId`, §5.4)
  and the personal wrap, never by the server's `type` label or a grant `role`. Exactly one personal
  wrap ever exists: it is sent with the register and never replaced. A served wrap that opens and
  names `personalVaultId` is in force on **any** device, including a fresh one, with no question. A
  withheld or unopenable wrap leaves "no personal vault" with an anomaly (no default save
  destination, no usage ledger; a default save, import or copy fails with "Choose a vault for this
  item."); a cached wrap still stands on a device that has one, in device state that outlives the
  offline cache. Vectors: `spec/test-vectors/personalwrap.json`.
- **Genesis-bound shared wraps.** The commitment `vkCommit` is public and a wrap used to bind only the
  key, the vault and the user; without the genesis hash, the server alone could serve a fresh device a
  fabricated log (its own genesis with the copied commitment, then an `add` for the victim). The AD
  names the genesis the wrapping device verified, and the account's devices also record it (spec 02
  §9, `vaults`), so a different genesis fails both. A client round-trips every wrap it posts (opens
  it again) before sending it. Vectors: `spec/test-vectors/wrapad.json`.

### 6.2 Key commitment

```
vkCommit = hexLower(HKDF-SHA-256(ikm = VK, salt = empty, info = "andvari/v2|vk-commit|" + vaultId, L = 32))
```

The creator puts `vkCommit` in the vault's `genesis` entry. **Every vault key a client obtains, from
any source** — its own owner wrap, a member self-wrap, a new owner's wrap, or a grant — is checked
against the verified log's `vkCommit` before use. A mismatch means the key is **refused**: the vault
shows "key doesn't match this vault's history — the server may be misbehaving", nothing is decrypted
or written under that key, and the anomaly is shown. A vault's key never legitimately changes (no
rotation exists, P6).

### 6.3 Grants (purpose 0x01)

An owner shares a vault's key with a new member by signing an `add` entry in the vault's log (spec 02
§10.1) and a `vault-grant` statement with `from` = the owner, `to` = the member, `toKey` = the
member's key as the `add` names it (`memberKey`), `vaultId`, `grantId` equal to the `add`'s,
`issuedAt` and `vk`; it seals the frame with `crypto_box_seal` to `memberKey`. The server delivers it
on the member's grant row as `signedGrant` (spec 03 §4). The recipient runs these checks in order; the
first failure is the verdict:

1. The seal opens with its identity keypair (`unopenable`).
2. The frame checks of §5.1, for purpose 0x01: `unknown_format` for another magic (a bare JSON grant
   included), `bad_frame` for a plaintext that is too short or a frame of another purpose.
3. Strict parse (`non_canonical`, `bad_statement`; `from != to` is a template rule).
4. `to` is this account and `toKey` its seed-derived identity key (`misaddressed`).
5. `vaultId` is the row's vault (`vault_mismatch`).
6. The vault's log verifies (spec 02 §10.5), and **this account's latest `add`** has `grantId` equal
   to the statement's, `member` this account and `memberKey` its key. Call that entry's actor O and the
   owner key at that entry K. A grant bound to an earlier `add` of the account, or to none, is
   `no_add_entry`. If the log itself does not verify, the grant is not evaluated
   at all: the log is replayed before any grant is opened, so the result is the log's own verdict even
   when the grant has a fault of its own.
7. `from = O`, and the signer maps to K (`not_authorized`).
8. The signature (`bad_signature`).
9. `vk` is 32 bytes and `commit(vk)` equals the log's `vkCommit` (`vk_commit_mismatch`).
10. No later `remove` or `leave` of this account without a later `add` (`removed`). After a remove
    and a re-add only the new `add`'s grant opens (step 6); otherwise a server could put an old grant
    back on the row and the accept prompt would name whoever owned the vault at the earlier `add`.

So only the vault's owner can grant, and no device can be pushed onto a different key: the key is
committed at genesis. Whether a device then **adopts** the key is spec 02 §10.4 (the accept prompt,
contacts current on the device, the account's vault records). A device that adopted a key from a
grant posts its self-wrap (§6.1), after which the account's other devices adopt through the wrap.
Vectors: `spec/test-vectors/sharedgrant-v2.json`.

### 6.4 Key sources, in short

A client takes a shared vault's key only from (a) its own owner wrap or self-wrap opening under the
genesis-bound AD, or (b) a grant passing §6.3; and in both cases only after §6.2 and spec 02 §10.4.
There is no anonymous seal of a key and no other source. A wrap that is present but does not open
(a structural refusal or an AEAD tag failure; the UVK has proven itself at unlock) makes the vault
"key unreadable", and the client never falls back to anything else.

### 6.5 The Chrome and Firefox extension (reduced rule)

The extension's crypto is pure JavaScript with no Montgomery map and no WASM, so it cannot run the full
verification. It follows this rule instead:

1. **Keys come only from UVK wraps**: the personal wrap, owner wraps and member self-wraps that a full
   client minted after its own checks. A shared wrap's AD names the vault's genesis hash, which the
   extension reads from the account state's `vaults[vaultId].genesisHash` (spec 02 §9), opening the
   account state under the UVK; a wrong or withheld value fails the AEAD and the vault stays closed.
   **It opens a shared wrap only when the account state's `accepted[vaultId].decision` is `accept`**;
   it cannot check `addSeq` (it verifies no log), so after a re-add a replayed old wrap can still open
   there (spec 05 R24). It opens no grant and verifies no vault log; a grant row with no wrap is counted
   ("N shared vaults are not open here. Review them in andvari if it asks you to, then lock and unlock
   this extension. Some may still stay closed here.", and for one vault "1 shared vault is not open
   here. Review it in andvari if it asks you to, then lock and unlock this extension. It may still stay
   closed here.").
2. **The account genesis is verified** (§5.4), comparing `signerPub` byte for byte with its own
   Ed25519 key.
3. **The instance card chain is verified** (§5.2), signers compared byte for byte with
   `operatorSignKey`. Its first pin is the baked `card0Hash` for the public instance or the Trust
   Gate's typed-address rule; it signs in only through one of those. Store builds start with no
   server.
4. **It writes only to the personal vault**, for every kind of item and every write path, a card's
   update included: the one function that sends an item refuses any other vault. A matching login
   that lives in a shared vault is not updated: "This login is in *vault*. Update it in the andvari
   app."
5. Its strict statement parser for purposes 0x04 and 0x05 is a third implementation, graded by the
   same vectors.
6. **It never seals or re-seals an escrow and never changes the recovery posture**: it cannot verify a
   0x08 rotation statement.
7. **It keeps the account state's high-water mark** (spec 02 §9) per origin and account in its trusted
   store and opens shared vaults only under a served document at or above it; the mark follows a move
   with the pin, and a mark that cannot be read keeps shared vaults closed (§5.2, "Trust records").
8. **It refuses the operator account**: a sign-in whose session has the operator role is revoked at
   once and refused, as on the web. Whenever the newest verified card names the signed-in account as
   `operator` (a handover made this member the operator), the extension signs it out with the same
   sentence, as the web client does; that needs no signal from the server and covers a quick unlock,
   which carries no role (design 2026-11-15 §12.2, rule 7).

The Safari extension uses the app's server and inherits the app's checks through the app's AutoFill
snapshot, which never holds a vault that is not accepted, is frozen or failed.

### 6.6 Roles, removal and deletion

- Roles: `owner` (exactly one per vault at every verified log state; reassigned only by an `offer`
  the target `accept`s, after which the old owner is a `writer`, keeping the key), `writer`,
  `reader`. Only the owner changes membership. Roles are server-enforced on writes (spec 02 §4) and
  every change is a signed log entry.
- **Removal** (`remove`, `leave`) stops the server serving the vault to that account. No step rotates
  the vault's key (P6). **Accepted risk (spec 05 R7):** a removed member who kept the key, working
  with the server, can still read later items and write new ones (items carry no author signature).
  The remove dialog says so and offers "Move everything to a new vault" (spec 02 §10.8).
- **Vault deletion** is a signed `delete`; the server destroys the vault's ciphertext after a grace
  window (spec 03 §11.1). It is NOT cryptographic erasure toward anyone who held VK (R7).
- **Writes under a vault key.** No item is ever sealed under a key that failed §6.2, or under the key
  of a vault that is frozen, failed or not yet accepted (spec 02 §10.4); copying items **out** of such
  a vault stays allowed. Item provenance and the item home are spec 02 §7.2.

## 7. Password change and KDF upgrade

- **Password change** (client, atomic server call `PUT /account/password`):
  derive MK′/authKey′/wrapKey′ from the new password (fresh 16-byte salt), re-wrap
  UVK → wrappedUvk′, send `{newSalt, newKdfParams, newAuthKey, newWrappedUvk}` with
  the CURRENT authKey as proof. UVK, identity keys, vault keys, items: unchanged.
  Server revokes all other sessions on success.
  - **The new password's cost.** The new password is derived, figure by figure, at the
    higher of the account's present cost and the policy's, inside the client-side sanity
    bounds (rule of 2026-11-17, "Every new wrap is made at a cost the server will take"
    below; until then the policy's cost was taken only when the KDF-upgrade rule below
    said an upgrade was due). It is never derived at a lower cost than the account
    already had. **The same holds wherever a client makes a new wrap of an existing
    account's key** (rules of 2026-11-17): a password change, a kit recovery, an assisted
    recovery and the quiet re-key all derive at least at the account's present cost where the
    client knows it, raised figure by figure to the policy's (below), and no recovery derives
    below what the server's policy asks, above all not below the server's floor (a recovering
    device does not know the account's own cost). A caller of the shared code names the cost;
    there is no default to fall back on. `andvari-cli account password` names the cost of the
    wrap its proof stands on (or the pending wrap's, when that is higher), and the shared code
    raises it figure by figure to the served cost (below); a run that does not know the cost
    derives nothing and says so (exit 1, nothing sent). **The order of a password change**
    (the shared code, since 2026-11-18): the new password's floor; the proof of the current
    password on the device (a wrong one returns here, with nothing sent); only then the read of
    the served cost (`GET /client-policy`, which carries nothing of the account) and the new
    password's derivation; the new password is wiped on every way out. **The cost of a recovery's new wrap** (rule of 2026-11-17): a recovering device
    cannot know the account's own cost (no wrap opens, and the first exchange's answer is the
    server's word), so the floor that can be had is this: the new wrap starts at the client's
    default, is raised figure by figure to the kept copy's own cost (or its pending wrap's) where the device keeps
    the account, and to the server's policy, read through the pinned server just before the
    commit; each raise is made only inside the client's limits, and a policy that cannot be
    read raises nothing. The shared code's kit recovery and assisted recovery do this, from the
    apps and from `andvari-cli recover` alike. The policy the server serves is never below the
    server's floor, so that a client that follows it is not refused (spec 03 §7.2). **A known
    limit** (accepted on 2026-11-17, spec 05 T1): on a device that keeps no copy, the new wrap is
    made at the cost the server serves, which a hostile server can hold at the floor; the floor
    is the least any client takes.
    **Every new wrap is made at a cost the server will take** (rule of 2026-11-17, for every
    client and every place a new wrap is made: a registration from any kind of link or ticket, a
    password change, both recoveries, and the quiet raising after an unlock below): the cost is,
    figure by figure (passes, memory), the higher of what the account already has, where the
    client knows it, and what the server serves, each kept inside the client's own limits; where
    there is no account yet, the served cost. A served figure lower than the account's never
    lowers it, and where a password change or a recovery makes a wrap, a policy that is higher on
    one figure and lower on the other raises the one and keeps the other. **What is kept
    (2026-11-18):** the shared code reads the served cost just before it derives and makes every
    new wrap at the highest, on each figure, of the served cost and the account's own costs it
    knows (the kept wrap, the pending wrap, the caller's), with the client's default as the
    least, each figure inside the client's limits (3 to 10 passes, 64 MiB to 1 GiB, memory rounded
    up to a whole KiB); a served cost outside those limits is left out and nothing is derived at
    it. This holds for a registration from a ticket and from every kind of link, a password
    change, both recoveries and the quiet raising (when the quiet raising is due is unchanged), in
    the apps and in `andvari-cli`, which go through it; the web client keeps the same rule. The
    server refuses a new wrap below its served cost on either figure (spec 03 §7.2), and it serves
    its cost raised to its floor.
  - **The current password is proven on the device first** (the in-session password
    proof below): a wrong one sends nothing.
  - **A pending record survives a lost answer (NORMATIVE).** Before the request is sent,
    the device keeps the new wrap (`newSalt`, `newKdfParams`, `newWrappedUvk`) as a
    pending record beside its own. A server that answers that the change was not made
    drops it at once; no answer, or a server error, leaves it. While it is pending, whichever password opens
    it opens the device's copy and proves a re-authentication, so the person is never
    left with "wrong password" for the password they just set. At the next opening of the
    vault the device reads the account's keys as the server holds them
    (`GET /account/keys`) and settles the record: the server holds the pending wrap, and
    it becomes the device's own; the server holds the device's previous wrap, and the
    pending one is dropped; anything else is a served wrap the device does not know, and
    the next bullet decides. A keys read made while the request is on its way does not drop
    its pending wrap. When the server took the change, the device keeps
    exactly the wrap it sent, same salt and same cost, as its own. A pending record is
    never overwritten: before a second change is sent, the device reads the account's
    keys as an opening does and settles the first record against them; while they settle
    neither wrap, nothing is sent. A refusal drops only the wrap of the request that was
    refused.
  - **A served wrap the device does not know (NORMATIVE, every client; rules of 2026-11-16
    and 2026-11-17).** One rule holds for every client:
    - **Known** means the same salt, cost and wrap together: a served wrap is the device's own,
      or its pending one, only when all three equal that wrap's. Anything else is a served wrap
      the device does not know, a wrap whose cost alone changed included.
    - It is tried only at an opening with the full master password and the server
      reachable, at most once per opening (a second call in the same opening does nothing),
      and only when the served cost passes the whole fence every served cost must pass (the
      KDF-upgrade bullet below: not below the floor, not above the ceiling, a whole number
      of KiB). The device then derives from the password it holds under the served salt and
      cost.
    - It is taken only when it opens to exactly the account key the client already holds,
      compared in constant time. There is no exception. A pending record is then settled
      against it as against the device's own wrap. A client that holds no account key to
      compare with takes nothing: it says that the account's keys on the server are not the
      ones it knows and asks for a sign-in, which is where a device without such a key
      establishes one. An opening on a client that holds nothing to compare with at all (no
      key and no wrap of its own) is a sign-in, with a sign-in's checks: the identity it
      recorded for the address when it has one, the first card and the pinned card, and the
      whole fence on the served cost. It is not the taking this rule speaks of.
    - Nothing derived there is sent, and nothing of it outlives the opening.
    - A served wrap that fails the fence, does not open, or opens to another key changes
      nothing ("leaves both") until a later answer settles it. When the device's own wrap
      opened, the vault opens from it as at any opening. The device records on the session
      that the account's keys on the server are not the ones it knows, and while that mark
      is set, a proof the server refuses is worded as that.
    - **A proof the server refuses is never worded as a wrong password** (rule of
      2026-11-17), in any client, whether or not the mark is set: a wrong password is found
      on the device and sends nothing, so whatever the server refuses after that is not a
      wrong password. Without the mark it is said as the server's refusal of a proof that
      this password made after it opened the account here.
    - A quick unlock, an offline opening and an opening that puts the re-key off try
      nothing.
    - A client that holds the open account's key inside one run while it holds none between
      runs (`andvari-cli`) settles before it proves: after a quiet re-key that sent a change,
      whatever its answer, it reads the account's keys again and settles its session by the
      same open-and-compare before any further proof in that run; a proof the server refuses
      is never reported as a wrong password found on the device. At its reopen at the start
      of a run such a client holds no key: when the served wrap does not open with the typed
      password, it cannot tell a lie from a wrong password, and "wrong email, master password,
      or one-time code" is what is so.
    - Why this is safe: a server cannot make a wrap that opens to the account's own key
      without the password, so it can only hand back a wrap the person's own password made,
      and the device tells the server nothing. Without the rule, a server that answered
      "done" for a change it never stored, or stored a change and answered with a refusal,
      would leave the device proving every re-authentication under the wrong salt, refused
      as a wrong password until the person signs in again. What the rule does not change:
      an older wrap of the same account key opens to that key too, so a server that kept one
      can serve it to whoever knows the older password (spec 05 R33).
  - **A sign-in on a device that already keeps the account (NORMATIVE, every client that keeps
    one; rules of 2026-11-17).** A sign-in is where a device takes what passes a sign-in's
    checks, and that stands: it is the road back for a person whose password was changed on
    another device. What a device keeps for an account (an offline copy, a kept, locked or
    server-ended session, a pending password change) is replaced by a sign-in only when the
    account key the server's wrap opened is shown to be that account's key as the device knows
    it, before anything kept is replaced.
    - **How it is shown.** Where a wrap the device keeps (its own, then a pending one) opens
      with the typed password, the key it opens must equal the signed-in key, compared in
      constant time: that wrap holds this device's account key. Where none opens, the signed-in
      key must open what the device keeps sealed under the account's key (the kept identity
      seed, `Ad.idkey(userId)`), and the identity derived from it must equal the kept one. The
      device wrote that sealed record only after it opened it under the key it held then, and an
      authenticated open of a fixed ciphertext succeeds only under that same key, so a server
      without the key cannot make another key pass.
    - **When it is not shown:** nothing kept is replaced (keys, copy, pending wraps, the
      device's records), the new session is not kept, and the sign-in is refused: the server's
      keys are not this account's keys as this device knows them
      (`server_keys_not_known_here`). A typed-password open of a kept wrap that gives another
      key decides it; the sealed record is not tried after it.
    - **The same key under another master password signs in and says so:** when it is shown
      and none of the device's kept wraps opens with the typed password, the sign-in goes on,
      the device's copy then follows the server's wrap, and the person is told in one line,
      after signing in, that this device's copy was sealed under another master password than
      the one typed and now follows the server's. When a kept wrap opened, or the signed-in wrap
      is the copy's own or a pending one, nothing is said.
    - **What remains** (spec 05 R33): a server that kept an older wrap, and a person who types
      the older password into a sign-in on that device, bring the older password back on that
      device; the server gains nothing it could not do with that password already.
    - **The shared code** (`KeptAccountCheck`) runs the comparison right after the server's wrap
      opens, before any identity check, before the device's records are written and before the
      session reaches the keeper. A kept wrap at the first exchange's salt and cost uses the
      sign-in's own wrap key; one at another salt or cost costs one derivation, made before the
      login is sent while the password is still held, only when its cost passes the fence, and
      kept through a two-step code step and wiped after. The refusal is
      `SignIn.Refused(server_keys_not_known_here)`; the one-line notice is
      `SignIn.SignedIn.copyUnderOtherPassword`. It keeps nothing for an account held as its
      server's operator. `andvari-cli` keeps nothing between runs, so it has nothing to compare
      and is unchanged.
    - **The web client** compares after the sign-in's own checks (the login's salt and cost
      equal to the first exchange's, then the identity checks) by opening the copy's own sealed
      identity seed with the signed-in key (`openAccount`) and requiring the identity it gives to
      equal the signed-in one. A refusal (`keys_not_this_account`) writes nothing, and the copy
      and its waiting wraps stay as they were; it says `SIGN_IN_KEYS_NOT_THIS_ACCOUNT` ("The
      server's keys for this account aren't this account's keys as this browser knows them, so
      nothing was opened or changed here, and this browser's copy stays as it was. Contact the
      person who runs this server."). When it is shown, a signed-in wrap equal to the copy's own
      or a pending one costs nothing more; otherwise the typed password is tried on the copy's
      wraps, and when none opens, one line above every view, for that session only, says
      `COPY_FOLLOWS_SERVER` ("This browser's copy of your vault was sealed under another master
      password than the one you typed, and now follows the server's."). A copy that cannot be
      read is not compared, and the sign-in writes as before, since refusing there would leave
      no way back; a copy wrap whose cost is outside the fence cannot be tried, and then no line
      is shown.
    - **A sign-in the device refuses ends exactly the session that sign-in opened, and nothing
      else** (rule of 2026-11-17): every refusal after a login was answered ends the new session
      through the call that ends one session by its token (`POST /auth/end-session`, spec 03
      §2) and leaves the device's other sessions, the kept one included, alone.
    - **A device's record of its own id for an address is written only after the session it
      belongs to was taken**, and a refusal by the part of the shared code that keeps sessions is
      a refusal of the sign-in, said as that by the shared code itself (rule of 2026-11-17).
    - **The screens say the way out** (rule of 2026-11-17): where a sign-in is refused because
      the server's keys are not this account's, the screen says that nothing was changed on this
      device; that the person can contact whoever runs the server; and that, if they are sure,
      they can remove this account's copy from this device and sign in again, knowing that
      changes not yet sent go with it (design §4.4's rule for a copy deleted over unsent
      changes applies). And the apps say both results: the refusal, and the one line after a
      sign-in that the copy now follows the server's.
    - **An account deleted and made again under the same address** is refused on a device that
      knew the earlier one, as a security fault: that is what the binding is for, since a server
      that swaps an account looks exactly like this. The only way out is the person's own
      decision on that device (decided on 2026-11-17; design §4.4 "What a device remembers of an
      account"): the refusal says both possibilities (the account was deleted and made again and
      this device remembers the earlier one; or the server is not giving this device the account
      it knows, and nothing should be forgotten) and how to tell them apart, and offers "Forget the
      earlier account on this device" behind a second confirmation, never by itself and never set
      off by a server or an operator. Forgetting removes exactly the record that ties the address
      at that server to the earlier account and that account's copy on the device (its unsent
      changes counted first), keeps the server's pin and every other account, sends nothing, and
      leaves the address new to the device. Its guards (rules of 2026-11-17; design §4.4): a flow
      under way for that address blocks it from the flow's first step to its end (a sign-in through
      its two-step code, a registration from its ticket, both recoveries to their commit, a device
      link to its pickup, a request for the operator's help while the device keeps it); it is
      judged by the account, so it removes nothing that belongs to an account the device still
      keeps or has open, under this address or another of the same server, and never takes a kept
      account's identity record; it never touches an account held as the server's operator; and
      afterwards nothing of the forgotten account is left on the device, in any store. **What the
      shared code keeps (2026-11-18)** (`SessionKeeper.forgetEarlierAccount`, called only after the
      second confirmation, by the person's act alone): each flow holds the forgetting for its address
      from its first step to its end (a sign-in through its two-step code; a registration from its
      ticket to its answer, a refusal of a too weak password included, or until the person leaves
      the sign-up; a kit recovery from its start to its commit; a device link, for every address of
      that server, from its start to its pickup; a request for the operator's help while a confirmed
      target is in memory or a request is kept, across restarts), and a forgetting then answers that
      a flow is under way and removes nothing. A hold has no time limit: a flow that is dropped
      without its cancel holds the forgetting back until the app is started again. The forgetting is
      judged by the account's id: where the account the address is tied to is the one the device
      keeps (open; kept at another address of the same server, after a followed move included; or
      held as its server's operator), it answers "open for that account" and removes nothing. It
      removes the record that ties the address at that server to the earlier account; that
      account's identity record, only when no other record and no kept session names the same
      account; and, where the device keeps that account's copy locked at this server under this
      address, the kept session and its quick-unlock record, ended as at the person's own sign-out
      so that the app deletes the account's data. It leaves what the device knows of the server
      (its card and its pin), the device's own id for the address, and every other account, and it
      sends nothing. **Accepted as they are** (2026-11-18): a server can keep a request for the
      operator's help, and with it the hold, until the person cancels it; a forgetting at an old
      address of an account can land while a flow under its new address runs (it removes what a
      forgetting just before the flow would have removed). Setting aside a request for the
      operator's help at its target's confirmation ends its hold (nothing is kept at that step);
      at every later step the kept request still holds the forgetting (the shared code keeps this
      since 2026-11-18). **What else goes with it, and how it ends** (rules of 2026-11-18):
      everything the device keeps for that server under the earlier account's user id goes too
      (the contacts it confirmed, its code and link records, its vault checkpoints from a link, its
      quick-unlock offer, its recovery requests, a session record that cannot be read, and the
      rest): the deletion walks the registered per-server kinds of record that carry a user id,
      each decided as the account's own (deleted) or kept by the server alone or by an address
      (kept: the device's own row, a kept request, the policy), and a kind registered later and not
      decided fails a test. Otherwise a server that later serves the same user id would have them
      read as that account's, and contacts would count as confirmed that this person never
      confirmed. A sign-out keeps them, as before: there the identity record stays and guards them.
      **A forgetting that was begun is finished:** a lasting mark (the server, the address, the
      user id, the servers it was held at) is written before the call and goes only when the
      deletion is complete; at a start, and at a second tap, a mark is finished only where the
      address is no longer tied to that account and the device keeps no session of it, and is
      otherwise dropped with nothing deleted; a second tap then answers "forgotten", never
      "nothing to forget". Where the device stops between the forgetting's two removals, the
      identity record stays without the address's record, which is the safer side. **The
      confirmation names every copy that will go**, also one the device holds at another address
      or cannot read as its session, with "cannot be told" for what it holds unsent; a
      confirmation does not outlive a lock (a lock between the two steps takes it back, accepted
      as built); after "forgotten" the sign-in stands at its password step; "a request is kept"
      is said only when the kept request is for this address. No offer to forget stands beside a
      kit: after a commit whose session the device refused for the account's identity, the kit's
      screen comes first, and the offer comes at the next sign-in that meets the same refusal
      (accepted). A person whose device still keeps the earlier account, signed out by its
      server, meets two refusals and two confirmations: first the sign-out of the kept copy, with
      what cannot be told of its changes, then the forgetting; each is for one thing that is lost,
      and neither can be skipped (accepted). **What the app interface keeps (2026-11-19):** the
      offer is raised only on the part that keeps sessions' own refusal for an address it has tied
      to another account (a sign-in, a registration, a kit's check or commit, an answer of the
      operator's help, a device link's pickup), never for the account the device has open or keeps
      elsewhere, and goes at every new try on the screen; it carries both possibilities as
      sentences of their own, how to tell them apart, and a second step that names every copy that
      goes with what cannot be told of its changes; a lock between the two steps takes the
      confirmation back; nothing is sent. After "forgotten" it deletes everything kept for that
      server under the earlier account's user id, walking the registered kinds of record, writes
      the lasting mark before the call and finishes a forgetting that was begun; a session record
      that cannot be read goes with it where it names the earlier account or does not read at all;
      the sign-in then stands at its password step; and the next sign-in under that address says
      that a new account is remembered there, until dismissed (the mark for that notice lives in
      memory, so a restart before that sign-in loses the one-line notice). A flow the app interface
      drops ends its hold. Both apps draw the offer, its two steps and the notice as the shared
      code hands them since 2026-11-19: two buttons alike in weight, neither the default; the
      forgetting only from the person's own click on the second step, never tried again by the
      app; a call that throws leaves the second step on show; nothing of a confirmation carried
      across a lock, a change of screen or a restart. At a device link the shared code raises the
      offer only where its stop names the address, which it names only where the address is tied
      to ANOTHER account id than the one served (since 2026-11-19).
      **The offer is for another account only** (rules of 2026-11-19, which narrow the decision of
      2026-11-17 to its meaning): it is made only where the account the server serves now is
      another account, by its id, than the one this device ties the address to. Where the server
      serves the SAME account under another identity key, nothing is offered and nothing can be
      forgotten: that is the substitution the record exists to stop, and an account deleted and
      made again never comes back under its old id. Every place that raises the offer knows the
      served account's id or raises none; a refusal whose cause the device cannot tell apart raises
      none. Where the device holds a record of the served account's own identity key and the
      served key differs from it, nothing is offered, whatever the address is tied to: that
      comparison comes before the question which account the address is tied to. The offer and its
      confirmation are refused once the address is tied to the account the server serves.
      **The forgetting keeps the device's record of the earlier account's identity key** (its id
      and public key; nothing secret), kept with the server's records, so that it goes when the
      server itself is forgotten and with a deletion of that account that its server confirmed.
      The earlier account then never comes back on this device under another key, also after a
      forgetting: a server that first shows another account under the address, to obtain the
      forgetting, and then serves the old account with a key of its own is refused at that second
      step; the old account served again with its own key is taken as itself, and gets the offer to
      forget the new one (someone who forgot by mistake finds the way back). **What a forgetting
      by mistake costs, in every client:** the account served again under its own key is taken as
      itself, with its key still known; its memory of the account's state starts again, so a
      server can serve it an older state once without being caught; and its device row at the
      server stays listed while a new one is made. The forgetting removes
      the tie between the address and the earlier account, that account's copy, and everything else
      the device keeps of that account. The confirmation's last sentence stays as it is (if the
      account was not made again, forgetting means trusting whatever account the server serves under
      this address from now on). Changes to shared vaults that the earlier account signed and did
      not send go with it and are counted in what the confirmation says, or it says that it cannot
      tell, never "every change was sent" over a held change; no plate that tells the person not to
      enter the password again stands above the offer; a failed write of the device's own record
      during the forgetting is not answered "forgotten"; the notice that a new account is
      remembered is kept at rest with the server's records (it goes with the server's forgetting
      and with an account's deletion under that address, and is carried when the server's address
      moves) and shown until dismissed; a tab or a process that has an account open holds a lock
      for it, and a forgetting is refused while that lock is held. **Not kept yet (2026-11-19):**
      the keeper's forgetting takes the confirmed account as an optional parameter (the one caller
      outside tests passes it; it is to become required). **The identity fault where the same
      account is served under another key** (rules of 2026-11-19), kept since 2026-11-19 in the
      shared code and both apps: the results of a sign-in, a kit's check and a new account's making
      that are that fault carry the shared code's line for it themselves, which names both causes,
      and no app words it; the operator's answer for the kept account under another key ends as
      that fault, in its line, in place of the stage's own line: nothing is opened or committed, the
      request is kept (across a lock and a restart), nothing is offered to forget on any screen, and
      a later honest answer is still taken; the request is also kept where the answer is malformed
      or does not agree with itself (accepted); where a forgetting's confirmation is taken back
      because the address came to name the very account the server serves, its own answer says that
      nothing was forgotten because this device now knows the address as that account, with no
      offer; the stand-in plays a device link's end where the device cannot tell the two causes
      apart, and that screen offers the password sign-in its line points to, beside another link,
      on both apps. Closed on 2026-11-19: at a sign-in or a device link's password that
      asks for a two-step code, the desktop no longer says a refusal without wording while the
      screen asks for the code; in the shared code
      the notice's mark is kept at rest with the server's records, carried when the server's
      address moves, and the notice is raised again after a restart until dismissed; the
      confirmation counts the earlier account's signed changes to shared vaults that were never
      sent also where no copy of that account is held, says how many or that it cannot tell, and
      a change in the count while it is on show makes a new confirmation; the notice after a
      deletion that kept the server says only that the device still keeps something of another
      account at that server, never that it holds another account's copy there; the offer for the same account under another key at a recovery and at
      a sign-in with disagreeing records, and the forgetting's removal of the key's record.
      `andvari-cli` has its own command since 2026-11-19 (below). Under a policy that keeps the
      keys at the server, the unlock that asks the server for them opens the account through the
      same place as every take, which compares the served key with the device's record of the
      account's identity key and with the address's record and refuses the same account under
      another key as the identity fault (kept since 2026-11-19, with the policy's keys work).
      **The shared code keeps since 2026-11-19 (its fix):** the session keeper tells the two causes apart and each
      flow carries the answer up; every place that raises the offer raises it only for another
      account; the offer and its confirmation are refused once the address is tied to the served
      account; the forgetting keeps the record of the earlier account's id and public key under a
      key of its own with the server's records (it moves with the server's address, goes with
      "Forget this server", and goes when that account is taken again under its own key). At a
      device link the offer is raised in one place, the link's end, only where the stop names the
      address AND another account is served, never at the pickup and never twice. The keeper's
      forgetting takes the account the confirmation named and removes nothing where the address's
      record names another one by then (the person is shown the confirmation again with what
      holds now, or none); a forgetting cut after the address's record went is finished at the
      next settle or tap, the key first written to the record a forgetting keeps and the identity
      record removed only where no address's record on the device names that account and the
      device does not keep it (a store that cannot list its records leaves it); the forgetting
      after a deletion of unknown outcome leaves the address's record and the key's record. A
      device link stopped before its pickup on a device that holds a record of the linked
      account's key offers nothing, since no key can be compared there; its line is to be true of
      both causes and point to a sign-in with the password, where the device can tell and the
      offer is made; that line covers a stop at the approval, and the ask just before the pickup,
      where the engine cannot yet tell that stop from the pickup's own identity checks, ends with
      the identity fault's existing line, which is true of both causes and offers nothing. **A kept
      record of another account's identity key at a server counts as something of another account
      kept there** (rule of 2026-11-19): a confirmed deletion of the account taken in the earlier
      one's place then keeps the server and that record and says that the server was kept, so the
      earlier account served afterwards under another key is refused with no offer; otherwise that
      deletion would forget the server with the kept key and reopen the very substitution the record
      exists for. "Forget this server" by the person's own hand still removes every kept record of
      that server (the person's own act of making the server new to the device, said as that). A
      forgetting that was cut and is finished by a later confirmation naming ANOTHER account
      finishes the earlier one without a word and goes on to forget the confirmed one; it never
      answers "forgotten" for an account it did not forget. Every caller of the keeper's forgetting
      outside tests passes the account the confirmation named (the parameter is to become required).
      All of this is kept since 2026-11-19, with the test stand-in's two cases (a stale offer and a
      stale confirmation refused once the address is tied to the served account; the earlier
      account served under its own key while the address names the new one, which gets the offer to
      forget the new one) and the link's own end and line at the approval (a stop that names no
      address ends as an identity fault that cannot tell its cause, with a line of its own that
      names no account and raises no offer). The device link's stop carries, since 2026-11-19, a
      mark set only where the session keeper refused the link before its pickup (at the approval or
      at the ask just before the pickup: nothing was picked up and the server opened no session),
      and the stand-in plays the new end. **Not kept yet (2026-11-19):** the layer above does not read
      that mark yet, so the ask just before the pickup still ends with the identity fault's existing
      line, which is true of both causes and offers nothing, not with the line that points to the
      password sign-in. **The notice that a new account is remembered** (rule of 2026-11-19): one plain
      record names the address at its server (the address as typed, no id) from the forgetting
      until the notice is dismissed, the server is forgotten or the account under that address is
      deleted on this device, also where no account was taken after the forgetting; a sign-out and
      a sign-in under that address without a dismissal say the notice again. Kept in the shared
      code since 2026-11-19.
      **The web client keeps this since 2026-11-19** (its own implementation): it refuses an
      address it knows under another account at a sign-in, an unlock of a kept session, a held
      copy's opening, a registration (before anything is sent) and a kit's check; the offer is made
      only where the server answers for another account than the one the browser remembers under
      the address, never where the served account's own key record differs, not while the earlier
      account's session is kept in the browser (the refusal then says to sign out of it first, with
      the sign-out and its count on the same card), and not where the address's two records
      disagree; the forgetting, behind its second step, removes everything the browser keeps of the
      earlier account (the tie, every record under its id, its device row, its tab records, its
      copy, its held changes to shared vaults, counted or "cannot tell") except the record of its
      identity key, sends nothing, and keeps the server's pin and card; a forgetting cut short is
      finished at the next start; the notice afterwards is kept until dismissed, also where the
      forgetting finished late, and reaches tabs already open; a policy wipe's notice for the
      forgotten copy moves under a key of its own that names no account, and a wipe still owed is
      not run again for it; forgetting after a deletion whose outcome is not known keeps the
      address's record and the key's record. **The extension** (the owner's decision of
      2026-11-17 binds it as every client that signs in; rules of 2026-11-19) keeps, per server,
      which account each address is and each account's identity key, read only by its worker.
      - **What is kept, and how it is compared.** The key's record keeps the verified 32 bytes in
        one fixed (canonical) form, never the text the server sent, and keys are compared as
        decoded bytes, at the sign-in and at the quick unlock alike: a served text that decodes to
        the kept key is the same key, and a server does not get to choose what the browser stores
        (a key served with padding at a first sign-in would otherwise get the true key refused
        there later). **Any value present under a record's name counts as a record**, a stored
        null included; a value there that is not a record refuses that account with the identity
        fault's line until "Forget this server" (accepted as a limit; no code writes one).
      - **What is refused.** A password sign-in, its one-time-code step and the quick unlock by PIN
        or by biometrics refuse the same account under another key (the quick unlock compares the
        served key with the kept record after the seed's own check and before any sync: nothing is
        synced, nothing written, the quick-unlock record kept, and the honest PIN works again once
        the server serves the true key); a password sign-in also refuses another account under a
        known address, with both possibilities said and the sentence that says what forgetting
        means where the account was NOT made again. A read of the records that fails refuses at
        the password, the one-time code and the PIN, with a line of its own (the extension could
        not read what it remembers of this server; nothing was taken; try again, and where it
        keeps happening, restart the browser), takes nothing, writes nothing and advises no step
        that forgets the records; the next try that reads them signs in. A browser with no store
        cannot choose a server at all, so nobody is refused for good by a missing store.
      - **What is written, and when.** A record is written only where none exists, in one
        transaction, and never replaces one. The device's own record is written after the two
        checks made on the device (the seed's key, the kept records) and before the first request
        after the login, so the two refusals whose line says that nothing was changed come before
        it and the line is true, and an honest loss of the network at that first request leaves no
        extra device row behind. A refusal that comes before that write (an operator's account,
        damaged keys) leaves no device row named, so the next sign-in makes a new one: one more row
        per such refused sign-in (accepted as a limit).
      - **The session of a refused sign-in.** A sign-in refused for an identity reason ends at the
        server the session the server gave it, at the sign-in's own address with its own tokens,
        while the server's pin is in force and only where no session of that account is open; it
        never ends an open session of that account. A sign-in refused because the records could not
        be read does not end its session (the next sign-in on the same device row ends it; on a
        first sign-in it lapses), and each refusal of another account under a known address leaves
        one signed-out row for that account at an honest server (both accepted as limits). A quick
        unlock refused for an identity reason does not end its session at the server: that session
        is the account's own, on this device's row, and the kept record stays as the evidence
        (accepted as it is).
      - **How long the records live.** They outlive every sign-out, lock and "Remove data for this
        server"; "Forget this server" removes them with everything else of that server.
      - **The first sign-in after the update**, where no record exists yet, is taken as on a new
        browser, without a notice: trust on first use (accepted), as for the command-line tool's
        home from before its record.
      - **The way out: "Forget the earlier account on this device" in the popup** (rules of
        2026-11-19). It is offered only at a password sign-in or its one-time-code step refused
        because another account was served under a known address, and drawn at both; never for the
        same account under another key (keys compared as decoded bytes), never at a quick unlock,
        and never where the records could not be read (there it refuses and forgets nothing). Only
        the person can set it off, from the extension's own popup, behind the second confirmation:
        a web page, a content script or another extension cannot send it, and the worker decides
        which account from its own memory. The second step is taken only from a press that began
        a full second after the confirmation stood on the screen, or from a click that comes with
        no press (as assistive technology may send one) whose own time is a full second after it;
        the first step moves the focus off the button, so two clicks in one turn, a double click,
        a held key or a press begun inside that second forget nothing, and a click not taken says,
        above the confirmation, which stays, that the confirmation is to be read first. While the
        confirmation stands the popup keeps the worker awake (a passive status request every
        fifteen seconds, ended when the step is taken, at a new attempt or when the popup closes),
        so the offer is not lost while the person reads. It
        removes, at that server only, the record that ties the address to the earlier account and
        that account's own records (its item homes, its cached personal wrap, its memory of the
        account's state, its device record, its quick unlock), the quick-unlock record first,
        before the one removal in the trusted store, so that a failure in between leaves every
        protective record as it was; the line for a forgetting that failed says that the account's
        quick unlock may already be gone. It keeps the record of the earlier account's identity
        key, the server's pin and card, every other account and every other server; it is not the
        routine that forgets a server, and it sends nothing to the server. It ends every sign-in
        and quick unlock under way, and the offer is cleared at every later attempt, lock and
        switch; since an attempt that opens that account clears the offer first, no road reaches
        the refusal of a forgetting while a session of that account is open, and that refusal stays
        as a second guard. Afterwards records are written only through the write that never replaces, so the
        earlier account forgotten, a new one taken and the earlier one then served under another
        key ends as the identity fault with no offer. The confirmation also says that a login the
        person asked to save while the extension was locked is saved in the account that signs in
        next (as at any change of account; a filing in the wrong place at most, not a disclosure).
        The mark that the extension now remembers the new account is kept at rest with the server's
        records, as the apps keep theirs: the first sign-in under the address says it once and
        removes it, whether or not it could be read (the worker remembers which marks it said, so
        an unreadable mark is not said twice), and "Forget this server" and "Remove data for this
        server" remove it; a mark under an address nobody signs in with again stays until one of
        those, holding only the address, which the remembered address already holds. The offer
        itself lives in memory only, so a stopped worker answers that nothing is offered and a new
        sign-in raises the refusal and the offer again, and its line says so. **Its costs** are
        every client's (above): an account forgotten by mistake and served again under its own key
        is taken as itself, its key still known; its memory of the account's state starts again,
        so a server can serve it an older state once without being caught; and its device row at
        the server stays listed while a new one is made.
      **Kept since 2026-11-19:** all of the extension's paragraph above, and the same guard on the
      second step of the popup's "Forget this server" where logins or cards were caught and not
      saved: the first click says how many and moves the focus to that line, the second forgets
      only from a press, or a click that comes with no press as assistive technology sends it,
      begun a second after that line stood; a click not taken says to read the line first and the
      line stays; with nothing waiting it forgets at once. Before the
      records existed (until 2026-11-19), "Forget this server" was the only way on from a refused
      sign-in, and it stays the way to remove every record of that server, the kept keys among
      them, after which the extension takes whatever card, account and key that server serves
      next, as the same act does in every client.
      **In the web client, since 2026-11-19 a tab holds a lock of the browser's own for an account for
      as long as it has that account open** (shared between tabs, from the vault's opening until
      its closing at a lock, a sign-out, the server's end of the session or a deletion; the
      browser lets it go when the tab closes, reloads or crashes; nothing is written, so a full
      storage cannot hide an open account). A forgetting takes that lock for itself alone, only if
      it is free, and is refused while any tab holds it, with the same line as for a kept session
      (sign out of the earlier account first); the settling of a forgetting cut short at a start
      does the same and otherwise leaves its mark for a later start; a browser that has no such
      lock cannot tell, forgets nothing and says so with a line of its own. This closes the gap of
      2026-11-19 on a tab whose session write failed. The opening of an account does not wait for
      the lock: a tab that opens the account in the moment in which another tab's forgetting runs
      is not held back (the window is a moment long and loses no key; making the opening wait for
      the lock is listed as an option, not decided, 2026-11-19). **Not kept yet
      (2026-11-19):** the test of record kinds catches a new kind, not a new shape under a known
      kind. **Accepted** (2026-11-19): a change the server acknowledged in
      a vault frozen at that position is counted as sent.
      **`andvari-cli`** (rules of 2026-11-19, the owner's decision of 2026-11-17 binding the tool as
      it binds the apps): the tool keeps a record of each account's identity key, looked up for its
      own server, checked on every flow (a sign-in, a reopen, a registration, the kit's check, both
      recoveries and their commit, the operator's pickup, a device link at its pickup), and refuses
      the same account under another key with no offer; a refusal that comes after a recovery's
      commit says truly that the server has already taken the new password and the earlier kit no
      longer works. It keeps a record of which account an address is at a server, which outlives a
      sign-out and the server's end of a session, and goes with the forgetting (the key's record
      stays), with `forget-server` and with the tool's own confirmed deletion; the records and the
      comparison are the tool's own, with the shared code's rules (below). The command
      `forget-earlier-account --email` says what would go, one record to a line, unless `--yes` is
      given, keeps the key's record and the server's pin, and looks at a kept request for the
      operator's help under the address first; the mark that an offer was made is cleared when the
      address's account is taken or reopened; a lock on the tool's home is taken by every command
      that changes a session or a tie. A device link before its pickup names an account that comes
      from the showing device under the link's secret, which a server cannot forge: the tool stops
      there with the offer, and the record of the key decides at the pickup (accepted). A home from
      before the record trusts the first key it sees at its next run (accepted). **What the tool
      keeps (2026-11-19):** the record of each account's identity key, looked up at its own server
      (for a flow that names only the account, at the flow's server, else the command's; only
      where neither is known does any server's record count, the stricter side), compared on every
      flow named above, both recoveries' commits included, and the same account under another key
      refused with no offer; a recovery stopped at its check by the record says that nothing was
      committed; a refusal of the session a recovery's commit opened says that the server took the
      recovery, that the new master password is in force and the earlier kit no longer works, that
      nothing of the answer was used, no session is kept and no kit was written, to forget nothing
      and to tell the operator, never "before the server changed anything". Such a person then has
      no recovery kit that works for the account: they keep the new master password, which is the
      only way into the account, tell the operator, and make a new kit once a sign-in with that
      password is taken under the recorded key. A registration refused under a known address has a
      sentence of its own that speaks of no account served. The command `forget-earlier-account
      --email` exists: without `--yes` it lists every record it would remove, one to a line, with
      their count, and changes nothing; with it, it removes them, keeps the key's record and the
      server's pin, and answers that nothing is to be forgotten where no offer stands or where the
      refusal was the same account under another key (the record's fault, not a remade account:
      tell the operator). The mark that an offer was made is cleared when the address's account is
      taken or reopened. A device link whose pickup the server took while another account was kept
      here says that the server added and lists this device, that nothing was kept and its session
      was ended, and how to remove the device; never "nothing was linked". **Kept since 2026-11-19:**
      the record of which account an address is at a server (`cli.address|<origin>|<email>`, the
      account's id), written at the first session the tool takes there and outliving a sign-out
      and the server's end of a session, compared on every road after the key's record, another
      account there refused with both possibilities and the offer, and the session the server
      opened for it ended; the record goes with the person's forgetting, with `forget-server` and
      with the account's confirmed deletion at that server; the tool's own confirmed deletion
      forgets the server only where nothing of another account is kept there (the owner's
      decisions of 2026-11-18 and 2026-11-19), and says which happened; a kept request for the
      operator's help under the forgotten address goes with a forgetting and is listed in its plan
      (spec 05 R46). The tool cannot
      use the shared code's keeper for these records without replacing its own session layer (one
      kept session per device there, one per server here; records written only by a take; the key
      looked up per device where the tool looks it up at its own server; a tie that outlives a
      forgotten server, where the tool's must not), so its records are its own, with the same
      rules (decided on 2026-11-19). **For a change to a shared vault** (rules of 2026-11-19): the
      tool's lines for a change that got no answer say what is so (the tool never sends such a
      change again by itself), a vault's deletion that waits has two commands, `vault
      send-deletion` to send it now and `vault keep` to keep the vault, each sending only the
      deletion the person signed, only to that vault, and nothing once the vault was kept, and each
      saying that the vault was deleted where the sync that runs first finds the deletion already
      made; a deletion kept that the server had in fact taken is said as made after all; and the
      line for a change that waits reads the change's state, since a change the server's own answer
      called stored is not given up after a day. Kept since 2026-11-19: the lines for a change, a
      new vault and a deletion that got no answer, also where a held change stops a new one; `vault
      send-deletion` reads the vault's log first, sending nothing, and sends the deletion as it was
      signed only where that read reached the server and the vault does not hold it, and says the
      vault deleted where its log holds the deletion; `vault keep` withdraws it for good and, where
      the server may already have made it, says so and how to see it. Kept since 2026-11-19 too: the
      line for a change that waits reads the change's own state, with three cases: a change the
      server's own answer called stored, not yet read back in the vault's log, is sent again as it is
      before the next change until the log shows it and never given up; a change every send of which
      the server answered "slow down" is known not made, and is sent again before the next change
      within a day of when it was first kept, then not again; any other change may have been made,
      and is sent again the same way within that day; what was found about a change that waited is
      said once at the next signed-in run. **Not kept yet (2026-11-19):** the line for a vault's
      DELETION that waits still opens "No answer: the deletion … may have been made" also where the
      server's own answer called it stored. **A confirmed deletion removes only what belongs to its own server** (rules of
      2026-11-19): the address and the device's id are matched only in records of the deleted
      account's own server, and the account's id in every record except one that names another
      server (that server's word alone put it there), so the same address kept at another server
      keeps there its record of which account the address is, its saved session and its device
      record; a request for the operator's help kept for another address at that server counts as
      something of another account kept there, so the deletion keeps the server and that request.
      Kept since 2026-11-19, together with the record of which account an address is (before it, a
      confirmed deletion removed every record, at every server, that named the deleted account's
      address, account id or device id). The same holds for the person's forgetting of an earlier
      account. **What it cannot keep apart:** the shared code keeps some records of an account by
      its id alone (the account's stored state with its checkpoint and high-water marks, the vault
      logs' live mark, the recovery mirror); two servers that name the same account id share them on
      the device. Since 2026-11-21 the apps' ends take them only where nothing at another server ties
      the account (below, "One account id at two server addresses"), and the tool's `forget-server`
      does too, through the shared code; **not kept yet (2026-11-21):** the tool's own confirmed
      deletion and its forgetting of an earlier account still remove them without reading that tie,
      so the other server's next read is then a first sight (spec 05 R46). Account ids are random and
      made by the registering client, so only a server that names an id it learned elsewhere
      reaches this. **One account id at two server addresses on a device** (rules of 2026-11-19 to
      2026-11-21; kept in the shared code since 2026-11-21; design §3.11 has each point): a
      sign-out, a confirmed deletion and the forgetting of an earlier account at one server take what
      is held there and at its former addresses, and "Forget this server" what is held there; the
      same account id held at another server keeps its copy (with what waits in it unsent), its
      entry among the held accounts, its per-server records and its name. The records kept by the
      account's id alone, its identity record among them, go only where nothing at another server
      ties the account, as one function decides for every end, read once before anything is removed:
      an address record there naming the account (or one that cannot be read, or names no account);
      any record there kept under the account's id; a record there for the same address, unless
      that server's own address record for it names another account, and, for a device's row,
      only where it holds a device id or cannot be read as one; a store that cannot list its
      records ties. The session keeper's record of an own end names its server and its reason, and
      the forgetting's mark keeps the tie it read. **The limit:** where one account id is served at
      two addresses, the records kept by that id alone are shared by both on the device. **The sweep
      of accounts the device no longer knows** (rule of 2026-11-21; kept since 2026-11-21 in the
      shared code's app engine, which the phone and the desktop app run, `AccountSweep.kt`;
      design §3.11 has each point; **not kept yet (2026-11-21):** `andvari-cli` has no sweep, R46): every record kept by the id of an
      account the device knows nowhere goes, whatever the tie said when something ended (the
      identity record, which goes last, the stored account state with its marks, the vault logs'
      records, the item engine's records, the recovery mirror, the escrow mark). An account is known
      while a session is kept for it (by this process's keeper, or in the secure store now), a copy is
      held for it at any address, an address record at any server names it, or something of it is in
      flight (an end of the person's own not yet settled, a forgetting not finished, a deletion whose
      outcome is not known); the record a forgetting keeps of an earlier account's key at its server
      stays and makes no account known, and a device's row names an address, not an account, so it
      makes none known either. It runs at every start, after the settling of own ends and of
      forgettings, and at the end of a confirmed deletion, of both forms of "Forget this server" and
      of the forgetting of an earlier account. It removes nothing where the store cannot list its
      keys or where one of the records it decides by cannot be read or does not parse as its form:
      the session record, the list of held copies, an address record, the record of own ends, the
      forgetting marks, a mark of a deletion of unknown outcome. A take writes the address's record
      before the identity record (`SessionKeeper.establish`), so no moment of a take leaves a record
      kept by the account's id that nothing names, apart from a registration the session keeper
      refused (spec 05 R48 (c)). **A deletion stopped part-way** (since 2026-11-21, spec 05 R48 (f)):
      a deletion its server confirmed writes a mark of a deletion begun (the server, the account,
      the address it was known by there, the tie and whether another account was known there, as
      read before anything was removed) before its first removal and removes it after its last; a
      start finishes what a mark names by the deletion's own steps, its server's pin included. A
      take at that server of the deleted account, or of any account under that address, removes
      the mark before the take writes anything of its own, and nothing is removed for a mark that
      ended; a take there of another account under another address, or of the same account at
      another server, leaves it, and the finish then leaves that account's records, the server's
      pin while the device knows another account there, and what the account keeps at its other
      server. A stop at the mark's own write leaves the device as before the deletion, while the
      server has deleted the account: the device keeps a session its server no longer knows. A
      record of deletions begun with an entry that does not read, or that does not read at all, is
      written again at the start from the entries that read, which are finished, with a diagnostic
      line that says how many were dropped; nothing is removed for a dropped entry. Its limits are in spec 05 R48. **The lock on the home is kept since 2026-11-19:** every command holds the
      system's lock on a file in its home from before it reads anything there until it ends, also
      one that only lists, so a script's commands run one after another; a second command in the
      same home waits ten seconds, or the wait a setting names, sixty at most and never endless,
      then stops with exit code 8 and a sentence of its own, having sent and changed nothing; the
      system drops the lock when the process that holds it ends in any way, so a lock left by a
      killed process blocks nobody. With it came the tests of the commit of a recovery with the
      operator's help under another key, of one taken while the home began keeping another
      account, and of a refresh whose answer is lost inside one run.
    - **A recovery, with the kit or with the operator's help, on a device that already keeps the
      account** (rules of 2026-11-17). The person has lost the password, so no kept wrap can be
      opened or compared: here the sign-in's rule gives way, and both the kept wrap and a pending
      one are replaced. It does not give way on what is sealed under the account's key itself:
      the recovered key must open the kept copy's sealed identity seed (`Ad.idkey(userId)`) to
      the kept identity key. Another key stops as `server_keys_not_known_here`: no commit is
      sent, no session exists, nothing kept changes, and a request for the operator's help stays
      as it was. A kept copy whose seed does not open always refuses; the way out is to remove the
      copy first, which says how many changes were not sent (design §4.4). The check is made
      before the person is asked anything (for the kit, right after the kit opens the key; for
      the operator's help, at the pick-up) and again before the commit is sent. The shared code
      does this (`KeptAccountCheck.recoveredKeyIsKept`).
    - **A device link on a device that already keeps the account follows the sign-in's rule in
      full** (rule of 2026-11-17): the kept keys are made ready before anything is derived for
      the pickup, and the comparison is made after the wrap opens and before the account is
      opened; another key stops (`server_keys_not_known_here`) and replaces nothing; the same key
      under another master password links and says so in one line
      (`NewStep.Linked.copyUnderOtherPassword`). The shared code does this.
    - **A floor under every flow** (rules of 2026-11-17): for the same account, the part of the
      shared code that keeps sessions takes a new session only when its key is shown to be the
      kept account's key. A sign-in whose own comparison held (a kept wrap that the typed password
      opened to the same key decides, as above) is taken also when the kept copy's sealed identity
      seed cannot be opened, and the seed is then written again from the session that was
      verified: a damaged copy is repaired by a sign-in with the right password, as before. Where
      no wrap could be compared (a recovery, a device link on a copy sealed under another
      password, a flow that compared nothing) the key must open the kept seed, and a session
      whose key does not is refused there (`server_keys_not_known_here`). There a copy whose seed
      does not open is refused, and the screen says the way out: remove this device's copy (which
      first says how many changes were not sent, or that it cannot tell), then sign in or recover.
      Whatever flow brings a key, design §4.4's rule holds beside it: no copy is replaced over
      changes that were not sent without the person being told.
    - **A repair is held to the identity the device knows** (rules of 2026-11-17): before a take
      over a kept copy writes anything (the repair of a damaged seed, and every other take, since
      each rewrites the stored record), the session's identity key must equal, in constant time,
      every record of it the device has: its own record of the account's identity, and the copy's
      own where it can be read. Another identity is the identity fault
      (`self_identity_mismatch`): nothing is written and the session is ended alone. A device with
      no record at all stands where a new device stands, and the take goes on. A device link's
      pickup hands the identity the device knows to its own opening, so another identity stops
      there already.
    - **"This device's copy is damaged" is said only of a copy that does not open** (rule of
      2026-11-17): the judgment reads a kept text with the same decoder as the opening, so a text
      the opening accepts is never judged unreadable, and a sign-in, recovery or link over a copy
      that opens is compared, never told that the copy is damaged.
    - **Account-key texts are taken only in their canonical form** (rule of 2026-11-17;
      design §2.2's strict decoding, kept at every take): the base64 texts a server serves for an
      account's keys (the salt, the wrapped account key, the sealed identity seed, the personal
      vault's wrap; the identity key and the genesis record were already read strictly) are
      checked to be canonical before anything of them is stored. One that is not is the server's
      fault: a sign-in, a registration and both recoveries' commits refuse it as an answer that is
      not the session it must be (`bad_response`), a device link stops as it stops for every such
      answer (`IDENTITY_MISMATCH`), the part that keeps sessions keeps nothing, a served wrap is not
      adopted at an opening and a password change's answer is not kept; in each case the session
      is ended alone and the copy still unlocks. A server could otherwise serve a valid seed in
      another spelling and have a healthy copy judged damaged.
    - **The key that proves a password is wiped on every way out** (rule of 2026-11-17), a
      cancellation of a device link's last step included.
    - **An answer to a request for the operator's help that names another account** (rule of
      2026-11-17): when this device keeps an account at the request's server under the request's
      address, or knows that address there as another account, an answer whose account is not
      that account is refused at the pick-up, before the person is asked anything and before
      the question of whether this device would take the account: no account is shown to check,
      no password is asked, no commit is sent, the request stays, and the refusal says, with a
      reason of its own, that the answer names an account that is not the one this device keeps.
      Whoever holds the operator's recovery key can make such an answer, and that holder is inside
      what the design guards against.
    - **A refusal reaches the screen as what it is, on every road** (rule of 2026-11-17): "the
      server's keys are not this account's as this device knows it" is never told as "another
      account is kept on this device", nor as a general failure, whether the flow or the part
      that keeps sessions refused; a kit whose identity does not match at its check is an
      identity fault, not a general failure.
    - **A refused session is ended alone** (rule of 2026-11-17): by its own refresh token
      (`POST /auth/end-session`, spec 03 §2), never by the logout, which ends every session of
      the device at that server. This holds for every refusal after a login, a kit commit, an
      assisted commit or a device-link pickup was answered, and for the session of a call the
      person left. **A device has one live session at a server, and the server keeps that rule
      itself** (rule of 2026-11-17; spec 03 §2): a kept session whose place a new sign-in of the
      same account takes on the same device is ended by the server when it gives the new session,
      and the client sends nothing of its own to end it (after a refresh whose answer was lost,
      the token the client holds is one the server has already replaced, and sending it would be
      taken for the reuse of a stolen token). A recovery's commit ends every session of the
      account at the server (spec 03 §12, §18.5). A device link's pickup makes a new device record
      and ends nothing of the old one, so there the client still ends the kept session by its own
      token. The shared code ends refused sessions alone; a refusal by the part that keeps
      sessions is the sign-in's own answer
      (`SignIn.Refused(another_session_kept)`, `SignIn.IdentityFault(self_identity_mismatch)`,
      `SignIn.Refused(server_keys_not_known_here)`), and the device's record of its own id is
      written only once the session was taken.
    - **A recovery, a registration or a device link on a device that keeps ANOTHER account**
      (rules of 2026-11-17), or an account at another server, or its server's operator account:
      - **It stops before anything is committed at the server, at every step where the device
        can know.** The part that keeps sessions is asked whether it would take this account at
        this server, and a no stops the flow with nothing sent, nothing derived for the server
        and nothing kept changed. Where it is asked: a kit recovery at its start, by the server
        alone (before anything is sent), again after the kit's check is answered (before a new
        password is asked) and again just before the commit; a recovery with the operator's help
        at the pick-up (before the account is shown to check, the request kept) and again just
        before the commit, and not when the request is opened, since a request may be answered
        after the other account was signed out; a registration, of every kind of link or ticket,
        before its key derivation and again just before it is sent; a device link at its start, by
        the server alone (before the claim), again once the link names the account (before the
        password is asked) and again before every pickup. The answer cannot be turned by a server
        or by a link's content: the kit's account id is bound by its wrap, a link's inside its
        authenticated outer part, a registration's is made on the device; an answer of the
        operator's help is first held to the account this device keeps for its address (above).
        `andvari-cli` keeps one account per server on a home, and stops a request for the
        operator's help on a home that keeps another account at that server already at the
        request, before anything is sent: there a wait could only end in a refusal on that home,
        while in the apps the kept account can be signed out during the wait from the same screens.
      - **A refusal after a commit hands the new kit over, and the kit reaches the screen.** When
        what the device keeps changed while a flow was under way, a recovery's commit or a
        registration may stand at the server when the session is refused: the new password is
        then in force, the new kit is the only one, and the old kit no longer works. The flow
        hands the new kit to the caller with the refusal, with the reason the part that keeps
        sessions gave (never one guessed from addresses); the screen shows it with the refusal
        in words that are true of a committed change (the new password is in force, or the
        account was made; the old kit no longer works; the account opens with that password once
        the way out the refusal names is taken), and the same holds for a recovery with the
        operator's help, whose result never says that a request the server has used is kept. A
        device link that is refused after its pickup keeps nothing: the link is spent and the
        password unchanged.
      - **How long such a kit holds, and what takes it off the screen** (rules of 2026-11-17).
        The device cannot tell the server that the kit was typed back, so the next sign-in to
        the account, on any device, shows a new kit that replaces this one; the line beside the
        kit says so (keep this kit until you next sign in; you will then be shown a new one, and
        this one stops working). The kit is wiped when the person has typed it back, and by a
        lock, by hand or by the idle limit, on every road, whether or not another account's
        session is established at that moment: a secret on the screen of a device nobody may be
        watching must not outlive a lock. While such a kit is on show in a flow with no account
        open, the app's idle limit is that of the browser's kit screens: five minutes without a
        touch or a key (the pointer's movement does not count), with a warning thirty seconds
        before; at its end the app locks, which wipes the kit. It never goes unsaid: the screen
        the person comes back to says that the recovery kit that was on the screen is gone,
        that the change itself stands (the new master password is in force, or the account was
        made), and that the next sign-in with that password, on any device, shows a new kit. On
        the roads where this device itself cannot take the account now (another account kept, a
        fault of the account's identity, the server's operator account held here) the notice does
        not say "on any device": it says that the next sign-in to that account shows a new kit,
        and the refusal's own line says what stands in the way here. The notice goes only when
        the person dismisses it; nothing else clears it, neither the opening of an account (a
        quick unlock included) nor a start of the app. The same is said when the app was closed
        with such a kit on show, where the device can know it at its next start without keeping
        anything of the kit: a mark at rest that holds the road (a recovery or a registration),
        the address and the name of the refusal's line while that refusal still stands, never
        anything of the kit, and that stays until the notice was dismissed; at a restart the
        notice says what stood when the mark was written and is not judged again. **An ordinary
        kit on show, with its account's keys open,** is covered by the app's own lock at the
        policy's time: the lock wipes it, and the next unlock makes a fresh one; the five minutes
        above are the limit where no account's keys are open and no policy applies. **Every kit
        in the journey has its limit and its warning from the shared code** (rules of
        2026-11-18, which complete the sentence before: an app cannot see the policy there): the
        lock time of the policy the device keeps for that server, five minutes where it keeps
        none, never more than five minutes for a kit shown with a refusal; and a warning thirty
        seconds before, shown from the start of the screen where the limit is not longer than
        that. A kit that replaces one shown before and not confirmed says on its first step that
        the earlier one no longer works and must not be kept, from a record that a kit was shown
        and not confirmed (kept per server and address; it goes with the server's forgetting, the
        account's deletion on the device and the forgetting of an earlier account for that
        address, and is carried when a server's move is followed); and an unlock for filling, from
        a surface that cannot show a kit, makes no kit and sends nothing about one. What both
        apps do with a kit on show is in design §10 ("Every kit on an app's screen"). The kit's
        text form (its groups and its code as strings) cannot be overwritten in memory, only
        dropped; its secret's bytes are zeroed (accepted). **Not a lock:** the refusal of some other session during the call, and
        the end, the sign-out or the removal of another account kept on the device; the kit stays
        on show above what the flow shows next. `andvari-cli` prints the kit and ends, so none of
        this applies to it.
      - **What the app interface keeps (2026-11-18):** a lock, by hand or by the idle limit, wipes
        such a kit on every road, with or without another account's session established, and
        sets the notice, which goes only with the person's dismissal; a start after the app was
        closed with such a kit on show says the same notice from the mark at rest; the end, the
        sign-out or the removal of another account kept here leaves the kit on show; the refusal
        of another session during the call leaves this call's own session and kit (each commit's
        own answer decides, not a count of refusals); a commit that happened and could not be
        opened is said as that, also when another session was refused during the call; the line
        beside the kit says how long it holds; and for a kit shown with a late refusal it hands
        the apps the idle limit (five minutes) and the warning line thirty seconds before.
      - **Kept since 2026-11-19:** the shared code hands every kit its limit and its warning as
        above (a policy may give as little as one second; the warning's line names no figure),
        keeps the record that a kit was shown as a record of its server (a followed move carries
        it; the server's forgetting, the account's deletion on the device and the forgetting of an
        earlier account for that address remove it), says on a kit's first step that it replaces
        one shown before, and has the unlock for filling that makes no kit, whose opening ends with
        every end of the session. Both apps draw such a kit with its results, its line and the
        notice; the desktop app since 2026-11-19, with every kit's limit and warning taken from the
        kit itself (a kit made in Settings over an open vault too).
        The Android app uses the unlock for filling from its autofill window and locks first where
        a kit is due when its own window comes on show, and a kit made in its Settings runs from the
        kit's own limit (2026-11-19). The app interface says a kit made while the app was away and
        wiped unseen as never shown, once the app tells it that it left the screen without a lock
        (2026-11-19).
      - **Kept since 2026-11-19 in both apps:** each tells the shared code when nothing of it is
        on show without a lock (Android: the background, the print screen, the autofill window
        closing; the desktop: its window minimised or hidden, not another application in front
        while the window stays on the screen), and at the return a lock that fell due comes
        first, before the shared code is told that the app is back; a kit made while the app was
        away and wiped unseen is then said as never shown; the warning for a short lock time is
        drawn from the kit's filled line, never the bare key.
      - **Each stop is said as what it is**, at every place that can show it: "this device keeps
        another account: sign it out first", with the sign-out saying how many changes were not
        sent (design §4.4); the identity fault for an address this device knows as another
        account; and, for a device that holds its server's operator account, that this device
        holds the operator's account of a server and that it must be removed from this device
        first, never "another account is kept", with a reason of its own, also when the flow is a
        recovery of that very account.
      - **A register link's flow is ended when its registration stops**, so its secret is not
        kept in memory after that.
    - **What is kept (2026-11-17).** The shared code asks the part that keeps sessions at each
      step named above and stops before any commit; hands a recovery's or a registration's new
      kit up with a refusal that comes after a commit; ends a registration whose session is
      refused instead of going on; ends a register link's flow when its registration stops;
      refuses at the pick-up an answer of the operator's help that names another account than
      the kept one; repairs a damaged copy at a sign-in with the right password, held to the
      identity the device knows; takes account-key texts only in their canonical form; ends
      every refused session, and the session of a call the person left, alone by its refresh
      token; and sends nothing of its own for a kept session that a sign-in replaces (the server
      ends it, spec 03 §2). The older account road of the shared code (`SessionEntry`, the
      unlock ladder) takes served account-key texts only in canonical form too (2026-11-18). The
      app interface tells each of these stops and refusals as what it
      is (another account kept; the identity fault; the operator's account held here; this
      device's copy damaged; an answer that names another account; a refusal after a commit,
      with the keeper's own reason and the words that the commit happened), shows the device
      link's one line, and hands the device link the call that ends one session. A
      registration's refusal after its commit is told by the keeper's own reason, never by a
      guess: another account kept; the server's operator account held here, whose way out is its
      removal, not a sign-out; or a fault of the account's identity, with a sentence of its own
      (2026-11-18). The browser
      ends only the session its own sign-in's call was given, and says the way out in full.
      `andvari-cli` asks the same questions through its own record of what a home keeps, stops
      a sign-in to another account on a home that keeps one at that server before anything is
      sent, says each stop in its own sentence, and ends a refused session alone.
      Both apps draw what the app interface hands up after a refusal that came after a commit
      (the sentence, the kit, then the first screen; the desktop app since 2026-11-19), and the
      desktop app's way out beside a stop, under a notice and on the request for the operator's
      help is the shared code's act for that cause (2026-11-19). `andvari-cli`, where a recovery
      or a registration that the server took meets a session its home did not keep (what the home
      keeps changed meanwhile), writes the account's kit to the file given, or shows it, or prints
      it rather than lose it, says that the change went through and why nothing is signed in, and
      ends exactly that session at the server (2026-11-19).
    - **Not kept yet (2026-11-18):**
      - the Android app's way out beside a stop, under a notice, on a device link that ended and
        on the request for the operator's help is the shared code's act for that cause since
        2026-11-19, which closes the gap of its own reading; under the notice that a kit is gone
        both apps offer a way out only while the kept session's mark equals the one the notice
        names (the marks are compared, never shown or kept), and the desktop offers there again
        the removal of this computer's damaged copy, behind its usual two questions (since
        2026-11-19, which closes the desktop's gap of that day);
      - "another account is kept" after a commit is to have a line of its own that does not say
        "nothing was changed";
      - the apps' sentences for these stops are placeholders awaiting their words.
- **KDF upgrade (F61, normative)**: after every successful **full-master-password**
  unlock with server connectivity, the client compares the account's stored
  `kdfParams` against the current policy's `kdfParams`
  (`GET /client-policy`) and, when an upgrade is due, **silently re-keys with the
  password it just verified**: re-derive MK′/authKey′/wrapKey′ under the policy
  params (fresh 16-byte salt), re-wrap UVK, and perform the same atomic
  `PUT /account/password` — the password itself is unchanged and the user is not
  prompted. Rules:
  - **Upgrade-only, never sideways or down.** An upgrade is due iff policy params
    are > the account's on at least one cost axis (`ops`, `memBytes`), with
    `policy.v ≥ account.v` (rules of 2026-11-17 and 2026-11-18, which replace "≥ on both, > on
    one"): the account is below the served cost on any figure. A
    mixed policy (one axis up, one down) raises the axis that is up and keeps the other at
    the account's own; policy params that are lower on both MUST NOT trigger a re-key, and
    no re-key ever lowers an axis — the policy JSON comes from
    the server, and a compromised server must not be able to talk a client into
    weakening its own KDF (spec 05 T1). When a re-key is made, its cost follows §7's
    rule "Every new wrap is made at a cost the server will take" (rule of 2026-11-17):
    figure by figure the higher of the account's and the policy's, so it never lowers
    either axis. **Below the floor on any figure, a re-key is due** (rule of 2026-11-17):
    an account whose cost is below the server's floor on either figure is raised, whatever
    the other figure, since the policy the server serves is never below its floor
    (spec 03 §7.2) and the server applies its floor to each figure by itself; the re-key takes the
    higher of the two on each figure, so it still lowers nothing. **What the shared engine
    keeps (2026-11-18):** on the new engine the quiet raising is due when the account is below
    the served cost on any figure, and the new wrap takes, figure by figure, the higher of the
    two, inside the client's fence: after a served cost of fewer passes and more memory the
    account stands at its own passes and the served memory, after one of more passes and less
    memory at the served passes and its own memory, one change is sent each time, and the same
    password opens the account on the next opening and on a second device. The older road the
    iPhone app runs on keeps "at least as high on both figures, higher on one". **Not kept yet
    (2026-11-18):** when a re-key is due is unchanged in the web client (a policy at least as
    high on both figures, higher on one), so there an account above the floor on one figure and
    below it on the other is never raised quietly; once a password
    change or a recovery makes a new wrap for it, that wrap takes the higher of the two on each
    figure (§7), and the server refuses a new wrap below its served cost on either figure
    (spec 03 §7.2).
  - **Client-side sanity bounds.** Regardless of policy, a client MUST refuse to
    re-key to `memBytes < 67108864` (64 MiB — the §9 floor) or `ops < 3`, and
    SHOULD refuse absurd cost inflation (`ops > 10` or `memBytes > 1 GiB`) — a
    hostile policy must be able to neither weaken the KDF nor turn every unlock
    into a memory-exhaustion DoS. A memory cost that is not a whole number of KiB
    (`memBytes % 1024 ≠ 0`) is never a re-key target. **The whole fence (floor, ceiling
    and whole KiB) applies to every hashing cost a server serves, before anything is
    derived at it, in every client** (rule of 2026-11-17): the sign-in after the first
    exchange (prelogin), `andvari-cli`'s reopen, the web client's unlock on every path,
    and the try of a served wrap the device does not know (above). The server refuses such
    a cost (`kdf_mem_not_kib_multiple`), and the Argon2id engines round it differently, so
    a wrap made at one could open on one client and read as a wrong password on another.
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
  - **What each client does today (2026-11-17), client by client.** The quiet re-key, and
    the rule above for a served wrap the device does not know:
    - **The app engine (the Android and desktop apps).** After an unlock or a sign-in with
      the master password, once the vault is open and inside the same opening,
      `SessionKeeper.reKeyAfterOpening` reads the account's keys, settles a pending change,
      tries a served wrap it does not know by the rule above (known only when the salt, the
      cost and the wrap all equal the device's own or its pending one; otherwise the fence
      with the whole KiB, then the comparison with the open account key, in constant time),
      then reads `GET /client-policy`, applies the upgrade rule above (the whole-KiB rule
      included), keeps the new wrap as pending before the `PUT`, and settles the answer by
      the pending-record rule; the proof is the in-session proof against the device's own
      wrap. A second call in the same opening reads nothing, derives nothing and sends
      nothing (`ReKeyOutcome.ALREADY_RAN`). Every served cost passes the whole fence before
      anything is derived at it (the sign-in after the first exchange, the unlock of the kept
      cost, the session's proof, a device link's pickup, the reopen of served keys), and a
      cost outside it is the server's fault, never a wrong password. After a server's lie,
      the next unlock takes the served wrap and re-keys in that same opening. An opening that
      must first make a recovery kit (one was never saved) does not re-key; the next
      full-password opening, with the kit saved, looks again. The Android autofill overlay
      puts the re-key off (`FastUnlock`) and tries nothing. A held session that a host keeps
      itself settles a served wrap by the same open-and-compare
      (`EstablishedSession.settleServed`). The shared code tells a server's
      `403 reauth_failed` to a proof apart from a wrong password found on the device (its own
      refusal code, `Reauthed.PROOF_REFUSED`), and while the mark (`serverKeysNotKnownHere`)
      is set, every action that proves the master password answers that the account's keys on
      the server are not the ones this device knows (`KEYS_NOT_KNOWN_HERE`), with a sentence
      that asks the person to sign in again on this device.
      Without the mark, the app interface gives the server's refusal of a proof made on the
      device a result of its own on every action that sends a proof (`PROOF_REFUSED`: the
      server refused it although this password opened the account on this device, so it is not
      a wrong password; nothing changed), and a wrong password found on the device stays a
      wrong password. **Not kept yet (2026-11-17):** a served wrap it did not take is not shown
      to the person when the vault opens.
    - **The web client.** After a sign-in or an unlock with the master password that
      reached the server, inline before the vault is shown, through its one password change
      (`quietReKey`), with the same pending-record rule; an unlock from the offline copy or
      from a read-only copy never counts. The web has no quick unlock (§8.3). It holds no
      account key before an unlock, so what it compares with is the offline copy: its own
      wrap and the wraps pending beside it. **What a served wrap must satisfy to be taken:**
      it equals the copy's own wrap or a pending one (salt, wrap and cost: known), or it
      opens under the typed password to exactly the account key that the copy's own or a
      pending wrap opens to, compared in constant time; either way its cost passes the whole
      fence first and the account passes the identity checks of every unlock (the pin, the
      genesis, the identity recorded for the address). **When it does not:**
      - the typed password opens the served wrap and none of the copy's: nothing is taken,
        written or sent, and the unlock says that the account's keys on the server are not
        the ones this browser knows and offers a sign-in, with the address filled in;
      - the copy's own or a pending wrap opens and the served one fails the fence, does not
        open, or opens to another key ("leaves both"): the vault opens from the copy, nothing
        is written to the copy and its pending wraps stay, the session carries the mark, no
        quiet re-key runs, and a line above every view says so.
      **What it holds at an unlock, read three ways:** no copy (the copy off, or on with no
      keys written yet: an unlock with nothing to compare, which is a sign-in with a
      sign-in's checks: the whole fence first, then the password, then the identity checks);
      a copy that cannot be read (its keys row there but not a usable key set, or a database
      that does not open or a read that fails: nothing is derived, and a sign-in is offered);
      or a copy, compared as above. **The whole fence** (floor, ceiling, a whole number, a
      whole number of KiB) applies to every served cost, at every wire boundary that brings
      one and before every derivation; a cost that is not whole is said as the server's
      fault, apart from the weak-settings words for a cost below the floor or above the
      ceiling. **The mark is read:** while it is set, a proof the server refuses
      (`403 reauth_failed`) is worded as the server's keys not being the ones this browser
      knows, never as a wrong password, for every action that sends a proof (the password
      change, a new kit, a device's removal, the device-link setting, both recovery settings,
      keeping the copy at the unlock's question, the account's deletion, and turning two-step
      sign-in on and off). **The salt and cost it writes are pinned:** a sign-in refuses a login
      whose `accountKeys` salt or cost differ from the first exchange's (the salt compared as
      bytes, in constant time; the cost on every field), before the account key is opened,
      saying that the server's answer did not make sense, with nothing written and nothing more
      derived from the password sent. **Wherever the browser writes keys that came back from the
      server it pins them the same way** (rule of 2026-11-17): the answer to a kit recovery and
      the answer to a registration are compared with the salt and cost the browser sent before
      anything is written, as the shared code does at both. The browser keeps this since
      2026-11-17: at a kit recovery's commit and at a registration, an answer whose salt, cost
      or wrapped key is not the wrap the browser sealed and sent opens and writes nothing, its
      session is ended as at a sign-in, and the person reads the sign-in's sentence for the
      same fault.
    - **`andvari-cli`.** It holds no key between runs, so it opens what the server serves
      at every run under the checks of a sign-in (the account's genesis against the pinned
      card among them), and that stays. After a reopen and after a password sign-in it calls the engine's routine
      (`EstablishedSession.reKeyAfterOpening`). **It settles before it proves:** after a
      re-key whose outcome may have sent a change (done, refused or unknown), it reads the
      account's keys again and settles its session with the engine's own open-and-compare
      (`EstablishedSession.settleServed`): a served wrap whose salt, cost and wrap all equal
      the session's own or pending one is known and is proven against with no derivation;
      any other served wrap passes the whole fence, is opened with the typed password under
      its own salt and cost, and is taken only when it opens to exactly the account key the
      run holds, compared in constant time.
      Anything else (no answer, a cost outside the fence, a wrap that does not open or opens
      to another key, keys that are not this account's) refuses every later proof in that
      run before anything is derived or sent. **The whole fence on every served cost:** every
      answer that brings a cost (the first exchange of a sign-in, the account's keys, a
      session, a device link's pickup) is fenced as it is read, so nothing is derived at a cost
      outside it; the reopen no longer falls back to a sign-in for such a cost.
      **What it says, by exit code** (`Main` puts these in place of the command's own words;
      the tool never tries again by itself):
      - **Exit 3, `[server_kdf_refused]`:** the server's answer names a password-hashing cost
        this device does not derive at (it names the passes and bytes); the device did not use
        that answer and derived nothing from the password at that cost; that is the server's
        fault, not a wrong password. It is said wherever a served cost fails the fence: the
        reopen, a sign-in's first exchange, the keys read again after a re-key, and a device
        link's first exchange. A refused cost comes before exit 6 when both apply. (Exit 3 also
        covers the server's other unusable answers: one too large, or a row the device will
        not show.)
      - **Exit 6, `[server_keys_not_known_here]`:** this run would not prove the password
        because the server's keys are not the ones it knows, and it says what is so in each
        case: they changed while it ran ("… they changed while it ran, and what the server
        holds now does not open here to this account's key"), or they could not be read again
        after the run sent a change of them ("… it sent the server a change of them, and they
        could not be read again afterwards (the server gave no usable answer), so they could
        not be checked here against this account's key"). Each ends: "So this device did not
        prove your master password and sent nothing for this command; that is not a wrong
        password. Run the command again: the next run opens the keys the server holds". A cost
        outside the fence in the keys read again keeps its own words and exit 3.
      - **Exit 7, `[proof_refused_by_server]`:** a proof made here and sent was refused by the
        server ("the server at O refused the proof of your master password, although that
        password opened the account on this device. The proof was sent; the server answered
        that it changed nothing …"), in place of every wrong-password sentence, on every
        command that proves the password (the password change, a new kit, a device's removal,
        "New devices must be linked", the recovery setting, the account's deletion, the
        operator's proofs, a card change and the hand-over). A password that does not open the
        wrap here is still a wrong password, with nothing sent.
      **The device link's first exchange:** when `link-device`'s pickup gets no usable answer
      to its first exchange, the pickup ends at once and the password is never asked for a
      second time: a cost this run refused in that exchange is exit 3 with the cost sentence;
      otherwise exit 1, "the server at O cannot be reached: the device link's first exchange
      got no usable answer, so the link stopped here. Nothing was derived from your password
      and nothing was sent with it. Try again when the server answers, with a new link from
      your other device if this one has expired". A stop of the shared step later in the
      pickup that got no answer says that the server cannot be reached, and claims nothing
      about what was sent. **The cost of a new wrap:** above, under the password change.
      **What it says, as a rule** (rule of 2026-11-17): a wrong two-step code is said as a
      wrong code, never as a wrong master password; "the server cannot be reached" is said only
      when it was not reached, and an answer that could not be used is said as that. The tool
      keeps it (2026-11-18): in `link-device` a refused two-step code is said as that and keeps
      the link (spec 03 §2); a first exchange that answered with something unusable is said as
      an answer that could not be used, never as "cannot be reached"; a refusal for too many
      requests at a link's step that can wait is said once with the server's wait, and the link
      waits within its own time; at a step that cannot wait it stops with the server's wait (or
      "a while" where the server named none); and `account password`'s success sentence says
      that the other devices were signed out, as a password change ends every other session of
      the account (spec 03 §3).
    - **The older core client code** (`SessionController`, which the iPhone app still uses)
      calls `KdfReKeyCore` after an online sign-in or full-password unlock. It does not try
      a served wrap; the rule above is not built there.
    - **The sentence each client says for a proof the server refused while the mark is set:**
      the web client a line of its own (`SERVER_KEYS_NOT_KNOWN_REFUSED`: "The server's keys for
      this account aren't the ones this browser knows, so it didn't accept your master password
      here. Nothing changed.");
      `andvari-cli` exit 6 or exit 7 above; the app engine its `KEYS_NOT_KNOWN_HERE` result
      for every action that proves the password, with a sentence that asks for a sign-in on
      this device. **Without the mark:** the web client `SERVER_REFUSED_PROOF` ("The server
      didn't accept your master password, although it opened your account in this browser.
      Nothing changed. If it keeps refusing, sign in again."), for every action that sends a
      proof; `andvari-cli` exit 7; the app engine its `PROOF_REFUSED` result, with a sentence of
      its own (above).
- **In-session password proofs (NORMATIVE; security review 2026-10, branch A9, M-1).** Every
  credential a client derives from the master password AFTER unlock and sends to the server — the
  `currentAuthKey` of a password change or KDF re-key, a TOTP enrolment, the recovery-capture gate,
  a recovery-posture change, a device revoke, account deletion and every operator † route (spec 03
  §0.1) — MUST go through
  ONE proof per client: in the app engine `SessionKeeper`'s proof against the device's own wrap
  (below); in `andvari-cli` its local proof against the session's own wrap (`Host.localProof`, through
  the engine's own proof `EstablishedSession.proveAuthKey` on the session the tool holds, then,
  only for a wrong password while a password change is pending, on a session the engine rebuilds
  over the pending wrap; below as well); in the web
  client `Account#reauthAuthKey`, against the session's own wrap (`SessionWrap`; below as well); in
  the older core client code (`SessionController`, which the iPhone app still uses)
  `Account.reauthAuthKey`. The last one takes the account's keys as `GET /account/keys` serves them,
  so that one request precedes its local proof; nothing derived from the password follows it when
  the proof fails. Each proof, before any KDF
  runs, (1) applies the §7 client-side sanity bounds to the served `kdfParams` (below the floor or
  above the ceiling: refused, surfaced as the weakened-settings block, never as a wrong password)
  and (2) refuses any `kdfSalt` other than the one THIS session unlocked or enrolled with ("Lock and
  unlock andvari, then try again"). A server that answers `GET /account/keys` with its own salt or
  minimal-cost params therefore never obtains a second, cheaper hash of the master password. The only
  derivation outside it is the sign-in after prelogin, where no session salt exists yet; it is fenced
  on the params and pinned to its call sites by a tripwire test. The raw KDF is called only inside
  the account types, the backup KDF (spec 07 §2.3, its own window) and the re-key (fenced by the
  upgrade rule above); a product call anywhere else fails the build. **The derivation is PROVED
  (A9 review, LOW-1):** the salt check is only a pre-check, because a quick-unlock session (the UVK
  came from the platform, spec 01 §8) records whatever salt the server served at that moment. So the
  same argon2id pass also yields the wrap key, which MUST open the served `wrappedUvk` to the UVK the
  session holds (the server cannot produce that without the password); only then is the auth key
  returned. A server-chosen salt or wrap, and a wrong password, derive nothing that leaves the device,
  and the wrong password is found out locally ("That master password isn't right") instead of by the
  server.
  **In the app engine, in `andvari-cli` and in the web client the proof runs against the device's
  own wrap (NORMATIVE).** Before any
  re-authentication leaves the device, the typed password is proven against the wrap this device keeps
  for the session (core `SessionKeeper`; the tool's held session; the web's `SessionWrap`): the salt, cost and `wrappedUvk` it
  holds from the sign-in or
  from its own last password change, and, while a password change is pending, the pending wrap too.
  The kept cost passes the same sanity bounds. `currentAuthKey` comes from that same pass, under the
  session's own salt and cost; no value a server names at that moment goes into it, and nothing is
  dialed for the proof: no prelogin, no `GET /account/keys`. A wrong password is found out on the
  device, and the action behind the re-authentication sends nothing at all: no proof, no signed
  statement, no request of its own (in the app engine an account deletion fetches not even its
  preview). A password change sent while another is pending first reads `GET /account/keys` to
  settle it (the pending record, above); that read belongs to the change, not to the proof. So does
  the read of the served cost a password change needs for its new wrap (`GET /client-policy`, §7):
  in the shared code it comes after the proof held, so that a wrong password sends nothing at all,
  not even that read (2026-11-18). The same order holds for an operator's change of the server's card
  (the proof before the cards are read; a change that would do nothing, or a bad value, is refused
  against the card this device already pins before the password is touched) and for the finishing of
  the server's setup (the proof before the instance's values are read): a wrong password sends nothing
  at all there either (2026-11-18).

## 8. Quick unlock (platform-local, never server-visible)

Quick unlock wraps the **UVK** — never the master password, MK, or a derived
authKey/wrapKey — under a **platform-local wrapping factor**: platform hardware
where the platform offers it (**Android**, §8.1), or a **PIN + a non-extractable
session-scoped co-key** where it does not (**the browser extension** under MV3,
§8.4). It is strictly device-local: the server is
never told quick-unlock exists, never sees the wrapped blob, and the wire protocol
is unchanged. Quick unlock never weakens the server story: the server still only
ever sees authKey. A quick unlock yields exactly the capability a full-password
unlock yields **except** knowledge of the password itself — so it can never perform
the §7 password change / KDF upgrade, and it MUST NOT count as a full-password
unlock anywhere the spec distinguishes the two. Each platform subsection states its
own wrapping factor and its honest at-rest exposure; there is **no single "platform
hardware" guarantee across platforms** (the extension has none — §8.4).

### 8.1 Android (NORMATIVE, v1)

**Eligibility & enrollment.** Quick unlock is per-device, per-account **opt-in**,
offered only while the vault is unlocked (the UVK is in memory). It REQUIRES:

- policy `offlineCacheAllowed == true` (spec 03 §1.1). The wrapped UVK is durable
  vault-opening secret material at rest; an operator who forbids the (ciphertext-only!)
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
device holder can set. A stamp in the future fails closed (stale), with no skew allowance.
Within one boot the monotonic clock (`elapsedRealtime`) is authoritative and its delta MUST
also be under the window. "One boot" MUST be decided from a boot identity the holder cannot
set (Android: `Settings.Global.BOOT_COUNT`, recorded with the stamp), never from
`wall − elapsedRealtime`: stepping the wall clock would otherwise make a same-boot device look
rebooted and skip the monotonic check exactly when the clock is the problem. Independently of
boot identity, an `elapsedRealtime` that has advanced a full window past the stamp's MUST fail
closed (sound in every case: within one boot it is the real duration, across a reboot this
boot alone has run that long since the stamp). (Security review 2026-10.) **Across a reboot** the client MUST evaluate the window against a *server-attested*
time anchor recorded after the stamp (`ClientPolicy.serverTime`, persisted monotonically);
with no such anchor the elapsed duration is unknowable and the client MUST fail closed and
require the master password. A device-clock high-water mark MAY be kept as an additional
one-way ratchet, but MUST NOT be the sole guard: it only advances while the app observes
it, so a dormant device freezes it. Why 30 and why time- rather than use-based: the rule exists
(a) so users do not lose master-password muscle memory — the classic quick-unlock
failure mode is "enabled biometrics in March, forgot the password by June", which
for a ZK design with only escrow recovery is an availability incident (A5);
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
  survives refresh) — the session ends with its tokens and the quick-unlock secret,
  while the device's copy stays (design 2026-11-15 §4.4, "A session the server ends
  does not delete the device's copy"; spec 05 T3).
- **Policy flip** `offlineCacheAllowed → false` — on the next policy fetch.
- **User disable** in Settings (no password required to *disable* — reducing
  standing secret material must never be gated).
- **Password change: does NOT clear it.** The UVK survives a password change by
  §7/§4 invariant, so the wrapped blob stays **cryptographically valid** — this is
  explicit and intended (changing the password on the web does not silently break
  the phone's biometric unlock). Device-side hygiene still applies: a password
  change made *elsewhere* revokes this device's session (§7), and the resulting
  definitive 401 purges the blob (the copy itself stays, as above) until the
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
opens the vault without the master password and is NOT a quick unlock.) **This "Web:
none" stance stands unchanged**: the browser *extension* is a distinct platform
(§8.4) with its own client token (`X-Andvari-Client: extension/x.y.z`, spec 03 §1)
and its own compartment (`chrome.storage.session`), and §8.4 governs it — a page in
a browser tab (the web client) still gets no quick unlock.

### 8.4 Extension (NORMATIVE, v1; design 2026-07-13-platform-fit §1, house 2-breaker pass)

The MV3 browser extension has **no platform hardware** to wrap the UVK — under MV3
there is no second key-storage compartment: the service-worker memory dies in ~30 s,
and `chrome.storage.session` / `.local` are readable by the same principal. So a
naïve session-key wrap (key beside ciphertext) would be pure UI theater — *worse*
than today's honest erase-on-lock. Quick unlock here is therefore a **PIN-wrapped,
session-scoped UVK double-wrapped under a non-extractable co-key**, and it is a real
but **narrower** weakening than Android's, stated honestly below.

**Why a PIN is acceptable here when §8.1 rejects `DEVICE_CREDENTIAL` / screen-PIN
authenticators.** §8.1 rejects a screen PIN as the *sole* factor because there it
would *replace* a strong biometric bound to hardware. Here there is no hardware to
replace; the PIN is not offered as an equal of the master password but as a
*second, weaker* factor guarding a *session-scoped* secret, and it is only
acceptable because of two mandatory properties this section requires:

- **(A1) A non-extractable session co-key.** The UVK is DOUBLE-wrapped:
  `ct = AEAD(K_pin, AEAD(K_nonexp, UVK))`, where `K_nonexp` is a
  `crypto.subtle.generateKey({name:"AES-GCM", length:256}, /*extractable*/false, …)`
  key held in IndexedDB. A PIN-only wrap is offline-crackable (a 6-digit PIN is
  GPU-*minutes*, not years) and is **rejected**. The co-key never leaves the browser
  and only ever unwraps this one session-scoped blob, so it is *not* a standalone
  durable vault opener; it MUST be deleted on **every** blob wipe (below).
- **(A2) An enforced entropy floor** (not copy-only): PIN ≥ 6 chars; an **all-digit
  PIN MUST be ≥ 10 digits** (a 6–8 char PIN MUST carry ≥ 1 non-digit); trivial
  sequences/repeats are blocked. Argon2id over the PIN is the *only* defense against
  a stolen blob (there is no hardware rate-limiter), so the floor is load-bearing.

**Eligibility & enrollment.** Per-install, per-account, **opt-in**, offered only
while unlocked (the UVK is in service-worker memory — memory-only custody, never
persisted), and never for a session the server ended (design 2026-11-15 §4.4). No
temporary password exists to gate on: an operator-assisted reset has the person set
their own new password and revokes every session (design 2026-11-15 §9.3). Enrollment **COPIES the
surviving full-password `lastFullUnlockAt`** into the blob and MUST NOT mint `now`
from a quick-unlocked session (a quick-unlocked session carries the *original*
stamp), so re-enrolling can never extend the freshness window (Android A1 parity).
`offlineCacheAllowed` does **NOT** gate Tier B: a `storage.session` blob is
memory-backed and browser-session-scoped — not durable, not at-rest — and lives in
the same compartment that already holds raw `vaultKeys` while unlocked; that bit
gates only durable at-rest openers (a future Tier C — durable `storage.local` under
WebAuthn/PRF — WOULD be gated, and is explicitly out of scope here).

**Construction.** `K_pin = Argon2id(PIN, salt, pinParams)`; `pinParams` are chosen
at enroll by a one-shot bench targeting **≤ 1 s** on that machine, **floored at
mem ≥ 32 MiB, ops ≥ 2** (raised toward 64 MiB where the bench allows) and recorded
in the blob. On use they are re-checked by a **dedicated `assertPinKdfParams`** with
a **floor AND a ceiling (≤ 1 GiB, ≤ 10 ops; reject non-finite/omitted)** — distinct
from the server-KDF assertion whose floor is the 64 MiB *master* floor; a blob
carrying sub-range params is treated as **corrupt → wipe** (a planted 4 GiB would
OOM the worker). Both AEAD layers bind the AAD
`UTF-8("andvari/v1|ext-quick-unlock|{userId}")` (per-account — a blob copied to
another account cannot open, and a tamper fails the tag). The blob + a sibling
attempt counter (starts 5) live under a **distinct `chrome.storage.session` key**,
NOT the session snapshot: `ensureLoaded` MUST NOT hydrate the live session from it,
so while locked-armed every `!session` gate still reports **fully locked**.

**Compartment precondition (hard).** The blob is a crackable UVK **plus a live
refresh token**, so it may sit in `chrome.storage.session` only where a content
script cannot read it, and since A16 (spec 05) that rests on sealing, not on the
area's access level: the record is AES-GCM sealed, its AAD binding the record kind
and the origin, under a **non-extractable session sealing key held in the extension
origin's IndexedDB**. The key is replaced, and every sealed record dropped, when the
browser reports a new browser session (`runtime.onStartup`, `runtime.onInstalled`); at
any other worker start it is kept only if a record sealed under it opens. Where the
report does not reach the worker, a record sealed in an earlier browser session can
open again (spec 05 A16(a) and its residual (7) say exactly what holds). Whatever
the worker held before such a report is dropped, never armed. The client MUST NOT arm
and MUST NOT retain tokens unless that key is available (it falls back to today's
full erase); where `setAccessLevel` exists (Chrome) its awaited call on
`storage.session` must also have resolved, as a second layer. That content scripts
cannot reach `storage.session` is not relied on, on either engine. The seal is not
a lock (a lock still erases): it keeps the record from anything that can reach
`storage.session` but not the extension's IndexedDB. A `storage.local` fallback for
the blob is **forbidden** (that is the rejected durable Tier C).

**Locked-but-authenticated state.** When armed, `doLock()` keeps a slim
`{access, refresh, userId, email, blob, counter}` record under the distinct key and
destroys everything else exactly as today (vaultKeys, items, tabs, **pending saves —
they hold plaintext page passwords and MUST still die at lock**, grants, badges);
when not armed it stays byte-identical to today's full erase. This retains the
refresh token across lock — new *client-side* state, not new server exposure
(today's `doLock` already leaves the refresh token valid server-side, merely
forgetting it).

**Known-logins digest (locked save-prompt check — amendment 2026-08-18).** A
second record deliberately survives an idle/manual lock, under its own distinct,
per-origin `chrome.storage.session` key: a random per-install HMAC key plus a set
of **truncated (16-byte) HMAC-SHA256 digests over (site key, normalized username)
pairs** — one per saved web uri of every login item, the site key being the same
eTLD+1 authority autofill matching uses. It carries **no password material** and
is rebuilt from the decrypted items on every session persist. Its function is the
locked capture path: a submitted credential whose (site, username) pair is in the
set is a re-login to something already held — recorded as a *quiet* pending (no
banner) and resolved by the unlock-time dedupe (unchanged → dropped silently;
changed → the Update offer). An unknown pair keeps the "unlock to save" banner.
Honest disclosure bound, accepted by design: a reader of the locked compartment
can test *guessed* (site, username) pairs for membership — strictly less than the
plaintext locked-minted pendings the same compartment already holds. Sealed like
the quick-unlock record (A16), wiped at sign-out / definitive-401 (with the
quick-unlock material), and never kept across a lock where the compartment
precondition above does not hold; a `storage.local` copy is **forbidden** (the
rejected durable Tier C, again).

**Locked-minted pendings (amendment 2026-08-18).** "Pending saves die at lock"
covers pendings alive AT the lock transition; a pending captured *while already
locked* necessarily post-dates it and persists in `storage.session` (with the
page's password, sealed since A16) for the post-unlock offer. That window is now **bounded**: a locked-minted
pending carries its capture stamp and is dropped unoffered once
`LOCKED_PENDING_TTL_MS` (30 min) passes — enforced at every re-offer surface and
at the unlock re-offer itself, ahead of any offer. Re-offers of a still-live
locked pending are additionally throttled to one per `REOFFER_MIN_GAP_MS`
(10 min); the immediate capture-time banner is exempt.

**Use** (new `unlockWithPin`, single-flight): `open(K_pin, …) → AEAD(K_nonexp)⁻¹ →
UVK`, then a **forced `POST /auth/refresh` rotation as the FIRST server contact** (a
revoked/rotated refresh → definitive 401 → wipe → full sign-in; this is also the
account-state read that makes a recovery or an operator-assisted reset — each revokes
every session, spec 03 — take effect), then `GET /account/keys` → open `encryptedIdentitySeed` under the UVK →
**the same seed-derived `identityPub` hard-compare as the password path (§5)** →
`sync(0)` → rebuild vault keys/items. The attempt is **RESERVED (counter decremented
+ persisted) BEFORE the AEAD attempt**, so a service-worker eviction or a racing
popup can never gift a free guess; a verified open resets the counter to 5.
`autoLockSeconds` is **re-derived on redeem** (via the policy fetch), so a stale
value cannot outlive a policy change; the master-KDF floor is re-asserted from the fetched `kdfParams`.

**Fail-closed rules (normative; wrong-PIN = full unlock, no oracle):**

| Event | Action |
|---|---|
| AEAD open fails (wrong PIN, tampered/corrupt blob, wrong co-key, unknown `v`, sub-range `pinParams` — **indistinguishable by design**) | decrement (already reserved); generic "That PIN didn't match — N tries left." No partial-correctness signal; the PIN never touches the wire, so there is **no remote oracle at all** |
| Attempts exhausted (5) | **wipe** blob + counter + co-key; master password only; re-enroll after a full unlock |
| Sub-range `pinParams` / missing co-key | **wipe** (corrupt/orphaned); master password |
| `encryptedIdentitySeed` won't open under the recovered UVK | **wipe** (stale/foreign UVK); master password |
| Seed-derived identityPub ≠ server identityPub | **HARD FAIL** (§5 security fault); blob **KEPT** (evidence; Android parity) |
| Definitive 401 on the forced refresh / `account/keys` / `sync` (revoked or password-changed elsewhere) | **full wipe** blob + counter + co-key + tokens → full sign-in (never the armed-retaining lock) |
| Network failure | master password this time; blob **KEPT** (the full path needs the network too) |
| `> 24 h` since `lastFullUnlockAt`, or a future stamp | master password; blob **KEPT**; a full unlock re-stamps |
| Browser exit | `storage.session` evaporates — blob, counter, tokens all gone (the natural ceiling) |
| Sign-out / disable in Settings / policy revocation | **wipe**; disable needs no auth gate (reducing standing secret material is never gated — §8.1 parity) |

**Periodic-full-password rule.** The Android 30-day durable-blob rule collapses here
to **min(browser session, 24 h)** since `lastFullUnlockAt`: `storage.session` cannot
outlive the browser, and the extension has no §7 re-key path (it never calls
`PUT /account/password`), so the rule serves muscle memory and bounds the locked-state
token-retention window. Clock handling is `Date.now()` with **fail-closed-on-future-stamp**;
the §8.1 cross-boot server-anchor machinery is NOT needed (a reboot kills the browser
kills the blob). The counter/stamp/pinParams are same-compartment and
attacker-resettable — stated plainly (spec 05 A7-extension); absent a hardware rate
limiter the counter brakes only the in-scope human-at-keyboard opportunist, and the
PIN entropy floor + session scoping are the actual bounds against blob exfiltration.

**Account switch (A6).** A full unlock as a *different* `userId` than a stored blob's
MUST wipe that blob (the AAD already blocks cross-account crypto use; this is the
explicit erase story).

### Auto-lock (policy `autoLockSeconds`)

All three clients enforce an **inactivity auto-lock** driven by the policy's
`autoLockSeconds` (spec 03 §1.1; `0` or absent = disabled). Clients use the most
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

### Keys in memory and the lock (NORMATIVE)

An opened account's secret keys live in memory only and end with the session. A lock,
a sign-out and the server's end of the session all end it. The rules below are those of
the app engine (core, used by the Android and desktop apps and by `andvari-cli`); a
second implementation that erases keys at a lock keeps all of them. The older core
client code that the iPhone app still uses erases its keys in place at a lock and goes
through the same floor (rule 4); its password proof compares with the key inside its
guarded use, so a lock during the slow derivation answers "locked" and never a verdict on
the password, and its readers of kept local records (unfinished moves, automatic saves,
saves with files) pass a lock through instead of reading it as a record that is not the
account's own (rule 5). The TypeScript clients erase no key at a lock: the last
paragraph.

1. **Keys are lent, never handed out.** The UVK, the identity and signing key pairs,
   the personal vault's key, and every shared vault's key unwrapped from them are held
   under ONE guard per opened account (`KeyGuard`). Work borrows a key for one plain
   block that cannot wait (it cannot suspend), and the block answers what it built from
   the key: a seal, a signature, a derived key, a decision. It never answers the key.
   An answer that is the key's array, an array equal to it (or to a signing secret's
   seed half), a key pair holding it, a list of its bytes, its base64url, base64 or hex
   text (as a string or as ASCII bytes), or any of these one level inside a pair, a
   triple, a collection or an array, counts as answering the key. Where the test
   machinery is on (the JVM and Android test suites the tripwire watches, spec 05 A17),
   such an answer is refused with `KeyEscapeException`, and a refused bare array is
   zeroed first. The refusal is a development check, not a rule of
   the running product: a shipped build hands back what the block answered and never
   compares it with the key, zeroes it or refuses it, because data can equal a key (a
   shared vault's name, an item or a file chosen by a member who holds that key), and
   refusing data would stop the app of everyone who reads it. No copy of a key leaves the
   guard.
2. **A lock erases the keys in place, and nothing started before it uses them after.**
   The lock zeroes every key under the guard in the arrays the account itself holds,
   while holding the guard: a use already running finishes on whole keys, no use starts
   after, and none sees a half-zeroed key. A lock reached from inside a running use
   marks the keys erased at once and zeroes them when the outermost use ends. Every
   erase registered with the guard runs even when another one fails. Once erased, every
   lend refuses with `KeysGoneException`.
3. **After every wait, the work checks that the keys are still there** before anything
   more is sealed, signed, derived or sent. A wait is anything that can suspend: an
   answer, a mutex, a network call, a key derivation. Where it can, the work does its
   key work before the wait and checks once before the send: a password change seals
   the new wrap before the re-authentication; a kit rotation, an account deletion's
   leave statements and an operator's card are built before their requests. The item
   engine checks that the vault is open before every seal and every send, with no wait
   between a seal and its send. A vault log's append, adoption and creation keep their
   pending record, check, then send.
4. **An all-zero key is never a key.** No legitimate key is all zeros, so the shared
   crypto path refuses one with `KeysGoneException` before the platform's provider is
   called: an envelope sealed or opened under it; an envelope whose plaintext is exactly
   32 or 64 zero bytes (a wiped key being wrapped); an HKDF input key of zeros; an
   Ed25519 signature whose secret's seed half is zeros (signed frames and signed
   statements); an escrow seal of a zero UVK; a file encrypted under a zero key; a
   grant opened with a zero identity private key or signed over a zero vault key; a
   device-link MAC under wiped link keys. In the shared code, decrypting a file is not on
   that list: it sits behind the check that the keys are still there. Data that would put zeros there is refused
   where it is read, as what it is: a link or device link whose secret is zeros is a
   bad link, a recovery kit whose secret is zeros stops the kit recovery as a bad kit,
   and a zero key matches no vault-key commitment. The rule has vectors of its own:
   `keyfloor.json` holds must-refuse rows, an all-zero input and the operation that
   refuses it (`links.derive`, `devicelink.derive`, `vaultlog.vkCommit`). No other vector
   row feeds an all-zero secret or key to a derivation: the three rows that once did
   (`links.json` `derive[2]`, `devicelink.json` `derive[2]`, `vaultlog.json`
   `vkCommit.derive[3]`) now carry the lowest input the rule accepts, 31 zero bytes and
   one 0x01, and are derived like any other row. The shared code and the
   specification-only oracle grade `keyfloor.json`. The web client keeps the same floor
   in its own crypto path (`web/src/crypto/keyfloor.ts`, refusing with `KeysGoneError`,
   which is not a crypto error; it also refuses a file decrypted under a zero key) and
   grades the row it has an operation for (`vaultlog.vkCommit`), naming the two link
   rows as other clients'. The extension keeps no floor yet and grades no row.
5. **An action a lock overtakes answers its own "stale"** (the screen it answered from
   has gone), or for a vault's content "not done": never an error, never "wrong
   password", never "not ours" or "damaged". `KeysGoneException` is deliberately not
   the error a failed open raises, so no handler reads a lock as a wrong key or a
   damaged record, and none deletes or overwrites what it would for one. The same
   refusal while the account still holds its keys is a fault, and is thrown.
6. **After a lock, only what was sealed and signed before it may be sent.** A request
   already on its way finishes, and its answer is taken without a key: a password change
   the server took is done, and the device keeps exactly the wrap it sent. An
   operator's card change whose first rotation was sent sends its remaining rotations
   and the card, all signed before the lock, so the server never holds rotations its
   newest card does not name. A device-link approval that a lock or a cancel overtakes
   sends no approval and asks the server to drop the link by its id. Nothing is built
   from a key after the lock.
7. **What is kept for the next unlock.** Fill uses recorded and not yet sent are
   sealed at the lock, before the erase and without a wait; where the opening may keep
   data at rest they are kept on the device and sent once by the next unlock's first
   completed sync, and elsewhere they are dropped. Uses that a flush had already taken
   when the lock came are kept like the others, not dropped. The kept record is keyed by
   the server and the account, and is removed when keeping data at rest is no longer
   allowed. A save with new files is sealed and
   kept before anything of it is sent, and the next unlock finishes it under the same
   ids. A plain save the lock overtook before its seal, and the batches of an import
   the lock stopped, are not kept (that would need a seal the lock took away); the next
   unlock names them, from the process's memory only. A vault-log entry signed before
   the lock and not yet sent stays as that log's pending record; it is not sent after
   the lock. Quick unlock's enrolment is no exception to rule 1: the platform asks the
   person's consent first, with nothing of the UVK outside the guard, and seals after the
   prompt, synchronously, inside the guarded use, lent the guard's own buffer, which it
   never zeroes or keeps. A lock or a change of session during the prompt makes that use
   refuse: nothing is sealed, what the prompt prepared is discarded and its key
   destroyed, and enrolment answers its own "stale".

The app engine keeps rule 7 since 2026-11-16: the uses a running flush had
taken when the lock came are taken by the lock with the others and kept sealed; the kept
record is keyed by server and account (an older record keyed by user id alone is removed
unread), and it goes when keeping is no longer allowed (the platform's consent turned, a
policy or consent that forbids keeping at the opening, a sign-out, another account
opening on the device), and a followed move carries it.

**The TypeScript clients** (the web client and the extension) erase no key in memory
at a lock. The lock drops the session's references, and the runtime's garbage collector
frees the arrays later. So they never hold a zeroed key and cannot seal under one. The
cost is that the keys stay in memory until the collector frees them, readable by
whatever can read the process's memory (T5's boundary, spec 05). In the web client a
lock or a sign-out closes the session's fence: every later call through the session's
transports refuses before anything is sent, a call already on its way finishes, and when
the fence cut work short the unlock card says that a change may not have reached the
server. Nothing in either client refuses a key to work that outlived the lock; what
stops such work in the web client is the fence, at its next call.

## 9. Benchmarks (P0 gate)

Measured 2026-07-05 on the reference build host — one 2.4 GHz E5-2640v4 core in a
Linux container, deliberately slow-core hardware; treat the numbers as a floor, not
a target. Median of 5 after warm-up, `--bench` mode of tools/vector-gen (JVM) and
node/V8 (WASM, Chrome-class engine):

| Platform | ops=3 m=64MiB | ops=2 m=64MiB | Notes |
|---|---|---|---|
| JVM native lazysodium (reference host) | **130 ms** | 101 ms | Android/desktop/server class |
| V8 WASM sumo (reference host, node 22) | **~380–500 ms** | ~195 ms | browser class; modern phones/desktops ≥2× faster |
| Android Chrome (phone, WASM) | pending | — | measure at P2 rollout; expected < the reference host's WASM row |
| Android app (native lazysodium) | pending | — | measure at P2; expected ≈ JVM row |

**Decision (P0): keep the default `{ops:3, memBytes:64 MiB}`** — the worst measured
platform (WASM on that slow-core reference host) sits at ~0.5 s, well under the
~1.5 s ceiling; phone rows get confirmed at P2 before family rollout. Never go below
64 MiB memory.
