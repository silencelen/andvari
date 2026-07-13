# andvari — Auth / Secret / Recovery Architecture Review + Per-Member Recovery Redesign

- **Date:** 2026-07-12
- **Status:** DECIDED 2026-07-12 → **building**. Owner chose **(b) Hybrid + per-member opt-out** and **recovery first, web-offline as its own later cut**. Build proceeds under full doctrine (design → breaker → parallel builders → gates → review → ship).
- **Grounding:** 4 parallel read-only code-survey passes at HEAD `74c2f8e`, every load-bearing claim cited `file:line`. Crypto is byte-parity across four impls (core Kotlin, web TS, MV3 extension, server) — `spec/01-key-hierarchy.md:1-9`.

---

## 0. Why this doc exists

Two owner asks:

1. **The enrollment "recovery check" is an onboarding roadblock.** Invited members should sign up with just the link; a recovery piece should be **given to them at signup, not required beforehand.** And: "go over the whole auth and secret scheme."
2. **Think about how data is stored across devices and transmitted.** Intended model, owner's words: *"each manager client should have a local copy they can use and decrypt; the andvari server is used for blind secure transfer and syncing, as well as recovery store, websites, updates, and account provisioning."*

This doc answers both: **(A)** the as-built auth/secret scheme, **(B)** the as-built storage/sync/transmission model measured against the stated model, **(C)** why the check exists and how per-member recovery removes it, **(D)** the trust-model decision that is the owner's to make, **(E)** the build plan once decided.

> ### DECISION — 2026-07-12 (owner)
> 1. **Recovery model: (b) Hybrid + per-member opt-out.** Build the per-member self-service recovery piece; keep org escrow as the default admin backstop; expose a **per-member opt-out** that waives the backstop for members who need privacy-from-admin (pure per-member for them, accepting hard-loss).
> 2. **Sequencing: recovery first.** Web/extension durable-offline (§B.5, §D.2) is deferred to its **own** later doctrine-complete cut — not blocking this one.
>
> **The opt-out authorization model (the one genuinely new decision the opt-out forces):** *who is allowed to waive the backstop?* → **The admin sets it per invite** (`escrowPolicy: required | waived`, default **required**). Rationale: in a household the admin provisions accounts and owns the policy; a member cannot *unilaterally* deny the admin a backstop (which would let a kid silently opt out and then lose everything), and the admin cannot *silently* strip a member's privacy either (the posture is shown to the member at signup). This keeps the knob in the admin's hand while making privacy an explicit, visible grant. Server-enforced: register accepts a missing org-escrow blob **iff** the invite's `escrowPolicy == waived`; otherwise escrow stays mandatory exactly as today (`Service.kt:87-89`). This is a **binding-amendment candidate** for the breaker to stress (see §E).

---

## A. The auth & secret scheme, as-built

### A.1 One root key, everything hangs off it

```
master password  ──Argon2id(t=3, 64 MiB, salt=kdfSalt)──►  MK (32B, never stored, never sent)
                                                              │
                        ┌──── HKDF-SHA-256 ────┬─────────────┘
                        │ info=".../auth"      │ info=".../wrap"
                        ▼                       ▼
                   authKey (→server)       wrapKey (KEK, stays client-side)
                        │                       │
             server stores argon2id(authKey)    └─ wraps ─► UVK (User Vault Key, 32B random, NEVER rotated)
             = "verifier" (one-way)                          │
                                              ┌──────────────┼───────────────────┐
                                              ▼              ▼                    ▼
                                   encryptedIdentitySeed   personal VK      (receives shared-vault grants)
                                     → X25519 identity      → items
                                        keypair
```

- **MK** = `Argon2id(password, kdfSalt, ops=3, mem=64 MiB, out=32)` — `Keys.kt:30-33`. Never persisted, never leaves the KDF step.
- MK is **HKDF-split** into two severed keys — `authKey` (the login proof, sent to the server) and `wrapKey` (the key-encryption key, never sent) — `Keys.kt:35-39`. Because HKDF severs them, the value on the wire (`authKey`) **cannot open any envelope**.
- **UVK** is the whole game: 32 random bytes, generated once at enroll, **never rotated by a password change** (`spec/01:60-67`). Everything derives from it — the X25519 identity seed is UVK-sealed, the personal vault key is UVK-wrapped, and shared-vault grants open via the UVK-derived identity key. **Any recovery scheme only has to protect the UVK** (`Account.kt:222-224`; confirmed by `recovery-cli recover`, which just unseals the UVK and re-wraps it under a new password — `tools/recovery-cli/.../Main.kt:153-189`).
- **Vault keys (VK):** one 32B key per vault; items encrypt under VK, never directly under UVK. Personal/owner VKs are UVK-wrapped; shared-vault member grants are `crypto_box_seal`'d to the member's identity pubkey (`spec/01:91-105`).

### A.2 Login is a double-Argon2id with an HKDF cut in the middle

- **prelogin** `{email}` → `{kdfSalt, kdfParams}`. Unknown email returns a **deterministic fake salt** (`HMAC(enumSecret, email)`) + timing-equalized path — anti-enumeration (`Service.kt:69-82`).
- Client derives `authKey = HKDF(Argon2id(password, salt), ".../auth")` and sends **only** that. Server verifies with `crypto_pwhash_str_verify(verifier, authKey)`; unknown users still run a dummy verify for uniform cost (`Service.kt:142-146`). **A DB leak of the verifier is not a replayable login** — it's a one-way argon2id hash.
- **Sessions:** opaque 256-bit access (1 h) + refresh (30 d, rotating, single-use — reuse revokes the whole device). Server stores **only `sha256(token)`** (`Service.kt:1022-1037`).
- **Public/break-glass origin only:** TOTP mandatory, login rate 5/min, and `register`+`refresh` **hard-disabled** (`App.kt:332,346`). LAN/tailnet origin does not require TOTP.

### A.3 The two linchpins that keep a hostile server honest

The system is zero-knowledge, but ZK alone doesn't stop a *malicious* server from substituting **public** keys. Two out-of-band checks close that:

1. **Identity-pubkey hard-fail.** On every unlock the client re-derives `identityPub` from the UVK-sealed seed and **hard-fails if it ≠ the server's stored value** (`Account.kt:308-318`). This stops a compromised server swapping in its own identity key to intercept shared-vault grants. **Preserve this in any redesign.**
2. **Recovery-pubkey fingerprint check** (the roadblock — see §C). The org recovery pubkey is served **unauthenticated** (`/recovery-pubkey`, `/client-policy` — `App.kt:287-297`) and triple-pinned (server env, policy, printed sheet). The enrollee must **type the first 16 hex of the fingerprint from the printed sheet** before the client seals escrow; the UI deliberately won't show it first (`Welcome.tsx:379-406`). This is the sole out-of-band anchor that a server-fetched pubkey is genuine.

### A.4 The zero-knowledge boundary (what the server sees vs. can't)

Authoritative table: `spec/02-vault-format.md:200-227`. Register writes nothing outside it (`Service.kt:108-127`), and a grep of `server/src/main` finds **zero item-plaintext decryption**.

| Server **sees** (plaintext metadata) | Server holds **only ciphertext** | Server **never sees** |
|---|---|---|
| userId, email, displayName, kdfSalt/params, identityPub, isAdmin, status, timestamps, TOTP columns, device labels, invite emails, session-token **hashes**, vault type/rev, item ids/rev/size/flags/formatVersion/attachmentIds, escrow fingerprint | wrappedUvk, encryptedIdentitySeed, vault metaBlob (names/icons), grant wrappedVk/sealedVk, item blob, attachments, escrow sealed blob | master password, MK, wrapKey, UVK, VK, identityPriv, item content, vault names, filenames, fileKeys, vault-stored TOTP secrets |

**Accepted leakage (by nature):** traffic analysis (who syncs when, item counts, ciphertext sizes), invite emails, device labels — `spec/02:225`, threat model `spec/05`.

**One honest note for the record:** `authKey` is a KDF-derived value the server *does* see every login. It opens nothing (HKDF severs it from `wrapKey`), but a hostile server could try to weaken the client KDF via prelogin params — countered by client-side floors + upgrade-only rules (`spec/01:138-176`) and a server-side floor gate (`Service.kt:233-234`).

---

## B. Storage / sync / transmission, as-built — vs the stated model

**Verdict up front:** the owner's model is **accurate for the server's roles and for the native clients, but "each client has a usable offline local copy it can decrypt" is FALSE for web and only partly true for the browser extension.**

### B.1 Server roles — FULLY MATCH the stated model, and "blind" is code-confirmed

| Stated role | As-built | Cite |
|---|---|---|
| blind secure transfer + syncing | `GET /sync`, `POST /sync/push`, attachments, item history — all operate on ciphertext | `App.kt:454-465, 388-447` |
| recovery store | `PUT /escrow/self`, `GET /recovery-pubkey`, admin escrow/recovery — stores + relays sealed blobs it can't open | `App.kt:566, 294, 635-640` |
| websites | static SPA (`/web`, self-only CSP) + `/downloads` | `App.kt:700-723, 304-313` |
| updates | `/downloads/manifest.json` + min-version pin → 426 | `App.kt:304, 287` |
| account provisioning | invite-only register + full admin/policy/sharing surface | `App.kt:330, 590-665` |

The **blind** property is real: the server holds no VK and never decrypts item content. Its only crypto is the argon2id login verifier, opaque token gen + `sha256(token)`, and an HMAC email-enumeration guard (`ServerCrypto.kt:11-35`).

### B.2 The per-device local copy — the divergence

| Client | Durable offline copy? | What's at rest | Cold-unlock offline? |
|---|---|---|---|
| **Android / desktop** | ✅ **Full** | per-account SQLite `vault-<userId>.db` — **item envelopes (ciphertext), grant/vault rows, outbound queue, sync cursor**; accountKeys stored separately | ✅ Yes — derive MK from cached params, open UVK, `hydrate()` decrypts every envelope **with no server call** (`SyncEngine.kt:306-329`) |
| **Web** | ❌ **None** | in-memory `Map`s only; `localStorage` holds **tokens + metadata only**, never vault data or the vault key | ❌ No — reload re-prompts for password and re-syncs from `since=0` (`store.ts:187-188`, `session.ts:3-7`, `spec/02:358`) |
| **Extension** | ◐ **Session-scoped** | decrypted items + **unwrapped VKs** in RAM-backed `chrome.storage.session` — survives SW idle-recycle, **wiped on browser exit** | ❌ No — unlock always hits prelogin+login+sync (`background.ts:30-44, 585`) |

- Natives persist **only ciphertext** at rest and decrypt in memory (`SqliteVaultCache` contract: "plaintext never touches disk" `:13-18`); the durable offline copy is **policy-contingent** — org `offlineCacheAllowed=false` forces in-memory + deletes the DB (`AndvariViewModel.kt:1908-1912`).
- **Attachments are online-only on every client** — item envelopes cache `attachmentIds` only; blob bytes are always fetched (`SyncEngine.kt:1202-1211`). So even natives are "offline for passwords/notes/TOTP, online for attachment downloads."

### B.3 Sync is blind, conflict-safe, and rollback-guarded

- **Pull** `GET /sync?since=<rev>` → one global monotonic rev, single-tx snapshot; **rev-rollback guards** reject a non-full response below the cursor or an unsolicited full; `410 Gone` → transactional resync-from-0 (fetch replacement first, then clear) (`SyncEngine.kt:350-368`).
- **Push** `POST /sync/push` → per-mutation `applied|conflict|denied`, idempotent on `(deviceId, mutationId)`, **200-mutation batch cap** (`Service.kt:339`). **The server never merges or re-encrypts** — it applies the newest write, archives the loser, sets `conflict=true`; the **client** materializes the visible "(conflict copy)" deterministically so concurrent clients converge (`SyncEngine.kt:1040-1086`).
- **Live-notify is a dirty-bell, not a data plane** — the WS carries only `{type:"rev"|"policy"|"revoked"}`; "nothing else rides the socket" (`spec/03:179-194`). Browsers mint a single-use 30 s ticket so long-lived bearers never hit edge logs.

### B.4 Transmission

- HTTPS JSON under `/api/v1`, 1 MiB cap. Primary origin `https://andvari.taila2dff2.ts.net` (tailnet, `tailscale serve` → loopback); break-glass `andvari.monahanhosting.com` (always-on Cloudflare tunnel). Both terminate TLS at the edge; Ktor listens plaintext on `localhost:8080` behind them.
- `Authorization: Bearer <accessToken>`; server stores only `sha256(token)`. Login sends `authKey`, never the password. (No app-level cert-pinning of the andvari server was found — a possible future hardening item, not a gap in the ZK contract.)

### B.5 The storage decision this surfaces

The owner's stated model wants **every** client to hold a usable local copy. Today that's a **native-only** property by deliberate spec choice (`spec/02:358`). Closing the gap for **web** means a durable, encrypted **IndexedDB** cache (envelopes + cursor + queue), which brings its own at-rest threat surface (browser-stored ciphertext, XSS-exfil considerations, a web quick-unlock story). This is a **real, separable feature decision** — see §D.2.

---

## C. The recovery roadblock — why it exists, and how per-member recovery removes it

### C.1 Why the check is there

The typed-fingerprint step is **not** required by the escrow math. It exists solely to defend **spec 05 T10**: a hostile server substituting *its own* recovery **public** key at an enrollment moment, so that every new account escrows its UVK to a key the attacker controls → silent total compromise. Every server-side pin (env, `/client-policy`, `/recovery-pubkey`) roots in the server and collapses together if the server is hostile; the **printed sheet, typed before the value is shown**, is the one comparison the server can't forge (`Escrow.kt`, `Welcome.tsx:379-406`, `spec/04:22-36`, `spec/05:25`).

So the check protects the **household-wide org escrow model**, not the member. That's the key to removing it.

### C.2 Per-member recovery dissolves the check — by construction

A per-member recovery piece is a **symmetric** secret the member holds at both seal-time and open-time. The correct primitive is the existing **AEAD `Envelope`** (XChaCha20-Poly1305 + domain-separated AD), **not** a sealed box. Because there is **no org public key to substitute**, T10 does not apply and **the fingerprint ceremony has nothing to defend — it disappears.** The worst a hostile server can do is serve a wrong blob → recovery **fails closed** (AEAD tag mismatch) = pure availability denial, already accepted under T1.

**The design (proposed):**

- **At signup**, client generates `recoverySecret` = **≥128 bits from `crypto.randomBytes`** (generated, *never user-typed*). HKDF-split into `recoveryWrapKey` + `recoveryAuthKey` (mirrors the existing auth/wrap split). Wrap the UVK: `recoveryWrappedUvk = Envelope(recoveryWrapKey, UVK, ad="andvari/v1|recovery-uvk|{userId}")`. Show the secret **once**, "type it back to confirm you saved it," then drop it from memory.
- **Server stores** a new `member_recovery(userId, recoveryWrappedUvk, recoveryVerifier)` row — `recoveryVerifier = crypto_pwhash_str(recoveryAuthKey)` (one-way, exactly like the login verifier). **ZK preserved:** server sees only ciphertext + a one-way hash.
- **Recovery flow** `POST /recovery/self`: member enters the piece → client re-derives keys, fetches + unwraps `recoveryWrappedUvk` → **UVK in hand** → picks a new password → re-wraps UVK. Server **verifies `recoveryAuthKey` against `recoveryVerifier`** (rate-limited like login), then applies the same reset as admin recovery (overwrite verifier/wrappedUvk/kdf, revoke sessions — `AdminService.kt:99-108`). *This verifier gate is the "account-takeover auth flow" the v6 trustee idea was vetoed for lacking (`docs/design/2026-07-08-v6-idea-tournament.md:23`).*
- **Entropy:** 128 bits generated is computationally unreachable → **HKDF alone suffices, no Argon2id on the recovery path** (unlike the human-chosen master password). This makes the piece *stronger* than the master password — it strengthens the weakest-link posture, **provided the "generated, never typed" rule holds.**
- **Form:** reuse the **exact printable sheet + QR** format `recovery-cli` already renders (`Main.kt:79-91`) — zero new deps. (A BIP39 phrase is nicer UX but needs a 2048-word list vendored byte-parity across all four crypto stacks — a follow-up, not MVP. One-time codes are the wrong pattern — they're a 2FA-backup shape, not a key-derivation shape.)

### C.3 Migration is additive — no re-enroll, no password change, UVK unchanged

Existing accounts (jacob) have an org `escrow` row and no `member_recovery` row. On the next **authenticated, unlocked** session (UVK in memory), the server returns `recoverySetupNeeded=true`; the client offers "set up your recovery phrase," wraps the in-memory UVK, `PUT /recovery/self-setup`. **Because the UVK never changes, the org escrow blob stays valid too** — jacob keeps his admin backstop *and* gains a self-service piece. Same shape as the existing F57 "re-seal on next unlock" nudge.

---

## D. The decisions (the owner's to make)

### D.1 PRIMARY — the recovery trust model

The irreducible fork: **admin backstop** and **privacy-from-admin** are mutually exclusive *at the recovery layer*. Org escrow buys the "nothing is ever lost" backstop precisely by holding a key that opens everyone; you cannot keep that key and also deny the admin read access.

| Option | Onboarding | Backstop if member loses password **and** piece | Member private from admin? | Verdict |
|---|---|---|---|---|
| **(a) Pure per-member** — drop org escrow | link only, no sheet | ❌ **Permanent loss** | ✅ Yes | Clean, minimal. Right *iff* privacy-from-admin is a hard requirement and hard-loss is acceptable. |
| **(b) Hybrid** — per-member piece + org escrow backstop, fingerprint rides the **in-person QR** | link only, no sheet | ✅ Admin recovers | ❌ No (admin can still decrypt — **R3 persists**) | **RECOMMENDED.** Delivers exactly what was asked (no sheet, per-member piece) *and* keeps the family safety net. |
| **(c) Keep org escrow, auto-trust server pubkey** (drop the check) | link only, no sheet | ✅ Admin recovers | ❌ No | **Dominated** — surrenders the T10 guarantee for the same UX option (b) gets while keeping it. |

**Recommendation: (b) Hybrid, with per-member escrow *opt-out*** so the household gets a knob, not a global vote. For a non-technical family, **silent permanent data loss is the worse failure mode** than imperfect privacy — and the common case (forgot password) becomes true self-service, while the rare case (lost password *and* piece) still has the admin backstop. The opt-out gives you *both* postures in one system.

**The single decisive question:** *Do household members need privacy FROM the admin (you)?*
- **No** → Hybrid (recommended default).
- **Yes, for some member** → that member opts out of escrow → pure per-member for them, accepting hard-loss.

**Honest caveat that must ship with (b):** removing the printed sheet means the org fingerprint has to be delivered *some* other way. It can ride the enroll link as a new `rfp` field — **but there are two compose sites:**
- **In-person QR** is **client-composed** on the admin's own device (`enrolllink.ts:84`) → the pin is as trustworthy as the old printed sheet. **Full T10 guarantee.**
- **Emailed link** is **server-composed** (`App.kt:598-620`) → a hostile server could stamp a fingerprint it controls. **That path is TOFU-from-server — only as trustworthy as the server at compose time** (already R8-adjacent territory, `spec/05:46-50`).

The UI **must not** silently treat a server-composed pin as equivalent to an out-of-band one. Recommend: **in-person QR for households that care; document the emailed path's weaker guarantee.**

### D.2 SECONDARY — should web get a durable offline copy?

Your stated model wants every client to hold a usable local copy; today only natives do (§B.2). Closing it for web = an encrypted **IndexedDB** cache (envelopes + cursor + queue) + a web quick-unlock story, and a new at-rest threat surface to reason about (browser ciphertext + XSS exfil). This is **separable** from the recovery fork and can be sequenced after it. Recommendation: **decide the recovery model first, ship it, then take web-offline as its own doctrine-complete cut** — not block one on the other.

---

## E. Build plan once decided (for the recommended Hybrid path)

Full doctrine: design → adversarial breaker → parallel disjoint builders → file-logged gates → find→refute review → fix confirmed → commit → snapshot-first ship → byte-verify → Telegram statement.

**Change surface (from the survey):**
- `core/.../crypto/MemberRecovery.kt` (new) — HKDF split + `Envelope`-wrap the UVK under a new `Ad.recovery(userId)`. **Org `Escrow.kt` untouched.**
- `core/.../model/Wire.kt` — additive: `RegisterRequest.memberRecovery`, `/recovery/self` DTOs, `AccountKeys.recoverySetupNeeded` (defaulted, same pattern as `escrowStale`).
- `core/.../client/Account.kt` — generate the piece in `enroll` (source of the fingerprint moves from typed-sheet → link-pin), add `recover()` + `setupMemberRecovery()`.
- `web/src/ui/Welcome.tsx` — **replace** the "type 16 chars" block with (i) auto-verify against the link-pinned fingerprint (fall back to typed only when the link lacks a pin), (ii) a one-time "here's your recovery phrase, save it" reveal+confirm; new `/recover` screen.
- `web/src/enroll/enrolllink.ts` + core `EnrollLink.kt` twin + `spec/test-vectors/enrolllink.json` — add `rfp` (byte-parity-vector-pinned — twins + vectors move together).
- Server: new `member_recovery` table; `POST /recovery/prelogin` (anti-enumeration) + `POST /recovery/self` (verifier-gated, rate-limited, replay-bound) + `PUT /recovery/self-setup`; persist the block in `register`; emailed-compose gains the `rfp` stamp **with the caveat documented**.
- `recovery-cli` + F57 re-seal — **unchanged** (org escrow backstop path).
- Specs: `04` gains a per-member section; `05` amends R3 + adds **R9** (member holds a UVK-equivalent piece — loss and theft faces); `01 §2` documents the two new HKDF infos; `03` documents new endpoints.

**Adversarial breaker checklist (pre-agreed):**
1. `/recovery/self` **is** the account-takeover flow — verify it's verifier-gated, rate-limited like login, replay-bound; an attacker *without* the piece cannot reset or lock out an account; `/recovery/prelogin` has deterministic-fake anti-enumeration.
2. **Link-pin trust boundary** — in-person QR is client-composed, emailed is server-composed; the UI must **not** present a server-composed pin as out-of-band-verified.
3. **Entropy + generation** — `crypto.randomBytes` with unbiased (rejection) sampling, never `Math.random`; **generated, never user-typed.**
4. **Fail-closed** on hostile blob/param substitution at recovery (wrong blob → AEAD tag fail; if Argon2id is ever added, refuse params below the `spec/01:151-156` floor).
5. **Shown-once discipline** — the phrase renders once, never persisted, cleared from memory, absent from logs/telemetry; the "I saved it" gate can't be trivially skipped (silent-loss trap).
6. **Double-wrap consistency** — after password change, self-recovery, and admin recovery, confirm *both* the org escrow and the member blob still open (UVK is invariant).
7. **Preserve the identity-pubkey hard-fail** (§A.3) — untouched by this change, must still fire.

---

## F. BUILD CONTRACT — binding amendments applied (authoritative; builders implement to THIS)

Two adversarial breakers (crypto/protocol + authorization/trust-boundary) ran against §C–§E. The design core is sound (symmetric `Envelope` genuinely dissolves T10; ≥128-bit generated piece is stronger than the master password), but the surrounding plumbing had four account-takeover-class gaps and a T10-reopening trust error. All confirmed amendments are folded in below. **This section overrides §C/§E wherever they differ.** Every builder implements to §F exactly.

### F.1 The fingerprint-provenance model (fixes the T10 reopen — CRITICAL)

**Rule:** the enrolling client MUST NEVER treat a **server-sourced** recovery-pubkey fingerprint as out-of-band-verified. A fingerprint is an anchor only when a **human** or a **build-baked value** put it there.

- **Waived members: no fingerprint anywhere, ever.** No org escrow ⇒ no org pubkey to substitute ⇒ nothing to verify. This is the frictionless path.
- **Required (backstop) members:** the org escrow must seal to the *genuine* org pubkey, so the org fingerprint must reach the invitee through a server-tamper-proof channel:
  - **In-person QR:** the **admin** type-confirms the org short-fingerprint against the **printed sheet** at compose time (reuse the `Account.resealEscrowFor` verified-fingerprint discipline, `Account.kt:539-545`) — the admin's client stamps *that confirmed value* as the link's `rfp`, never a `/admin/status` or `/client-policy` fetch. The invitee scans the QR off the admin's screen (bypasses the server) and **eyeball-confirms** the displayed `rfp` matches what the admin shows — a one-tap confirm, not a 16-char type.
  - **Remote/emailed required:** unsupported safely → the server-composed emailed link carries **NO authoritative `rfp`**; the invitee must type the fingerprint from a sheet the admin shared out-of-band (the current ceremony). Discouraged by UI.
- **Emailed invites default to `escrowPolicy=waived`** (no fingerprint needed) — the common remote case is frictionless and safe. The admin may still choose an in-person QR backstop invite.
- **Fallback polarity (fail-safe):** a **missing** `rfp` ⇒ fall back to the **typed-sheet** ceremony (or, if waived, nothing) — **NEVER** auto-trust the server pubkey. A **present** `rfp` is honored only via the in-person affirmation above. The server can force "missing" (safe) but can never force silent auto-trust.
- The invitee client cannot cryptographically distinguish a client-composed from a server-composed link (no shared secret at enroll; identity keys are box not signing keys). Provenance is therefore a **human** decision surfaced in the UI, not a client guess.

### F.2 Wire contract (all additive; old clients `ignoreUnknownKeys`; new fields default fail-SAFE)

- `RegisterRequest` (`core/.../model/Wire.kt`):
  - `escrow: Escrow?` — **becomes nullable** (was non-nullable). Present iff the invite is `required`.
  - `memberRecovery: MemberRecoveryBlock?` — NEW. `{ recoveryWrappedUvk: String /*b64url*/, recoveryAuthKey: String /*b64url*/ }`. **MANDATORY for all NEW registrations** (see F.4). Server stores `recoveryVerifier = crypto_pwhash_str(recoveryAuthKey)` + `recoveryWrappedUvk`; it never persists `recoveryAuthKey` raw (identical to how `authKey → verifier` works).
- `AccountKeys` (`Wire.kt:58-70`): add `recoverySetupNeeded: Boolean = false` (same additive shape as `escrowStale`). `true` ⇒ an existing account with no `member_recovery` row (migration nudge).
- Enroll link payload `EnrollPayload` (`EnrollLink.kt` + `enrolllink.ts` twin + `spec/test-vectors/enrolllink.json`): add `rfp: String?` (org recovery **short** fingerprint, 16 hex). **Byte-parity vector-pinned — the two twins + the vector file move together in one commit.** Server-composed compose (`App.kt` emailed path) MUST pass `rfp = null`.
- Invite (server-side): new column `invites.escrowPolicy TEXT NOT NULL DEFAULT 'required'`. Admin `createInvite` (`InviteRequest`) gains `escrowPolicy: String = "required"`. Read **server-side from the invite row** at register — never from the client body.
- New table `member_recovery(userId TEXT PRIMARY KEY, recoveryWrappedUvk TEXT NOT NULL, recoveryVerifier TEXT NOT NULL, updatedAt INTEGER NOT NULL)` via `ALTER`/`schemaVersion` bump (`Db.kt`).
- Recovery DTOs — see F.3.

### F.3 Two-phase self-recovery protocol (fixes enumeration oracle + pre-auth blob handout + replay — CRITICAL)

No `/recovery/prelogin` is needed — the recovery secret is high-entropy and derivation uses **HKDF only, no server salt/params**, so there is nothing to fetch first. Two endpoints + one setup endpoint, **all refused on the public break-glass origin** (`isPublicOrigin` guard, like register `App.kt:332`), all per-IP rate-limited ≥ public-login tightness (`RateLimiter.kt`, ≥5/min bucket):

1. **`POST /recovery/self/verify`** `{ email, recoveryAuthKey }` → server runs `crypto_pwhash_str_verify(recoveryVerifier, recoveryAuthKey)`. **Anti-enumeration (F.5):** on unknown email OR known-email-without-a-`member_recovery`-row, run a fixed `DUMMY_RECOVERY_VERIFIER` verify and return a uniform `401`. On success only: mint a **single-use, short-TTL, userId-bound recovery ticket** (reuse the `WsTicketStore` pattern, `App.kt:678`) and return `{ recoveryTicket, recoveryWrappedUvk, encryptedIdentitySeed, identityPub }`.
2. **`POST /recovery/self/commit`** `{ recoveryTicket, newAuthKey, newKdfSalt, newKdfParams, newWrappedUvk }` → validate the ticket (live, unconsumed, consume it). Then a **dedicated reset method (NOT `AdminService.applyRecovery` verbatim)**: (a) load user, **refuse if `status != 'active'`** (`recovery_account_not_active` — a disabled account is admin-recoverable only); (b) **do NOT set `status='active'`**; (c) **do NOT set `mustChangePassword=1`** (the user just chose it); (d) enforce `requireKdfFloor(newKdfParams)` (`Service.kt:233`); (e) overwrite `verifier/wrappedUvk/kdfSalt/kdfParams`; (f) revoke all sessions. Audit `recovery_self_commit`.
3. **`PUT /recovery/self-setup`** (authenticated) `{ currentAuthKey, memberRecovery }` → **require fresh master-password reauth**: verify `currentAuthKey` against the login verifier exactly like `changePassword` (`Service.kt:238-244`) before storing `member_recovery`. A quick-unlock/biometric session (no password in hand) **defers** the setup nudge to the next full-password unlock. Audit `recovery_self_setup`. This is the migration/rotation path (F.6).

Client `Account.recover()` MUST route the unwrap through the shared `unlockFromUvk` tail so the **seed-derived identity-pubkey hard-fail fires** (`Account.kt:308-318`) before commit; it MUST NOT regenerate UVK / identitySeed / identityPub (the new `newWrappedUvk` wraps the **same** UVK — invariant, so both the org-escrow and member-recovery blobs stay valid).

### F.4 Register gate — a TOTAL function (fixes zero-recovery hole + self-waive — CRITICAL)

Server-side at register, `policy = invites.escrowPolicy` (read from the invite row; any value other than the literal `"waived"` — NULL, unknown, typo — is treated as `required`):

- **`memberRecovery` is MANDATORY for every new account** → reject `recovery_required` if absent/structurally invalid. *(This is the owner's core ask — every member gets a self-service recovery piece at signup, regardless of policy.)*
- **`policy == required`** → `escrow` MANDATORY + fingerprint-match exactly as today (`Service.kt:87-89`). *(Member has BOTH: self-service piece + admin backstop.)*
- **`policy == waived`** → `escrow` **FORBIDDEN** → reject `escrow_not_allowed_when_waived` if present. *(Member has only the self-service piece; no admin backstop.)*
- **Invariant, guaranteed by the above:** an account can NEVER be created with neither recovery path. Enforce server-side; never trust the client. Gate pre-`memberRecovery` clients out via the min-version pin (`enforceVersion`, `App.kt:331`) so an old client can't register into a partial state.
- **Posture binding (both sides):** the member must check a posture-specific acknowledgment before a `waived` register — copy: *"There is NO admin backstop. Only your recovery phrase can restore this account. Lose both your master password and this phrase and this account is gone forever."* — visually distinct from the escrow/backstop copy. The Admin UI renders each user's enrolled posture and **distinguishes "waived (intended)" from "escrow missing/failed"** (`AdminUserSummary.escrowFingerprint == null`) so a server-side policy flip is visible on reconciliation. Spec 05 records this honestly: opt-out authorization is **server-trusted state with admin-visible reconciliation, made non-silent** — not tamper-proof (acceptable under T1 for the household model).

### F.5 Anti-enumeration parity

`/recovery/self/verify` must be timing/shape-uniform across **all three** states (no such email / email-but-no-recovery-row / email-with-row) — run `DUMMY_RECOVERY_VERIFIER` on the first two, bare `Unauthorized()` for all failures, mirroring login's `DUMMY_VERIFIER` (`Service.kt:143,1050`). A null/absent/malformed stored verifier must never match.

### F.6 Crypto constants + generation invariant (the invariant the whole T8 posture rests on)

- `recoverySecret = randomBytes(32)` (**256-bit**, ≥128 required, 256 recommended to match the org seed) via `CryptoProvider.randomBytes` / libsodium `randombytes_buf` — **NEVER `Math.random`, never user-influenced/typed.**
- `recoveryWrapKey = HKDF-SHA-256(recoverySecret, info="andvari/v1/recovery-wrap", 32)`; `recoveryAuthKey = HKDF-SHA-256(recoverySecret, info="andvari/v1/recovery-auth", 32)` — empty-salt HKDF (uniform IKM), same construction as `Keys.kt:35-39`. Infos confirmed **distinct** from existing `auth`/`wrap`.
- `recoveryWrappedUvk = Envelope(recoveryWrapKey, UVK, ad="andvari/v1|recovery-uvk|{userId}")` — new `Ad.recovery(userId)` (`Ad.kt:18`), confirmed distinct from `Ad.uvk`, so blobs can't be cross-substituted between slots.
- **Sheet form:** reuse the `recovery-cli` printable format — grouped **base64url of the raw 32 random bytes** + QR (`Main.kt:79-91`). base64url-of-CSPRNG is unbiased → **no rejection sampling needed** (rejection sampling is required only if a restricted-alphabet/BIP39 encoding is ever added — a deferred, separately-broken cut). No Argon2id on the recovery path.
- The "type it back to confirm you saved it" step is a **`ctEquals` confirmation only** — NEVER the KDF source (a mistype must fail the confirm, never silently mis-key).
- New crypto is **byte-parity vector-pinned**: `spec/test-vectors/member-recovery.json` with deterministic inputs (fixed secret bytes + userId → expected `recoveryWrapKey`/`recoveryAuthKey`/`recoveryWrappedUvk`), asserted by BOTH the core (Kotlin) and web (TS) tests.

### F.7 Shown-once discipline (web leak vectors, concrete)

- `recoverySecret` lives in a **`useRef` cleared immediately after the confirm passes** — never long-lived `useState`; the confirm input is not a controlled `value` bound to the secret.
- Render the phrase as **text** (not `type="password"`), confirm input `autoComplete="off"` and **outside** the credential `<form>`, so the browser's password manager never offers to save it.
- A "copy phrase" button is a **secret** clipboard write (auto-clear after `clipboardClearSeconds`, like `Vault.tsx:833`) — NOT the non-secret setup-material exemption.
- **Never** write `recoverySecret` to `localStorage`/`sessionStorage`/IndexedDB (and it must never reach the deferred durable-web-cache cut). **Static** error strings only — never interpolate secret material into `setErr`/`console.*`/telemetry/audit.
- The confirm gate blocks account usability and is **un-skippable** (silent-total-loss guard), matching today's `fpConfirmed` gate.

### F.8 Preserved invariants (do NOT regress)

- The **identity-pubkey hard-fail** (`Account.kt:308-318`) is untouched and must still fire on every unlock **and** during `recover()`.
- Org escrow (`Escrow.kt`), `recovery-cli`, and F57 re-seal (`escrowStale`) are **unchanged** — `member_recovery` is symmetric and not sealed to the org key, so an org-key rotation never touches it. Both blobs stay valid across password change / self-recovery / admin recovery (UVK invariant).
- `/recovery/self/*` limiter is **per-IP fixed-window** (no per-account counter → no attempt-lockout DoS on a targeted account), consistent with `login`/`prelogin`.

---

## F.9 Round-2 amendments — from the adversarial build review (applied)

A 9-lens find→refute review of the BUILT code confirmed the security core clean (crypto parity, two-phase protocol, register gate, provenance UI, back-compat all empty) but found 7 confirmed defects in the web seams + a capture-durability gap. Fixes:

**Capture-confirmation durability (fixes the two HIGH findings + the dead migration nudge):** `memberRecovery` stays MANDATORY at register (the never-zero-recovery server guarantee is preserved — do NOT weaken it), but a registered piece the user never *captured* (interrupted reveal) was a silent-total-loss path for waived accounts, and the migration nudge (`recoverySetupNeeded`) was consumed by no client. Add a **durable, cross-device confirmation signal**:
- **Server:** new `users.recoveryConfirmed BOOLEAN NOT NULL DEFAULT 0` (schema **v7**). Register sets it `0`; existing accounts default `0` (they get nudged — harmless, they retain the escrow backstop). New `POST /api/v1/recovery/self/confirm` (authenticated, public-origin-refused, rate-limited) sets it `1` — called after the user demonstrably captures the phrase (types it back). **`recoveryConfirmed` is flipped ONLY by `/recovery/self/confirm`, in BOTH the enroll path and the block-path gate.** `PUT /recovery/self-setup` COMMITS/rotates the piece but does **NOT** set `recoveryConfirmed` — the block-path gate calls self-setup on mount, *before* the reveal is captured, so flipping there would mark an interrupted reveal "captured" and re-open the silent-loss hole (this was a round-3 review catch). Surface `recoveryConfirmed: Boolean` on `AccountKeys` (core `Wire.kt` + web types). `recoverySetupNeeded` (=`!hasMemberRecovery`) stays as informational.
- **Web:** a **vault-entry capture gate** — on Unlock + SignIn success (where the master password → `currentAuthKey` is in hand), if `!recoveryConfirmed`, BLOCK vault access and force setup-and-reveal: `setupMemberRecovery(currentAuthKey)` regenerates + commits a fresh piece (commit only — the flag stays false) → shown-once un-skippable reveal → **on the type-back confirm, `POST /recovery/self/confirm` flips the flag** → vault. Because the flag flips only after demonstrated capture, an interrupted gate reveal leaves `recoveryConfirmed=false` and the gate correctly re-fires on the next entry (any device). The enroll happy-path uses the same `POST /recovery/self/confirm` after its reveal (no regenerate; the register-committed piece is what was shown).
- **Native:** call `POST /recovery/self/confirm` after the existing `RecoverySetupScreen` confirm (native enrollees marked confirmed). The native vault-entry gate for migration/interrupted is **deferred to recovery-cut-2** — native `waived` is not enabled (no native total-loss reachable) and `required` retains the escrow backstop.

**Web seam + hygiene fixes:** align error strings to the server's actual values (`recovery_public_disabled` at `Recover.tsx:82`, `invalid_ticket` at `:123`); zero the enroll `secretRef` on unmount (mirror `Recover.tsx`'s cleanup); **disable the Sign-in/Enroll tab bar while the reveal is showing** (closes the un-skippable-gate escape); rekey the admin posture display on the server-sent `recoveryEnrolled` (`escrowFingerprint != null` → "admin backstop"; else `recoveryEnrolled` → "waived (intended)"; else → "no recovery / needs setup").

**Deferred to recovery-cut-2 (documented, not silently dropped):** native vault-entry capture gate + native waived + native self-recovery screen + native admin fingerprint-confirm; and the fuller admin reconciliation that persists the invite's `escrowPolicy` onto the users row to flag a *required*-member-with-missing-escrow (which `recoveryEnrolled` alone cannot distinguish — rare, arises only from post-hoc escrow deletion or a hostile flip on a required invite).

---

## Appendix — the four survey passes (HEAD `74c2f8e`, read-only)

- **A — auth + key hierarchy:** full key-hierarchy diagram, secret inventory, register payload, ZK boundary. Linchpins: identity-pubkey hard-fail + recovery fingerprint.
- **B — recovery/escrow:** org keypair from `recovery-cli keygen` (X25519); escrow = UVK sealed to org pubkey (`crypto_box_seal`), mandatory at enroll; the fingerprint check is the sole out-of-band anchor; recovery doubles as vault succession.
- **C — per-member redesign:** symmetric `Envelope` design, verifier-gated `/recovery/self`, additive migration, three-option fork, Hybrid recommendation, breaker checklist.
- **D — storage/sync/transmission:** server roles all match the stated model + blind confirmed; native = full offline, web = none, extension = session-only; sync rollback-guards + client-side conflict materialization; WS is a dirty-bell.
