# Design — native admin-fingerprint-confirm (2026-07-15)

**Status: DESIGN ONLY — and the design's own verdict is DO NOT BUILD STANDALONE.**
This resolves the deferred item "native admin-fingerprint-confirm (needs a native admin
surface)" (`docs/ROADMAP.md:37-38`; the originating TODO is
`app-android/src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt:692-696` —
"the native admin fingerprint-confirm-for-QR [is] deferred"). It answers what threat the
check still defends now that per-member recovery is symmetric, where it would live on the
natives, the exact derivation and UX, fail-closed semantics, a breaker checklist, and an
honest cost/benefit. The verdict (§7): **no live T10 gap exists on the natives today**,
because the natives have no admin surface at all — this document is a **binding
constraint on any future native admin surface**, not a build order.

Companion reading: `docs/design/2026-07-12-auth-secret-recovery-review.md` (§A.3
linchpin 2 at :64, §C.1 at :128, §C.2 at :132-134, §F.1 at :209-217, the deferral at
:292), `spec/04-escrow-recovery.md` §§1-2 + §6.5, `spec/05-threat-model.md:25` (T10).

---

## 1. What threat remains — precisely

### 1.1 What T10 is, and what dissolved

**T10 = a malicious server substituting *its own* org recovery PUBLIC key at a moment a
client is about to seal a UVK to it** (`spec/05-threat-model.md:25`). Every server-side
pin (env, `/client-policy`, `/recovery-pubkey` — served unauthenticated,
`server/.../App.kt:394,401`) roots in the server and collapses together if the server is
hostile; only a **human- or build-anchored** fingerprint comparison survives
(`spec/04-escrow-recovery.md:22-36`, review §A.3 linchpin 2 at :64).

The **per-member self-service recovery piece is symmetric** (AEAD `Envelope`, no public
key anywhere — `spec/04-escrow-recovery.md:115-131`, review §C.2 at :132-134,
`core/.../crypto/MemberRecovery.kt:8`). There is nothing to substitute, so **T10 does not
apply to the member-piece path on any client** — the worst a hostile server can do is
serve a wrong blob, which fails the AEAD tag = availability denial, already accepted
under T1. That dissolution is complete and needs no fingerprint UI, native or web.

### 1.2 Where T10 still lives: every place a client seals the UVK to a server-fetched org pubkey

Three seal sites exist. **All three are already human-anchored on every client that has
them:**

| Seal site | Who acts | Web | Android | Desktop |
|---|---|---|---|---|
| (a) `required`-posture **enroll** (seal UVK → org pubkey) | enrollee | typed-sheet ceremony (`Welcome.tsx:768-807`) or one-tap rfp affirm (`Welcome.tsx:751-765`), gated by `escrowGate` (`enrollposture.ts:57-78`) | typed-sheet via shared `EnrollCeremony.ready` (`MainActivity.kt:580-606`, `core/.../EnrollCeremony.kt:20-36`) | typed-sheet via the same `EnrollCeremony` (`Ui.kt:380`) |
| (b) **F57 re-seal** after an org re-ceremony (`escrowStale`) | member | `ReSealBanner` typed-sheet (`Vault.tsx:738-756`) | `ReSealCard` typed-sheet (`AndvariViewModel.kt:730-745`) | `ReSealCard` typed-sheet (`Ui.kt:253-286`) |
| (c) **Admin compose-time anchor**: type-confirm the org short-fingerprint against the PRINTED sheet and stamp it as the in-person QR invite's `rfp` | **admin** | `InviteForm` confirm + `stampedRfp` (`Admin.tsx:390-424, 457-459, 536-558, 337-344`) | **does not exist — no invite surface** | **does not exist — no invite surface** |

The deferred item is **(c)'s native twin, and only (c)**. It is NOT the member-piece
capture confirm (`recoveryConfirmed` — durable, server-side, shipped native in
recovery-cut-2), and NOT the shared-vault identity fingerprint (`SharedGrant.fingerprint`
— a different keypair, already shipped as native identity codes).

### 1.3 The honest answer: nothing remains open on the natives *today*

Row (c) has **no native attack site** because the natives have no admin surface of any
kind:

- **No admin API in the shared client.** `core/.../client/AndvariApi.kt` exposes zero
  `/admin/*` routes; the entire admin API (`adminUsers`, `adminInvite`,
  `adminUserEscrow`, `adminPolicy`, …) exists only in `web/src/api/client.ts:524-575`.
- **Natives don't even read `isAdmin`.** `SessionResponse.isAdmin`
  (`core/.../model/Wire.kt:107`) is consumed by web (`Welcome.tsx:587,594`) and ignored
  by both native state holders (grep: zero hits in `app-android/` and `app-desktop/`).
- **Android has no enroll-link channel at all** — the invite token is typed, so
  `linkRfp` is always null and the rfp/required-affirm posture is unreachable
  (`MainActivity.kt:523-529`, `enrollReady` note at :652-655).
- **Desktop deliberately IGNORES a pasted link's `rfp`** — "a paste has no provenance"
  (`DesktopState.kt:108-120`, `Ui.kt:414-416`) — so it fails safe to typed-sheet/waived.
  A `required`-QR invite pasted into desktop without the sheet dies server-side with
  `recovery_required` and honest copy (`DesktopState.kt:2467`).

So: **a native admin-fingerprint-confirm currently has nothing to defend, because there
is no native path that composes an invite, stamps an `rfp`, or seals anything in an
admin role.** The T10 defense on natives is already complete for the roles natives
actually have (enrollee + member: rows (a) and (b)). The deferred item is a
**pre-commitment**: *if* the natives ever gain an invite-compose surface (the plausible
ask: "mint an in-person QR invite from the admin's phone"), that surface MUST ship with
the human-anchored confirm from day one — shipping it without one would be the first
regression of §F.1 ("MUST NEVER treat a server-sourced recovery-pubkey fingerprint as
out-of-band-verified", `spec/04:205-207`, review §F.1 at :211).

We do not invent a need beyond that. The rest of this document specifies the constraint
so a future builder cannot get it wrong.

---

## 2. Where the native admin surface would live (when/if built)

### 2.1 Current native surface inventory

- **Android** (`app-android/.../app/`): Welcome (Sign-in/Enroll tabs), Vault, Settings,
  Sharing, Autofill Status, RecoverySetup/Capture, Recover — all member-facing.
  Single-activity Compose (`MainActivity.kt`), state in `AndvariViewModel.kt`.
- **Desktop** (`app-desktop/.../desktop/`): one-window Compose
  (`Ui.kt`/`DesktopState.kt`), screens enumerated as `DesktopScreen` (Unlock, Vault,
  Settings, Sharing, RecoveryCapture, Recover — `DesktopState.kt:~60-107`). All
  member-facing.

### 2.2 Minimal admin surface to host the confirm

The smallest honest slice is **one admin-gated "Invite" screen** per platform (NOT a full
admin cockpit — no user list, no device revocation, no policy editor; those stay web):

1. **Core plumbing (shared, `:core`):**
   - `AndvariApi.adminInvite(InviteRequest): InviteResponse` (+ optionally
     `adminStatus()` for `emailConfigured` only — never as a fingerprint source). The
     wire types already exist (`Wire.kt:483-518` — `AdminUserSummary`, `InviteRequest`
     with `escrowPolicy`, `InviteResponse`); the server route exists
     (`AdminService.kt:46 createInvite`).
   - Plumb `SessionResponse.isAdmin` into `AndvariViewModel.UiState` /
     `DesktopState` (UI visibility only — authorization stays server-side).
   - A private-origin predicate twin of web `isPrivateOrigin`
     (`web/src/ui/origin.ts`) keyed on the configured base URL, because the QR-compose
     affordance is private-origin-only (`Admin.tsx shouldOfferQr:308-310`; a
     public-origin link dies at `register` anyway, but the affordance must not exist —
     same reasoning, pinned pure + tested like web's).
   - Link composition is **the existing `core EnrollLink.compose(origin, token, email,
     rfp)`** (`EnrollLink.kt:90`), already byte-parity vector-pinned against the web twin
     (`spec/test-vectors/enrolllink.json` — 8 `rfp` rows). **A native invite surface must
     call it, never hand-roll a third composer.**
2. **Android:** an "Invite a household member" entry in Settings, visible iff
   `isAdmin && isPrivateOrigin(baseUrl)`. Fields: email, TTL (mirror web's
   `InviteTtl`/`INVITE_TTL_DEFAULT = 1h`, `Admin.tsx:285-301`), posture selector
   (`required`/`waived`), the §3 fingerprint-confirm block, mint button, result =
   token + QR of the composed link.
3. **Desktop:** the same section in Settings. (Lower value: a desktop admin nearly
   always has the web app one tab away; see §7.)
4. **Net-new dependency alert:** the natives have **no QR encoder** (web vendored
   `qrcode-generator@1.4.4` under `web/src/vendor/`). A native QR-compose screen needs a
   vendored Kotlin port or a new dependency — against the zero-external-deps discipline;
   this is a real cost line, not a footnote. (A QR-less variant — show the composed
   *link* for hand-transfer — dodges the dep but loses the entire point of the in-person
   channel, which is scan-off-the-admin's-screen bypassing the server.)

---

## 3. The exact fingerprint derivation + confirm UX

### 3.1 Derivation — MUST be byte-identical across clients (it already is)

- **Full fingerprint** = lowercase hex SHA-256 of the 32-byte org recovery X25519 public
  key (`spec/04-escrow-recovery.md:13-14`).
  - core: `Escrow.fingerprint` → `Bytes.toHexLower(crypto.sha256(publicKey))`
    (`core/.../crypto/Escrow.kt:55-57`).
  - web: `fingerprint()` (`web/src/crypto/escrow.ts:56-59`).
- **Short form** = first 16 hex chars (`Escrow.kt:59-60`, `escrow.ts:61-63`).
- **Normalization of a typed/scanned value**: lowercase, strip every non-`[0-9a-f]`,
  valid iff exactly 16 chars (`Escrow.shortFormMatches`, `Escrow.kt:68-71`; web
  `shortFormMatches` `escrow.ts:70-74`; `normalizeOrgFp` `Admin.tsx:346-349`;
  `normalizeShortFp` `enrollposture.ts:27-29`).
- **Display form**: grouped in 4s (`groupHex` — `Welcome.tsx:1070`,
  `MainActivity.kt:2729`, desktop inline `Ui.kt:481`). Same on printed sheets
  (`spec/04:13-14`).
- **Vector pin**: `spec/test-vectors/seal.json` pins `fingerprint`
  (`14f1bf4220e132f39314cabd75e7fa8d…`) and `shortFingerprint` (`14f1bf4220e132f3`) for
  the fixed vector keypair — both impls already test against it. A native admin confirm
  adds **no new derivation** and therefore no new vector; it reuses `Escrow` verbatim.
  The live org fingerprint is `b26efdd3eafc9dad…` (`docs/ROADMAP.md:179`).

### 3.2 Confirm UX — mirror web `InviteForm` exactly

**The critical subtlety: the ADMIN-side confirm has NO comparison target, by design.**
Web's `confirmOrgFp` (`Admin.tsx:417-424`) validates *shape only* (16 hex after
normalization). The typed value — from the **printed sheet**, which the admin owns — *is*
the anchor; comparing it against `/admin/status`'s `recoveryFingerprint` or
`policy.recoveryFingerprint` would make the server the anchor and reopen T10
(`stampedRfp`'s doc-comment pins this: "never a server-fetched value", `Admin.tsx:337-344`;
the `/admin/status` fingerprint at `Admin.tsx:818` is display-only). Native parity:

1. Posture `required` + private origin + not-emailed → show the confirm block
   ("Confirm your recovery sheet (first 16 characters) — from your printed sheet, not
   the server"). Monospace field, IME suggestions off (android: `mono` field
   discipline, `MainActivity.kt:2602`).
2. On confirm: normalize; `!= 16` hex → inline error, no state change. Valid → hold the
   value in **session memory** (§4.2), show "Recovery sheet confirmed for this session"
   + a `change` affordance (web parity `Admin.tsx:541-545`).
3. On mint: `rfp = stampedRfp(escrowPolicy, confirmedOrgFp)` — a pure function ported
   with its unit test, exactly like web's (`Admin.tsx:342-344`): stamps **only** on
   `required` + confirmed; `waived` or unconfirmed stamps **nothing**.
4. Declining to confirm is allowed and safe: the QR then carries no `rfp` and the
   invitee falls back to the typed-sheet ceremony ("Skip this and the invitee will type
   your recovery sheet's fingerprint themselves", `Admin.tsx:555`).

**The compare-and-tap in this flow belongs to the INVITEE, not the admin** — the
enrollee's device shows the scanned `rfp` grouped and asks for the in-person eyeball
match + one tap (`Welcome.tsx:751-765`); cryptographic verification then happens twice
downstream (§4.1). A native admin surface adds no compare step of its own; adding one
against a server value is a **forbidden** "improvement" (see breaker item B1).

Per `spec/04:35-36`, a native client MAY additionally show a **build-baked** fingerprint
(a compile-time constant is a legitimate second anchor); none does today and this design
does not require it — it's an optional hardening line for the future surface.

---

## 4. Fail-closed semantics

### 4.1 What is blocked until confirmed — and the chain that catches everything else

**Blocked:** exactly one privileged output — **stamping `rfp` into a composed enroll
link/QR**. Nothing else. Minting invites (any posture), emailing invites (always
`rfp=null` — server-composed, `spec/04:217-224`), and waived QR invites all proceed
without the confirm.

**The downstream fail-closed chain (all shipped, all clients):**
1. Invitee client, `required-affirm`: seals **iff** `normalizeShortFp(linkRfp) ==
   shortFingerprint(fetched /recovery-pubkey)` — mismatch → refuse + "STOP and contact
   your admin" (`enrollposture.ts:67-72`, `Welcome.tsx:556-559`).
2. `Account.enroll` independently recomputes `Escrow.fingerprint(recoveryPublicKey)` and
   **hard-throws** on mismatch with the passed `recoveryFingerprint`
   (`core/.../client/Account.kt:269-274`; same discipline in `resealEscrowFor`,
   `Account.kt:651-656`).
3. The server refuses escrow uploads whose fingerprint differs from the pinned env value
   (`spec/04:24-27`), and refuses a `required` register without escrow
   (`recovery_required`, `spec/04:173`).
4. Fail-safe polarity is pinned: **missing `rfp` ⇒ typed-sheet fallback (or waived),
   NEVER server auto-trust** (`spec/04:225-231`); android can't receive an rfp at all,
   desktop ignores pasted rfp (§1.3).

Consequence of an admin **typo** that still passes the 16-hex shape check: every invite
minted in that session fails at step 1 on the invitee's device — an availability
nuisance, never a security hole. The admin-facing remedy is the `change` affordance +
error copy that says to re-confirm from the sheet (breaker item B6).

### 4.2 The durable flag: there is NONE — deliberately

Web holds the confirmed value in **per-page-load session memory** (`sessionOrgFp`,
`Admin.tsx:390-392`): confirm once per session, not per invite, gone on reload. The
native twin MUST scope it to the **unlocked session**: in-memory only, cleared on lock,
sign-out, and account switch (android additionally: never `rememberSaveable` — no
plaintext Bundle persistence, even though the value is public; the discipline is
uniformity with `MainActivity.kt:508-513`).

Why not durable:
- A **durable value** would silently stamp a *stale* fingerprint after an org
  re-ceremony (`spec/04 §4`): still fail-closed downstream (§4.1 step 1), but every
  invite would be DOA until the admin notices. Session scoping keeps the human in the
  loop at roughly the cadence the value can change.
- A **durable boolean** without the value is meaningless — the value itself is what gets
  stamped.
- Contrast with `recoveryConfirmed` (`Wire.kt:95-97`): that flag IS durable and
  server-side because it attests a member captured a *specific server-minted piece*
  (piece-binding, design 2026-07-13). The admin confirm attests a *human comparison
  performed now* — the correct lifetime is the session that contains the human.

---

## 5. Breaker checklist (what the 2-breaker pass MUST attack before any build ships)

- **B1 — rfp provenance (the §F.1 CRITICAL):** prove no code path can stamp a
  server-sourced value (`/admin/status.recoveryFingerprint`,
  `policy.recoveryFingerprint`, `AccountKeys.escrowFingerprint`) as `rfp`. Port
  `stampedRfp` as a pure function WITH its pinned test, web-style. Also attack the
  inverse "helpful" bug: any admin-side comparison of the typed value against a server
  value that *gates or auto-fills* the confirm (warn-only display is a design decision —
  default NO, matching web; the lazy-eyeball hazard outweighs the typo catch).
- **B2 — session-memory lifetime:** confirmed value must not survive lock, sign-out,
  account switch, or (android) process death/recreation into a different account's
  session. Attack multi-account and the Activity-recreation path specifically.
- **B3 — composer parity:** the native surface must call `core EnrollLink.compose`
  (vector-pinned) — attack any hand-rolled link/QR assembly, origin normalization
  divergence (trailing slash/`:443`/case — the emailed-link DOA lesson,
  `ROADMAP.md:358-359`), and UTF-16 ill-formed email handling (web's compose-note
  fallback, `Admin.tsx:452-459`).
- **B4 — private-origin gate twin:** a native client pointed at the public break-glass
  origin must not offer QR compose (mirror `shouldOfferQr`; pin it pure + tested). Also
  attack base-URL switching mid-session.
- **B5 — bearer-token surface:** the composed QR/link embeds the invite token (bearer;
  TTL is the SOLE containment — `Admin.tsx:285-288`). Attack: TTL default parity (60
  min; server clamp [5,4320]), the QR screen's screenshot/Recents exposure on android
  (FLAG_SECURE can't stop another camera — that's the feature — but Recents thumbnails
  and screenshots of a still-live token should be considered), clipboard writes of the
  link (non-secret setup-material exemption vs. secret discipline), and that the result
  screen states the fuse (web parity `Admin.tsx:563`).
- **B6 — typo availability:** confirm the mismatch error the INVITEE sees routes the
  admin to re-confirm (copy audit), and that a re-ceremony (fingerprint rotation)
  mid-session produces fail-closed invites, not silently-working-wrong ones.
- **B7 — isAdmin trust boundary:** `isAdmin` is server-asserted state gating UI
  visibility only; verify no client secret or seal decision rides on it (a hostile
  server flipping it gains a screen the server-side authz still gates).
- **B8 — email path never carries rfp from a native:** if the surface exposes
  `sendEmail`, the request must not include any client-side rfp material (the emailed
  link is server-composed and contractually `rfp=null`, `spec/04:217-224`).

---

## 6. Cost/benefit — honest

**Benefit (small, contingent):** the only user-visible gain is minting an **in-person QR
invite from the admin's phone** (the household admin's Fold) without opening the web app
— a genuine convenience for the "new family member standing next to you" moment, and the
one channel that carries the full T10 guarantee for `required` members. Security-wise it
closes **nothing that is open**: every existing native seal path is already
human-anchored (§1.2), and emailed/waived invites (the common remote case) need no
fingerprint at all (`spec/04:200-202,217-224`).

**Cost (M, recurring):** core admin API additions + `isAdmin` plumbing + a screen ×2
platforms + a vendored native QR encoder (new code, zero-dep discipline) + the
private-origin predicate twin + pure-function tests mirroring web's pinned set + the §5
breaker pass — and a **third admin surface to keep consistent forever** (the web admin
UI has already needed posture-reconciliation and TTL-policy iterations; every future
admin change would triple).

**Also weigh:** the web admin surface is deliberately the admin cockpit (break-glass
posture, reconciliation views, audit) and is reachable from any phone browser on the
tailnet — the marginal convenience of a native screen over "open andvari.web on the same
phone" is thin.

## 7. Build-order recommendation

1. **Do not build now.** No open threat on natives; the demand signal ("invite from my
   phone") has not been voiced by the owner. Recording the constraint (this doc) is the
   deliverable.
2. **Re-point the ROADMAP deferral** at this doc: "native admin-fingerprint-confirm —
   design landed `docs/design/2026-07-15-admin-fingerprint-confirm.md`; verdict
   constraint-not-gap; build only with a native invite surface, trigger = owner asks for
   phone-minted invites" (same trigger-based pattern as the iOS/passkeys assessments).
3. **If the trigger fires:** build **android-only** first (the admin's daily device;
   desktop's marginal value over web is ~zero), as ONE cut = invite screen + confirm +
   QR, implementing §§2-4 exactly, with the §5 breaker pass before merge. Do not build a
   wider native admin cockpit around it.
4. **Standing rule for any future native admin surface** (binding, the actual point of
   this doc): it MUST ship the §3 confirm from day one; an invite-compose path without a
   human-anchored `rfp` (or with a server-sourced one) is a §F.1 violation and reopens
   T10 for `required` members — the exact class the 2026-07-12 breaker flagged as
   CRITICAL (review :209-217).
