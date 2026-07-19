# Spec — biometric quick-unlock (WebAuthn-PRF) for the extension

Status: **SPEC / GO-WITH-CAVEATS** (owner idea 2026-07-18). Target: extension **0.17.0**, additive.
Companion to the 0.16.3 TOTP-unlock-seam fix. Grounded in a WebAuthn-PRF feasibility spike + crypto
and UX design, both red-teamed. The earlier toggle idea (client-scoped TOTP) is dropped.

## 1. What & why

Add a **biometric** quick-unlock method (Windows Hello / Touch ID) beside today's PIN. It replaces
only the OUTER wrap key of the existing double-wrap: `ct = AEAD(K_bio, AEAD(coKey, UVK))`, where
`K_bio` comes from a **WebAuthn PRF (`hmac-secret`)** secret the platform authenticator releases only
after OS user-verification. The non-extractable co-key inner wrap (breaker A1) is unchanged.

Why it's safe for this surface (owner's reasoning, confirmed): quick-unlock already grants 24 h of the
extension's fill/view surface behind a short PIN; biometric is a **stronger** secret for the **same
window** — device/credential-gated, phishing-resistant, never typed, and the stolen blob is **not
offline-crackable** (the outer key is a full-entropy hardware secret, never at rest) where the PIN
relies on Argon2id to slow a crack. Full account control (shares/deletes/exports/settings) still
requires the master password — but that's a web/desktop concern; the extension has no such actions.

## 2. Feasibility & platform matrix (the caveats)

**Verdict: GO-WITH-CAVEATS.** Bio is strictly **capability-probed and additive**; the PIN lane stays
the universal fallback and is never replaced.

- **Extension-page WebAuthn**: works from `chrome-extension://` / `moz-extension://` pages — **Chrome 122+**, **Firefox 150+** (MDN "Use the Web Authn API in web extensions"). `clientDataJSON.origin` is the extension origin; irrelevant here — this is a purely local ceremony with **no server-side RP validation**.
- **PRF platform support** (the gate): **Windows** Hello needs **Win 11 25H2 + KB5077181 (build ≥26200.7840) + Chrome 147 / Firefox 148**; **macOS** Touch ID via iCloud Keychain, **Chrome 132+ / Safari 18+ / Firefox 139+**. **EXCLUDED (no PRF)**: Windows 10 Hello, pre-Feb-2026 Win 11, **Linux desktop and no-iCloud macOS** (Chrome-profile software authenticator has no `prf`). ⇒ **Runtime-probe, never manifest-gate.**
- **Ceremony surface**: the OS prompt can steal focus. **Firefox action popups provably close** during a credential request (bug 2026687, unlanded → treat the tab/window workaround as permanent). **Chrome popups very likely survive** (the same bug thread says it "already works in Chromium and Safari") — but **verify day-1 per platform**. ⇒ ship a **surface abstraction**: run the ceremony in the popup where it empirically survives, else a dedicated connector window.
- **PRF portability**: rely on it in **NEITHER** direction. iCloud-synced devices produce **different** PRF outputs per device; Windows Hello is device-bound. A synced profile on another device therefore can't redeem → full unlock + silent re-enroll. (Device-binding is provided by the **co-key** regardless — a synced PRF still can't open the co-key inner wrap.)

## 3. RP ID

**Fixed `rp.id = "andvari.monahanhosting.com"`**, claimable because the manifest already carries the
install-time `host_permissions: ["https://andvari.monahanhosting.com/*"]` (Chrome 122+ / Firefox 150+
let an extension claim any domain covered by host permissions). Rationale: zero new permissions, works
offline, independent of the user's configured server (a self-hoster's domain lives only in
`optional_host_permissions` and would drag ROR/consent). Related-Origin Requests
(`/.well-known/webauthn`) is **moot and non-viable** — a `chrome-extension://` origin has no
registrable domain to survive that pipeline.

⚠️ **Runtime-withheld host permission** (Chrome "site access: on click"; Firefox optional-by-default
host perms) breaks the RP-ID claim with `SecurityError` at enroll **or redeem**. Probe
`chrome.permissions.contains({origins:["https://andvari.monahanhosting.com/*"]})` before every
ceremony; on absence → treat as capability loss → PIN fallback, **zero counter burn**.

## 4. Crypto & blob (with the 4 required red-team amendments folded in)

- **Double-wrap reused verbatim** (`quickunlock.ts` `sealDoubleWrap`/`openDoubleWrap`): inner
  non-extractable co-key AES-GCM, per-userId AAD on both layers, wipe couples record + co-key. **No
  custody regression** vs the PIN path (red-team CONFIRMED SOUND).
- **`K_bio` = `HKDF-SHA256(ikm = prfSecret(32 B), salt = ∅, info = "andvari/qu-bio/v1|" + userId, L = 32)`.**
  Never use the PRF output raw. **No Argon2id, no KDF params in the blob** — the PRF output is
  full-entropy, so the entire `assertPinKdfParams` floor/ceiling fence is **pin-only** and disappears
  for this kind. HKDF added to `crypto.ts` (pure, node-testable — no injection).
- **`QuBlob` discriminated union on `kind`:**
  - `{v, kind:'pin', salt, kdfParams, ct, createdAt, lastFullUnlockAt}` (today, unchanged)
  - `{v, kind:'biometric', credentialId, prfSalt, ct, createdAt, lastFullUnlockAt}`
  - **One method at a time in v1** — enroll (either kind) still `wipe()`s the other first; the
    fallback when biometric fails is the **master password** (or a co-present PIN, if we allow dual
    wraps later — deferred to v2).
- **Attempt counter is inert for bio**: never decremented, pinned at `MAX_PIN_ATTEMPTS`, so
  `arm()`/`status()`/exhausted checks pass vacuously. The 24 h stamp (`isStampFresh`), not the counter,
  bounds token retention — unchanged.
- **AMENDMENT 1 (HIGH) — per-kind shape validation, kind-check BEFORE the reserve-decrement.** As
  coded today a `kind`-stripped bio blob (the in-model A8 storage-writer attacker) narrows to `'pin'`,
  `beginRedeem` persists the reserved decrement, then `assertPinKdfParams(undefined)` derefs `p.v` →
  an **uncaught `TypeError`** (not `PinKdfPolicyError`) that escapes `doUnlockWithPin` (no try around
  `beginRedeem`) — blob **NOT wiped**. Fix: on every read reaching a redeem lane, validate the narrowed
  kind's required fields (`pin` ⇒ `salt`+`kdfParams` present & object-typed; `biometric` ⇒
  `credentialId`+`prfSalt` present); any mismatch → `corrupt` → `wipe()`. Make `assertPinKdfParams`
  null-safe; hard `blob.kind` entry-check before any reservation.
- **AMENDMENT 2 (MED) — authenticate the `kind`.** Bio blobs use a kind-distinguished AAD
  `ad("ext-quick-unlock-bio", userId)` (pin AAD unchanged for live-record compat) so a
  downgrade/cross-kind transplant fails the AEAD tag, not merely `K_pin`/`K_bio` key-space disjointness.
- **AMENDMENT 3 (MED) — enroll order: ceremonies BEFORE `wipe()`.** `enrollBio` = capability probes →
  `create()` (`prf.enabled` gate) → `get()`/`evalPrf` → PRF secret in hand → **then** `wipe()` →
  `coKey.generate()` → HKDF → `sealDoubleWrap` → `store.write`. A cancelled/focus-killed ceremony (the
  likeliest failure) must never strand the user with the old quick-unlock already wiped and no new one.
  All-or-nothing after `wipe()`.
- **AMENDMENT 4 (MED) — persist `{credentialId, prfSalt, userId}` in namespaced `storage.local`**
  (non-secret, peer of the existing DKEY) so a re-enroll after a browser restart **reuses** the
  credential (one `get()` prompt) instead of minting a fresh TPM/SEP passkey every session (litter).
  The secret `QuRecord` (ct + tokens + counter) stays in `storage.session`. Cleared on explicit disable.

## 5. Ceremony host & flows

**Surface abstraction (`connector`):** the popup's "Unlock with Windows Hello / Touch ID" button only
**signals** the SW; the SW opens a minimal `connector.html` (`chrome.windows.create({type:'popup',
~360×480, centered}`) — same precedent as the Firefox host-grant flow that already routes
gesture-needing calls out of the popup. The connector presents its **own** "Continue" button (fresh
user activation — `create()` needs it and the popup→SW→connector hop can lose the popup's), runs the
ceremony, **pings the SW every 15 s** (the 0.16.3 TOTP-keepalive pattern) so redeem state survives,
posts the PRF secret to the SW over **sender-verified intra-extension messaging** (`sender.tab ===
undefined` + extension-origin URL; zeroize the buffer after HKDF), and closes. On Chrome, if day-1
testing shows the action popup survives, the inline popup path may be used; Firefox always uses the
connector.

- **Enroll** (`enrollQuickUnlockBio`): keeps `enrollQuickUnlock`'s exact gates — session unlocked,
  `session.uvk` present (B1), `!mustChangePassword` (A4/§8.1), `lastFullUnlockAt` COPIED from the
  session (never `now()`). Ceremony: `create({rp:{id:"andvari.monahanhosting.com"}, user:{id:hash(userId)},
  challenge:randomBytes(32), pubKeyCredParams:[-7,-257], authenticatorSelection:{authenticatorAttachment:"platform",
  residentKey:"required", userVerification:"required"}, extensions:{prf:{}}})` → **hard gate
  `getClientExtensionResults().prf.enabled === true`** (else `bio_unsupported`, no state written) →
  `get()` with the new credentialId + `prf.eval.first = prfSalt` to obtain the secret → verify the
  **UV flag bit** in `authenticatorData` (local check — we run no RP server) → then the amendment-3 tail.
- **Redeem** (`unlockWithBio`): the **same single-flight slot** as `unlockWithPin` (one redeem lane),
  then the **byte-identical** background server dance — `forceRefresh` (catches rescue/revocation) →
  `getAccountKeys` → `verifyServerIdentity` → `sync` → session. The engine swaps only the KDF step for
  the PRF eval; `arm`/`wipe`/`reconcileUser`/`onFullUnlock`/`completeRedeem` are behaviorally unchanged.
- **Failure taxonomy**: ceremony failure (`NotAllowedError` = cancel/timeout/deleted-credential, all
  indistinguishable by design) → `bio_cancelled`, record UNTOUCHED, retry allowed (with a cooldown
  after N consecutive failures — no auto-retry). Post-PRF AEAD-open failure → deterministic `corrupt` →
  immediate `wipe()`. Passkey deleted outside the extension → fail closed to full online unlock +
  silent re-enroll offer (identical shape to co-key deletion, breaker A1).

## 6. Seam changes (keep the engine node-testable)

`QuDeps` gains one optional injected dep — the WebAuthn call stays OUT of `quickunlock.ts`:
```
biometric?: {
  enroll(prfSalt: Uint8Array): Promise<{ credentialId: string; prfEnabled: boolean }>;
  evalPrf(credentialId: string, prfSalt: Uint8Array): Promise<Uint8Array>; // 32-byte PRF output
}
```
Engine adds `enrollBio`/`beginRedeemBio` (mirroring `enroll`/`beginRedeem`, with the kind checks);
`background.ts` wires the dep to the connector broker. Node breaker tests pin: kind-strip → corrupt→wipe;
cross-kind transplant → AAD tag fail; enroll ceremony-fail-after-wipe → prior record intact; counter
never moves on bio; HKDF vectors.

## 7. Threat-model deltas (documented, accepted)

- **Stolen blob**: strictly stronger (uncrackable offline) vs PIN's Argon2-bounded resistance.
- **Household UV boundary**: the OS UV gate accepts **any** biometric/PIN enrolled in that computer's
  **OS account** — on a shared login, any family member's fingerprint quick-unlocks the vault. This is
  a per-OS-account gate (vs the PIN's per-person secret). **Document + enroll-time copy**; can advise
  (not enforce — undetectable) against bio on a shared OS login.
- **Prompt-fatigue**: with the counter inert, bound client-side with a cooldown after N failed
  ceremonies; never auto-retry.
- **PRF secret in transit**: intra-extension messaging only, sender-verified, zeroized after use.

## 8. Rollout

Additive, spike-gated, **ext 0.17.0**. Existing `v:1` PIN records read as `kind ?? 'pin'` (no migration
write until the user next enrolls). **No nag** for PIN users — discovery is the settings "Change…" path
only. Same code ships in `manifest.json` + `manifest.firefox.json`; runtime detection makes the bio UI
simply never render where the probe fails. Windows lane floored at **Chrome 147** to sidestep the
Chrome-146 enroll ambiguity. Bump `minimum_chrome_version` consideration is runtime, not manifest.

## 9. Day-1 empirical spike — RESULTS (2026-07-18, owner hardware)

**GREEN. Key decisions settled:**
- `UVPAA = true`, **`prf.enabled = true`**, PRF output **32 bytes, deterministic** across two `get()`s
  → the lane is feasible and `K_bio = HKDF(PRF)` is reliable on this hardware.
- `create()`/`get()` with `rp.id = andvari.monahanhosting.com` **succeeded with no SecurityError** →
  the fixed-RP-ID-via-host-permission decision (§3) is confirmed; the host permission was honored.
- **The action popup CANNOT host the ceremony** — `create()` failed twice with `NotAllowedError`,
  while the **connector window survived every prompt** and reached DONE. ⇒ **DECISION: connector-only,
  no inline popup fast-path** (simpler + universal; §5 updated). Firefox already required it — now
  it's the single path everywhere.
- `PRF at create() present? false` on this platform → enroll must do `create()` **then** `get()` (two
  prompts) to obtain the secret; matches the §5 enroll flow.

Still worth a quick confirm before/while building (not blocking the architecture): the same four
values on **Firefox** and on **macOS/Touch ID**, and that a synced second device yields a *different*
PRF (the "rely on portability in neither direction" stance). The tested browser/OS should be recorded.

## 10. Related decisions (from the design chat, for the record)

- **(B) Tiered re-auth**: full master password ALWAYS for account-control actions; quick-unlock only
  for fill/view. Already the extension's model (it has no Tier-2 actions) — formalize as a step-up if
  it ever gains one; mostly a web/desktop concern.
- **(C) Client-scoped TOTP toggle**: **dropped** per owner (2026-07-18). Biometric quick-unlock is the
  balanced convenience answer; the toggle was a straight security reduction (the extension reads all
  secrets, so password-only = full-vault read) and isn't pursued.

## Open questions for the owner

- v1 **one-method-at-a-time** (recommended) vs allowing **PIN + biometric simultaneously** as mutual fallbacks (v2)?
- When NO PIN exists yet, is **"biometric only, master-password fallback"** acceptable for the household, or require a PIN as the always-present backup?
- Confirm the **household shared-OS-login** caveat is acceptable (bio = per-OS-account, not per-person).
