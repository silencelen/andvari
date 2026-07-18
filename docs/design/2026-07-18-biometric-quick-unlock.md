# Design note — biometric quick-unlock + tiered re-auth (owner idea, 2026-07-18)

Status: **PROPOSED** (not scheduled). Companion to the 0.16.3 TOTP-unlock-seam fix.

## The idea (owner)

> Because the extension's functionality is deliberately limited — it can't create shares, delete,
> export, or change account settings — it may be safe to use Windows Hello / a platform biometric
> for quick-unlock. Full account control (as the web/desktop apps have) should still warrant the
> full master password.

Two proposals, both sound: **(A)** a biometric quick-unlock provider for the extension, and **(B)** a
tiered re-auth model where dangerous/account-level operations always step up to the full master password.

## Why the security tradeoff holds

The extension's surface is **fill / save / view** — no shares, deletions, exports, or account
settings (those live in web/desktop). The relevant fact: **quick-unlock already grants 24 h of that
exact surface behind a short PIN** (`quickunlock.ts`, `QU_MAX_AGE_MS`). So biometric quick-unlock is
not a *new* weakening — it is a **different secret for the same window**, and a *stronger* one:
device-bound, non-shoulder-surfable, phishing-resistant, and never typed. It is at least at parity
with today's PIN and materially more convenient. (Caveat worth stating plainly: "view" reveals
plaintext secrets — the crown jewels — so this is not a low-value gate; it is justified only because
the PIN path already sets this bar, and biometric raises it.)

## How (A) would work — WebAuthn PRF, not a bare assertion

A biometric assertion (`navigator.credentials.get`) is a *signature*, not a key — it can't unwrap a
vault. The mechanism that can is the **WebAuthn PRF extension** (`hmac-secret`): the platform
authenticator, gated by the biometric, deterministically derives a stable secret from (credential,
salt). That secret becomes the wrapping key over the same UVK blob the PIN path wraps today.

- **Enroll:** `navigator.credentials.create` with a platform authenticator + `prf` → store the
  credential id + a per-install salt; wrap the UVK under `PRF(salt)` (mirrors the PIN co-key blob).
- **Unlock:** `get({ publicKey: { extensions: { prf: { eval: { first: salt } } } } })` → biometric
  prompt → PRF secret → unwrap the UVK → the existing quick-unlock tail (`beginRedeem` shape).

Fits `quickunlock.ts`'s existing provider abstraction: a `biometric` provider alongside `pin`, same
retained-UVK-in-memory + 24 h re-stamp rules, same origin/identity hard-fails on redeem.

**Constraints to verify before committing a lane:**
- WebAuthn + PRF in an **MV3 extension popup** (`chrome-extension://` origin): supported in Chrome
  with an RP-ID caveat — needs a spike. Chrome/Edge/platform-authenticator first; **Firefox PRF is
  behind flags / limited** → keep PIN as the universal fallback, biometric as an opt-in upgrade.
- Fallback is the OS login (Windows Hello PIN / device passcode) — acceptable and explicit.
- No server change: this is entirely a client-side wrapping-key swap; the server never sees it.

## (B) Tiered re-auth — already the model, make it explicit

The extension **already** enforces tier separation by not implementing account-control features
(and it routes `mustChangePassword` / recovery to the web vault). Formalize it:

- **Tier 1 (extension: fill / save / view):** quick-unlock — PIN today, biometric proposed. TOTP is
  skipped inside the window (the 0.16.3 seam handles the *full* sign-in that opens the window).
- **Tier 2 (account control: shares, deletions, exports, TOTP/password/settings):** **full master
  password every time**, even in web/desktop — a step-up prompt on the dangerous action, independent
  of how the session was unlocked. Quick-unlock (any provider) must NEVER satisfy Tier 2.

If the extension ever grows a Tier-2 action, it must step up to the full password (or bounce to web),
never ride the quick-unlock session.

## (C) Client-scoped TOTP policy (owner idea, 2026-07-18)

> If TOTP is enrolled, keep it **required for web/desktop** (the extra-functionality clients), but let
> it be **toggled on/off for the extension**.

Coherent, and it composes with (A)/(B). Server shape: a per-account flag (e.g. `totpExtensionExempt`)
+ the login path keying the TOTP requirement off the **client type** — the login already carries a
`ClientId`/version, so the server can waive the second factor for `client=extension` when the account
opted in, while web/desktop stay gated. No change to the 0.16.3 code-entry seam (it just isn't hit
when exempt). Owner-facing toggle in the web account UI.

**One honest caveat to weigh first:** the extension *reads* every secret (fill/view), so "TOTP off for
the extension" means **password-only access to the whole vault's plaintext** — the exact thing TOTP
defends when a password is phished/keylogged. It's a real reduction, not a free convenience.

**Recommendation / sequencing.** The *convenience* the toggle chases is already delivered more safely
by quick-unlock: do TOTP **once** on the full sign-in, then ~24 h of PIN — or, per (A), biometric —
relocks with no code. That keeps the 2FA gate on the credential while removing the repeated friction.
So: land **biometric quick-unlock (A)** first; if that doesn't satisfy the owner's "trusted personal
browser, no 2FA" preference, add **(C)** as an explicit, clearly-labelled opt-out (never a default).
The two are compatible — (C) is a deliberate lower-security choice, (A) is the balanced one.

## Scope / sequencing

Own lane, breaker-vetted (custody of the PRF-wrapped blob; the biometric-bypass threat model; the
Firefox gap). **Not** 0.16.3 — that ships the dead-end fix. Natural next after the owner confirms the
Chrome-first / PIN-fallback shape. Effort: moderate (one new `quickunlock.ts` provider + enroll UI +
a WebAuthn-PRF spike); Tier-2 step-up is mostly a web/desktop concern with a small extension guard.
