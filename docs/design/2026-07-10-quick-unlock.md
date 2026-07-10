# Quick unlock (Android biometric) + KDF upgrade — design (2026-07-10)

**Status:** cycle-2 design (PLAN-autonomous-2026-07 item 2), resolves backlog **F84** (quick
unlock) with **F61** (KDF upgrade) riding along. Spec deltas landed with this doc:
spec 01 §7 (F61 normative), spec 01 §8.1 (Android quick unlock normative, Windows explicitly
deferred), spec 05 (asset A7 + the quick-unlock at-rest threat rows). Android **only** this
cycle — **Windows/desktop quick-unlock stays DEFERRED past the 0.7.0 MSI refresh** (backlog),
and web has none by spec (§8.3). Build follows a 2-breaker pass on this doc.

**No wire change.** Verified: unlock-by-UVK consumes the existing `accountKeys` payload;
the KDF upgrade rides the existing `PUT /account/password`; the server never learns quick
unlock exists. Nothing in this design touches spec 03 beyond what §7 already promised.

## The shape in one paragraph

The UVK — 32 bytes, never rotated by password change (spec 01 §4) — is the perfect
quick-unlock payload: wrapping *it* (never MK/password/wrapKey) means a biometric unlock
reconstructs exactly the state a password unlock reaches *minus* knowledge of the password.
Android Keystore wraps it under an auth-per-use, biometric-strong-gated, non-exportable
AES-GCM key; the blob sits in `noBackupFilesDir`; every failure falls back to the master
password (never silently weaker); a 30-day periodic full-password rule keeps password
muscle-memory alive and gives F61's silent KDF re-key a guaranteed hook.

## 1. Core API (commonMain, `Account.kt`)

```kotlin
companion object {
    /** Unlock from a platform-recovered UVK (quick unlock, spec 01 §8). Performs the SAME
     *  seed-derived identityPub verification as [unlock]; a wrong/stale UVK fails the
     *  encryptedIdentitySeed AEAD open (CryptoException) — the caller treats that as an
     *  invalid quick-unlock secret (wipe + password fallback), NEVER as a soft error. */
    fun unlockWithUvk(userId: String, uvk: ByteArray, keys: AccountKeys,
                      crypto: CryptoProvider = createCryptoProvider()): Account
}
```

- **Implementation is the tail of `unlock()`** (Account.kt:257): factor the existing body so
  `unlock()` = {derive MK→wrapKey, open `wrappedUvk` (wrong password → CryptoException)} then
  delegate to the shared tail = {open `encryptedIdentitySeed` under UVK with `Ad.idkey(userId)`,
  `boxKeypairFromSeed`, **hard-fail on identityPub mismatch** (verbatim existing message —
  the §5 pubkey-substitution check runs on BOTH paths), construct `Account`}. ~15 lines net.
- **What it validates:** (a) the UVK is *the* UVK — proven by the identity-seed envelope
  opening (AEAD tag + `Ad.idkey` AAD); (b) the server isn't substituting identity keys —
  same check, same hard-fail as `unlock()`. It does NOT validate freshness/policy — that's
  the platform layer's job (spec 01 §8.1 gates).
- **How it gets vaultKeys:** exactly like `unlock()` — it returns an `Account` with an empty
  key map + `personalVaultId=""`; `SyncEngine.hydrate()`/`sync()` feed grants through
  `addGrant` (wrappedVk opens under the UVK we now hold; sealedVk under the derived identity
  key), `setPersonalVault` lands the personal id. Zero engine changes.
- **UVK ownership:** the `Account` keeps the passed reference (constructor is private; both
  callers hand over a fresh array). The Android caller must not reuse/zero the array after the
  call. R1 (JVM zeroization) applies as everywhere else.
- **UVK egress for enrollment:** new narrow accessor
  `fun uvkCopyForPlatformWrap(): ByteArray` — returns a copy, loudly documented as
  quick-unlock-enrollment-only (pass straight into a hardware-backed cipher, drop the ref).
  A breaker should attack this; the honest defense: the UVK already lives in this process's
  heap for the session's lifetime — a same-process accessor adds no new exposure *class*
  (T5/R1 unchanged), and the alternative (threading a JVM `Cipher` into commonMain) is a
  platform leak into the multiplatform core for zero security delta.

Also new in core (JVM-testable, pure): the F61 decision function —

```kotlin
object KdfUpgrade {
    /** spec 01 §7: policy ≥ account on BOTH axes, > on ≥1, v ≥, inside the sanity bounds
     *  (mem ∈ [64 MiB, 1 GiB], ops ∈ [3, 10]). Never sideways, never down, never absurd. */
    fun shouldUpgrade(account: KdfParams, policy: KdfParams): Boolean
}
```

## 2. Android Keystore + BiometricPrompt flow

**Dependency:** wire `libs.androidx.biometric` (1.2.0-alpha05, already catalogued in
`libs.versions.toml`, confirmed unreferenced by any module) into `app-android/build.gradle.kts`.

New file `app-android/.../app/QuickUnlock.kt` (single owner of alias, file format, AAD,
wipe semantics — nothing else touches these):

- `isEligible(context, store)`: `BiometricManager.canAuthenticate(BIOMETRIC_STRONG) == SUCCESS`
  **and** `store.cacheAllowed` (the persisted `offlineCacheAllowed`, same fail-open-until-seen
  semantics as the cache itself — spec 01 §8.1 gates quick unlock on the same policy bit).
- `isEnrolled(context, userId)` / `isFresh(...)`: blob file exists, `v` known, and
  `now - lastFullPasswordUnlockAt < 30 d` (wall clock; spec 01 §8.1 — calendar rule, so
  `currentTimeMillis`, unlike the monotonic auto-lock).
- **Enroll** (`suspend enroll(activity, account, userId)`) — called only while unlocked:
  1. Generate Keystore key `andvari-qu-<userId>`: AES-256-GCM, ENCRYPT|DECRYPT,
     auth-per-use (`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` API 30+;
     `setUserAuthenticationValidityDurationSeconds(-1)` on API 29 — minSdk is 29),
     `setInvalidatedByBiometricEnrollment(true)`, `setUnlockedDeviceRequired(true)`,
     StrongBox attempted → TEE fallback on `StrongBoxUnavailableException`.
  2. Init ENCRYPT cipher → `BiometricPrompt.authenticate(CryptoObject(cipher))` — auth-per-use
     keys need auth for the *encrypt* too, which doubles as the user's explicit consent.
  3. `updateAAD("andvari/v1|quick-unlock|<userId>")`, `doFinal(account.uvkCopyForPlatformWrap())`,
     write `quick-unlock-<userId>.json` `{v:1, alias, iv, ct, createdAt,
     lastFullPasswordUnlockAt}` to **`noBackupFilesDir`** (atomic: temp + rename).
- **Use** (`suspend recoverUvk(activity, userId): ByteArray`):
  read blob → get key → init DECRYPT(iv) → `BiometricPrompt` (negative button
  "Use master password") → `updateAAD` → `doFinal` → UVK bytes. Every failure maps per the
  spec 01 §8.1 table (`KeyPermanentlyInvalidatedException` → wipe+notify; GCM fail → wipe;
  `ERROR_LOCKOUT` → password this time, keep; `ERROR_LOCKOUT_PERMANENT` → wipe; cancel →
  password, keep). **No app-level attempt counter** (Keystore/BiometricPrompt already
  rate-limit; an app counter beside the blob is resettable by exactly the attacker it targets).
- `wipe(context, userId)`: delete blob file + `KeyStore.deleteEntry(alias)` — idempotent,
  never throws. Called from: the failure table; **sign-out** (`AndvariViewModel.signOut`,
  beside `deleteCache`); **definitive 401** (`purgeOfflineData` — both call sites); **policy
  flip** to `offlineCacheAllowed=false` (`applyPolicy` + the two probe paths that already
  purge the cache); **Settings disable**.
- `stampFullPasswordUnlock(context, userId)`: rewrite `lastFullPasswordUnlockAt` (no-op when
  not enrolled). Called from every successful full-password unlock: `AndvariViewModel.signIn`,
  `AndvariViewModel.unlock`, `AutofillUnlock.unlock` — including offline ones.

**Password change / KDF upgrade leave the blob VALID** — the UVK survives both (spec 01
§4/§7); this is intended (a web password change must not break the phone's biometric). The
cross-device hygiene path is session revocation → definitive 401 → `purgeOfflineData` → wipe.

## 3. Unlock-path integration

**`AutofillUnlock` refactor (shared scaffolding, zero drift):** `unlockLocked` today does
api-build → accountKeys-or-cached → `Account.unlock(password)` → cache/engine/hydrate →
bind. Parameterize the one differing step:

```kotlin
suspend fun unlock(context, store, session, password: String)          // existing signature
suspend fun unlockWithUvk(context, store, session, uvk: ByteArray)     // new sibling
// both → unlockLocked(appContext, store, session) { keys -> Account.unlock/…WithUvk(...) }
```

Everything else — the unlockMutex + winner-reuse, single-token-holder invariant, F74 throw-path
hygiene, cacheAllowed cache selection, `AutofillHardLock.arm()` — is inherited verbatim. The
password variant additionally calls `stampFullPasswordUnlock` on success (it does NOT attempt
the F61 re-key — latency-sensitive path; spec 01 §7 allows the deferral).

- **`AutofillUnlockActivity`:** after the existing fast path and signed-out check, if
  `QuickUnlock.isEligible && isEnrolled && isFresh` → launch the BiometricPrompt immediately
  over the (still rendered) password card; success → `AutofillUnlock.unlockWithUvk` →
  the existing `finishAfterUnlock` dataset build. Failure/cancel → the card is already there;
  wipe-class failures show the mapped message in `errorText`. `SaveConfirmActivity` gets the
  identical hook (same `AutofillUnlock` entry — it's why the refactor lives there).
- **MainActivity/`AndvariViewModel`:** the Unlock screen mirrors it — eligible+enrolled+fresh
  → auto-show the prompt on entry, password field beneath as the always-available fallback.
  New `fun unlockWithBiometric()` beside `unlock(email, password)`: recoverUvk → (mutex) →
  accountKeys-or-cached → `Account.unlockWithUvk` → bind — same skeleton as `unlock()` minus
  the KDF, plus the failure mapping. Post-unlock UI additions:
  - **Enrollment offer:** after a successful full-password unlock, when eligible and not
    enrolled, a one-time dismissible card ("Unlock with fingerprint next time?") + a
    persistent Settings toggle ("Quick unlock — fingerprint/face"). Disable in Settings =
    `wipe()` with no auth gate (reducing standing secret material is never gated).
  - **Stale notice:** when enrolled-but-not-fresh, the unlock screen says why it's asking
    ("It's been 30 days — enter your master password to keep quick unlock active").

## 4. F61 KDF upgrade — where it runs and the quick-unlock interplay

On successful **online full-password** unlock in `AndvariViewModel.signIn`/`unlock` (the
password is still in scope, keys just fetched):

1. `policy = _ui.value.policy ?: fetched` — must be a **server-fetched** policy this session;
   never upgrade off a stale persisted value (staleness can't make `shouldUpgrade` true
   incorrectly per the ≥-both-axes rule, but a fresh fetch also picks up a *raised* floor).
2. `if (KdfUpgrade.shouldUpgrade(keys.kdfParams, policy.kdfParams))` → off-main:
   derive current authKey (have it from unlock… no — unlock derives wrapKey; re-derive
   authKey from the same MK — **keep MK in scope through the check** to avoid a third
   Argon2id), fresh salt, MK′ under policy params → authKey′/wrapKey′ → re-wrap UVK →
   `api.changePassword(PasswordChangeRequest(currentAuthKey, newAuthKey, newSalt,
   policyParams, newWrappedUvk))`.
3. On success: re-fetch `/account/keys` (or construct the new `AccountKeys` locally) →
   `persistAccountKeys` — the offline cache must hold the NEW salt/params/wrappedUvk or the
   next offline unlock derives with stale params and fails.
4. On ANY failure: swallow + log-free continue (unlock already succeeded; retries next time).
   A concurrent re-key from another device surfaces as a 401 here — also non-fatal.

**Interplay (the actual F61 mechanism for biometric users):** a quick unlock has no password
→ **cannot** upgrade → the spec 01 §8.1 30-day periodic-full-password rule is the guarantee:
every enrolled device types the password ≤30 days after any policy bump, and the upgrade
runs then. The quick-unlock blob survives the re-key (UVK unchanged) — no re-enrollment.
Accepted residuals (spec 01 §7): the re-key revokes the account's *other* sessions (existing
`PUT /account/password` semantics — taking a `reason` flag to skip revocation would be a wire
change, rejected this cycle); a device that only ever full-unlocks offline, or only via the
autofill overlay, upgrades late (next online main-app unlock).

## 5. Failure / fallback matrix

The normative table lives in spec 01 §8.1. Build-contract mapping:

| Condition | Detected in | UX | Blob |
|---|---|---|---|
| Enrollment changed (`KeyPermanentlyInvalidatedException`) | cipher init | "Biometrics changed — enter your master password" | wiped |
| Blob/key missing, corrupt, unknown `v`, GCM/AAD fail | QuickUnlock | plain password prompt | wiped |
| identity seed won't open under recovered UVK | `unlockWithUvk` (CryptoException) | password prompt | wiped |
| identityPub mismatch | `unlockWithUvk` | HARD FAIL banner (same as password path) | kept (evidence) |
| Temp lockout / user cancel | BiometricPrompt callback | password prompt | kept |
| Permanent lockout | BiometricPrompt callback | password prompt | **kept** (A8) |
| >30 d stale | `isFresh` pre-check | password prompt + why-copy | kept; re-stamped on success |
| `offlineCacheAllowed=false` seen | applyPolicy/probes | quick unlock disappears | wiped |
| Wrong-password-class errors on the fallback | existing paths | unchanged | n/a |

Invariant a breaker should try to violate: **no failure path may leave the user with neither
a working biometric NOR the password prompt**, and no path may auto-retry biometrics in a
loop (each prompt is one explicit user gesture).

## 6. Test plan

**JVM (core, runs in the normal gate):**
- `unlockWithUvk` happy path: enroll → take `uvkCopyForPlatformWrap` → unlockWithUvk →
  identical decrypt capability (grant open, item decrypt) as the password-unlocked twin.
- Wrong UVK (random 32B) → CryptoException at the identity-seed open; truncated/empty UVK.
- identityPub substitution → hard-fail message (mirror the existing `unlock()` test).
- `unlock()` regression: password path byte-identical behavior through the refactor.
- `KdfUpgrade.shouldUpgrade` table: equal → false; both-axes-up → true; one-up-one-down →
  false; down → false; below-floor policy (32 MiB) → false; absurd (2 GiB / ops 50) → false;
  `v` regression → false.
- Server-side (existing suites already cover `PUT /account/password`): one added test that a
  same-password re-key with stronger params logs in with the OLD password + NEW params after
  (VirtualClient.buildPasswordChange is the template).
- Android-free logic worth JVM-hosting: the blob JSON (de)serialization + version gate, and
  the 30-day freshness arithmetic (pure functions in QuickUnlock, extracted for testability).

**Device / instrumentation (owner feel-check + manual matrix — Keystore and BiometricPrompt
do not exist on the JVM; no emulator step in the gate this cycle):**
- Enroll → kill process → biometric unlock (main app; autofill overlay; SaveConfirm).
- Add a fingerprint in OS Settings → key invalidated → wipe + password fallback + re-offer.
- 30-day rule: stamp `lastFullPasswordUnlockAt` back 31 d (debug hook) → password required.
- Policy flip `offlineCacheAllowed=false` on the server → blob gone on next foreground.
- Sign-out / 401-revocation → blob gone. Airplane-mode quick unlock (cached accountKeys).
- Lockout: 5 bad biometric attempts → temp lockout → password works; permanent → wiped.

## 6b. Breaker amendments (NORMATIVE — supersede any conflicting text above)

Two adversarial breakers (crypto/Keystore + threat/lifecycle, 2026-07-10) returned **0 fatal,
9 serious**. Both independently found A1/A2 and both independently found the autofill-path
gaps — convergence, not noise. The cryptographic core (wrap the UVK, never MK/password;
per-device non-exportable auth-per-use AES-GCM key; userId-bound AAD; no IV-reuse surface;
identityPub hard-fail preserved) SURVIVED both. These amendments are the build contract.

**A1. The freshness stamp must prove a password was actually typed.**
`lastFullPasswordUnlockAt` lives in SessionStore per-userId, OUTSIDE the wrapped blob, and is
written ONLY by a real full-password unlock. Enrollment COPIES it — never mints `now`.
`VaultSession` tracks unlock **provenance** (`PASSWORD` | `QUICK`). Enrolling (or
disable→re-enable) from a QUICK-originated session with no surviving stamp REQUIRES a password
confirmation. Without this, "re-enroll" and "toggle off/on in Settings" each silently reset the
30-day clock with no password ever entered — an indefinite bypass of the periodic rule.

**A2. The 30-day rule must not trust the wall clock.**
*(Hardened by the build review, 2026-07-10 [2] — the rule below is the SHIPPED one.)*
`highWaterWallMs` ratchets only from the DEVICE clock as this app observes it, so a dormant
phone freezes it, and a reboot resets `elapsedRealtime` (voiding the monotonic cross-check). An
attacker could then set the clock to a moment INSIDE the window and quick-unlock forever.
Elapsed time cannot be bounded from an attacker-settable clock at all. Shipped rule:
**same boot** → the monotonic clock proves duration (plus the wall guards); **cross boot** →
require a SERVER-attested anchor taken after the stamp (`serverTimeFloorMs > stampWallMs`, from
`ClientPolicy.serverTime`, persisted monotonically) and measure the window against it — with no
anchor, fail CLOSED (master password). Practical effect: the first unlock after a reboot needs
the password unless the app has since reached the server, matching Android's own
before-first-unlock posture.

Freshness fails CLOSED on clock tampering: any stamp in the future (`now < stamp − skew`) is
STALE → password required (safe direction; self-heals on the next full unlock, which re-stamps).
Persist a monotonically non-decreasing `highWaterWallMs` and evaluate against `max(now,
highWater)`. Also stamp `elapsedRealtime` + boot id; within one boot the monotonic delta must
ALSO be < 30 d. Spec 05's residual row names the **clock**, not just the file, as the tamper
surface. (A Settings rollback otherwise buys unlimited quick-unlock forever.)

**A3. The autofill process must enforce revocation — this closes a PRE-EXISTING hole.**
`purgeOfflineData` becomes a shared helper reachable from BOTH processes (main + autofill-only).
`AutofillUnlock.unlockLocked` maps a **definitive 401** (an ApiException surviving the api's own
refresh) to that purge — vault cache + cached accountKeys + `store.clear()` + `QuickUnlock.wipe(userId)`
— and then rethrows. Today a revoked/stolen device that is only ever used through the autofill
overlay keeps opening the cached vault offline **forever** with the old password, because the
only purge site is the ViewModel. Quick-unlock would promote that path to a primary unlock; the
hole gets fixed as part of this cycle, and a `definitive 401` row joins §5's failure table.

**A4. Policy flips must reach the autofill process too.**
`offlineCacheAllowed=false` currently wipes only via main-app code paths. The autofill unlock
path fetches `/client-policy` (cheap, unauthenticated) on its ONLINE path and applies the same
wipe logic; additionally persist `policyFetchedAt` and REFUSE quick-unlock when the last-seen
policy is older than 7 days, forcing a main-app refresh. An admin who forbids the durable cache
must not be silently ignored by the overlay.

**A5. F58 × F61 (security — do not skip).** While `mustChangePassword = true`:
(a) the F61 silent re-key is **skipped**, and (b) quick-unlock enrollment is **refused** (offer
card and Settings both say "change your master password first"). Otherwise the F61 re-key
performs a `PUT /account/password` with the admin-issued TEMP password, which clears
`mustChangePassword` **server-side** while the admin-known temp password stays the live
credential — and quick-unlock would wrap that temp password's UVK into Keystore for 30 days.
The server cannot distinguish a re-key from a real change; the client must. Stated in spec 01
§7 and §8.1.

**A6. F61's "guaranteed upgrade" must be true for overlay-only users.**
An autofill-overlay full-password unlock stamps the 30-day window, so a user who never opens the
main app would stamp forever and never upgrade. After a successful ONLINE overlay password
unlock, the F61 check + re-key runs as a **detached coroutine after the FillResponse is
delivered** (the latency argument only covers the blocking path; the password may be held for
the async derivation). §4's "guaranteed hook" is reworded to match reality.

**A7. State the KDF-bump fleet effect honestly.**
A policy bump means the first device to re-key calls `PUT /account/password`, which revokes all
other sessions: every OTHER enrolled device then hits a definitive 401, must sign in with the
password, and must RE-ENROLL quick-unlock (its blob is wiped by A3's purge). §4 and spec 01 §7
say this plainly, and the re-enrollment offer fires after that post-401 sign-in. The clean
alternative remains the rejected wire change (a `sameSecret` flag suppressing revocation for
same-password re-keys); revisit it only if the churn proves unacceptable — do not paper over it.

**A8. Never destroy enrollment on a lockout.** `ERROR_LOCKOUT_PERMANENT` (and any lockout) falls
back to the master password and LEAVES the blob intact. Wiping there is attacker- and
toddler-triggerable destruction of the user's enrollment that buys no security (the Keystore key
is already gated). Only the wipe-class events in §8.1's table (sign-out, revocation, policy flip,
enrollment-change invalidation, password-reset-by-recovery) destroy the blob.

**A9. Catch invalidation at BOTH surfaces.** `KeyPermanentlyInvalidatedException` may surface at
`Cipher.init` OR at `doFinal`, depending on OEM/API level. The failure matrix must handle it in
both places and converge on the same outcome (wipe blob → fall back to password → offer re-enroll).

**A10. `offlineCacheAllowed`'s meaning is re-scoped, and we say so.** The flag historically meant
"ciphertext at rest"; A4/§8.1 extend it to "durable vault-OPENING key material at rest." That is
a deliberate widening, documented in spec 03 §7's field description, not a silent reinterpretation.

## 7. Honest costs / rejected scope

- **A real T3 narrowing, opt-in:** a stolen device + the owner's biometric (sleeping owner,
  Class-3 spoof) now opens the vault where before only the password did. Recorded as the A7
  rows in spec 05. Class-3-only + auth-per-use + `setUnlockedDeviceRequired` is the fence.
- **DEVICE_CREDENTIAL rejected** (weaker than the master password, high shoulder-surf rate).
  Cost: no quick unlock on biometric-less devices. Fine — password unlock is unchanged.
- **Windows quick unlock DEFERRED** past the MSI refresh (spec 01 §8.2 stays a sketch).
  **Web: none by spec.** iOS: not a target (see the cycle-8 assess doc when it lands).
- **Use-count cap (M) rejected**; time-based 30-day rule only — reasoning is normative in
  spec 01 §8.1 (calendar-shaped pressures; count punishes heavy autofill users for nothing).
- **No app-level failed-attempt wipe counter** — Keystore/BiometricPrompt already enforce;
  a file-side counter is attacker-resettable theater.
- **Session-revocation side effect of the F61 re-key accepted** — avoiding it is a wire
  change (out of scope, loudly noted in spec 01 §7).
- **`uvkCopyForPlatformWrap` widens core's API surface** by one deliberate, documented hole;
  the alternative leaks `javax.crypto.Cipher` into commonMain. Breaker target.
- **Freshness stamp is advisory plaintext** (T5-only tamper surface; the Keystore key still
  gates). Binding it into the AAD was rejected: the stamp mutates on every full unlock,
  which would force a re-encrypt of the blob (a biometric prompt!) on every password unlock.
- Argon2id cost at unlock grows by 2 derivations in the (rare) upgrade case only.

## 8. Open questions (non-blocking; defaults chosen)

- Should the enrollment offer re-appear after a wipe-class invalidation, or only live in
  Settings? Default: one dismissible re-offer after the next full-password unlock, then
  Settings-only (no nag loop).
- `setUnlockedDeviceRequired(true)` had OEM bugs on some API 29–30 builds (keys unusable
  even when unlocked). Default: keep it; if the owner's Fold trips it, drop to a documented
  spec amendment rather than a silent code fork.
- Does the 0.9.0 cut (cycle 3) ship quick unlock enabled-by-offer or Settings-only-quiet?
  Default: offer-card on, per this doc — it's the owner-requested feature.
