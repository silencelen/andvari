package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.CryptoException
import kotlinx.io.IOException

/**
 * HouseholdCopy — the shared household-voice error canon for the NATIVE clients, and the
 * Kotlin twin of the web canon (`web/src/ui/errors.ts` + its per-screen mappers:
 * `Welcome.tsx` sign-in/unlock ladders + `enrollError`, `Recover.tsx`
 * `verifyErrorMessage`/`resetErrorMessage`, `web/src/crypto/keys.ts` `WEAK_KDF_MESSAGE`)
 * and of `extension/src/errors.ts`.
 *
 * UI-audit #23 (docs/design/2026-07-12-frontend-ui-audit.md): the native apps rendered raw
 * wire/exception text to non-technical family members at their most fragile moments —
 * [AndvariApi.errorFrom] builds [ApiException] carrying the SERVER'S raw `message`, and
 * ~13 android/desktop sites did `t.message ?: "something went wrong"`. The server message
 * is debugging detail ("authentication failed", "cursor predates retained history",
 * SQL-ish constraint text on a bad day) — never copy. Web/extension solved this with a
 * copy canon; this object is that canon for android + desktop: map the error's CODE (or
 * its exception TYPE) to a warm, honest, jargon-free sentence, and NEVER return the raw
 * `message` of any exception.
 *
 * House rules (mirror the web/extension canon):
 *  - No mapper here ever returns `t.message` — not even a fragment of it. A curated
 *    sentence per code/type, a curated fallback for everything else.
 *  - "Can't reach the server" (transport, [IOException]) is kept distinct from "the
 *    server said no" ([ApiException]) — never blame the network for a refusal or the
 *    user's password for a network blip (web `errors.ts` `net()` rationale).
 *  - Security faults never soften: an identity-key mismatch (pubkey substitution,
 *    spec 01 §5) and a weakened-KDF push (H1, spec 05 T1) each keep their distinct
 *    warning — they must never read as "wrong password" or "try again".
 *  - Every sentence is pinned verbatim by HouseholdCopyTest (the extension
 *    `errors.test.ts` idiom), so cross-client copy drift fails a test instead of
 *    confusing a family member.
 *
 * CROSS-CLIENT TWINS (byte-equal on purpose; editing one side is a deliberate twin-side
 * change — update the listed source AND its pin test together):
 *  - [UNREACHABLE]                    ← web/src/ui/errors.ts UNREACHABLE + extension/src/errors.ts UNREACHABLE
 *  - [WRONG_EMAIL_OR_PASSWORD]        ← web Welcome.tsx sign-in 401 + extension unlockErrorCopy("bad_credentials")
 *  - [WRONG_EMAIL_PASSWORD_OR_CODE]   ← web Welcome.tsx sign-in 401 (after a TOTP attempt)
 *  - [SIGN_IN_FAILED]                 ← web Welcome.tsx sign-in terminal + extension unlockErrorCopy("unknown")
 *  - [SIGN_IN_SERVER_PROBLEM]         ← web Welcome.tsx sign-in ApiError + extension unlockErrorCopy("server_error")
 *  - [UNLOCK_SERVER_PROBLEM]          ← web Welcome.tsx unlock-gate ApiError ("your password may be fine")
 *  - [SESSION_EXPIRED]                ← web Welcome.tsx unlock-gate 401
 *  - [WRONG_MASTER_PASSWORD]          ← web Welcome.tsx unlock-gate terminal
 *  - [PUBLIC_LOGIN_REQUIRES_TOTP]     ← web Welcome.tsx sign-in "public_login_requires_totp"
 *  - [IDENTITY_MISMATCH]              ← web account.ts IdentityMismatchError message + extension unlockErrorCopy("identity_mismatch")
 *  - [WEAK_KDF_ACTION]                ← web crypto/keys.ts WEAK_KDF_MESSAGE
 *  - [SERVER_PROBLEM]                 ← web Recover.tsx verifyErrorMessage/resetErrorMessage ApiError branch
 *  - [SAVE_FAILED]                    ← extension saveErrorCopy("failed")
 *
 * NATIVE-PINNED (sentences the natives already show today, promoted here byte-equal so
 * next-wave adoption is a zero-copy-diff swap; the android/desktop friendlyError maps and
 * autofill `friendly()` helpers are the prior source):
 *  - [WEAK_KDF_SIGN_IN] (both natives' H1 branch; the extension's variant deliberately
 *    says "contact your admin." — popup brevity — and stays extension-local),
 *  - [TOO_MANY_REQUESTS], the ten vault-lifecycle rows inside [forError]'s code map,
 *  - [SAVE_OFFLINE] (SaveConfirmActivity), [SYNC_OFFLINE] (desktop manual refresh),
 *  - [SESSION_EXPIRED_AUTOFILL] + [UNLOCK_OFFLINE_NO_KEYS] (android autofill activities —
 *    exposed as constants for that lane; no mapper returns them because only the autofill
 *    overlay, rendered inside ANOTHER app, may say "open andvari"),
 *  - [BAD_TOTP_CODE] (desktop wording, deliberately unifying android's shorter variant).
 *
 * Surface-specific copy stays at the surface: enrollment codes (`invalid_invite`,
 * `recovery_required`, `escrow_not_allowed_when_waived`, …) keep their per-client
 * phrasing (web `enrollError`, the desktop enroll sheet), and a lane may still map ITS
 * codes first and delegate the rest here (the desktop move flow's gesture exceptions do
 * this). Callers should keep catching [UpgradeRequiredException] for the blocking
 * platform-specific upgrade screen; the [UPGRADE_REQUIRED] sentence below is only the
 * honest inline fallback when a 426 reaches a generic error slot.
 */
object HouseholdCopy {

    // ---- canonical sentences (see the twin table above) ----

    /** TWIN of web/src/ui/errors.ts UNREACHABLE + extension/src/errors.ts UNREACHABLE. */
    const val UNREACHABLE = "Can't reach the andvari server — check you're on the home network or VPN, then try again."

    /** The one neutral, retryable terminal — never a raw `.message`. */
    const val SOMETHING_WENT_WRONG = "Something went wrong — please try again."

    /** TWIN of web Recover.tsx's ApiError branch (the context-free "server said no"). */
    const val SERVER_PROBLEM = "The server had a problem answering — try again in a moment."

    /** TWIN of web Welcome.tsx unlock-gate 401. */
    const val SESSION_EXPIRED = "Session expired — sign in again."

    /** Android autofill variant (SaveConfirmActivity/AutofillUnlockActivity today): rendered
     *  inside ANOTHER app, so it must point the user back to andvari. For that lane only. */
    const val SESSION_EXPIRED_AUTOFILL = "Session expired — open andvari and sign in again."

    /** NATIVE-PINNED: both natives' 429 sentence (friendlyError). */
    const val TOO_MANY_REQUESTS = "Too many requests — please wait a bit and try again."

    /** Platform-neutral inline 426. The BLOCKING upgrade screens keep their platform copy
     *  (android: devstore; desktop: /downloads) — catch [UpgradeRequiredException] first. */
    const val UPGRADE_REQUIRED = "This andvari server requires a newer version of the app — update andvari, then try again."

    /** TWIN of web account.ts IdentityMismatchError + extension "identity_mismatch": a
     *  tampering signal (spec 01 §5) — NEVER softened into wrong-password or retry copy. */
    const val IDENTITY_MISMATCH = "Server identity key mismatch — possible tampering. Do not proceed; contact your admin."

    /** TWIN of web crypto/keys.ts WEAK_KDF_MESSAGE (H1, spec 05 T1) — the general-context
     *  variant ("The action was blocked"): password change, sync, any non-sign-in surface. */
    const val WEAK_KDF_ACTION = "This server sent weakened security settings for your master password. The action was blocked to protect you — contact your administrator."

    /** NATIVE-PINNED: both natives' H1 sentence today — the sign-in/unlock-context variant.
     *  (The extension's popup says "contact your admin." — deliberate, extension-local.) */
    const val WEAK_KDF_SIGN_IN = "This server sent weakened security settings for your master password. Sign-in was blocked to protect you — contact your administrator."

    /** TWIN of web Welcome.tsx unlock-gate terminal (crypto throw = bad secret). */
    const val WRONG_MASTER_PASSWORD = "Wrong master password."

    /** TWIN of web Welcome.tsx sign-in 401 + extension "bad_credentials". */
    const val WRONG_EMAIL_OR_PASSWORD = "Wrong email or master password."

    /** TWIN of web Welcome.tsx sign-in 401 after a one-time code was submitted. */
    const val WRONG_EMAIL_PASSWORD_OR_CODE = "Wrong email, master password, or one-time code."

    /** TWIN of web Welcome.tsx sign-in terminal + extension "unknown". */
    const val SIGN_IN_FAILED = "Sign-in failed. Please try again."

    /** TWIN of web Welcome.tsx sign-in ApiError branch + extension "server_error". */
    const val SIGN_IN_SERVER_PROBLEM = "The server had a problem answering — your details may be fine. Try again in a moment."

    /** TWIN of web Welcome.tsx unlock-gate ApiError branch (password-only form, so
     *  "password", not "details"). */
    const val UNLOCK_SERVER_PROBLEM = "The server had a problem answering — your password may be fine. Try again in a moment."

    /** Unlock terminal for a Throwable web can never see there: web's unlock structure
     *  guarantees only a crypto throw reaches its terminal (hence WRONG_MASTER_PASSWORD);
     *  a general Throwable mapper must not blame the password for an arbitrary failure. */
    const val UNLOCK_FAILED = "Couldn't unlock — please try again."

    /** TWIN of web Welcome.tsx "public_login_requires_totp" (spec 03 §2 break-glass). */
    const val PUBLIC_LOGIN_REQUIRES_TOTP = "This account has no TOTP enrolled — sign-in from the public address is blocked. Connect from inside (VPN/LAN), enroll TOTP in Settings, then retry."

    /** Native sign-in fallback for `totp_required` reaching an error slot (both natives
     *  normally handle it as control flow — reveal the code field — before mapping). */
    const val TOTP_CODE_NEEDED = "This account needs a one-time code — enter the code from your authenticator app."

    /** NATIVE-PINNED: desktop totpOp's wording, unifying android's "That code didn't
     *  match — try again." (the authenticator hint is the actionable half). */
    const val BAD_TOTP_CODE = "That code isn't right — check your authenticator and try again."

    /** NATIVE-PINNED: SaveConfirmActivity's IOException sentence (autofill save offline). */
    const val SAVE_OFFLINE = "Offline — try saving again when you're connected."

    /** TWIN of extension saveErrorCopy("failed") — retryable, no jargon. */
    const val SAVE_FAILED = "Could not save — try again."

    /** NATIVE-PINNED: desktop manual-refresh offline notice — reassuring (cached data is
     *  still on screen), so sync flows prefer it over the bare [UNREACHABLE]. */
    const val SYNC_OFFLINE = "Can't reach the server right now — showing what's synced on this device."

    /** Sync fallback: honest about the operation, silent about internals. */
    const val SYNC_FAILED = "Sync didn't finish — please try again."

    /** Local file read/parse failed (import picks, attachment picks) — the bytes never
     *  reached the network, so this must not send anyone VPN-debugging. */
    const val FILE_READ_FAILED = "Couldn't read that file — try choosing it again."

    /** NATIVE-PINNED: AutofillUnlockActivity's offline-with-no-cached-keys sentence. For
     *  that lane (it knows the cache state); [forUnlockError] itself maps IO → [UNREACHABLE]. */
    const val UNLOCK_OFFLINE_NO_KEYS = "Offline, and no saved keys — open andvari once while online."

    // ---- general mapper ----

    /**
     * Map any failure to household copy. An [ApiException] maps by its `code` first
     * (vault-lifecycle rows, `rate_limited`, `bad_totp_code`, `recovery_piece_stale`,
     * `upgrade_required`), then by status class (400/401/403/404/409/410/413/429/5xx);
     * a transport failure ([IOException] — on JVM/Android every `java.io.IOException`,
     * including ktor's connect/socket timeouts) maps to [UNREACHABLE]; anything else to
     * [SOMETHING_WENT_WRONG]. NEVER the exception's own `.message`.
     */
    fun forError(t: Throwable): String = when {
        t is KdfPolicyViolationException -> WEAK_KDF_ACTION
        isIdentityMismatch(t) -> IDENTITY_MISMATCH
        t is ApiException -> apiCopy(t)
        t is IOException -> UNREACHABLE
        else -> SOMETHING_WENT_WRONG
    }

    // ---- context helpers (specialized fallbacks; ApiException codes still route through
    // the shared map unless the context knows better) ----

    /**
     * Sign-in (email + master password [+ one-time code]) — the native twin of web
     * Welcome.tsx's sign-in catch ladder / extension unlockErrorCopy. [totpTried] widens
     * the 401 sentence to include the one-time code, exactly like web's `totpNeeded`.
     * A non-API, non-transport throw is "Sign-in failed." (web parity): after a 200 login
     * the password is proven, so a late crypto throw must not read as wrong-password.
     */
    fun forSignInError(t: Throwable, totpTried: Boolean = false): String = when {
        t is KdfPolicyViolationException -> WEAK_KDF_SIGN_IN
        isIdentityMismatch(t) -> IDENTITY_MISMATCH
        t is ApiException -> when {
            t is UpgradeRequiredException || t.code == "upgrade_required" || t.status == 426 -> UPGRADE_REQUIRED
            t.code == "totp_required" -> TOTP_CODE_NEEDED
            t.code == "public_login_requires_totp" -> PUBLIC_LOGIN_REQUIRES_TOTP
            t.status == 401 -> if (totpTried) WRONG_EMAIL_PASSWORD_OR_CODE else WRONG_EMAIL_OR_PASSWORD
            t.code == "rate_limited" || t.status == 429 -> TOO_MANY_REQUESTS
            else -> SIGN_IN_SERVER_PROBLEM
        }
        t is IOException -> UNREACHABLE
        else -> SIGN_IN_FAILED
    }

    /**
     * Unlock (master password against known account keys) — web Welcome.tsx unlock-gate +
     * AutofillUnlockActivity territory. Here (and only here + [forSaveError]'s re-auth
     * path) a plain [CryptoException] IS "wrong master password" — the sole un-wrapped
     * crypto step — EXCEPT the identity-mismatch signal, which never softens. The android
     * autofill lane may pre-map IO → [UNLOCK_OFFLINE_NO_KEYS] and 401 →
     * [SESSION_EXPIRED_AUTOFILL] when its context applies, then delegate the rest.
     */
    fun forUnlockError(t: Throwable): String = when {
        t is KdfPolicyViolationException -> WEAK_KDF_SIGN_IN
        isIdentityMismatch(t) -> IDENTITY_MISMATCH
        t is CryptoException -> WRONG_MASTER_PASSWORD
        t is ApiException -> when {
            t is UpgradeRequiredException || t.code == "upgrade_required" || t.status == 426 -> UPGRADE_REQUIRED
            t.status == 401 -> SESSION_EXPIRED
            t.code == "rate_limited" || t.status == 429 -> TOO_MANY_REQUESTS
            else -> UNLOCK_SERVER_PROBLEM
        }
        t is IOException -> UNREACHABLE
        else -> UNLOCK_FAILED
    }

    /**
     * Save/edit an item (editor save, autofill save-confirm). IO → [SAVE_OFFLINE] (the
     * vault will retry when connected — kinder than VPN instructions mid-save); server
     * refusals route through the shared code map (409/conflict → "changed somewhere
     * else", 401 → session expired, lifecycle rows); a crypto throw on the save-time
     * re-auth path is wrong-password; anything else → [SAVE_FAILED].
     */
    fun forSaveError(t: Throwable): String = when {
        t is KdfPolicyViolationException -> WEAK_KDF_ACTION
        isIdentityMismatch(t) -> IDENTITY_MISMATCH
        t is CryptoException -> WRONG_MASTER_PASSWORD
        t is ApiException -> apiCopy(t)
        t is IOException -> SAVE_OFFLINE
        else -> SAVE_FAILED
    }

    /**
     * Import, local read/parse phase (file picker bytes → [CsvImport.parse]/plan): the
     * file never left the device, so BOTH an IO failure and an unclassified throw are
     * honestly "couldn't read that file" — never network copy. Recognized
     * [CsvImport.ImportException] codes keep their richer per-surface copy at the call
     * site; the PUSH phase of an import (network) should map with [forError]/[forSyncError].
     */
    fun forImportError(t: Throwable): String = when {
        t is KdfPolicyViolationException -> WEAK_KDF_ACTION
        isIdentityMismatch(t) -> IDENTITY_MISMATCH
        t is ApiException -> apiCopy(t)
        else -> FILE_READ_FAILED
    }

    /**
     * Sync/refresh. IO → [SYNC_OFFLINE] (cached data is still showing — reassure, don't
     * alarm); callers that special-case a silent background poll or the blocking 426
     * screen do so BEFORE delegating, exactly like today.
     */
    fun forSyncError(t: Throwable): String = when {
        t is KdfPolicyViolationException -> WEAK_KDF_ACTION
        isIdentityMismatch(t) -> IDENTITY_MISMATCH
        t is ApiException -> apiCopy(t)
        t is IOException -> SYNC_OFFLINE
        else -> SYNC_FAILED
    }

    /**
     * Server-TOTP setup/confirm/disable/status. The TOTP specialization lives in the
     * shared code map's `bad_totp_code` row ([BAD_TOTP_CODE]) — this named seam exists so
     * TOTP call sites bind one stable helper if the wording ever diverges from [forError].
     */
    fun forTotpError(t: Throwable): String = forError(t)

    // ---- internals ----

    /**
     * The shared ApiException code/status map. Named codes first (the ten vault-lifecycle
     * rows are byte-equal to what BOTH natives' friendlyError maps show today — the
     * hand-synced duplication #23 exists to delete), then the status-class ladder.
     * [AndvariApi.errorFrom]'s non-JSON fallback mints code `http_<status>`, so the
     * ladder keys on STATUS — unknown codes still land on honest copy.
     */
    private fun apiCopy(e: ApiException): String = when (e.code) {
        // Vault lifecycle (§11) — NATIVE-PINNED, identical in android + desktop today.
        "owner_must_transfer_or_delete" -> "You own this vault, so you can't just leave it — make someone else the owner first, or delete it."
        "vault_deleted" -> "This vault was deleted. The owner can restore it for a few more days."
        "vault_gone" -> "The restore window has passed — this vault's data has been erased."
        "vault_state_changed" -> "This vault changed since you tried that — reload and try again."
        "transfer_not_pending" -> "This ownership offer is no longer active."
        "not_transfer_target" -> "This ownership offer isn't for you, or it couldn't be verified."
        "stale_meta" -> "This vault changed somewhere else — reload and try the rename again."
        "not_a_member" -> "They have to be a member of this vault first."
        "user_inactive" -> "That account has been disabled — ask your admin to re-enable it first."
        "not_vault_owner" -> "Only the vault's owner can do that."
        // Named specifics.
        "bad_totp_code" -> BAD_TOTP_CODE
        "recovery_piece_stale" -> "Your recovery phrase was replaced from another device — set up recovery again from Settings."
        "rate_limited" -> TOO_MANY_REQUESTS
        "upgrade_required" -> UPGRADE_REQUIRED
        else -> when {
            e is UpgradeRequiredException || e.status == 426 -> UPGRADE_REQUIRED
            e.status == 401 -> SESSION_EXPIRED
            e.status == 403 -> "You don't have permission to do that."
            e.status == 404 -> "The server couldn't find that — it may have been removed on another device."
            e.status == 409 -> "That changed somewhere else — sync, then try again."
            e.status == 410 -> "That's no longer available — it may have expired or been removed."
            e.status == 413 -> "The server refused that upload — it may be too large, or storage may be full."
            e.status == 429 -> TOO_MANY_REQUESTS
            e.status >= 500 -> SERVER_PROBLEM
            e.status == 400 -> "The server couldn't accept that request — try again, and update andvari if it keeps happening."
            else -> SOMETHING_WENT_WRONG
        }
    }

    /**
     * The identity-mismatch tampering signal (spec 01 §5): core `Account.unlockFromUvk`
     * throws a [CryptoException] whose message starts with "identity key mismatch" —
     * DISTINCT from the wrong-password AEAD failures on purpose. Same marker check the
     * android autofill unlock uses today; the marker string is pinned by HouseholdCopyTest
     * so a reword in Account.kt cannot silently break this detection.
     */
    private fun isIdentityMismatch(t: Throwable): Boolean =
        t is CryptoException && t.message?.contains("identity key mismatch") == true
}
