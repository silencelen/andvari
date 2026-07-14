package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * Pins every [HouseholdCopy] sentence VERBATIM (the extension errors.test.ts idiom, #23):
 * expected values are string literals, never the constants themselves, so an edit to
 * either side is a loud test failure — cross-client copy drift fails here instead of
 * confusing a family member. The web/extension sources of the byte-equal twins are named
 * in HouseholdCopy's KDoc; editing a twin is a deliberate BOTH-sides change.
 */
class HouseholdCopyTest {

    /** Raw wire detail that must never reach a family member's screen. */
    private val leak = "SQLSTATE 23505 duplicate key value violates unique constraint \"items_pkey\""

    private fun api(status: Int, code: String) = ApiException(status, code, leak)

    /** The exact sentence core Account.unlockFromUvk throws (spec 01 §5) — pins the
     *  "identity key mismatch" marker [HouseholdCopy] detects; reword Account.kt and this
     *  fails, pointing at the coupled contains() check. */
    private val identityMismatch = CryptoException(
        "identity key mismatch — the server returned an identity public key that " +
            "your account's sealed seed does not derive; possible server compromise. Do not proceed.",
    )

    private fun weakKdf() = KdfPolicyViolationException("kdf_below_floor", KdfParams())

    // ---- the canon constants, verbatim ----

    @Test
    fun canonConstants_pinnedVerbatim() {
        // TWIN: web/src/ui/errors.ts UNREACHABLE + extension/src/errors.ts UNREACHABLE
        // (em dash U+2014, ASCII apostrophes).
        assertEquals("Can't reach the andvari server — check you're on the home network or VPN, then try again.", HouseholdCopy.UNREACHABLE)
        assertEquals("Something went wrong — please try again.", HouseholdCopy.SOMETHING_WENT_WRONG)
        // TWIN: web Recover.tsx verify/reset ApiError branch.
        assertEquals("The server had a problem answering — try again in a moment.", HouseholdCopy.SERVER_PROBLEM)
        // TWIN: web Welcome.tsx unlock-gate 401.
        assertEquals("Session expired — sign in again.", HouseholdCopy.SESSION_EXPIRED)
        // NATIVE-PINNED: android autofill activities (rendered inside another app).
        assertEquals("Session expired — open andvari and sign in again.", HouseholdCopy.SESSION_EXPIRED_AUTOFILL)
        // NATIVE-PINNED: both natives' friendlyError 429 row.
        assertEquals("Too many requests — please wait a bit and try again.", HouseholdCopy.TOO_MANY_REQUESTS)
        assertEquals("This andvari server requires a newer version of the app — update andvari, then try again.", HouseholdCopy.UPGRADE_REQUIRED)
        // TWIN: web account.ts IdentityMismatchError + extension "identity_mismatch".
        assertEquals("Server identity key mismatch — possible tampering. Do not proceed; contact your admin.", HouseholdCopy.IDENTITY_MISMATCH)
        // TWIN: web crypto/keys.ts WEAK_KDF_MESSAGE (H1, spec 05 T1).
        assertEquals("This server sent weakened security settings for your master password. The action was blocked to protect you — contact your administrator.", HouseholdCopy.WEAK_KDF_ACTION)
        // NATIVE-PINNED: both natives' H1 friendlyError sentence.
        assertEquals("This server sent weakened security settings for your master password. Sign-in was blocked to protect you — contact your administrator.", HouseholdCopy.WEAK_KDF_SIGN_IN)
        // TWIN: web Welcome.tsx unlock-gate terminal.
        assertEquals("Wrong master password.", HouseholdCopy.WRONG_MASTER_PASSWORD)
        // TWIN: web Welcome.tsx sign-in 401 + extension "bad_credentials".
        assertEquals("Wrong email or master password.", HouseholdCopy.WRONG_EMAIL_OR_PASSWORD)
        // TWIN: web Welcome.tsx sign-in 401 with a one-time code in play.
        assertEquals("Wrong email, master password, or one-time code.", HouseholdCopy.WRONG_EMAIL_PASSWORD_OR_CODE)
        // TWIN: web Welcome.tsx sign-in terminal + extension "unknown".
        assertEquals("Sign-in failed. Please try again.", HouseholdCopy.SIGN_IN_FAILED)
        // TWIN: web Welcome.tsx sign-in ApiError branch + extension "server_error".
        assertEquals("The server had a problem answering — your details may be fine. Try again in a moment.", HouseholdCopy.SIGN_IN_SERVER_PROBLEM)
        // TWIN: web Welcome.tsx unlock-gate ApiError branch ("password", not "details").
        assertEquals("The server had a problem answering — your password may be fine. Try again in a moment.", HouseholdCopy.UNLOCK_SERVER_PROBLEM)
        assertEquals("Couldn't unlock — please try again.", HouseholdCopy.UNLOCK_FAILED)
        // TWIN: web Welcome.tsx "public_login_requires_totp" (spec 03 §2).
        assertEquals("This account has no TOTP enrolled — sign-in from the public address is blocked. Connect from inside (VPN/LAN), enroll TOTP in Settings, then retry.", HouseholdCopy.PUBLIC_LOGIN_REQUIRES_TOTP)
        assertEquals("This account needs a one-time code — enter the code from your authenticator app.", HouseholdCopy.TOTP_CODE_NEEDED)
        // NATIVE-PINNED: desktop totpOp wording (deliberately unifies android's variant).
        assertEquals("That code isn't right — check your authenticator and try again.", HouseholdCopy.BAD_TOTP_CODE)
        // NATIVE-PINNED: SaveConfirmActivity's IOException sentence.
        assertEquals("Offline — try saving again when you're connected.", HouseholdCopy.SAVE_OFFLINE)
        // TWIN: extension saveErrorCopy("failed").
        assertEquals("Could not save — try again.", HouseholdCopy.SAVE_FAILED)
        // NATIVE-PINNED: desktop manual-refresh offline notice.
        assertEquals("Can't reach the server right now — showing what's synced on this device.", HouseholdCopy.SYNC_OFFLINE)
        assertEquals("Sync didn't finish — please try again.", HouseholdCopy.SYNC_FAILED)
        assertEquals("Couldn't read that file — try choosing it again.", HouseholdCopy.FILE_READ_FAILED)
        // NATIVE-PINNED: AutofillUnlockActivity's offline-no-cache sentence.
        assertEquals("Offline, and no saved keys — open andvari once while online.", HouseholdCopy.UNLOCK_OFFLINE_NO_KEYS)
    }

    // ---- forError: the shared map ----

    @Test
    fun forError_vaultLifecycleCodes_renderTheNativeFriendlyErrorRows() {
        // Byte-equal to BOTH natives' friendlyError maps today (§11) — the duplication #23 retires.
        assertEquals("You own this vault, so you can't just leave it — make someone else the owner first, or delete it.", HouseholdCopy.forError(api(409, "owner_must_transfer_or_delete")))
        assertEquals("This vault was deleted. The owner can restore it for a few more days.", HouseholdCopy.forError(api(410, "vault_deleted")))
        assertEquals("The restore window has passed — this vault's data has been erased.", HouseholdCopy.forError(api(410, "vault_gone")))
        assertEquals("This vault changed since you tried that — reload and try again.", HouseholdCopy.forError(api(409, "vault_state_changed")))
        assertEquals("This ownership offer is no longer active.", HouseholdCopy.forError(api(409, "transfer_not_pending")))
        assertEquals("This ownership offer isn't for you, or it couldn't be verified.", HouseholdCopy.forError(api(403, "not_transfer_target")))
        assertEquals("This vault changed somewhere else — reload and try the rename again.", HouseholdCopy.forError(api(409, "stale_meta")))
        assertEquals("They have to be a member of this vault first.", HouseholdCopy.forError(api(400, "not_a_member")))
        assertEquals("That account has been disabled — ask your admin to re-enable it first.", HouseholdCopy.forError(api(403, "user_inactive")))
        assertEquals("Only the vault's owner can do that.", HouseholdCopy.forError(api(403, "not_vault_owner")))
    }

    @Test
    fun forError_namedCodes() {
        assertEquals("That code isn't right — check your authenticator and try again.", HouseholdCopy.forError(api(400, "bad_totp_code")))
        assertEquals("Your recovery phrase was replaced from another device — set up recovery again from Settings.", HouseholdCopy.forError(api(409, "recovery_piece_stale")))
        assertEquals("Too many requests — please wait a bit and try again.", HouseholdCopy.forError(api(429, "rate_limited")))
        // The code is the contract (errorFrom rule) — and the typed subclass maps the same.
        assertEquals("This andvari server requires a newer version of the app — update andvari, then try again.", HouseholdCopy.forError(api(426, "upgrade_required")))
        assertEquals("This andvari server requires a newer version of the app — update andvari, then try again.", HouseholdCopy.forError(UpgradeRequiredException("upgrade_required", leak)))
    }

    @Test
    fun forError_statusLadder_unknownCodesStillLandOnHonestCopy() {
        // errorFrom's non-JSON fallback mints code "http_<status>" — the ladder keys on status.
        assertEquals("The server couldn't accept that request — try again, and update andvari if it keeps happening.", HouseholdCopy.forError(api(400, "http_400")))
        assertEquals("Session expired — sign in again.", HouseholdCopy.forError(api(401, "unauthorized")))
        assertEquals("You don't have permission to do that.", HouseholdCopy.forError(api(403, "no_grant")))
        assertEquals("The server couldn't find that — it may have been removed on another device.", HouseholdCopy.forError(api(404, "not_found")))
        assertEquals("That changed somewhere else — sync, then try again.", HouseholdCopy.forError(api(409, "conflict")))
        assertEquals("That's no longer available — it may have expired or been removed.", HouseholdCopy.forError(api(410, "resync_required")))
        assertEquals("The server refused that upload — it may be too large, or storage may be full.", HouseholdCopy.forError(api(413, "attachment_too_large")))
        assertEquals("Too many requests — please wait a bit and try again.", HouseholdCopy.forError(api(429, "http_429")))
        assertEquals("The server had a problem answering — try again in a moment.", HouseholdCopy.forError(api(500, "internal")))
        assertEquals("The server had a problem answering — try again in a moment.", HouseholdCopy.forError(api(502, "http_502")))
        // No named code, no recognized status — the neutral terminal, never the raw message.
        assertEquals("Something went wrong — please try again.", HouseholdCopy.forError(api(418, "im_a_teapot")))
    }

    @Test
    fun forError_transportSecurityAndUnknownTypes() {
        assertEquals("Can't reach the andvari server — check you're on the home network or VPN, then try again.", HouseholdCopy.forError(IOException("connect timed out")))
        assertEquals("This server sent weakened security settings for your master password. The action was blocked to protect you — contact your administrator.", HouseholdCopy.forError(weakKdf()))
        // The tampering signal NEVER softens — and never echoes the long core message.
        assertEquals("Server identity key mismatch — possible tampering. Do not proceed; contact your admin.", HouseholdCopy.forError(identityMismatch))
        // A plain crypto failure in a GENERIC context is not attributable to the password.
        assertEquals("Something went wrong — please try again.", HouseholdCopy.forError(CryptoException("aead open failed")))
        assertEquals("Something went wrong — please try again.", HouseholdCopy.forError(RuntimeException("raw leak")))
        assertEquals("Something went wrong — please try again.", HouseholdCopy.forError(IllegalStateException()))
    }

    // ---- the #23 guarantee: raw text never surfaces, from ANY mapper ----

    @Test
    fun noMapper_everReturnsTheRawMessage() {
        val throwables = listOf<Throwable>(
            api(400, "weird_new_code"), api(401, "unauthorized"), api(409, "conflict"),
            api(500, "internal"), api(418, "im_a_teapot"),
            UpgradeRequiredException("upgrade_required", leak),
            IOException("raw leak"), RuntimeException("raw leak"), CryptoException("raw leak"),
        )
        val mappers = listOf<(Throwable) -> String>(
            HouseholdCopy::forError,
            { HouseholdCopy.forSignInError(it) },
            { HouseholdCopy.forSignInError(it, totpTried = true) },
            HouseholdCopy::forUnlockError,
            HouseholdCopy::forSaveError,
            HouseholdCopy::forImportError,
            HouseholdCopy::forSyncError,
            HouseholdCopy::forTotpError,
        )
        for (t in throwables) for (map in mappers) {
            val copy = map(t)
            assertFalse(copy.contains("SQLSTATE"), "leaked server message for $t: $copy")
            assertFalse(copy.contains("raw leak"), "leaked exception message for $t: $copy")
            assertFalse(copy.contains("im_a_teapot"), "leaked wire code for $t: $copy")
        }
    }

    @Test
    fun forError_genericRuntimeException_returnsTheNeutralSentence_notItsMessage() {
        assertEquals("Something went wrong — please try again.", HouseholdCopy.forError(RuntimeException("raw leak")))
    }

    // ---- sign-in ladder (web Welcome.tsx / extension unlockErrorCopy parity) ----

    @Test
    fun signInLadder_rendersWebsExactCopy() {
        assertEquals("This server sent weakened security settings for your master password. Sign-in was blocked to protect you — contact your administrator.", HouseholdCopy.forSignInError(weakKdf()))
        assertEquals("Server identity key mismatch — possible tampering. Do not proceed; contact your admin.", HouseholdCopy.forSignInError(identityMismatch))
        assertEquals("Wrong email or master password.", HouseholdCopy.forSignInError(api(401, "unauthorized")))
        assertEquals("Wrong email, master password, or one-time code.", HouseholdCopy.forSignInError(api(401, "unauthorized"), totpTried = true))
        assertEquals("This account needs a one-time code — enter the code from your authenticator app.", HouseholdCopy.forSignInError(api(401, "totp_required")))
        assertEquals("This account has no TOTP enrolled — sign-in from the public address is blocked. Connect from inside (VPN/LAN), enroll TOTP in Settings, then retry.", HouseholdCopy.forSignInError(api(403, "public_login_requires_totp")))
        assertEquals("This andvari server requires a newer version of the app — update andvari, then try again.", HouseholdCopy.forSignInError(UpgradeRequiredException("upgrade_required", leak)))
        assertEquals("Too many requests — please wait a bit and try again.", HouseholdCopy.forSignInError(api(429, "rate_limited")))
        // A refusal that isn't about the credentials — the server answered; details may be fine.
        assertEquals("The server had a problem answering — your details may be fine. Try again in a moment.", HouseholdCopy.forSignInError(api(500, "internal")))
        assertEquals("Can't reach the andvari server — check you're on the home network or VPN, then try again.", HouseholdCopy.forSignInError(IOException("no route")))
        // Post-login the password is PROVEN — a late throw is never "wrong password" (web parity).
        assertEquals("Sign-in failed. Please try again.", HouseholdCopy.forSignInError(CryptoException("aead open failed")))
        assertEquals("Sign-in failed. Please try again.", HouseholdCopy.forSignInError(RuntimeException("raw leak")))
    }

    // ---- unlock ladder (web unlock-gate / AutofillUnlockActivity parity) ----

    @Test
    fun unlockLadder_cryptoIsWrongPassword_butTamperingNeverSoftens() {
        assertEquals("Wrong master password.", HouseholdCopy.forUnlockError(CryptoException("aead open failed")))
        // The crown rule: the identity-mismatch CryptoException must NOT read as wrong-password.
        assertEquals("Server identity key mismatch — possible tampering. Do not proceed; contact your admin.", HouseholdCopy.forUnlockError(identityMismatch))
        assertEquals("This server sent weakened security settings for your master password. Sign-in was blocked to protect you — contact your administrator.", HouseholdCopy.forUnlockError(weakKdf()))
        assertEquals("Session expired — sign in again.", HouseholdCopy.forUnlockError(api(401, "unauthorized")))
        assertEquals("Too many requests — please wait a bit and try again.", HouseholdCopy.forUnlockError(api(429, "rate_limited")))
        assertEquals("The server had a problem answering — your password may be fine. Try again in a moment.", HouseholdCopy.forUnlockError(api(500, "internal")))
        assertEquals("This andvari server requires a newer version of the app — update andvari, then try again.", HouseholdCopy.forUnlockError(UpgradeRequiredException("upgrade_required", leak)))
        assertEquals("Can't reach the andvari server — check you're on the home network or VPN, then try again.", HouseholdCopy.forUnlockError(IOException("offline")))
        // Unknown Throwable: never blame the password for an arbitrary failure (unlike web,
        // whose unlock structure guarantees only crypto reaches its terminal).
        assertEquals("Couldn't unlock — please try again.", HouseholdCopy.forUnlockError(RuntimeException("raw leak")))
    }

    // ---- save / import / sync / totp specializations ----

    @Test
    fun saveLadder() {
        assertEquals("Offline — try saving again when you're connected.", HouseholdCopy.forSaveError(IOException("socket closed")))
        assertEquals("Wrong master password.", HouseholdCopy.forSaveError(CryptoException("aead open failed")))
        assertEquals("Server identity key mismatch — possible tampering. Do not proceed; contact your admin.", HouseholdCopy.forSaveError(identityMismatch))
        // Server refusals route through the shared map — 401, conflict, lifecycle rows.
        assertEquals("Session expired — sign in again.", HouseholdCopy.forSaveError(api(401, "unauthorized")))
        assertEquals("That changed somewhere else — sync, then try again.", HouseholdCopy.forSaveError(api(409, "conflict")))
        assertEquals("This vault was deleted. The owner can restore it for a few more days.", HouseholdCopy.forSaveError(api(410, "vault_deleted")))
        assertEquals("Could not save — try again.", HouseholdCopy.forSaveError(RuntimeException("raw leak")))
    }

    @Test
    fun importLadder_localReadPhase_neverTalksAboutTheNetwork() {
        // The bytes are LOCAL — an IO failure here is a file problem, not a VPN problem.
        assertEquals("Couldn't read that file — try choosing it again.", HouseholdCopy.forImportError(IOException("stream closed")))
        assertEquals("Couldn't read that file — try choosing it again.", HouseholdCopy.forImportError(RuntimeException("charset boom")))
        // An ApiException reaching import still gets honest server copy, not file copy.
        assertEquals("Too many requests — please wait a bit and try again.", HouseholdCopy.forImportError(api(429, "rate_limited")))
    }

    @Test
    fun syncLadder_offlineReassuresAboutCachedData() {
        assertEquals("Can't reach the server right now — showing what's synced on this device.", HouseholdCopy.forSyncError(IOException("unreachable")))
        assertEquals("This andvari server requires a newer version of the app — update andvari, then try again.", HouseholdCopy.forSyncError(UpgradeRequiredException("upgrade_required", leak)))
        assertEquals("Session expired — sign in again.", HouseholdCopy.forSyncError(api(401, "unauthorized")))
        assertEquals("Sync didn't finish — please try again.", HouseholdCopy.forSyncError(RuntimeException("raw leak")))
    }

    @Test
    fun totpLadder_delegatesToTheSharedMap() {
        assertEquals("That code isn't right — check your authenticator and try again.", HouseholdCopy.forTotpError(api(400, "bad_totp_code")))
        assertEquals("Can't reach the andvari server — check you're on the home network or VPN, then try again.", HouseholdCopy.forTotpError(IOException("offline")))
        assertEquals("Something went wrong — please try again.", HouseholdCopy.forTotpError(RuntimeException("raw leak")))
    }
}
