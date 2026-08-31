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
 *  - [replayDeniedNotice]             ← web Vault.tsx noticeBody "replay-denied" (BOTH count
 *    branches; web carries them as template literals, pinned byte-equal against this file's
 *    literals by web/src/ui/vault-copy.test.ts)
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
 * ENROLLMENT CODES ARE NO LONGER SURFACE-SPECIFIC (audit F26). They used to be — this KDoc
 * said so — and the result was a three-way split where web and desktop each hand-wrote the
 * table and android wrote none at all, so a family member whose invite QR was scanned twice
 * got "try again, and update andvari if it keeps happening" on the phone (false on both
 * counts) and a one-tap fix on the laptop. The ten [Service.register] refusal rows now live
 * ONCE, in [apiCopy]'s code map below, and every client reads them; [forEnrollError] is the
 * enroll surface's named seam. A lane may still map ITS OWN codes first and delegate the rest
 * here (the desktop move flow's gesture exceptions do this) — what it may not do is re-write a
 * row that already exists here. Callers should keep catching [UpgradeRequiredException] for the
 * blocking platform-specific upgrade screen; the [UPGRADE_REQUIRED] sentence below is only the
 * honest inline fallback when a 426 reaches a generic error slot.
 */
object HouseholdCopy {

    // ---- canonical sentences (see the twin table above) ----

    /** TWIN of web/src/ui/errors.ts UNREACHABLE + extension/src/errors.ts UNREACHABLE. */
    const val UNREACHABLE = "Can't reach the andvari server — check your connection (and your VPN, if your server is private), then try again."

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

    /** TWIN of web Welcome.tsx "public_login_requires_totp" (spec 03 §2 break-glass — only
     *  an armed opt-in break-glass twin origin answers this; single-origin instances never do). */
    const val PUBLIC_LOGIN_REQUIRES_TOTP = "This account doesn't have two-factor sign-in turned on, and this address only accepts accounts that do. Connect from inside (VPN/LAN), turn it on in Settings, then retry."

    /** Native sign-in fallback for `totp_required` reaching an error slot (both natives
     *  normally handle it as control flow — reveal the code field — before mapping). */
    const val TOTP_CODE_NEEDED = "This account needs a one-time code — enter the code from your authenticator app."

    /** NATIVE-PINNED: desktop totpOp's wording, unifying android's "That code didn't
     *  match — try again." (the authenticator hint is the actionable half). */
    const val BAD_TOTP_CODE = "That code isn't right — check your authenticator and try again."

    /** NATIVE-PINNED: SaveConfirmActivity's IOException sentence (autofill save offline).
     *  G23: the push queue is durable — an IO failure leaves the save QUEUED, and it applies
     *  on the next sync. So this must not claim failure or invite a re-save: a followed
     *  retry of a new-item save mints a fresh itemId and the item lands twice. */
    const val SAVE_OFFLINE = "Offline — your save is queued and will finish when you're connected."

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

    /**
     * ANDROID-ONLY (audit F27), for that lane the way [SESSION_EXPIRED_AUTOFILL] is: Android's
     * network security config bans cleartext to everything but loopback, so OkHttp refuses a
     * plain-`http://` LAN server with `java.net.UnknownServiceException` — an IOException, which
     * the mappers below would otherwise read as [UNREACHABLE] ("check your connection… and your
     * VPN"). That sent self-hosters debugging a network that was never dialled, while the SAME
     * address works on desktop (the ktor Java engine has no such policy). The refusal is the
     * PLATFORM's, permanent, and fixable only one way, so it says exactly that. Mapped by the
     * android surface (AndvariViewModel's `cleartextBlockedCopy`); desktop must NOT use it —
     * UNREACHABLE is the truth there.
     */
    const val CLEARTEXT_BLOCKED = "Android blocks unencrypted http:// connections to other devices — put your server behind https (a reverse proxy, or Tailscale Serve), then try again."

    // ---- vault-lifecycle disclosure (not an error: a limitation the user must hear BEFORE it bites) ----

    /**
     * TWIN of web Vault.tsx's Trash header sentence. Delete is irreversible for ATTACHMENTS
     * only, and normatively so (spec 02 §7): the server nulls the blob and unlinks the files
     * at delete time, and both the web store and core [SyncEngine] drop the refs on restore —
     * so a restored item comes back without its files, forever.
     * Every client framed the 30-day trash as fully reversible and said nothing about this
     * (audit F04); the disclosure had existed once, in the 0.6.0 user-test guide, and was lost.
     * Both moments that matter carry it — the delete confirm, when the item still HAS
     * attachments, and the Trash header — but only the Trash header is byte-equal on all three
     * clients. Web's delete confirm renders a COUNT-bearing variant instead ("Its 3 attached
     * files cannot be restored, even from Deleted items.", Vault.tsx), because there the file
     * count is already on screen; the natives append this constant verbatim. Pin the header
     * wording across clients, not the confirm's.
     */
    const val TRASH_RESTORE_NO_ATTACHMENTS = "Restoring brings the item back, but not its attachments — those were permanently removed when the item was deleted."

    // ---- lifecycle-notice copy (spec 03 §11) ----

    /**
     * TWIN of web Vault.tsx noticeBody's "replay-denied" branch (android SharingScreen +
     * desktop Ui call this directly). Not an error map: the §11 notices are calm statements,
     * and this is the one whose sentence INTERPOLATES (count + vault name) — which is why it
     * stayed hand-written on all three surfaces and drifted three ways (ux-copy--3, polish
     * audit 2026-07-27) while every surface's comment claimed to mirror the others. Wording
     * decisions, recorded so the next editor doesn't re-litigate them:
     *  - "your access", not the natives' "your role": role is the mechanically accurate term
     *    (the member's role likely changed across the grace) but it is jargon to a family
     *    member, and the sibling notice already says "Your access to “X” was removed."
     *  - the reason clause stays (web's half): a notice that only says "couldn't be applied"
     *    invites the reader to suspect data loss — naming the cause IS the reassurance.
     *  - "while the vault was deleted", not web's "while it was deleted" — "it" sat next to
     *    "your access" and could be read as the edit.
     *  - "A recovered edit", not the natives' "1 recovered edit": the article idiom its own
     *    banner neighbour already uses ("An offline change to “X” was refused").
     * [count] is the notice's `parkedCount` with a null taken as 0, and [vaultName] is already
     * resolved by the caller — every §11 notice falls back to "a vault" for a blank name.
     */
    fun replayDeniedNotice(count: Int, vaultName: String): String =
        if (count == 1) {
            "A recovered edit to “$vaultName” couldn't be applied — your access may have changed while the vault was deleted."
        } else {
            "$count recovered edits to “$vaultName” couldn't be applied — your access may have changed while the vault was deleted."
        }

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

    /**
     * Enrollment (invite → register). Every refusal `Service.register` can throw has a curated
     * row in [apiCopy]'s code map below, so this mapper is thin on purpose: its ONE job is the
     * H1 context — an enroll is a credential ceremony, so a weakened-KDF push reads with the
     * sign-in wording ([WEAK_KDF_SIGN_IN]), not the neutral [WEAK_KDF_ACTION].
     *
     * The register-gate rows are asserted COMPLETE against the server source by
     * `RegisterRefusalCoverageTest` — a new BadRequest in `register` fails that test rather
     * than shipping as "The server couldn't accept that request", which is what android showed
     * for every one of them before F26.
     */
    fun forEnrollError(t: Throwable): String =
        if (t is KdfPolicyViolationException) WEAK_KDF_SIGN_IN else forError(t)

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
        // Enrollment / invite (§F.4, every BadRequest `Service.register` throws — audit F26).
        // Promoted byte-equal from web `enrollError` + the desktop enroll sheet wherever those two
        // already agreed, so adopting this table is a zero-copy-diff swap on both. The two that
        // did NOT agree are resolved here, once:
        //  - `invalid_invite` takes desktop's "code" over web's "token" — the field a household
        //    member types into is labelled "Invite code or link" on every client; "token" is the
        //    wire's word for it, not theirs.
        //  - `escrow_not_allowed_when_waived` drops web's "reload and" (a browser-only gesture:
        //    the natives toggle the step in place) and keeps curly quotes, the canon's house style.
        "invalid_invite" -> "That invite code is not valid."
        // Benign double-use dominates (a second family device scanning the same QR) — nudge to
        // Sign in rather than alarming.
        "invite_used" -> "That invite has already been used. Already set up this account? Switch to Sign in."
        "invite_expired" -> "That invite has expired."
        "invite_email_mismatch" -> "This invite was created for a different email address — ask your admin for a new invite."
        "email_taken" -> "An account with that email already exists."
        // §F.4 posture gate. `escrow_required` = the invite wants the admin backstop but this
        // enrollment offered none (the waived posture — where an invite is passed on as a bare
        // token, `enrollPosture` defaults to waived, so this is the DEFAULT-path refusal, not an
        // exotic one). It had no curated row on ANY client: web printed the raw wire code and
        // desktop fell through to the generic 400, because the sentence that fits it was keyed to
        // `recovery_required` — a different condition entirely (see its row below).
        "escrow_required" -> "This invite needs the admin backstop — set up with the recovery-sheet step (you'll need the printed sheet your admin gave you), or ask your admin for a member-only invite."
        "escrow_not_allowed_when_waived" -> "This invite is set to “member-only” (no admin backstop) — set up without the recovery-sheet step, or ask your admin for a new invite."
        // The org has no recovery key configured at all, so no invite of this posture can be
        // completed by anyone. Only the admin can clear it.
        "escrow_not_configured" -> "This server hasn't finished setting up the admin backstop — ask your admin to finish it, or to send you a member-only invite."
        // A tampering signal (the sealed escrow would go to a key the printed sheet doesn't
        // attest) — never softened into retry copy, exactly like [IDENTITY_MISMATCH].
        "escrow_fingerprint_mismatch" -> "Recovery fingerprint mismatch — do not proceed; contact your admin."
        // NOT the posture gate (that is `escrow_required` above): the server refuses because the
        // per-member recovery block was absent or malformed. Every client always sends one, so
        // this is an app fault, never something the user did — say so without blaming them.
        "recovery_required" -> "andvari couldn't finish setting up your recovery phrase — start the setup again, and update andvari if it keeps happening."
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
