package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.session.QuickGate

/**
 * Where the app is (design 2026-11-09, "Session layer"). Each screen's data is in [AppState]; a UI renders
 * the screen this names and nothing else.
 */
enum class AppScreen {
    /** Starting: reading the stored session and probing the server. */
    LOADING,

    /** No server is chosen yet (iOS first launch has no default server), or the person is changing it. */
    CHOOSE_SERVER,

    /** A typed address is a real change of server: the Trust Gate shows [AppState.trustGate] before anything is sent. */
    TRUST_GATE,

    /** Signed out at [AppState.server]: sign in, or enroll with an invite. */
    WELCOME,

    /** A stored session is locked: the master password, or Face ID when [AppState.quickUnlock] allows it. */
    UNLOCK,

    /** The shown-once recovery phrase ([SessionController.recoveryPhrase]), typed back to confirm it was saved. */
    RECOVERY_REVEAL,

    /** The vault-entry gate (§F.9): a fresh recovery piece is being committed; Retry when it failed. */
    RECOVERY_CAPTURE,

    /** Unlocked: the vault list. */
    VAULT,

    /** This build is too old for the server (426): only an update helps. */
    UPGRADE_REQUIRED,
}

/**
 * One immutable snapshot of what the UI shows. It never carries a secret: passwords, notes, one-time codes
 * and the recovery phrase are read through explicit calls on [SessionController].
 */
data class AppState(
    val screen: AppScreen,
    /** The origin the client dials, or null before a server is chosen. */
    val server: String?,
    /** What [server]'s policy says, once a probe answered; null before, or after a failed probe. */
    val policy: PolicyView?,
    /** The last probe of [server] failed: sign-in may still work, enrollment needs the policy. */
    val serverUnreachable: Boolean,
    /** TRUST_GATE: what the gate shows for the address being confirmed. */
    val trustGate: TrustGateView?,
    /** WELCOME: this sign-in needs the one-time code from an authenticator. */
    val totpRequired: Boolean,
    /** UNLOCK (and WELCOME after a sign-out): the account the stored session belongs to. */
    val accountEmail: String?,
    /** VAULT: captured logins that could not be saved by themselves; each says why and can be saved or discarded. */
    val pendingSaves: List<PendingSaveView>,
    /** VAULT: captured logins this unlock saved by itself, until dismissed; each can be undone ([AppliedSaveView]). */
    val appliedSaves: List<AppliedSaveView>,
    /** The quick-unlock gates: the Face ID button shows when [QuickUnlockView.usable]. */
    val quickUnlock: QuickUnlockView,
    /** Why the vault locked or the session ended, for UNLOCK and WELCOME; null when nothing needs saying. */
    val lockReason: String?,
    /** VAULT: the items matching [query], sorted by name. */
    val items: List<ItemSummary>,
    /** VAULT: the search text [items] is filtered by. */
    val query: String,
    /** VAULT: a sync is running in the background. */
    val syncing: Boolean,
    /** RECOVERY_REVEAL: the invite waived org escrow, so this phrase is the only way back in. */
    val recoveryWaived: Boolean,
    /** RECOVERY_CAPTURE: why the last commit failed (static copy), for its Retry. */
    val recoveryCaptureError: String?,
    /** RECOVERY_CAPTURE: the phrase shown before was replaced by another device; this is a new one. */
    val recoveryReplacedNotice: Boolean,
    /** The account signed in with a recovery temporary password: it must be changed. */
    val mustChangePassword: Boolean,
    /** An action is running: disable what would start another. */
    val busy: Boolean,
    /** A sentence to show as an error, until dismissed. */
    val error: String?,
    /** A sentence to show as a notice, until dismissed. */
    val notice: String?,
    /** UPGRADE_REQUIRED: what to tell the person. */
    val upgradeMessage: String?,
) {
    companion object {
        /** Before [SessionController.start]. */
        val initial = AppState(
            screen = AppScreen.LOADING, server = null, policy = null, serverUnreachable = false, trustGate = null,
            totpRequired = false, accountEmail = null, pendingSaves = emptyList(), appliedSaves = emptyList(), quickUnlock = QuickUnlockView(available = false, enrolled = false, fresh = false, refusal = null, reason = null),
            lockReason = null, items = emptyList(), query = "", syncing = false, recoveryWaived = false,
            recoveryCaptureError = null, recoveryReplacedNotice = false, mustChangePassword = false, busy = false,
            error = null, notice = null, upgradeMessage = null,
        )
    }
}

/** What the server's policy says, as far as a screen needs it. */
data class PolicyView(
    /** The server lets this device keep an offline copy (and a quick-unlock key). */
    val offlineCacheAllowed: Boolean,
    /** The auto-lock window, already clamped. */
    val autoLockSeconds: Int,
    /** The org recovery key's fingerprint, first 32 hex: what a recovery sheet's check is typed against. Empty when none. */
    val recoveryFingerprintShort: String,
    /** "invite-only", "closed" or "landing" (spec 03 §2.1). */
    val signupMode: String,
)

/** What the Trust Gate shows for an address (design 2026-07-15 §4.3): the raw origin, never a display name. */
data class TrustGateView(
    /** The exact origin the client will dial (punycode for an internationalized name). */
    val origin: String,
    /** The name is internationalized: say so, since it can imitate another. */
    val punycodeCaution: Boolean,
    /** Plain http: say so. */
    val httpCaution: Boolean,
    /** This platform refuses plain http to this host: Connect cannot work. */
    val cleartextBlocked: Boolean,
)

/** The quick-unlock gates for the stored account (spec 01 §8.1). */
data class QuickUnlockView(
    /** The policy allows it and the device has Face ID or Touch ID: it can be turned on. */
    val available: Boolean,
    /** It is turned on for this account on this device. */
    val enrolled: Boolean,
    /** Turned on, and the last master-password unlock is recent enough to use it. */
    val fresh: Boolean,
    /** The first gate that refuses it now; null when it can be used. [QuickGate.NOT_ENROLLED] is the normal "turned off". */
    val refusal: QuickGate?,
    /** What to show under the switch while [refusal] stands: null when it is null or [QuickGate.NOT_ENROLLED]. */
    val reason: String?,
) {
    /** Show the Face ID button. */
    val usable: Boolean get() = available && enrolled && fresh
}

/** A row of the vault list. No secret: the password, notes and one-time code are read on request. */
data class ItemSummary(
    val itemId: String,
    val name: String,
    /** "login", "note" or "card". */
    val type: String,
    val username: String?,
    /** The first web address's host, for the row's subtitle and icon. */
    val host: String?,
    val favorite: Boolean,
    val hasTotp: Boolean,
    /** Saved here but not yet on the server. */
    val pendingSync: Boolean,
)

/** An item's detail screen. Secrets are read through [SessionController.revealSecret] and [SessionController.oneTimeCode]. */
data class ItemDetail(
    val itemId: String,
    val vaultId: String,
    val type: String,
    val name: String,
    val username: String?,
    val uris: List<String>,
    val hasPassword: Boolean,
    val hasNotes: Boolean,
    val hasTotp: Boolean,
    val favorite: Boolean,
    /** Unix milliseconds. */
    val updatedAt: Long,
    /** This account may change the item (a reader of a shared vault may not). */
    val editable: Boolean,
    /** How many earlier passwords the login keeps in its history (an automatic save adds the one it replaced). */
    val previousPasswords: Int,
)

/** A secret field of an item, read only on an explicit reveal or copy. */
enum class SecretField { PASSWORD, NOTES, TOTP_SECRET }

/** A one-time code and how long it stays valid. */
data class OneTimeCode(val code: String, val secondsRemaining: Int, val periodSeconds: Int)

/** The fields of a login being added or edited. Not a data class: no toString of the password. */
class LoginInput(
    val name: String,
    val username: String,
    val password: String,
    /** Web addresses, one per entry; blanks are dropped. */
    val uris: List<String>,
    val notes: String,
    /** An otpauth:// URI or a base32 secret; blank for none. */
    val totp: String,
    val favorite: Boolean,
)

/** The enroll form. Not a data class: no toString of the password. */
class EnrollForm(
    /** The invite token, or an enroll link (a link for another server is answered with [ActionResult.OtherServer]). */
    val invite: String,
    /** Blank takes the address an enroll link names. */
    val email: String,
    /** Blank takes the address's local part. */
    val name: String,
    val password: String,
    /** The person was handed a printed recovery sheet; without one the invite's org escrow is waived. */
    val hasRecoverySheet: Boolean,
    /** With a sheet: its first 32 hex characters, typed. */
    val sheetCode: String,
)

/** Password generator settings (spec 05). */
data class GeneratorSettings(
    val length: Int,
    val lower: Boolean,
    val upper: Boolean,
    val digits: Boolean,
    val symbols: Boolean,
    val avoidAmbiguous: Boolean,
) {
    companion object {
        val standard = GeneratorSettings(length = 20, lower = true, upper = true, digits = true, symbols = true, avoidAmbiguous = true)
    }
}

/** What an action came to. The screen follows from [AppState]; this is what to say in place, if anything. */
sealed class ActionResult {
    /** Done. [AppState] shows where it landed. */
    data object Ok : ActionResult()

    /** Sign-in needs the authenticator's code. [wrongCode]: the code sent was refused. */
    data class NeedsCode(val wrongCode: Boolean) : ActionResult()

    /** The phrase typed back does not match the one shown. */
    data object Mismatch : ActionResult()

    /** The invite is for another server: change to [origin] through the Trust Gate first. */
    data class OtherServer(val origin: String) : ActionResult()

    /** Nothing was done, by the person's choice or a gate (a cancelled Face ID prompt); [message] says why, if it should. */
    data class NotDone(val message: String?) : ActionResult()

    /** Refused or failed. [message] is the sentence to show; never raw server or exception text. */
    data class Failed(val message: String) : ActionResult()
}

/** What an address typed into the server field means. */
sealed class ServerChoice {
    /** Not a server address (a path, a query, credentials, not http(s)): [message] says so. */
    data class Invalid(val message: String) : ServerChoice()

    /** The server already chosen, spelled differently: nothing changes. */
    data class Applied(val origin: String) : ServerChoice()

    /** A real change: the Trust Gate is up ([AppState.trustGate]); confirm or cancel it. */
    data class NeedsGate(val gate: TrustGateView) : ServerChoice()
}

/** A registration that can be cancelled: [SessionController.observe] returns one. */
interface Subscription {
    fun close()
}

/**
 * A login as the system's AutoFill suggestions need it (iOS `ASCredentialIdentityStore`): the host and the username
 * in the clear, never a password. One per web address of a login.
 */
data class CredentialIdentity(
    val itemId: String,
    /** The normalized host of one of the login's web addresses. */
    val host: String,
    val username: String,
    val hasTotp: Boolean,
)

/** A login an extension captured, shown before anything is written. The password is not here: it is read on request. */
data class PendingSaveView(
    val id: String,
    /** The host it was captured on. */
    val host: String,
    val username: String,
    /** The name of the login whose password saving would replace; null when saving adds a new login. */
    val replaces: String?,
    /** It was captured on a plain-http page: the row says so, and it is saved as an http address. */
    val plainHttp: Boolean,
    /** Why it was not saved by itself (offline, no personal vault, a login in a shared vault matches); null while that is still being tried. */
    val reason: String?,
)

/** A captured login the app saved by itself at unlock. No secret. */
data class AppliedSaveView(
    val id: String,
    val host: String,
    val username: String,
    /** The login's name when its password was replaced (the old one is in the login's password history); null for a new login. */
    val replaced: String?,
    val plainHttp: Boolean,
)
