package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.HouseholdCopy
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

    /**
     * Forgot the master password: the email and the recovery phrase, then (once [AppState.recoverVerified]) a new
     * master password.
     */
    RECOVER,

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
    /** RECOVER: the email and phrase were verified; the screen now asks for the new master password. */
    val recoverVerified: Boolean,
    /** VAULT: what happened to shared vaults since the last look (spec 03 §11), each dismissable. */
    val vaultNotices: List<VaultNoticeView>,
    /** The shared vaults screen while it is open ([SessionController.openSharing]); null otherwise. */
    val sharing: SharingView?,
    /** One shared vault's members while their screen is open ([SessionController.openMembers]); null otherwise. */
    val members: MembersView? = null,
    /** A comparison of identity codes while it is open ([VerifyView]); null otherwise. */
    val verifying: VerifyView? = null,
    /** The people this account verified, while their screen is open ([SessionController.openHousehold]); null otherwise. */
    val household: HouseholdView? = null,
    /** VAULT: shared vaults waiting for this account to verify who sent them. */
    val invitations: List<InvitationView> = emptyList(),
    /** VAULT: offers to make this account the owner of a shared vault, each verified under that vault's key (spec 03 §11). */
    val ownershipOffers: List<OwnershipOfferView> = emptyList(),
    /** VAULT: shared vaults readable only through an older kind of sharing nobody vouched for: read only until reviewed. */
    val legacyReviews: List<LegacyReviewView> = emptyList(),
    /** "You own <vault>?" while it is open ([SessionController.describeOwnership]); null otherwise. */
    val ownershipClaim: OwnershipClaimView? = null,
    /** Two-step sign-in while its screen is open ([SessionController.loadTwoStep]); null otherwise. */
    val twoStep: TwoStepView?,
    /** The server's trash while it is open ([SessionController.openTrash]); null otherwise. */
    val trash: List<TrashItemView>?,
    /** One item's earlier versions while they are open ([SessionController.openItemHistory]); null otherwise. */
    val history: ItemHistoryView?,
    /** The files of the item an editor has open ([SessionController.openAttachmentDraft]); null otherwise. */
    val attachmentDraft: AttachmentDraftView? = null,
    /** A save with new files is sending them ([UploadView]); null otherwise. Leaving the app gives it a short grace. */
    val upload: UploadView? = null,
    /** VAULT: the personal vault is not confirmed on this device; what the person has to decide. Null when it is. */
    val personalVault: PersonalVaultView?,
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
            totpRequired = false, accountEmail = null, recoverVerified = false, vaultNotices = emptyList(), sharing = null, twoStep = null, trash = null, history = null, personalVault = null, pendingSaves = emptyList(), appliedSaves = emptyList(), quickUnlock = QuickUnlockView(available = false, enrolled = false, fresh = false, refusal = null, reason = null),
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
    /** How long a copied secret may stay on the clipboard, already clamped (1 to 300 seconds). */
    val clipboardClearSeconds: Int,
    /** The largest one file may be, already clamped ([AttachmentRules.limits]). */
    val attachmentMaxBytes: Long = AttachmentRules.DEFAULT_FILE_BYTES,
    /** The most one item's files may come to, already clamped. */
    val itemAttachmentsMaxBytes: Long = AttachmentRules.DEFAULT_ITEM_BYTES,
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
    /** A payment card's fields; null for any other kind of item. */
    val card: CardDetail?,
    /** The item's files, by name and size; opened one at a time ([SessionController.readAttachment]). */
    val attachments: List<AttachmentView> = emptyList(),
)

/**
 * A payment card as its detail shows it. The number and the security code are not here: they are read on request
 * ([SecretField.CARD_NUMBER], [SecretField.CARD_CODE]), like a password.
 */
data class CardDetail(
    /** "Visa ••4242": the brand and the last four digits. */
    val summary: String,
    val cardholder: String?,
    /** "07/2031", or whichever half the card has. */
    val expiry: String?,
    val postalCode: String?,
    val hasNumber: Boolean,
    val hasCode: Boolean,
    /** The stored month and year, each as stored ("07", "2031"), for an editor: never re-split from [expiry]. */
    val expMonth: String?,
    val expYear: String?,
)

/** The vaults this account holds, and the shared vaults it can bring back (spec 03 §10, §11). */
data class SharingView(
    /** The personal vault first, then the shared ones by name. */
    val vaults: List<SharingVaultView>,
    /** Shared vaults this account deleted that are still in their 7-day grace: Restore brings one back for everyone. */
    val deleted: List<DeletedVaultView>,
    /** Shared vaults this account lost access to, a sealed copy of which this device keeps for a while. Read only. */
    val removed: List<RemovedVaultView>,
    /** A copy of a vault's items into the personal vault, running ([CopyProgressView]) or done ([copied]). */
    val copying: CopyProgressView?,
    /** What the last copy into the personal vault came to. */
    val copied: String?,
)

data class SharingVaultView(
    val vaultId: String,
    val name: String,
    val personal: Boolean,
    /** "owner", "writer" or "reader" in a shared vault; null for the personal vault. */
    val role: String?,
    /** The server reports this account as the owner, and this account's own record agrees. */
    val ownershipConfirmed: Boolean,
    val itemCount: Int,
    val attachmentCount: Int,
    /** Readable only through an older kind of sharing nobody vouched for ([LegacyReviewView]): nothing is saved into it yet. */
    val awaitingReview: Boolean = false,
)

data class DeletedVaultView(val vaultId: String, val name: String, val deletedAtMs: Long, val purgeAtMs: Long)

data class RemovedVaultView(
    val vaultId: String,
    val name: String,
    /** Why access went and until when the sealed copy is kept, in words. */
    val line: String,
    /** The removal could not be verified as a real owner action. */
    val warning: Boolean,
)

data class CopyProgressView(val vaultId: String, val done: Int, val total: Int)

/**
 * One shared vault's members while its screen is open ([SessionController.openMembers]). Who is listed, their names and
 * addresses are the server's word; whether each was verified is this device's own record (root cause A §7.2).
 */
data class MembersView(
    val vaultId: String,
    val vaultName: String,
    /** The server lists this account as the vault's owner: it changes roles and removes members. */
    val owner: Boolean,
    /**
     * This account's own record says it owns the vault, so it may add someone: an add seals the vault's key to them, and
     * the server's word that this account is the owner is not enough for that (A6b).
     */
    val canAdd: Boolean,
    /** Null until the server answered. */
    val members: List<MemberView>?,
    /** Someone being added, after a look-up ([SessionController.findNewMember]); null otherwise. */
    val adding: NewMemberView?,
    /** The owner's offer to make a member the owner, while it waits for their answer ([SessionController.offerOwnership]). */
    val offer: OwnerOfferView? = null,
    /** Members the server lists as still on the older kind of sharing, for the owner to share with again ([LegacyGrantView]). */
    val legacy: List<LegacyGrantView> = emptyList(),
)

/**
 * A member the server lists as still on the older kind of sharing (root cause A §8.2 step 4): their devices hold the
 * vault's key only from a seal nobody signed. The owner shares the vault with them again under the signed kind, one
 * person at a time, and only ever to the key this device verified for them. The list itself is the server's word.
 */
data class LegacyGrantView(
    val userId: String,
    /** What the server calls them. */
    val name: String,
    /** The address the server has for them. */
    val email: String,
    /** Whether this device verified them, now. */
    val check: MemberCheck,
    /** The name shown when this device verified them; null unless [check] is [MemberCheck.VERIFIED]. */
    val verifiedLabel: String?,
    /** When this account's own record says it shared the vault with them before (it decides nothing); null without one. */
    val sharedAtMs: Long?,
)

/**
 * A shared vault this account reads only through an older kind of sharing andvari cannot check (root cause A §8.2): it
 * cannot confirm who sent it, so nothing is saved into it until the person accepts it (trust on first use) or leaves it.
 */
data class LegacyReviewView(
    val vaultId: String,
    /** Its name, read with the key the server delivered; null when that does not read. */
    val name: String?,
    val itemCount: Int,
    /** What the server calls the vault's owner, once it said; null before (or when it could not say). */
    val owner: String?,
)

/**
 * "You own <vault>?" (A6b): the server lists this account as a vault's owner, but the account's own record does not say
 * so. What the server reports of the vault is shown first; the master password, checked on this device, confirms it.
 */
data class OwnershipClaimView(
    val vaultId: String,
    val vaultName: String,
    /** What the server reports: how the vault came to this account, and who else holds it. */
    val lines: List<String>,
    /** This device first received the vault as a member: the person also confirms that its owner handed it over. */
    val receivedAsMember: Boolean,
)

/**
 * The people this account verified by comparing identity codes with them (root cause A §7.2): the account's own record,
 * kept for it on the server sealed so only it can read it, and the same on all its devices.
 */
data class HouseholdView(
    /** By the address typed to find them, else the name shown when they were verified. */
    val contacts: List<ContactView>,
    /** What was wrong with the copy of the record the server sent last (an older one, or one this account did not write). */
    val warning: String?,
)

data class ContactView(
    val userId: String,
    /** The address typed to find them when they were verified; null when none was typed. */
    val email: String?,
    /** The name shown when they were verified. */
    val label: String,
    /** How: "qr", "typed" or "enrol". */
    val method: String,
    val verifiedAtMs: Long,
    /** Verified on this device. One verified on another device counts here once verified here too. */
    val confirmedHere: Boolean,
)

/** An offer this account made to hand a vault over: to whom (the server's name for them), and until when. */
data class OwnerOfferView(val toUserId: String, val toName: String, val expiresAtMs: Long)

/**
 * An offer to make this account the owner of a shared vault. It is listed only once it verified under the vault's own
 * key, so the server cannot make one up; who sent it is the server's word ([from]), to confirm with them in person.
 */
data class OwnershipOfferView(
    val vaultId: String,
    val vaultName: String,
    /** What the server calls the vault's owner, once it said; null before (or when it could not say). */
    val from: String?,
    val expiresAtMs: Long,
)

data class MemberView(
    val userId: String,
    /** What the server calls them. */
    val name: String,
    /** The address the server has for them. */
    val email: String,
    /** "owner", "writer" or "reader". */
    val role: String,
    /** The server reports their account as disabled. */
    val disabled: Boolean,
    /** This account. */
    val you: Boolean,
    /** Whether this device verified them; null for this account. */
    val check: MemberCheck?,
)

/** What this device knows of someone's identity key. */
enum class MemberCheck {
    /** Verified on this device, and the server serves the key that was verified. */
    VERIFIED,

    /** Verified, but the server now serves another key for them: their code has to be checked again, in person. */
    KEY_CHANGED,

    /** Not verified on this device. */
    NOT_VERIFIED,
}

/** Someone the owner is adding: the address typed, and what this device knows of the account the server answered with. */
data class NewMemberView(
    /** The address the owner typed. */
    val email: String,
    /** What the server calls the account it answered with: its word, never proof of who they are. */
    val serverName: String,
    val step: NewMemberStep,
    /** [NewMemberStep.READY]: who was verified for this address, and when. The add seals to the key verified. */
    val verified: VerifiedPersonView?,
    /** [NewMemberStep.VERIFY_AGAIN] and [NewMemberStep.REFUSED]: why, in a sentence. */
    val reason: String?,
)

/** A verification this device holds for someone (a pin), as the add confirmation shows it. */
data class VerifiedPersonView(
    /** The address typed when they were verified. */
    val email: String,
    val verifiedAtMs: Long,
    /** The name the server gave them when they were verified. */
    val label: String,
    /** Their identity code as verified (32 hex), from the verified key. */
    val code: String,
)

enum class NewMemberStep {
    /** Not verified on this device: compare codes first ([SessionController.verifyNewMember]). */
    VERIFY,

    /** Verified before andvari recorded addresses, or the server now serves another key for them: verify again. */
    VERIFY_AGAIN,

    /** Verified for this address: choose a role and add ([SessionController.addNewMember]). */
    READY,

    /** The server answered this address with an account this device verified as someone else: never added. */
    REFUSED,
}

/**
 * Comparing identity codes with someone, while it is open (root cause A §7.2): together, in person or on a call the two
 * trust, they read their code from THEIR screen and it is typed here, or their QR code is scanned. Only a match records
 * them as verified.
 */
data class VerifyView(
    /** What the server calls them: its word; the codes are the check. */
    val serverName: String,
    /** The address typed to find them (adding a member): recorded with the verification. Null otherwise. */
    val email: String?,
    /** They sent an invitation: the vault they share opens once they are verified. */
    val invitation: Boolean,
    /** This account's own identity code (32 hex), for them to type. */
    val myCode: String,
    /** This account's identity QR code payload, for them to scan. */
    val myQr: String,
)

/**
 * A shared vault someone wants to share with this account, from someone this device has not verified (root cause A
 * §1.6): it stays closed until they are. Its name is not shown, since it would come from a key nobody checked.
 */
data class InvitationView(
    val id: String,
    /** What the server calls the sender, once it said; null before (or when it could not say). */
    val from: String?,
)

/** Two-step sign-in, as the server reports it for this account. */
data class TwoStepView(
    /** A code from an authenticator is asked for at every sign-in. */
    val enrolled: Boolean,
    /** A new key is being set up on this device ([SessionController.twoStepSetup]) and waits for its first code. */
    val settingUp: Boolean,
    /**
     * The person left the app in the middle of setting up (to add the key to an authenticator) and has just unlocked
     * again: the app opens the two-step screen on its confirm step.
     */
    val resumed: Boolean = false,
)

/**
 * The key a two-step setup adds to an authenticator, shown once: base32 and as an otpauth:// link. Not a data class: no
 * toString of the key.
 */
class TwoStepSetup(val secret: String, val uri: String)

/** One lifecycle notice (spec 03 §11): a vault deleted, restored, left, transferred, or an anomaly the server reported. */
data class VaultNoticeView(
    val id: String,
    /** The whole sentence, Android's word for word ([io.silencelen.andvari.core.client.LifecycleNoticeCopy]). */
    val text: String,
    /** An anomaly: something the server said that could not be verified, or a change that was refused. */
    val warning: Boolean,
)

/** A vault an item can be put in ([SessionController.vaultsForNewItems], [SessionController.moveTargets]). */
data class VaultChoiceView(
    val vaultId: String,
    val name: String,
    /** The account's personal vault; any other is shared, and everyone in it sees what is put there. */
    val personal: Boolean,
)

/** What the trash screen says above the list. */
const val TRASH_EXPLANATION: String =
    "Deleted items are kept for 30 days, then removed automatically. " + HouseholdCopy.TRASH_RESTORE_NO_ATTACHMENTS + " \"Delete forever\" removes one now."

/** One deleted item in the server's trash. Nothing secret: its name and kind, a username or a card's last four. */
data class TrashItemView(
    val itemId: String,
    /** From its last readable version; null when none could be read (it can then only be deleted for good). */
    val name: String?,
    /** "login", "note" or "card"; null when no version could be read. */
    val type: String?,
    /** A login's username or a card's brand and last four. */
    val detail: String?,
    /** The vault it was deleted from, by the name this device knows it by. */
    val vault: String?,
    val deletedAtMs: Long,
    /** Restore brings it back (without its attachments); false for an unreadable one or a vault this account only reads. */
    val canRestore: Boolean,
    /** Delete forever removes it and its history now; false in a vault this account only reads. */
    val canPurge: Boolean,
)

/** One item's earlier versions (the server keeps the last 10), newest first. Secrets are read through [SessionController.historyPassword]. */
data class ItemHistoryView(
    val itemId: String,
    val versions: List<ItemVersionView>,
    /** False in a vault this account only reads. */
    val canRestore: Boolean,
)

data class ItemVersionView(
    val rev: Long,
    val archivedAtMs: Long,
    val name: String,
    /** A login's username or a card's brand and last four. */
    val detail: String?,
    val hasPassword: Boolean,
)

/** A secure note being added or edited, as typed. Not a data class: no toString of the text. */
class NoteInput(
    val name: String,
    /** The note itself. */
    val text: String,
    val favorite: Boolean,
)

/** The fields of a card being added or edited, as typed. Not a data class: no toString of the number. */
class CardInput(
    val name: String,
    val cardholder: String,
    val number: String,
    /** The month, or a whole expiry ("07/31") when [expYear] is blank. */
    val expMonth: String,
    val expYear: String,
    val securityCode: String,
    val postalCode: String,
    val notes: String,
    val favorite: Boolean,
)

/** A secret field of an item, read only on an explicit reveal or copy. */
enum class SecretField { PASSWORD, NOTES, TOTP_SECRET, CARD_NUMBER, CARD_CODE }

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
    /** Where and how it was captured, in a sentence (which extension, and whether the system named an address or only a domain). */
    val detail: String,
)

/** A captured login the app saved by itself at unlock. No secret. */
data class AppliedSaveView(
    val id: String,
    val host: String,
    val username: String,
    /** The login's name when its password was replaced (the old one is in the login's password history); null for a new login. */
    val replaced: String?,
    val plainHttp: Boolean,
    /** When it was saved (unix milliseconds). The list survives a lock until it is dismissed. */
    val appliedAtMs: Long,
    /** The name of the vault the login is in now; null when the vault does not hold it (the row then says so). */
    val vault: String?,
)
