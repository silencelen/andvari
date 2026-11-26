package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.trust.MemberRole

/**
 * Links this account makes and opens (§6). A link's secret stays on the device that made it (T-B6): it is never in
 * a snapshot, and the web client has no link code path at all (§13).
 */
class LinksScreen internal constructor(
    /** The links this device made that are still open. One dropped at its expiry or revoked is gone (T-R3). */
    val links: List<OwnLinkRow>,
    /**
     * Links this device made that were answered while this session was open, newest first, each with the contact
     * the answer made. It is what ties a link on show to its contact: in person (§6.7), the screen that shows a
     * link's QR watches for its [OwnLinkRow.linkId] here and goes on to [ContactsApi.openCompare] with that
     * contact, so the codes are compared at once. A row leaves once its contact is compared.
     */
    val answered: List<AnsweredLinkRow>,
    /** Vaults attached to a link that was answered, waiting for the codes ([CopyKey.SHARE_ONCE_COMPARED]). */
    val waitingShares: List<PendingShareRow>,
    /**
     * This account may make register links here (§6.6: any member of a private instance that allows it, otherwise
     * the operator). Then offer [CopyKey.SEND_INVITATION_INSTEAD].
     */
    val invitationsAllowed: Boolean,
)

/** A link this device made and still holds the record of (the engine's `CreatedLink`). */
class OwnLinkRow internal constructor(
    val linkId: String,
    val kind: OwnLinkKind,
    /** The vaults attached to it. */
    val shares: List<ShareChoice>,
)

/**
 * A link this device made, answered: the engine processed the answer, pinned whoever answered as a contact,
 * uncompared, and posted the reveal (the engine's `CreatorStep.Processed`, or its `KeyChanged` when the answerer was
 * a contact already, under another key).
 */
class AnsweredLinkRow internal constructor(
    /** The [OwnLinkRow.linkId] of the link that was answered. */
    val linkId: String,
    /** Who answered, as a contact of this account: hand it to [ContactsApi.openCompare]. */
    val contact: ContactRow,
    /** They were a contact already, and answered under another key: only a matched comparison accepts it (§6.8 step 6). */
    val keyChanged: Boolean,
)

enum class OwnLinkKind {
    /** A connect link: two people pin each other. */
    CONNECT,

    /** A register link: an invitation to make an account here, which also pins the two accounts to each other. */
    INVITATION,
}

/**
 * A vault to share with whoever answers a connect link, and as what (§6.10; the engine's `LinkShare`). Choosing it is
 * the person confirming that vault for that person; it is still shared only after the codes matched, or by a release
 * behind [UncomparedShareWarning] (T-B2). A link with shares is therefore never a bearer token for those vaults.
 */
class ShareChoice(val vaultId: String, val role: MemberRole)

/** A vault attached to an answered link, not yet shared. */
class PendingShareRow internal constructor(
    val vaultId: String,
    val vaultName: String,
    val role: MemberRole,
    val userId: String,
    /** The contact's label. */
    val label: String,
) {
    val line: CopyLine get() = CopyLine.of(CopyKey.SHARE_ONCE_COMPARED, vaultName, label)
}

/** How long the apps let a link live (§6.6, §6.7; the server's own bounds are a little wider, SR-1). */
object LinkLifetimes {
    const val SHORTEST_MINUTES: Int = 5

    /** A connect link shown in person. */
    const val IN_PERSON_MINUTES: Int = 15
    const val CONNECT_LONGEST_MINUTES: Int = 7 * 24 * 60
    const val INVITATION_LONGEST_MINUTES: Int = 72 * 60
}

/**
 * An invite opened while signed in, after every check of §6.8 (the engine's `RecipientStep`). Nothing has been sent
 * yet.
 */
sealed class OpenedInvite {
    /** "Connect with … (as they call themselves)?" (`RecipientStep.Confirm`). Only [LinksApi.connect] sends the answer. */
    class Connect internal constructor(
        val instance: InstanceLabel,
        /** The creator's name as they chose it. */
        val from: String,
    ) : OpenedInvite() {
        val question: CopyLine get() = CopyLine.of(CopyKey.CONNECT_QUESTION, from)
    }

    /**
     * The link's creator is a contact, under another key than the pinned one (`RecipientStep.KeyChanged`). Nothing
     * is replaced; the person may go on to connect, and only a matched comparison accepts the new key.
     */
    class KeyChanged internal constructor(
        /** The contact's label as pinned. */
        val label: String,
    ) : OpenedInvite() {
        val line: CopyLine get() = CopyLine.of(CopyKey.CONTACT_KEY_CHANGED, label)
    }

    /**
     * The dead end of §6.7: the invite is for another instance than the one this app is signed in to
     * (`RecipientStep.OtherInstance`). Switching signs out here; this instance's data stays in its own namespace.
     * [inviteInstance] is a pinned card's word: the link's own offer anchored it, this device pinned that server
     * before, or the person passed [TrustGate] for it.
     */
    class OtherInstance internal constructor(
        val inviteInstance: InstanceLabel,
        val signedInTo: InstanceLabel,
        /**
         * "New devices must be linked" for the signed-in account, as this device knows it: true or false when this
         * device set it during this session, null when it cannot tell (the server serves no read of it). Additive.
         */
        val linkRequired: Boolean? = null,
    ) : OpenedInvite() {
        val line: CopyLine get() = CopyLine.of(CopyKey.OTHER_INSTANCE, inviteInstance.name, inviteInstance.origin, signedInTo.name)
        val switchLabel: CopyLine get() = CopyLine.of(CopyKey.OTHER_INSTANCE_SWITCH, inviteInstance.name)

        /**
         * Said beside [switchLabel]: [LinksApi.switchInstance] signs out of [signedInTo] on this device, as "Sign out"
         * does (this device's copy goes; the account and its vaults stay on that server, and its pin stays). When the
         * account has "New devices must be linked" on, or this device cannot tell ([linkRequired]), it also says that
         * signing in again here will not bring the account back by itself. Additive.
         */
        val signOutLine: CopyLine
            get() = CopyLine.of(
                when (linkRequired) {
                    false -> CopyKey.OTHER_INSTANCE_SIGNS_OUT
                    true -> CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_REQUIRED
                    null -> CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_UNKNOWN
                },
                signedInTo.name, signedInTo.origin,
            )
    }

    /**
     * An enrol link for a server this device holds no pin for, opened while signed in elsewhere
     * (`RecipientStep.TrustGate`). An enrol link is minted by its host, so nothing vouches for the server it names:
     * there is no [InstanceLabel] for it, and the Trust Gate comes before anything else, in its enrol wording
     * ([gate]). [LinksApi.confirmOpenedGate] pins it and goes on to [OtherInstance]; [LinksApi.dismissOpened]
     * declines, and nothing was sent to that server but the request for its card. (An enrol link to the public
     * instance never gets here: the build vouches for it.)
     */
    class TrustGate internal constructor(val gate: TrustGatePrompt, val signedInTo: InstanceLabel) : OpenedInvite()

    /**
     * The invite is for another server this device holds a pin for, and that server cannot be opened as the pin
     * stands (`RecipientStep.PinChanged`, or a stop for a fork or a damaged record): it moved, changed its `kind`,
     * serves an older chain, or is blocked. [instance] names it as pinned and its card says which, as on
     * [EntryScreen.ServerChanged]; [InstanceApi.followMove], [InstanceApi.acceptKindChange] and
     * [InstanceApi.forgetServer] take that card and that instance, and act on that server, not on the one this app
     * is signed in to. Afterwards the invite is opened again. [LinksApi.openInvite] answered
     * [InviteResult.SERVER_CHANGED] or [InviteResult.IDENTITY_CONFLICT] to get here.
     */
    class ServerChanged internal constructor(val instance: InstanceSnapshot) : OpenedInvite()

    /**
     * [LinksApi.connect] posted the answer: [contact] is who made the link, a contact now, uncompared
     * (`RecipientStep.Answered`). It is what ties the invite to its contact: in person, go straight on to
     * [ContactsApi.openCompare] with it; the codes can be compared once the creator's reveal arrives.
     * [LinksApi.dismissOpened] closes it.
     */
    class Connected internal constructor(val contact: ContactRow) : OpenedInvite()
}

interface LinksApi {
    suspend fun openLinks(): PlainResult

    fun closeLinks()

    /**
     * "Connect with someone": make a connect link that lives [minutes] ([LinkLifetimes]), with the vaults to share
     * once the codes matched. The record is written to this device before anything is sent.
     */
    suspend fun createConnectLink(shares: List<ShareChoice>, minutes: Int): LinkCreateResult

    /** "Send an invitation instead": make a register link, where [LinksScreen.invitationsAllowed]. */
    suspend fun createInvitation(minutes: Int): LinkCreateResult

    /**
     * The link itself, for the QR, the share sheet or Copy. An explicit read, because it carries the link's secret.
     * Null once the link is answered, revoked or expired, and on any device but the one that made it.
     */
    fun linkToShare(link: OwnLinkRow): String?

    /**
     * How long [link] still lives, in milliseconds, counted down from what the server answered at its creation on a
     * clock the person cannot set, never from the device's own time against an expiry (SR-1). 0 once it is gone.
     */
    fun linkTimeLeftMs(link: OwnLinkRow): Long

    /** Revoke an open link. An answer that arrives later is ignored, whatever the server says. */
    suspend fun revokeLink(link: OwnLinkRow): PlainResult

    /**
     * Share a waiting vault now. With an uncompared contact this shares nothing: it raises
     * [AccountSnapshot.shareWarning], and only [SharedVaultsApi.confirmUncomparedShare] goes on.
     */
    suspend fun releaseShare(share: PendingShareRow): VaultActionResult

    /**
     * An invite scanned or pasted while signed in. **Only an invite is acted on** (a device link and a kit are
     * refused, as on "Scan an invite"). On [InviteResult.DONE], [AccountSnapshot.opened] says what it is.
     */
    suspend fun openInvite(payload: String, source: PayloadSource): InviteResult

    /** Go on to "Connect with …?" although the creator's key differs from the pinned one. */
    fun acknowledgeKeyChange(prompt: OpenedInvite.KeyChanged)

    /**
     * "Connect": post the answer and pin the creator, uncompared. On [ConnectResult.DONE],
     * [AccountSnapshot.opened] is [OpenedInvite.Connected] with the contact that was made. When the server gave no
     * answer ([ConnectResult.UNREACHABLE]) the prompt stays, and calling this again with it is the retry.
     */
    suspend fun connect(prompt: OpenedInvite.Connect): ConnectResult

    /**
     * Confirm the Trust Gate of an enrol link opened while signed in elsewhere: pin the server (an enrol pin, which
     * is not a password pin) and show [OpenedInvite.OtherInstance] for it.
     */
    suspend fun confirmOpenedGate(prompt: OpenedInvite.TrustGate): ServerResult

    /**
     * Close the opened invite: decline its gate, cancel its question, or put its result away. Nothing more is
     * sent; a pin its gate would have made does not exist.
     */
    fun dismissOpened()

    /**
     * Post the answer [prompt] names once more ([AccountPrompt.ConnectionNotMade.canRetry]). On
     * [ConnectResult.DONE] the prompt is gone and the creator is a contact; on [ConnectResult.UNREACHABLE] it stays.
     */
    suspend fun retryConnection(prompt: AccountPrompt.ConnectionNotMade): ConnectResult

    /** Give the connection up: the prompt closes and the link's flow is dropped. Nothing is sent. */
    fun dropConnection(prompt: AccountPrompt.ConnectionNotMade)

    /**
     * "Switch to …": sign out of this instance and continue with the invite on its own. Creating an account there
     * needs nothing more; signing in to one there shows the Trust Gate first (§6.7).
     *
     * The switch is a sign-out, so it deletes this device's copy: when [AppApi.signOutCheck] says the act needs a second
     * confirmation, this answers [ServerResult.UNSENT_NOT_CONFIRMED] before anything is asked of the other server, and
     * the person confirms with [switchInstanceConfirmed].
     */
    suspend fun switchInstance(prompt: OpenedInvite.OtherInstance): ServerResult

    /**
     * [switchInstance] after the person's second confirmation of [check] ([AppApi.signOutCheck], its line shown beside
     * [OpenedInvite.OtherInstance.signOutLine]): [ServerResult.UNSENT_NOT_CONFIRMED] when [check] is no longer what
     * [AppApi.signOutCheck] says. Additive.
     */
    suspend fun switchInstanceConfirmed(prompt: OpenedInvite.OtherInstance, check: SignOutCheck): ServerResult

    /**
     * The name this account signs into its links' offers and answers (§6.3, §6.7: "the creator's display name, as they
     * chose it"), as this device keeps it. The server serves no account its own name, so a device keeps only the name
     * chosen on it: at the registration, or with [setOwnName]. Null when this device keeps none (the account was made on
     * another device) or the vault is not open: then [createConnectLink], [createInvitation] and [connect] answer
     * `NAME_NEEDED` with nothing sent, and the screen asks for the name ([CopyKey.LINK_NAME_NEEDED]). Additive.
     */
    fun ownName(): String?

    /**
     * Keep [name] on this device as the name this account's links carry. It must be a `name` (spec 01 §5.1: 1 to 64
     * bytes, no control or invisible character, no leading or trailing space), else [OwnNameResult.NOT_A_NAME]. Nothing
     * is sent. An opened "Connect with …?" stays open, so "Connect" afterwards goes on with it. Additive.
     */
    fun setOwnName(name: String): OwnNameResult
}

/** [LinksApi.setOwnName]. Additive. */
enum class OwnNameResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /** Empty, longer than 64 bytes, a refused character, or a leading or trailing space: nothing was kept. */
    NOT_A_NAME(sentence = CopyKey.LINK_NAME_NOT_A_NAME),
    STALE(Trouble.STALE),
    ;

    override val done: Boolean get() = this == DONE
}

/** `POST /links` (the engine's `CreateOutcome`). */
enum class LinkCreateResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /** This account may not make register links here, or a vault among the shares is not one it owns. */
    NOT_ALLOWED,

    /** `413 quota_exceeded` for `openLinks` (20 by default). */
    TOO_MANY_OPEN_LINKS,

    /** The account holds 1,000 contacts, the most it can (§5.4). */
    TOO_MANY_CONTACTS,

    /** [LinkLifetimes] does not allow that many minutes. */
    BAD_LIFETIME,

    /** This device keeps no name for this account ([LinksApi.ownName]): nothing was made or sent. Additive. */
    NAME_NEEDED(sentence = CopyKey.LINK_NAME_NEEDED),
    STALE(Trouble.STALE),

    /** No answer. The link may exist; its record is kept and dropped at its expiry. */
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** `POST /links/{id}/answer`. */
enum class ConnectResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** Connected: the creator is a contact now, uncompared. */
    DONE,

    /** Someone answered first (T12): whoever read the link before this device. */
    ALREADY_USED,
    EXPIRED,

    /** The account holds 1,000 contacts, the most it can (§5.4). */
    TOO_MANY_CONTACTS,

    /**
     * This device keeps no name for this account ([LinksApi.ownName]): nothing was sent, and the opened invite (or the
     * connection a sign-in still owes, which can be retried) stays. Ask for the name, [LinksApi.setOwnName], then
     * "Connect" again. Additive.
     */
    NAME_NEEDED(sentence = CopyKey.LINK_NAME_NEEDED),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}
