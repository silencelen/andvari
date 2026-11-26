package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.trust.MemberRole

/**
 * One shared vault, with what this device believes about its signed history (§3). Everything here comes from the
 * log this device verified, never from what the server reports about the vault.
 *
 * **There is no list of lifecycle notices to dismiss.** What happened to a vault (deleted and in its grace, deleted
 * for good, this account removed or gone from it, a history that no longer checks out) is the state of its row
 * ([log], [purgeAtMs], [heldUntilMs], [removedByOwner]), and the row stays listed for as long as this device keeps
 * its copy: 30 days in the holding area, or until [SharedVaultsApi.removeFromThisDevice].
 */
class SharedVaultRow internal constructor(
    val vaultId: String,
    /**
     * The vault's name, plain text; null when nothing may be decrypted ([VaultLogState.CONNECT_FIRST],
     * [VaultLogState.CONFIRM_FIRST], a key that was refused or could not be opened): the name is sealed under the
     * vault's key, so a row without the key has none to show, only [owner] where this device knows them.
     */
    val name: String?,
    /** This account's role in the verified log; null when it is not a member there. */
    val role: RoleInVault?,
    val log: VaultLogState,
    /**
     * The vault's owner in the log this device verified: their label where the log's key for them equals a pinned
     * contact's key that is current here, [PersonName.You] for this account, otherwise only what the server calls
     * them. Null when no log verified ([VaultLogState.NOT_CHECKED_YET], [VaultLogState.CONNECT_FIRST],
     * [VaultLogState.CONFIRM_FIRST]). It is what a [VaultLogState.KEY_MISSING] row has in place of a name.
     */
    val owner: PersonName?,
    /** [VaultLogState.CONNECT_FIRST] and [VaultLogState.CONFIRM_FIRST]: who wants to share it, as the server reports them. Null otherwise. */
    val sharedBy: PersonName.Unverified?,
    /**
     * [VaultLogState.CONFIRM_FIRST]: the sender as a contact of this account that is not current on this device.
     * [ContactsApi.confirmOnThisDevice] with it is the way on. Null in every other state.
     */
    val senderToConfirm: ContactRow?,
    /** An item mentions history the server has not shown (§3.9, FS-R4): note [CopyKey.VAULT_HISTORY_HINT] in the vault's details. The state does not change. */
    val historyHint: Boolean,
    /** A save into this vault was refused for space (§7.4): show [CopyKey.OWNER_OUT_OF_SPACE]. */
    val ownerOutOfSpace: Boolean,
    /**
     * The owner deleted the vault ([deleted]) and the server served the day its grace ends for this very deletion: unix
     * milliseconds, the day a screen may name. 0 when the vault is not deleted, AND when it is deleted but the server
     * served no day: this device never hands a screen a day of its own estimate (a server may keep a deleted vault for a
     * shorter time than a device assumes; the operator sets it). Whether the vault is deleted is [deleted], never this.
     */
    val purgeAtMs: Long,
    /** [VaultLogState.PURGED] and [VaultLogState.REMOVED]: until when this device keeps its copy in the holding area (30 days), unix milliseconds; 0 otherwise. */
    val heldUntilMs: Long,
    /** [VaultLogState.REMOVED]: the owner's signed `remove` was verified. False: this account left, or the removal could not be verified and is shown as such (§3.12). */
    val removedByOwner: Boolean,
    /** An ownership offer that is pending in the verified log; null when none. */
    val offer: OwnershipOfferRow?,
    /**
     * A change this device signed for the vault is sent and not yet acknowledged
     * ([VaultActionResult.SENT_PENDING], §3.7): it is kept and sent again byte for byte until the server confirms
     * it. Mark the row until then; nothing has to be done again.
     *
     * GAP (§3.7): the design gives no wording for an entry that waits.
     */
    val changeWaiting: Boolean,
    /** Items may be saved, edited, moved in or restored here, and log entries signed (the engine's `writeAllowed`). */
    val writable: Boolean,
    /** Items may be copied out ([SharedVaultsApi.saveItemsElsewhere]): any state that holds a key the log commits to (T2-R-k). */
    val canSaveElsewhere: Boolean,
    /** "Remove from this device" is offered: a frozen, failed or withheld vault, and a held copy. */
    val canRemoveFromDevice: Boolean,
    /**
     * A "Move everything" out of this vault is not finished (design §3.13): the line for the vault's own panel. It is
     * [CopyKey.MOVE_DELETE_WAITING] while the vault's deletion is signed and waiting for the server (it cannot be taken
     * back, and the move must be finished; never "kept", never "deleted"), and [CopyKey.MOVE_UNFINISHED] for a move
     * that stopped before that. [SharedVaultsApi.openMoveEverything] on this row finishes it. Null when no move of this
     * vault is unfinished on this device. Additive.
     */
    val unfinishedMove: CopyLine? = null,
    /**
     * "Move everything to a new vault" is offered on this vault ([SharedVaultsApi.openMoveEverything] would open it): this
     * account owns it in the verified log, its history is verified, frozen or failed, it is not deleted (unless a move of
     * it is being finished), and its items can be copied out. The apps show the offer from this field and no longer
     * infer it. Additive.
     */
    val canMoveEverything: Boolean = false,
    /**
     * Why this vault takes no new item and no change on this device although its history is verified and this account
     * may write: [CopyKey.MOVE_WAITING_READ_ONLY] while its deletion by "Move everything" is signed and waiting ({0} this
     * vault's name, {1} the new vault's). [writable] is false meanwhile, and the item engine treats the vault as read-only
     * (no save, edit, delete, restore, import or move into or out of it; copying out still works). The one line goes
     * above the vault's items and on its panel. Null otherwise. Additive.
     */
    val readOnlyLine: CopyLine? = null,
    /**
     * The owner deleted the vault in the verified log (its signed `delete` stands) and its grace is running on this
     * device's reading. This, not [purgeAtMs], says that a vault is deleted: the restore is offered from it, rename,
     * delete and "Move everything" are not. Where the server served the grace's end, [purgeAtMs] carries that day;
     * where it served none, [deletedNoDayLine] is the line instead. Additive.
     */
    val deleted: Boolean = false,
    /**
     * The change this device signed for the vault and keeps to send again (§3.7), as a screen draws it: kind, member,
     * since when, what is known of it, whether it is being sent, may be withdrawn, or is a deletion asked about. Settled
     * against what this device has read of the vault's log before it is drawn. Null when none waits, and for a move's own
     * steps ([unfinishedMove] says those). Additive; [changeWaiting] stays as it was.
     */
    val waiting: WaitingChange? = null,
    /**
     * A "Move everything" out of this vault that stopped because the vault froze after the move's own deletion was sent:
     * [CopyKey.MOVE_FROZEN_CLOSE], what closing it does, with "Close this move" calling
     * [WaitingChanges.closeFrozenMove]. Null otherwise. Additive.
     */
    val frozenMoveClose: CopyLine? = null,
) {
    /**
     * [CopyKey.VAULT_DELETED_NO_DAY] for a [deleted] vault whose grace end the server did not serve ([purgeAtMs] 0): the
     * vault can be restored for a limited time, and no day is named. Null otherwise (a screen names the day of
     * [purgeAtMs] where it is served, and says nothing of a grace on a vault that is not deleted).
     */
    val deletedNoDayLine: CopyLine?
        get() = if (deleted && purgeAtMs == 0L) CopyLine.of(CopyKey.VAULT_DELETED_NO_DAY) else null

    /**
     * Under [CopyKey.OWNER_OUT_OF_SPACE] while [ownerOutOfSpace]: approved entry 27 ([CopyKey.OWNER_OUT_OF_SPACE_YOURS])
     * when this account owns the vault in the verified log, entry 28 ([CopyKey.OWNER_OUT_OF_SPACE_THEIRS]) when someone
     * else does. Null otherwise. Derived from [role], which said it already.
     */
    val outOfSpaceLine: CopyLine?
        get() = when {
            !ownerOutOfSpace -> null
            role == RoleInVault.OWNER -> CopyLine.of(CopyKey.OWNER_OUT_OF_SPACE_YOURS)
            else -> CopyLine.of(CopyKey.OWNER_OUT_OF_SPACE_THEIRS)
        }

    /** [CopyKey.INCOMING_CONNECT_FIRST] for a [VaultLogState.CONNECT_FIRST] row; null for any other. */
    val connectFirstLine: CopyLine?
        get() = if (log == VaultLogState.CONNECT_FIRST) CopyLine.of(CopyKey.INCOMING_CONNECT_FIRST, sharedBy?.serverName.orEmpty()) else null
}

/**
 * What this device believes about a shared vault's history (§3.8, §3.9), and whether it may use the vault at all
 * (§3.6). One to one with the engine's `VaultLogStatus`, plus the two outcomes of its `Adoption` that close a vault.
 */
enum class VaultLogState(val sentence: CopyKey?) {
    /** `VaultLogStatus.Unknown`: not fetched on this device yet. */
    NOT_CHECKED_YET(null),

    /** `Verified`: the log verified, and this device uses the vault's key. */
    VERIFIED(null),

    /** `Failed`: an entry did not verify. What was decrypted stays readable; nothing is written until the log verifies again. */
    FAILED(CopyKey.VAULT_HISTORY_FAILED),

    /** `Withheld`: the server serves less than this device verified, or the vault vanished without a verified deletion. Read-only. */
    WITHHELD(CopyKey.VAULT_HISTORY_WITHHELD),

    /**
     * `Frozen`: two validly signed entries at one position (a fork). Read-only.
     *
     * GAP (§3.9): the design says the device "shows the anomaly" and gives no sentence for it.
     */
    FROZEN(null),

    /**
     * `Purged`: "deleted for good". Said only once the log verified through the tombstone's head and ends in the
     * owner's signed `delete`. This device's copy moves to the holding area; it is never dropped on the server's word.
     */
    PURGED(CopyKey.VAULT_DELETED_FOR_GOOD),

    /** `Removed`: this account is no longer a member in the verified log. Its copy is in the holding area. */
    REMOVED(null),

    /**
     * `Adoption.ConnectFirst`, when this account has no connection with the sender at all: they are a stranger to
     * it. The vault's name is not shown and nothing is decrypted: [SharedVaultRow.connectFirstLine]. The way on is a
     * connect link between the two people.
     */
    CONNECT_FIRST(null),

    /**
     * `Adoption.ConnectFirst`, when the sender **is** a contact of this account and only is not current on this
     * device (made on another device, left unticked, or put off): nothing is decrypted either, but no link is
     * needed. [SharedVaultRow.senderToConfirm] names the contact, and [ContactsApi.confirmOnThisDevice] opens the way.
     *
     * GAP (§3.6, §6.9): the design has one sentence, "Connect with them first", which is wrong for this case.
     */
    CONFIRM_FIRST(null),

    /** `Adoption.Refused` for the key's commitment (§3.4): nothing is decrypted or written under that key. */
    KEY_REFUSED(CopyKey.VAULT_KEY_REFUSED),

    /**
     * `Adoption.Refused` because no key could be opened (a withheld or unreadable wrap). The log verified, so the
     * row has an [SharedVaultRow.owner]; it has no name, which only the key would open.
     *
     * GAP: the design gives no sentence for it.
     */
    KEY_MISSING(null),
}

/** A role in a vault's verified log. */
enum class RoleInVault { OWNER, WRITER, READER }

/*
 * The roles an owner gives are the trust layer's [MemberRole] (§2.2 `role`: writer or reader, never owner), used as it is:
 * ownership moves only by an offer the other person accepts.
 */

/** `S.pending` (§3.3): an offer to hand the vault over. */
class OwnershipOfferRow internal constructor(
    val to: PersonName,
    /** This account is the one it is offered to: it may accept, or decline with [SharedVaultsApi.cancelOffer]. */
    val toMe: Boolean,
    /** The offer's end as the signed log entry names it (`expiresAt`): the day to show. */
    val expiresAtMs: Long,
)

/** An ownership offer's life, the one value every app and the engine use (§3.3: at most 14 days). */
object OwnershipOffer {
    /** The days an offer lasts; the approved dialog says "They have 14 days". */
    const val DAYS: Int = 14

    /** [DAYS] in milliseconds: an offer made at `at` ends at `at + LIFE_MS`. */
    const val LIFE_MS: Long = DAYS * 24L * 60 * 60 * 1000
}

/**
 * One vault's members (§3.9): the audience **as far as this device verified the log**. A later `add` the server
 * withheld is not in it (R20).
 */
class MembersScreen internal constructor(
    val vault: SharedVaultRow,
    val members: List<MemberRow>,
    /** An item's hint is unresolved: mark the list [CopyKey.MEMBERS_MAY_BE_INCOMPLETE] (FC-10). */
    val mayBeIncomplete: Boolean,
    /** This account is the owner in the verified log and the vault is writable: it may add, change roles, remove and offer. */
    val canManage: Boolean,
)

class MemberRow internal constructor(
    val vaultId: String,
    val userId: String,
    /** Their label where the log's member key equals a pinned contact's key; otherwise only the server's name for them (T-R5). */
    val who: PersonName,
    val role: RoleInVault,
    /**
     * The member is in the verified log but holds no grant: the operator deleted their account (§3.11). The owner's
     * app offers [CopyKey.REMOVE_FROM_THE_LIST], which is [SharedVaultsApi.removeMember].
     *
     * THE SERVER'S WORD ONLY: true when the server's member list, read against the verified head on show, leaves this
     * member out (`NO_GRANT_AS_SERVER_SAYS`); an unread or unreadable list is false. A server can make it true for any
     * member, so it is a line on the screen and nothing more: every intent treats the person as the verified log says.
     */
    val deletedByOperator: Boolean,
) {
    /** [CopyKey.MEMBER_DELETED_BY_OPERATOR] when [deletedByOperator]; null otherwise. */
    val deletedLine: CopyLine?
        get() = if (!deletedByOperator) null else CopyLine.of(
            CopyKey.MEMBER_DELETED_BY_OPERATOR,
            when (who) {
                is PersonName.Contact -> who.label
                is PersonName.Unverified -> who.serverName.orEmpty()
                is PersonName.You -> ""
            },
        )
}

/**
 * The warning a vault is shared with an uncompared contact behind (§6.7 step 8, T-B2): show
 * [CopyKey.UNCOMPARED_WARNING]. It exists only after the person asked for exactly this share, and it is the only
 * thing [SharedVaultsApi.confirmUncomparedShare] takes, so one confirmation releases one vault to one person.
 */
class UncomparedShareWarning internal constructor(
    val vaultId: String,
    val vaultName: String,
    val userId: String,
    /** The contact's label. */
    val label: String,
    val role: MemberRole,
)

/**
 * "Move everything to a new vault" (§3.13): the rotation until vault keys can rotate. The owner's only, offered on a
 * vault that is verified, frozen or failed and whose key this device holds (never on a withheld or deleted one). In
 * the design's order: the member the remove dialog was opened for is removed on the old log first ([removing]); a new
 * vault with the name the person types; every live item copied into it (fresh ids and file keys; the originals stay);
 * the remaining members added again with the role they hold now; and the old vault deleted into its grace, only when
 * everything before succeeded and nothing is left behind ([oldVaultKept] says beforehand when it will be kept). Nothing
 * is ever in neither vault.
 */
class MoveEverythingScreen internal constructor(
    val vault: SharedVaultRow,
    /**
     * The old vault is frozen or failed: it stays where it is and nothing is signed on its log, because this device
     * cannot tell which branch is real (T2-R-k). Show [CopyKey.CHECK_WHAT_YOU_COPY].
     */
    val sourceStays: Boolean,
    /**
     * Who would be added to the new vault. On a vault in good standing every one of them is added again, and [MoveMemberRow.ticked]
     * says who will be. On a frozen or failed vault ([ticksOffered]) **none is ticked** (FS-R3): the last verified
     * state may predate a removal this device never saw. The member in [removing] is not among them.
     */
    val members: List<MoveMemberRow>,
    /**
     * The server refused a copy of this move for space (`quota_exceeded`: the server's refusal, since the
     * account's usage is not served); [stopped] says where it stopped.
     */
    val shortOfSpace: Boolean,
    /** The move is running: [copied] of [total] items so far. */
    val running: Boolean,
    val copied: Int,
    val total: Int,
    /**
     * The member the remove dialog was opened for ([SharedVaultsApi.openMoveEverythingRemoving]): on a vault in good
     * standing their `remove` is signed on the old log first, so a later restore of the old vault cannot bring them
     * back. They are never added to the new vault. Null when the move was opened on its own.
     */
    val removing: MoveMemberRow?,
    /**
     * Tick boxes are shown only on a frozen or failed vault ([sourceStays]). On a vault in good standing there are none:
     * every remaining member is added again (§3.13), and [SharedVaultsApi.tickMember] changes nothing.
     */
    val ticksOffered: Boolean,
    /** Live items of the vault this device cannot read. They cannot be copied, so the old vault is kept. */
    val unreadable: Int,
    /**
     * Said before the person starts: why the old vault will be kept when the move is done, or null when it will be
     * deleted into its grace at the end.
     */
    val oldVaultKept: MoveKept?,
    /** Said before the person starts: only the items in the vault now move; its trash and earlier versions stay with the old vault. */
    val whatMoves: CopyKey,
    /** The last run stopped part-way: where. Moving again carries on from there, into the same new vault. */
    val stopped: MoveStop?,
    /**
     * The run finished and the old vault was kept: what came of it, and why. (When the old vault is deleted the screen
     * closes at once.) [SharedVaultsApi.closeMoveEverything] closes it.
     */
    val finished: MoveFinished?,
    /**
     * Said before the person starts, when a stopped run's half-made new vault holds someone this plan does not add:
     * moving again starts a fresh vault with a fresh key, and the half-made one (which holds only
     * copies) is deleted once the fresh move has finished. Null otherwise. Additive.
     */
    val startsFresh: CopyKey? = null,
    /**
     * The check for space the last run made before it signed or sent anything (design §3.13, spec 03 §14.4), when it
     * found the account short: [io.silencelen.andvari.core.app.content.SpaceVerdict.NOT_ENOUGH] stopped the run before
     * anything was signed or sent ([stopped] with [VaultActionResult.OUT_OF_SPACE]);
     * [io.silencelen.andvari.core.app.content.SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES] let it go on (the shortage
     * rests only on file sizes a member's items state, and the server decides). Show its
     * [io.silencelen.andvari.core.app.content.SpaceCheck.line]: which limit and by how much
     * ([io.silencelen.andvari.core.app.content.SpaceCheck.limits]). Null when there was room, the server gave no use and
     * limits (the move starts and the server decides), or no run was made. Additive.
     */
    val space: io.silencelen.andvari.core.app.content.SpaceCheck? = null,
)

class MoveMemberRow internal constructor(
    val userId: String,
    val who: PersonName,
    val role: MemberRole,
    val ticked: Boolean,
    /**
     * They can be added from this device: a contact current here. Anyone else is named before the person starts
     * ([MoveEverythingScreen.oldVaultKept] is [MoveKept.MEMBER_CANNOT_BE_ADDED]) and must be connected with first.
     */
    val canBeAdded: Boolean,
)

/** Why "Move everything" keeps the old vault. */
enum class MoveKept {
    /** The old vault is frozen or failed: it stays, untouched (T2-R-k). */
    SOURCE_STAYS,

    /** A remaining member cannot be added from this device ([MoveMemberRow.canBeAdded] false): they would lose the vault. */
    MEMBER_CANNOT_BE_ADDED,

    /** Some of its items cannot be read here ([MoveEverythingScreen.unreadable]), so they were not copied. */
    UNREADABLE_ITEMS,
}

/** The steps of "Move everything", in the design's order (§3.13). */
enum class MoveStage { REMOVE_MEMBER, CREATE_VAULT, TRANSFER_ITEMS, ADD_MEMBERS, DELETE_OLD_VAULT }

/**
 * A move that stopped at [stage]: every step before it completed. Every item is still in the old vault, which nothing
 * before the last step changes; [copied] of [total] are also in the new vault [toVaultName]. [result] is what the step
 * came to (for a refusal for space, [VaultActionResult.OUT_OF_SPACE]). [line] says so: {0} the new vault's name, {1}
 * the old vault's name, {2} [copied], {3} [total].
 */
class MoveStop internal constructor(
    val stage: MoveStage,
    val toVaultName: String,
    val copied: Int,
    val total: Int,
    val result: VaultActionResult,
    val line: CopyKey,
)

/**
 * A move that finished with the old vault kept ([oldKept]): [copied] items are in the new vault [toVaultName], and
 * [notAdded] are the remaining members it was not shared with. [line] says why the old vault was kept.
 */
class MoveFinished internal constructor(
    val toVaultName: String,
    val copied: Int,
    val oldKept: MoveKept,
    val notAdded: List<PersonName>,
    val line: CopyKey,
)

/**
 * Shared vaults: the ten log actions (§3.1), incoming vaults, and the ways out of a vault whose history does not
 * check out. The engine builds, signs and checks each entry; an intent never takes a key, a position or a signer.
 */
interface SharedVaultsApi {
    /** `genesis`: create a shared vault this account owns. */
    suspend fun createVault(name: String): VaultActionResult

    /**
     * Rename a shared vault. Only its owner can, and only while it is writable: a deleted, frozen, failed or
     * withheld vault takes no rename ([VaultActionResult.READ_ONLY]). The name is sealed under the vault's key; the
     * server never reads it.
     */
    suspend fun renameVault(vault: SharedVaultRow, name: String): VaultActionResult

    suspend fun openMembers(vault: SharedVaultRow): VaultActionResult

    fun closeMembers()

    /**
     * `add`: share the vault with a contact. The contact must be current on this device. With an uncompared contact
     * this shares nothing: it answers [VaultActionResult.NEEDS_UNCOMPARED_WARNING] and raises
     * [AccountSnapshot.shareWarning].
     */
    suspend fun addMember(screen: MembersScreen, contact: ContactRow, role: MemberRole): VaultActionResult

    /** Share the one vault the warning names with the one contact it names, although their codes were never compared. */
    suspend fun confirmUncomparedShare(warning: UncomparedShareWarning): VaultActionResult

    fun cancelUncomparedShare(warning: UncomparedShareWarning)

    /** `role`. */
    suspend fun changeRole(member: MemberRow, role: MemberRole): VaultActionResult

    /**
     * `remove`, and "Remove from the list" for a member whose account the operator deleted. The dialog shows
     * [CopyKey.REMOVE_MEMBER_WARNING] and offers [CopyKey.MOVE_EVERYTHING]: removal does not change the vault's key (T-R6).
     */
    suspend fun removeMember(member: MemberRow): VaultActionResult

    /** `leave`. The one entry that is allowed on a deleted, frozen or failed vault. */
    suspend fun leaveVault(vault: SharedVaultRow): VaultActionResult

    /**
     * `offer`: offer ownership to a member, for [OwnershipOffer.DAYS] days (the approved "They have 14 days"; §3.3 bounds
     * an offer at 14 days). On DONE the vault's row carries the offer, and [OwnershipOfferRow.expiresAtMs] is the end
     * to show (the `{2}` of `OWNERSHIP_OFFER`'s second line): no screen adds the days itself.
     */
    suspend fun offerOwnership(member: MemberRow): VaultActionResult

    /** `cancel`: the owner withdraws the offer, or the person it was made to declines it. */
    suspend fun cancelOffer(vault: SharedVaultRow): VaultActionResult

    /** `accept`: take the ownership offered to this account. */
    suspend fun acceptOwnership(vault: SharedVaultRow): VaultActionResult

    /** `delete`: the vault enters its grace; members stay in the log and keep read access to it (B3). */
    suspend fun deleteVault(vault: SharedVaultRow): VaultActionResult

    /** `restore`, during the grace. */
    suspend fun restoreVault(vault: SharedVaultRow): VaultActionResult

    /**
     * `restore` from the owner's "Recently deleted" list ([io.silencelen.andvari.core.app.content.ContentState.deletedVaults]),
     * [vault] being one of its entries on show: STALE otherwise. The vault comes back for everyone; the content syncs and
     * the list is read again.
     */
    suspend fun restoreDeletedVault(vault: DeletedVaultView): VaultActionResult

    /** Accept an incoming vault: recorded once for the account, for the `add` the prompt names. */
    suspend fun acceptIncoming(prompt: AccountPrompt.IncomingVault): VaultActionResult

    /**
     * Decline: the vault is hidden on every device of the account, and a `leave` is signed so the owner sees it. A
     * decline is final for that `add` (§5.4): no later accept answers the same one, and only a new `add` by the
     * owner asks again.
     */
    suspend fun declineIncoming(prompt: AccountPrompt.IncomingVault): VaultActionResult

    /**
     * Copy every item of [vault] into [toVaultId] (null: the personal vault). It writes only under the destination's
     * key, so it works from a frozen, failed or withheld vault and from the holding area. For those, show
     * [CopyKey.CHECK_WHAT_YOU_COPY] first.
     */
    suspend fun saveItemsElsewhere(vault: SharedVaultRow, toVaultId: String?): VaultActionResult

    /** "Remove from this device": drop this device's copy. A local act that tells the server nothing. */
    fun removeFromThisDevice(vault: SharedVaultRow)

    /** "Move everything to a new vault" on its own, from the vault's settings. The owner's only ([VaultActionResult.NOT_OWNER]). */
    suspend fun openMoveEverything(vault: SharedVaultRow): VaultActionResult

    /**
     * "Move everything to a new vault" from the remove dialog of [member] (§3.13): the move removes them on the old log
     * first ([MoveEverythingScreen.removing]) and never adds them to the new vault.
     */
    suspend fun openMoveEverythingRemoving(member: MemberRow): VaultActionResult

    /** Close the move's screen; not while it runs. A move that stopped can be opened again and carries on. */
    fun closeMoveEverything()

    /**
     * "Not now" on the first screen's offer to finish [move] ([AccountSnapshot.unfinishedMoves]): it is not offered there
     * again until the next unlock. The move itself stays unfinished, and the vault's row still says so. New (only core
     * implements this interface).
     */
    fun unfinishedMoveLater(move: UnfinishedVaultMove)

    /**
     * Copy into the new vault, from the copy this device holds of the old vault, every item [notice] counts as added or
     * changed after the move's copies ([AccountSnapshot.movesStoredOutside]). A changed item replaces its earlier copy,
     * never stands beside it; a second call copies nothing again. DONE, then [MoveStoredNotice.copiedLine] says how many;
     * an item with files is left out here and still counted on the notice. New (only core implements this interface).
     */
    suspend fun bringLateIntoMove(notice: MoveStoredNotice): VaultActionResult

    /** Dismiss [notice]. The held copy stays in the holding area for its days, as any held vault. New. */
    fun dismissMoveStored(notice: MoveStoredNotice)

    /** Tick or untick a member of the new vault: only where [MoveEverythingScreen.ticksOffered]. */
    fun tickMember(screen: MoveEverythingScreen, member: MoveMemberRow, ticked: Boolean)

    /**
     * Run the move into a new vault called [name] (after a stop, the new vault keeps the name it was made with). DONE:
     * it finished; the screen closes when the old vault was deleted, and stays with [MoveEverythingScreen.finished] when
     * it was kept. Any other answer stopped it, and [MoveEverythingScreen.stopped] says where.
     */
    suspend fun moveEverything(screen: MoveEverythingScreen, name: String): VaultActionResult
}

/** What a vault action came to (the engine's `AppendOutcome`, with the server's refusals named). */
enum class VaultActionResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /**
     * Signed, and no answer yet (`AppendOutcome.Pending`): the entry is kept and sent again byte for byte until the
     * server acknowledges it (§3.7). It is never signed a second time. The vault's row says so until then
     * ([SharedVaultRow.changeWaiting]).
     *
     * GAP (§3.7): the design gives no wording for an entry that waits.
     */
    SENT_PENDING,

    /** The contact's codes were never compared: nothing was shared; [AccountSnapshot.shareWarning] is up. */
    NEEDS_UNCOMPARED_WARNING,

    /** Only the vault's owner can do this. */
    NOT_OWNER,

    /** The log's rules do not allow it now (`AppendOutcome.NotAllowed`): nothing was signed. */
    NOT_ALLOWED,

    /** The vault is frozen, failed or withheld: nothing is written to it but a `leave`. */
    READ_ONLY,

    /** The vault's history moved on while this was signed, and the entry was not stored: ask again. */
    CHANGED_MEANWHILE,
    CLOCK_AHEAD(sentence = CopyKey.CLOCK_AHEAD),

    /** `409 offer_expired`. */
    OFFER_EXPIRED,

    /** `409 not_connected`: the server knows no link between the two accounts. */
    NOT_CONNECTED,

    /** The contact is not current on this device, or not a contact at all. */
    NOT_A_CONTACT_HERE,

    /** `409 member_limit`: they are in 500 shared vaults already. */
    MEMBER_LIMIT,

    /** `413 quota_exceeded`: the owner's storage or shared-vault quota. */
    OUT_OF_SPACE(sentence = CopyKey.OWNER_OUT_OF_SPACE),

    /**
     * The vault's deletion by "Move everything" is signed and waiting for the server: nothing else is signed or sent on
     * that vault's log from this device until the move is finished (finish it from the vault's row or the first screen).
     * Nothing was changed; a share attached to a link stays waiting.
     */
    MOVE_DELETE_WAITING(sentence = CopyKey.MOVE_WAITING_REFUSED),

    /**
     * Another change this device signed for the vault still waits ([SharedVaultRow.waiting]): this one was neither signed
     * nor sent. Nothing new is signed for a vault while a change of it waits; once that change is settled or withdrawn,
     * the person can make this one again.
     */
    OTHER_CHANGE_WAITS(sentence = CopyKey.WAITING_OTHER_CHANGE_FIRST),

    /**
     * This device's copy is being removed for the server's policy (the one try to send what waits, then the wipe):
     * nothing was signed or sent; the same line as a content write refused meanwhile. Additive.
     */
    REMOVING_COPY(sentence = CopyKey.SAVE_COPY_BEING_REMOVED),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}
