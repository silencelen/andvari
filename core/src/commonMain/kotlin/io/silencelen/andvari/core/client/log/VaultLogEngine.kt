package io.silencelen.andvari.core.client.log

import io.silencelen.andvari.core.model.wire.LogDeleted
import io.silencelen.andvari.core.trust.Checkpoint

/**
 * The verified state of one shared vault's log (design §3.3 `S`), as this device replayed it. Every
 * field comes from frames this device verified with the trust layer's `VaultLog.verify`; nothing is copied from
 * the server's `logHead`, members list or grant role.
 */
data class VerifiedVaultState(
    val vaultId: String,
    val headSeq: Long,
    /** `hex64` frame hash of the head. */
    val headHash: String,
    val headAt: Long,
    /** `hex64` frame hash of entry 0 (the genesis hash bound into shared-vault wraps, design §2.3). */
    val genesisHash: String,
    val owner: String,
    /** `b64_32` X25519 key of [owner]. */
    val ownerKey: String,
    /** `hex64` vault-key commitment (design §3.4). */
    val vkCommit: String,
    val members: Map<String, LogMember>,
    val pending: PendingOffer?,
    /** The `deleteId` of a standing `delete`, or null. */
    val deletedId: String?,
)

/** A declined share's leave signed again ([VaultLogEngine.leaveAgainForDeclines]): the vault and the leave's outcome. */
data class LeftAgain(val vaultId: String, val outcome: AppendOutcome)

/** One member in the verified state: key and role (`owner`, `writer`, `reader`), and the `seq` of its latest `add`. */
data class LogMember(val userId: String, val key: String, val role: String, val addSeq: Long?)

/** `S.pending` (design §3.3). */
data class PendingOffer(val offerId: String, val to: String, val toKey: String, val expiresAt: Long)

/**
 * What this device believes about a vault's log (design §3.8, §3.9). Writes under the vault's key are
 * allowed only in [Verified] with no unresolved fork; copying items OUT is allowed in every state that
 * holds a committed key (design §3.6, T2-R-k).
 */
sealed class VaultLogStatus {
    abstract val vaultId: String

    /** Never fetched on this device. */
    data class Unknown(override val vaultId: String) : VaultLogStatus()

    /**
     * The log verified through [state]. [itemHintUnresolved] is set while an item mentioned history the
     * server has not shown (design §3.9, FS-R4): the member list is then "may be incomplete".
     */
    data class Verified(override val vaultId: String, val state: VerifiedVaultState, val itemHintUnresolved: Boolean) : VaultLogStatus()

    /**
     * An entry failed verification: [lastGood] stays, writes are refused until the log verifies again
     * ("This shared vault's history doesn't check out"). [verdict] is the shared verifier's code (`bad_signature`, …).
     */
    data class Failed(override val vaultId: String, val lastGood: VerifiedVaultState?, val verdict: String) : VaultLogStatus()

    /**
     * The server served less than this device verified (a head below the verified one, or below the
     * account's vault record or a bundle checkpoint): "The server is showing an older version". Local
     * state is kept; the vault is read-only with copy-out and "Remove from this device".
     */
    data class Withheld(override val vaultId: String, val state: VerifiedVaultState, val servedSeq: Long?) : VaultLogStatus()

    /** Two validly signed entries at one position (or a record/checkpoint contradiction at the same seq): frozen, read-only. */
    data class Frozen(override val vaultId: String, val state: VerifiedVaultState, val seq: Long) : VaultLogStatus()

    /**
     * "Deleted for good": the log verified through the tombstone's `finalHead` and ends in the owner's
     * signed `delete` with no later `restore` (design §3.8, T2-R-h). The local copy moves to the 30-day
     * holding area; it is never dropped on the server's word.
     */
    data class Purged(override val vaultId: String, val state: VerifiedVaultState, val purgedAt: Long) : VaultLogStatus()

    /** This account is no longer in the verified members (a verified `remove` or `leave`). */
    data class Removed(override val vaultId: String, val state: VerifiedVaultState, val byOwner: Boolean) : VaultLogStatus()
}

/** Where a candidate vault key came from (design §3.6 (d)). */
enum class KeySource { OWN_GENESIS_WRAP, OWNER_WRAP, SELF_WRAP, GRANT }

/**
 * Whether this device may start using a shared vault's key (design §3.6). The engine checks (a) the log
 * verifies, (b) this account is a member, (c) the key matches `vkCommit`, (d) the key source's rule, and
 * (e) the account's vault record agrees — in that order; a caller can only read the outcome.
 */
sealed class Adoption {
    abstract val vaultId: String

    /** All five hold: the key is in use. */
    data class Adopted(override val vaultId: String, val source: KeySource) : Adoption()

    /**
     * A grant from a current contact passed (a)–(c): the person must accept, once per account, naming the
     * owner ([ownerLabel] only where the owner's key equals a pinned contact key). The vault name is
     * decrypted only now, as plain text. [addSeq] is the `add` the answer will bind to (FS-R6).
     */
    class AskAccept internal constructor(override val vaultId: String, val owner: String, val ownerLabel: String, val vaultName: String, val addSeq: Long) : Adoption()

    /** The `add`'s actor is not a current contact with that key: "Connect with them first". Nothing decrypted. */
    data class ConnectFirst(override val vaultId: String, val serverName: String?) : Adoption()

    /** The person declined this `add` (an `accepted` record with `decline`): hidden on every device. */
    data class Declined(override val vaultId: String) : Adoption()

    /** Refused: [reason] names the failing condition. */
    data class Refused(override val vaultId: String, val reason: AdoptionRefusal) : Adoption()

    /**
     * The person's answer to a share ([VaultLogEngine.answerIncoming]) was written to the account state without an answer
     * that settles it: whether it is recorded cannot be told (told apart from recorded, [Adopted] or [Declined], and from
     * not recorded, a fresh [AskAccept]). [accepted]: what the person answered. For an acceptance, [adopted]: the key is in
     * use on this device all the same (this device's copy holds the answer). For a decline, the leave was signed as asked
     * and is held or waiting ([VaultLogEngine.heldChange]); once the log holds it the vault is left whatever the record
     * says, and the answer is [Declined]. The next read of the account state tells; the question comes back only where the
     * answer was not recorded.
     */
    data class AnswerNotKnown(override val vaultId: String, val accepted: Boolean, val adopted: Boolean) : Adoption()
}

enum class AdoptionRefusal(val code: String) {
    LOG_NOT_VERIFIED("log_not_verified"),
    NOT_A_MEMBER("not_a_member"),
    KEY_COMMIT_MISMATCH("vk_commit_mismatch"),
    WRAP_UNOPENABLE("wrap_unopenable"),
    GRANT_REFUSED("grant_refused"),
    RECORD_GENESIS_MISMATCH("record_genesis_mismatch"),
    RECORD_AHEAD("record_ahead"),
    RECORD_FORK("record_fork"),
    NO_KEY("no_key"),
}

/**
 * A log entry the person asked for (design §3.1). The engine builds the frame at its verified head with
 * `at = max(own clock, head.at)`, signs it with the account's identity key, and runs §3.3's
 * preconditions itself before anything is sent. A caller never supplies a key, a seq or a signer.
 */
sealed class LogAction {
    /**
     * Create a shared vault: genesis plus the owner wrap and metadata (spec 03 §10.2). [vaultId] is null (the engine
     * picks a random id) except for a restore that must be resumable (spec 07 §3): then it is the lowercase uuid the
     * restore chose and kept. Asked again for that id, a genesis this device still holds pending is re-posted byte for
     * byte, and one this device already verified (created by this account) answers [AppendOutcome.Appended]; a vault
     * by that id created by someone else is refused (`vault_id_taken`), and an id that is not a uuid is `bad_vault_id`.
     */
    data class Create(val vaultName: String, val vaultId: String? = null) : LogAction()

    /**
     * Add a CURRENT contact (design §6.9) with [role] `writer` or `reader`. Requires `compared = true` or an explicit per-vault release (design §6.10).
     * [movesOwn]: an addition "move everything" signs for its own run; held, it is sent again and given up after a day like
     * any addition, but never withdrawn one by one ([HeldChange.movesOwn]).
     */
    data class Add(
        val contactUserId: String, val role: String, val releaseUncompared: Boolean = false, val movesOwn: Boolean = false,
    ) : LogAction()
    data class Role(val member: String, val role: String) : LogAction()
    data class Remove(val member: String) : LogAction()
    data object Leave : LogAction()

    /** Offer ownership to a member; [expiresInMs] at most 14 days. */
    data class Offer(val to: String, val expiresInMs: Long) : LogAction()
    data object Cancel : LogAction()

    /** Accept a pending offer to this account; the engine round-trip-checks the new owner wrap first. */
    data object Accept : LogAction()
    /** The person's deletion of the vault: [DeleteVault] with nothing set. */
    data object Delete : LogAction()

    /**
     * A vault's deletion. [movesOwn]: signed by "move everything" for a vault of its run (the old vault, or a half-made one
     * it made): held, it is on the move's own road, which reads before it re-posts ([VaultLogEngine.repostHeld]); the
     * general re-send never sends it, gives it up or withdraws it. Without it, the person's deletion ([Delete]).
     * [itemsAtMost]: the sync `rev` up to which the caller read the vault's items (its cursor as it stood when the sync whose
     * items it checked was committed), sent unsigned beside the entry, also at every re-post. The server refuses the
     * deletion when any item of the vault moved since: [AppendOutcome.Refused] with
     * [io.silencelen.andvari.core.model.wire.WireErrors.VAULT_ITEMS_MOVED], nothing stored and nothing held; the caller
     * reads again and may sign afresh. An older server ignores it.
     */
    data class DeleteVault(val movesOwn: Boolean = false, val itemsAtMost: Long? = null) : LogAction()
    data object Restore : LogAction()
}

/** What an append came to (spec 03 §10.3, §10.4). */
sealed class AppendOutcome {
    /** Stored (or a byte-identical retry acknowledged). The verified state now includes it. */
    data class Appended(val state: VerifiedVaultState) : AppendOutcome()

    /** §3.3's precondition failed locally; nothing was signed. */
    data class NotAllowed(val reason: String) : AppendOutcome()

    /** The vault is frozen, failed or withheld: only `leave` is allowed (design §3.6). */
    data object VaultReadOnly : AppendOutcome()

    /** The head moved and a refetch showed the frame was not stored: discarded; the caller may ask again. */
    data object HeadMoved : AppendOutcome()

    /** "Your device's clock is ahead" (`400 at_ahead`); the frame is discarded, no server time adopted. */
    data object ClockAhead : AppendOutcome()

    /**
     * Any other refusal (`no_grant`, `not_connected`, `member_limit`, `quota_exceeded`, `offer_expired`, `rate_limited`, …).
     * The frame is dropped, nothing of it stored, except where [held]: the server asked this device to slow down
     * (`rate_limited`) at every send of the frame so far, so it is known NOT stored, and it is KEPT and sent again byte
     * for byte ([VaultLogEngine.retryPending]); until then it can be withdrawn ([VaultLogEngine.withdrawHeld]). A frame
     * that had been sent before without a known outcome is never [Refused] for a later "slow down": that is [Pending].
     */
    data class Refused(val code: String, val retryAfterSeconds: Long? = null, val held: Boolean = false) : AppendOutcome()

    /** No answer: the signed frame stays in the durable pending-append record and is re-posted byte for byte. */
    data object Pending : AppendOutcome()
}

/**
 * What re-posting a vault's held change came to ([VaultLogEngine.repostHeld]). Nothing new is signed for any of these: the
 * held frame is the one signed before, re-posted byte for byte (design §3.7).
 */
sealed class HeldRepost {
    /** This device holds no change for the vault: nothing was sent. */
    data object NothingHeld : HeldRepost()

    /** The held change is stored: the verified log holds it (a re-post the server acknowledged, or one it stored earlier). */
    data class Stored(val state: VerifiedVaultState) : HeldRepost()

    /**
     * Its place was taken: this device verified another entry at its position, so the held frame is dropped by the log's
     * own rule (design §3.7) and will never be stored. The caller reads the log again before it signs anything new.
     */
    data object Dropped : HeldRepost()

    /**
     * Still waiting: no answer, an answer the refetch could not confirm, a stopped origin, or a vault whose records cannot
     * be read. The held frame stays and is re-posted later; nothing is said stored or dropped.
     *
     * Also an addition that was not sent because the contact it names is no longer current here with the key it was
     * signed for: it was let go of (nothing is held any more, and a [FoundKind.CONTACT_CHANGED] finding says so). After
     * [Waiting] the caller reads [VaultLogEngine.heldChange] again: where nothing is held, the finding carries the line.
     */
    data object Waiting : HeldRepost()

    /**
     * Refused for a reason about the entry while its outcome could not be told (an earlier send of it got no answer that
     * settles it): given up, nothing is held any more, and it is remembered; a [FoundKind.GIVEN_UP] finding with the
     * refusal's [code] says what became of it. Never "refused, not made": the earlier send may have stored it, and a later
     * read that finds it says "made after all".
     */
    data class RefusedCannotTell(val code: String) : HeldRepost()

    /**
     * The change held for the vault is not the one the caller named (its signed entry's hash differs: another change was
     * signed since, or the one named settled and another followed): nothing was sent and nothing was changed.
     */
    data object NotThisChange : HeldRepost()

    /**
     * The server refused it for good ([code]: `at_ahead`, `not_vault_owner`, …): the held frame is dropped. With
     * [StoredVaultLogs.VAULT_FROZEN] the server's own earlier `200` named it stored where the verified log holds another
     * entry: the vault is frozen, and nothing is said of the change.
     */
    data class Refused(val code: String, val retryAfterSeconds: Long? = null) : HeldRepost()
}

/** What a held change is ([HeldChange.kind]): the kind of its signed entry. */
enum class HeldKind { CREATE, ADD, ROLE, REMOVE, LEAVE, OFFER, CANCEL, ACCEPT, DELETE, RESTORE, OTHER }

/** What this device knows of a held change ([HeldChange.known]). */
enum class HeldKnown {
    /**
     * The server answered that it took it (a `200` answer to its send), and the vault's log as this device read it does
     * not hold it yet: stored by the server's word, not yet by the log's. Sent again byte for byte until the log shows it;
     * never offered for withdrawal ([HeldWithdrawal.STORED_BY_SERVERS_WORD]) and never given up after a day.
     */
    STORED_BY_SERVERS_WORD,

    /** Known not stored: every send of it so far was answered "slow down" (`429 rate_limited`), which the server says before it looks at the change. */
    NOT_STORED,

    /** Cannot tell: a send of it had no answer that settles it (none, one that broke off, a server error), or one is out now. It may be stored. */
    CANNOT_TELL,
}

/**
 * One vault's held change as a screen shows it ([VaultLogEngine.heldChanges]): a change this device signed and keeps to
 * send again byte for byte, because the server's word has not settled it (design §3.7). Facts only; the words are the
 * layer's.
 */
data class HeldChange(
    val vaultId: String,
    val kind: HeldKind,
    /** The member an addition, a removal or a change of role names, or the member an ownership offer goes to; null for the other kinds. */
    val names: String?,
    /** The role an addition or a change of role gives (`writer`, `reader`, `owner`); null for the other kinds. */
    val role: String?,
    /** When this device first held it, by the engine's clock (a record from before this field: the first time it was seen). */
    val heldSince: Long,
    val known: HeldKnown,
    /** A request of it is out at this moment (from this engine). */
    val requestOut: Boolean,
    /**
     * It may be withdrawn now ([VaultLogEngine.withdraw]): an addition, a removal, a change of role, an ownership offer or a
     * vault's deletion, not one a move signed for its own run ([movesOwn]), not while its FIRST request is still out, and
     * never one the server's own answer called stored ([HeldKnown.STORED_BY_SERVERS_WORD]: the server has it).
     */
    val withdrawable: Boolean,
    /**
     * A vault's deletion the person asked for: the general re-send ([VaultLogEngine.resendHeld]) never sends it; only the
     * person's word does ([VaultLogEngine.repostHeld]), or they keep the vault ([VaultLogEngine.withdraw]).
     */
    val waitsForWord: Boolean,
    /** Signed by "move everything" for its own run ([LogAction.Add.movesOwn], [LogAction.DeleteVault.movesOwn]): never withdrawn one by one. */
    val movesOwn: Boolean,
    /**
     * The identity of this very change: the hash (lowercase hex SHA-256) of its signed entry. [VaultLogEngine.withdraw] and
     * [VaultLogEngine.repostHeld] act only where the change held at that moment has this hash.
     */
    val hash: String,
    /**
     * The identity key the change names its member by: an addition's or an ownership offer's own key, as signed; for a
     * removal or a change of role, the member's key in the vault's log as verified here (null where the log does not list
     * them). A screen names the member only by this key, never by a contact's current key.
     */
    val memberKey: String?,
)

/** What [VaultLogEngine.withdraw] did. */
sealed class HeldWithdrawal {
    abstract val vaultId: String

    /**
     * Dropped, and never sent again by this device. [known] is what this device knew of it at that moment:
     * - [HeldKnown.NOT_STORED]: it was not made and will not be; nothing more is said of it.
     * - otherwise it may already be made: it is remembered by its signed entry's hash and position, the vault's log is read
     *   (at once where it can be, and at every later read of that vault), and what the reads find is kept as a
     *   [HeldFinding] until the layer says it was shown ([VaultLogEngine.findingShown]).
     */
    data class Withdrawn(val change: HeldChange, val known: HeldKnown) : HeldWithdrawal() {
        override val vaultId: String get() = change.vaultId
    }

    /** Nothing changed: [reason] is one of the companion's codes. */
    data class Kept(override val vaultId: String, val reason: String) : HeldWithdrawal()

    companion object {
        /** No change is held for the vault. */
        const val NOTHING_HELD = "nothing_held"

        /** Its first request is still out: it can be withdrawn once that request has ended. */
        const val FIRST_REQUEST_OUT = "first_request_out"

        /** Not a change that is withdrawn ([HeldChange.withdrawable]): a departure, a create, a move's own step, … */
        const val NOT_WITHDRAWABLE = "not_withdrawable"

        /** The vault's records cannot be read: nothing is said either way. */
        const val RECORD_UNREADABLE = "record_unreadable"

        /**
         * The server's own answer called it stored ([HeldKnown.STORED_BY_SERVERS_WORD]): it is made, and this device has
         * only not read it back yet. Withdrawing cannot undo it; the way to undo it is the act that does (remove the member
         * again, and so on), once it is read back. It stays held and is sent as it is until the log shows it.
         */
        const val STORED_BY_SERVERS_WORD = "stored_by_servers_word"

        /** [VaultLogEngine.dropHalfMade]: the change held for the vault is not a deletion of it. */
        const val NOT_A_DELETION = "not_a_deletion"

        /** The change held for the vault is not the one the caller named ([HeldChange.hash]): nothing was withdrawn. */
        const val NOT_THIS_CHANGE = "not_this_change"
    }
}

/** What one held change came to in the general re-send ([VaultLogEngine.resendHeld]). */
sealed class HeldResend {
    abstract val vaultId: String

    /** The vault's log holds it: made. */
    data class Stored(override val vaultId: String, val state: VerifiedVaultState) : HeldResend()

    /** Another entry took its place: it will never be made (a [FoundKind.PLACE_TAKEN] finding is kept). */
    data class PlaceTaken(override val vaultId: String) : HeldResend()

    /** Refused for good ([code]); dropped (a [FoundKind.REFUSED] finding is kept). */
    data class Refused(override val vaultId: String, val code: String) : HeldResend()

    /** Still held: no answer, a "slow down", or an answer the log does not show yet. */
    data class Waiting(override val vaultId: String) : HeldResend()

    /**
     * Held a day: not sent again; given up after a read (a [FoundKind.GIVEN_UP] finding is kept, with what the read showed).
     * Also a change whose outcome could not be told and whose re-send the server refused for the entry: given up with the
     * refusal's code ([HeldFinding.code]) and remembered, never said "refused" (a later read may show it made).
     */
    data class GivenUp(override val vaultId: String) : HeldResend()

    /**
     * An addition not sent again: the contact it names is gone from this device, has another key than the one it was
     * signed for, or is no longer compared. Let go of and remembered (a [FoundKind.CONTACT_CHANGED] finding is kept).
     */
    data class ContactChanged(override val vaultId: String) : HeldResend()

    /** A vault's deletion the person asked for: not sent; it waits for their word ([HeldChange.waitsForWord]). */
    data class WaitsForWord(override val vaultId: String) : HeldResend()

    /** A deletion a move signed for its own run: not sent here; the move re-posts it itself, after its own read. */
    data class MovesOwn(override val vaultId: String) : HeldResend()

    /** Withdrawn or settled by another road while this call ran: nothing of it is this call's. */
    data class NotHeld(override val vaultId: String) : HeldResend()

    /**
     * The server's own `200` named it stored at its position, and the vault's log as verified here holds another entry
     * there (or another hash at the head the answer named): the answer and the log cannot both be true. The vault is
     * frozen ([VaultLogStatus.Frozen]), the change is dropped, and nothing is said of it: the frozen vault is the notice.
     */
    data class Frozen(override val vaultId: String) : HeldResend()
}

/** What [VaultLogEngine.lookHeld] found. Nothing was sent for any of these. */
sealed class HeldLook {
    abstract val vaultId: String

    /**
     * The vault's log holds it: made, and no longer held. For the person's own deletion of a vault a [FoundKind.MADE]
     * finding is kept (the vault was deleted; it can be restored while its grace lasts): never ask about it.
     */
    data class Made(override val vaultId: String, val state: VerifiedVaultState) : HeldLook()

    /** Another entry took its place: it did not happen and never will ([FoundKind.PLACE_TAKEN] finding kept). Never ask about it. */
    data class PlaceTaken(override val vaultId: String) : HeldLook()

    /** The server's own answer named it where the log holds another entry: the vault is frozen and nothing is said of it ([HeldResend.Frozen]). */
    data class Frozen(override val vaultId: String) : HeldLook()

    /**
     * Still held: the log as read does not hold it and its place is free (or nothing could be read: [readReached] is
     * false when this look's read did not reach the server and verify to the head it served). Only now may a deletion
     * that waits for the person's word be asked about.
     */
    data class StillHeld(val change: HeldChange, val readReached: Boolean) : HeldLook() {
        override val vaultId: String get() = change.vaultId
    }

    /** Nothing is held for the vault (settled or withdrawn by another road). */
    data class NothingHeld(override val vaultId: String) : HeldLook()

    /** The vault's records cannot be read: nothing was read and nothing is said. */
    data class Unreadable(override val vaultId: String) : HeldLook()
}

/** What a [HeldFinding] says. */
enum class FoundKind {
    /**
     * The person's own deletion of a vault, held while it waited for their word, is in the vault's log: the vault was
     * deleted (by a deletion signed at [HeldFinding.signedAt]), and can be restored while its grace lasts
     * ([VaultLogEngine.serverGraceEnd]).
     */
    MADE,

    /** A change this device let go of ([HeldFinding.letGo]: withdrawn, or given up) is in the vault's log after all. */
    MADE_AFTER_ALL,

    /**
     * A change withdrawn while its outcome could not be told is not made. [HeldFinding.final]: another entry took its
     * place, so it never will be; otherwise the log as read (a read that reached the server, and reached every head the
     * server's own answer had named) does not hold it, and it is still remembered: [MADE_AFTER_ALL] may follow.
     */
    NOT_MADE,

    /**
     * Held a day and given up, after a read. [HeldFinding.final]: it was known not stored. Otherwise it is remembered, and
     * [HeldFinding.absentAtRead] says whether the read showed it absent (as [NOT_MADE] above) or nothing can be told.
     */
    GIVEN_UP,

    /** A change sent again will never be made: another entry took its place. */
    PLACE_TAKEN,

    /**
     * An addition held to be sent again was not sent: the contact it names is gone from this device, has another key than
     * the one it was signed for, or is no longer compared ([LetGo.CONTACT_CHANGED]). [HeldFinding.final]: it was known not
     * stored, so it was not made. Otherwise an earlier send may have reached the server: it is remembered, and a later
     * read that finds it keeps a [MADE_AFTER_ALL] finding.
     */
    CONTACT_CHANGED,

    /**
     * A change sent again was refused for good ([HeldFinding.code]), where it was known not stored. A refusal about the
     * session (`401`) says nothing of any held change; a change the server's own answer called stored is never refused
     * (it is sent again as it is); one whose outcome cannot be told is [GIVEN_UP] with the code instead.
     */
    REFUSED,
}

/** How a change this device no longer sends was let go of ([HeldFinding.letGo]). */
enum class LetGo {
    WITHDRAWN,
    GIVEN_UP,

    /**
     * A deletion of a vault half-made by a stopped move, dropped unsent by the move's next run ([VaultLogEngine.dropHalfMade]).
     * Found made after all: the vault was deleted by a deletion signed at [HeldFinding.signedAt], and can be restored while
     * its grace lasts ([VaultLogEngine.serverGraceEnd]): a line of its own.
     */
    HALF_MADE,

    /** An addition not sent again because the contact it names changed ([FoundKind.CONTACT_CHANGED]). */
    CONTACT_CHANGED,
}

/**
 * Something the person must be told about a change this device held ([VaultLogEngine.heldFindings]). Kept at rest, across
 * locks and restarts, until the layer says it was shown ([VaultLogEngine.findingShown]); never sent anywhere.
 */
data class HeldFinding(
    /** Unique; what [VaultLogEngine.findingShown] takes. */
    val id: String,
    val vaultId: String,
    val change: HeldKind,
    /** As [HeldChange.names]. */
    val names: String?,
    val what: FoundKind,
    /** For [FoundKind.MADE_AFTER_ALL]: whether it had been withdrawn or given up. */
    val letGo: LetGo?,
    /** For [FoundKind.NOT_MADE] and [FoundKind.GIVEN_UP]: nothing later can make it (see each). */
    val final: Boolean,
    /** For [FoundKind.GIVEN_UP] not [final]: the read reached the server and its log did not hold the change. */
    val absentAtRead: Boolean,
    /**
     * For [FoundKind.REFUSED], and [FoundKind.GIVEN_UP] after a refusal: the server's code where this client knows it,
     * else [StoredVaultLogs.OTHER_REFUSAL] (the server's own text is never kept).
     */
    val code: String?,
    /** When the change was signed (its entry's `at`): for "a deletion signed at …". */
    val signedAt: Long,
    /** When this device found it, by the engine's clock. */
    val at: Long,
    /** As [HeldChange.memberKey], kept with the finding (null where it was not known when the change was let go of). */
    val memberKey: String? = null,
    /**
     * For a change of role: the role (`writer`, `reader`, `owner`) the member held in the log as verified here when this
     * device let go of the change, which an undo of it goes back to; null for other kinds, or where it was not known.
     */
    val roleBefore: String? = null,
)

/**
 * The vault-log half of the engine (design §3): fetch and verify, adoption, item-head hints, accept and
 * decline, and every log action. Per signed-in account; state is durable in device state and outlives
 * the offline cache (design §3.9).
 */
interface VaultLogEngine {
    /** The current belief about [vaultId]. */
    fun status(vaultId: String): VaultLogStatus

    /**
     * Fetch from the verified head and verify (design §3.9) when [servedSeq]/[servedHash] (the `/sync`
     * `logHead`) differ from it, or when forced. Updates the account's vault record (batched, design §5.4).
     */
    suspend fun refresh(vaultId: String, servedSeq: Long?, servedHash: String?, force: Boolean = false): VaultLogStatus

    /**
     * The sync answer of the round about to [refresh] carried [counter] as its `accountStateSeq` (spec 03 §4), or none
     * (null). Told once per sync round, before that round's refreshes. With a counter, the round reads the account
     * state only when the counter differs from the one this device last saw ([AccountStateStore.heldCounter]): another
     * device wrote it, or the counter went back (never read as "nothing new"). Without one, as before: at most once per
     * round. A host that never tells keeps the behaviour before the counter.
     */
    fun accountStateServed(counter: Long?) {}

    /** Run §3.6 for [vaultId] against every candidate key the device holds. */
    suspend fun adoption(vaultId: String): Adoption

    /**
     * Reopens a key this device already adopted, sending and writing nothing: for a cold start offline or under a forked
     * pin. Only the genesis-bound UVK wrap the cached grant row holds, checked by §3.6's wrap rules against this device's
     * verified log and the account's local records; never a grant (that needs a contact check and posts a self-wrap) and
     * never an [Adoption.AskAccept]. Anything else is [Adoption.Refused]; [adoption] remains the online path.
     */
    fun reopenAdopted(vaultId: String): Adoption = Adoption.Refused(vaultId, AdoptionRefusal.NO_KEY)

    /** Answer an [Adoption.AskAccept]: accept records `accepted` (bound to its `addSeq`); decline records it and signs a `leave`. */
    suspend fun answerIncoming(ask: Adoption.AskAccept, accept: Boolean): Adoption

    /**
     * Signs again the leave of every share this account declined whose leave the server did not store (design §5.4): once
     * per engine (one unlock), after the session's first sync. For each vault the account's own record answers `decline`:
     * skipped where this engine already signed a leave for it (the answer's own leave counts) or holds a change for it
     * ([resendHeld] sends that one as it is); otherwise, where the verified log still lists this account as a member
     * through the very `add` that was declined, the log is read afresh, checked again, and one leave is signed. Nothing is
     * signed where the log no longer lists the account, lists it through a later `add` (a new invitation, asked anew), or
     * cannot be read. Answers what was signed, one per vault, with the leave's own outcome; nothing more is said to the
     * person than that the owner may still see the invitation until it goes through.
     */
    suspend fun leaveAgainForDeclines(): List<LeftAgain> = emptyList()

    /** An item decrypted under the vault's key named [seq]/[hash] (design §3.9): a hint to fetch, never a verdict. */
    suspend fun noteItemHead(vaultId: String, seq: Long, hash: String): VaultLogStatus

    /** Perform [action] on [vaultId] (or, for [LogAction.Create], on a fresh vault id the engine mints). */
    suspend fun append(vaultId: String?, action: LogAction): AppendOutcome

    /**
     * [append], signed only over the head its caller checked. [expectHead] is the verified head (seq and hash) the caller
     * read and decided against (the members it checked before a delete, say). The engine compares it with the verified
     * head it is about to sign over, in the same step that signs, with no wait in between: when they differ (another
     * change was verified meanwhile, by a sync or by a held change of this device stored first) nothing is signed or sent
     * and the answer is [AppendOutcome.NotAllowed] with [StoredVaultLogs.LOG_MOVED_ON]: the caller reads again and decides
     * again. A held change is still re-posted first, as by [append]. With [expectHead] null, exactly [append].
     *
     * An engine that cannot compare heads (a test fake) signs nothing: [StoredVaultLogs.EXPECT_HEAD_UNSUPPORTED].
     */
    suspend fun append(vaultId: String?, action: LogAction, expectHead: Checkpoint?): AppendOutcome =
        if (expectHead == null) append(vaultId, action) else AppendOutcome.NotAllowed(StoredVaultLogs.EXPECT_HEAD_UNSUPPORTED)

    /**
     * Re-post [vaultId]'s held change, if there is one, byte for byte, and sign nothing new (design §3.7): no statement
     * is ever built here. A held change this device already verified in the log (stored, or its place taken) is settled
     * without sending it again. See [HeldRepost] for the answers. A lock before the send sends nothing
     * ([io.silencelen.andvari.core.crypto.KeysGoneException]); the held frame then stays for the next unlock.
     *
     * Only the change the caller named: [expectHash] is the [HeldChange.hash] of the change it read and decided on. The
     * engine compares it with the change held at that moment, in the same step that sends, with no wait in between; where
     * they differ nothing is sent and the answer is [HeldRepost.NotThisChange].
     *
     * An engine that holds no changes (a test fake) answers [HeldRepost.Waiting]: never "stored", never "nothing held".
     */
    suspend fun repostHeld(vaultId: String, expectHash: String): HeldRepost = HeldRepost.Waiting

    /**
     * Withdraw [vaultId]'s held change before it is sent again, only where this device KNOWS the server did not store
     * it: every send of it so far was answered "slow down" (`429 rate_limited`), which the server answers before it
     * looks at the frame ([AppendOutcome.Refused.held]). True when the held change was dropped; false, and nothing
     * changed, when none is held or when any send of it may have been stored (no answer, an answer that broke off, a
     * server error, an answer the refetch could not confirm): such a change cannot be withdrawn, only waited for.
     * Nothing is sent. The default (a fake) withdraws nothing.
     */
    fun withdrawHeld(vaultId: String): Boolean = false

    /**
     * Every vault's held change, as [HeldChange]. Sends nothing. Each is first settled against what this device already
     * verified (a sync's read): one the vault's log holds, or whose place another entry took, is no longer held and not
     * listed (with a [FoundKind.MADE] finding for the person's own deletion of a vault, a [FoundKind.PLACE_TAKEN] one for a
     * taken place); one the server's own answer named where the log holds another entry freezes the vault. The default (a
     * fake) holds none.
     */
    fun heldChanges(): List<HeldChange> = emptyList()

    /** [vaultId]'s held change, settled first as in [heldChanges], or null when none is held (or its record cannot be read). Sends nothing. */
    fun heldChange(vaultId: String): HeldChange? = heldChanges().firstOrNull { it.vaultId == vaultId }

    /**
     * The look before a question (a deletion that waits for the person's word, say): [vaultId]'s log is read from the
     * server (where the origin may be dialed) and its held change settled against it, with NOTHING sent and no other
     * vault's change touched. See [HeldLook]; the words come from [heldFindings], as for [resendHeld]. The default (a
     * fake) reads nothing.
     */
    suspend fun lookHeld(vaultId: String): HeldLook =
        heldChange(vaultId)?.let { HeldLook.StillHeld(it, readReached = false) } ?: HeldLook.NothingHeld(vaultId)

    /**
     * Withdraw [vaultId]'s held change in either state ([HeldWithdrawal]): never sent again by this device. Where it may
     * already be made it is remembered and the vault's log is read now (where the origin may be dialed); the findings
     * follow in [heldFindings]. A withdrawal that took effect answers [HeldWithdrawal.Withdrawn] also where a lock cuts off
     * that read (the next read of the vault looks). Only the change the caller named: [expectHash] is the
     * [HeldChange.hash] of the change the person saw; the engine compares it with the change held at that moment, with no
     * wait before the drop, and where they differ nothing is withdrawn ([HeldWithdrawal.NOT_THIS_CHANGE]). The default (a
     * fake) withdraws nothing.
     */
    suspend fun withdraw(vaultId: String, expectHash: String): HeldWithdrawal = HeldWithdrawal.Kept(vaultId, HeldWithdrawal.NOTHING_HELD)

    /**
     * Drops [vaultId]'s held deletion, unsent, for a vault half-made by a stopped move that the move's next run keeps
     * (it holds other items): the person's own deletion or one the move marked as its own ([LogAction.DeleteVault.movesOwn]).
     * Sends and reads nothing. Settled first as in [heldChanges]. Where the deletion may already be stored it is remembered
     * as [LetGo.HALF_MADE]: no "not made" line, and a later read that finds it in the log keeps a
     * [FoundKind.MADE_AFTER_ALL] finding with that [HeldFinding.letGo]. Answers as [withdraw] ([HeldWithdrawal.Withdrawn]
     * with what was known), or [HeldWithdrawal.Kept] with [HeldWithdrawal.NOTHING_HELD], [HeldWithdrawal.NOT_A_DELETION],
     * [HeldWithdrawal.FIRST_REQUEST_OUT] or [HeldWithdrawal.RECORD_UNREADABLE]. The default (a fake) drops nothing.
     */
    fun dropHalfMade(vaultId: String): HeldWithdrawal = HeldWithdrawal.Kept(vaultId, HeldWithdrawal.NOTHING_HELD)

    /**
     * The general re-send (on reconnect, at an unlock): every held change byte for byte, except a vault's deletion (the
     * person's waits for their word, a move's is the move's) and a change held a day (an addition, a removal, a change of
     * role, an offer, the person's deletion), which is not sent again: the log is read first and it is given up unless the
     * read shows it made or its place taken. An addition whose contact is gone from this device, has another key than the
     * one it was signed for, or is no longer compared is not sent again either, on this road or any other that sends a held
     * change ([append], [repostHeld]): it is let go of ([HeldResend.ContactChanged]). One result per held change; what the person
     * must be told is also kept in [heldFindings]. The default runs [retryPending] and says nothing.
     */
    suspend fun resendHeld(): List<HeldResend> {
        retryPending()
        return emptyList()
    }

    /** What the person must be told about changes this device let go of or sent again ([HeldFinding]), oldest first per vault. */
    fun heldFindings(): List<HeldFinding> = emptyList()

    /** The layer showed finding [id]: it is forgotten. An unknown id does nothing. */
    fun findingShown(id: String) {}

    /** Re-post every pending-append record byte for byte (design §3.7), as [resendHeld] without its results. Called on reconnect. */
    suspend fun retryPending()

    /** True when a write under [vaultId]'s key is allowed (item saves, moves in, renames, the iOS save queue). */
    fun writeAllowed(vaultId: String): Boolean

    /** True when items may be copied OUT of [vaultId] (any state with a committed key, design §3.6). */
    fun copyOutAllowed(vaultId: String): Boolean

    /**
     * True when the adoption rules have nothing to decide for [vaultId]: its key is adopted, or a key is held for copying
     * out of a vault whose verified log does not name this account a member. A key held for a vault that names it a
     * member again is not: that add is to be answered, and a held key never makes the vault one this account may use.
     */
    fun adoptionSettled(vaultId: String): Boolean = copyOutAllowed(vaultId)

    /**
     * True while a key is held for [vaultId] with its time not over, the vault's verified log names this account a member
     * again, and this device holds an invitation its person can answer now: the reason the held key is not offered then.
     * Reads only.
     */
    fun heldWhileMemberAgain(vaultId: String): Boolean = false

    /**
     * [block] with the vault's key for this device, only when [Adoption.Adopted]; never a key that failed the commitment.
     * Null when there is none. The key stays inside the engine, under the guard of the account it was unwrapped from:
     * once that account's keys are wiped this throws [io.silencelen.andvari.core.crypto.KeysGoneException].
     */
    fun <T> withKey(vaultId: String, block: (ByteArray) -> T): T?

    /**
     * The server's `deleted` for [vaultId] (spec 03 §10.3, §10.6), kept beside the `delete` this device verified: answered
     * only while the stored verified state ends in a standing `delete`, and only for that `delete` (after a verified
     * `restore`, or a later `delete`, an older value is never answered). It was taken only from an answer whose head is
     * this device's verified head. Null on an older server, before any answer carried it, and when the record cannot be
     * read: the caller then shows what it showed before.
     *
     * The server's word only ([LogDeleted]): it is for the "restorable until" a screen shows, and nothing in the engine
     * reads it. No vault is deleted, closed, purged, hidden or made read-only because of it.
     */
    fun serverGraceEnd(vaultId: String): LogDeleted? = null

    /**
     * What the server's member list (`GET /vaults/{vaultId}/members`, spec 03 §10.7) says about each member of the
     * verified log, for "*name*'s account was deleted by the server's operator" (design §3.11, spec 02 §10.7). The log is
     * fetched and verified up to the head the server names first, then the list is read, then the log again: only when
     * the verified head did not move in between, the vault's verified state is [VaultLogStatus.Verified] and not
     * deleted, is the answer [ServerGrants.Read]. Anything else is [ServerGrants.Unknown], never "no grant".
     * Sends nothing under a stopped origin. Kept nowhere: each call reads afresh. See [ServerGrants] for what it may
     * and may not be used for.
     */
    suspend fun serverGrants(vaultId: String): ServerGrants = ServerGrants.Unknown(vaultId, ServerGrants.NOT_READ)
}

/** One verified member's grant as the server's member list shows it ([ServerGrants.of]). */
enum class ServerGrant {
    /** The server lists this member. */
    LISTED,

    /**
     * A member of the verified log the server does not list, while the vault is not deleted: "no grant, as the server
     * says". An honest server answers this for a member whose account its operator deleted (spec 03 §7.1, §10.7).
     */
    NO_GRANT_AS_SERVER_SAYS,

    /** The list could not be read, or could not be read against a verified head, or the person is not a verified member. */
    UNKNOWN,
}

/**
 * The server's member list held against this device's verified log ([VaultLogEngine.serverGrants]).
 *
 * THE SERVER'S WORD ONLY. A server can make an app show "no grant" — and so "*name*'s account was deleted by the
 * server's operator" — about ANY member, simply by leaving them out of its list; the copy is transparency from an
 * honest operator, never evidence. So it changes nothing else: for every signature check, key decision, adoption,
 * write rule and log action the person stays a member until the verified log says otherwise (a `remove` or `leave`),
 * and no key, grant, member or record is dropped because of it.
 */
sealed class ServerGrants {
    abstract val vaultId: String

    /** [userId]'s grant as this answer shows it. */
    abstract fun of(userId: String): ServerGrant

    /**
     * The list was read while the verified log stood at [headSeq]/[headHash] (the head the server named, before and
     * after the read). [noGrant]: the verified members absent from the list. [listed]: the verified members it lists.
     */
    data class Read(
        override val vaultId: String,
        val headSeq: Long,
        val headHash: String,
        val listed: Set<String>,
        val noGrant: Set<String>,
    ) : ServerGrants() {
        override fun of(userId: String): ServerGrant = when (userId) {
            in noGrant -> ServerGrant.NO_GRANT_AS_SERVER_SAYS
            in listed -> ServerGrant.LISTED
            else -> ServerGrant.UNKNOWN
        }
    }

    /** Nothing can be said: [reason] is one of the companion's codes (or [ORIGIN_STOPPED][io.silencelen.andvari.core.client.net.ORIGIN_STOPPED]). */
    data class Unknown(override val vaultId: String, val reason: String) : ServerGrants() {
        override fun of(userId: String): ServerGrant = ServerGrant.UNKNOWN
    }

    companion object {
        /** This engine does not read member lists. */
        const val NOT_READ = "not_read"

        /** The log is not [VaultLogStatus.Verified] up to the head the server names (withheld, failed, frozen, removed, unknown). */
        const val LOG_NOT_VERIFIED = "log_not_verified"

        /** The verified state ends in a standing `delete`: a deleted vault's list says nothing about accounts. */
        const val VAULT_DELETED = "vault_deleted"

        /** The list did not come (no answer, a refusal, or a body that is not a member list). */
        const val LIST_UNREADABLE = "list_unreadable"

        /** The verified head moved while the list was read: the list may predate a `remove` or `leave`. */
        const val LOG_MOVED = "log_moved"
    }
}
