package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.net.NoAnswerKind

/** What an [ItemEngine] operation came to. A failure is always a value here, never a swallowed exception. */
sealed class ItemResult<out T> {
    data class Ok<T>(val value: T) : ItemResult<T>()
    data class Failed(val why: ItemFailure) : ItemResult<Nothing>()

    fun valueOrNull(): T? = (this as? Ok<T>)?.value
}

/** Why an operation did not complete. */
sealed class ItemFailure {
    /** No usable answer (offline, a timeout, a proxy's page). A write's outcome is unknown; queued rows stay queued. */
    data class Unreachable(val kind: NoAnswerKind) : ItemFailure()

    /** The server refused with [code] (spec 03 §0.1). For a write the server could never apply, [code] is its `rejected` reason. */
    data class Refused(val code: String, val status: Int, val retryAfterSeconds: Long? = null) : ItemFailure()

    /**
     * The server went backwards (spec 05 T1, spec 03 §4): a non-full answer below the cursor, or a full snapshot
     * nobody asked for. Nothing was applied and local state is kept.
     */
    data class Rollback(val unsolicitedFull: Boolean) : ItemFailure()

    /** The engine is halted for a fork of the origin's card chain (design §4.4): nothing was sent, accepted or written. */
    data object Halted : ItemFailure()

    /** This device refused before anything was sent. */
    data class NotAllowed(val reason: ItemRefusal) : ItemFailure()

    /**
     * The cycle completed, and the server DENIED [count] of this device's own writes in a vault that is still this
     * account's (a role change, spec 03 §5 `denied`): those rows were dropped for good. Never silent.
     */
    data class Denied(val count: Int) : ItemFailure()

    /** An attachment failed its own checks (spec 02 §6): a MAC, a truncation, a size that is not the ref's. */
    data class Corrupt(val what: String) : ItemFailure()
}

enum class ItemRefusal {
    /** No personal vault is in force (design §5.3) and no destination was named: "Choose a vault for this item." */
    NO_PERSONAL_VAULT,

    /** The vault is not one this account may read now (not accepted, removed, never verified here). */
    VAULT_NOT_OPEN,

    /** The vault's status or this account's role forbids the write (design §3.6: frozen, failed, withheld, or a reader). */
    VAULT_READ_ONLY,

    /** The item is no longer here: removed, or its vault went away mid-edit. Never re-targeted. */
    ITEM_GONE,

    /** INV-EDIT, INV-SEAL (spec 02 §7.2): the item lives in another vault than the one named. "Reopen it." */
    ITEM_CHANGED_VAULTS,

    /** An edit did not name the vault its editor opened on. */
    EDIT_UNBOUND,

    /** A move's source changed since it was read: nothing was deleted. */
    ITEM_CHANGED,

    /** The destination denied the copy: the source is untouched. */
    COPY_DENIED,

    /** The copy could not be confirmed: nothing was moved. */
    COPY_UNCONFIRMED,

    /** The copy was made, and the source could not be deleted: the item is in both vaults. */
    SOURCE_DELETE_DENIED,

    /** An id that is not a canonical UUID. */
    BAD_ID,

    /**
     * The app interface closed the vault for writing on this device ([ItemEngine.markClosedForWriting], with a
     * [VaultClosedReason]): nothing is put into it or changed in it, and nothing was sealed. A copy out is allowed.
     */
    VAULT_CLOSED_FOR_WRITING,
}

/** Why the app interface closed a vault for writing on this device ([ItemEngine.markClosedForWriting]). */
enum class VaultClosedReason {
    /** The vault's deletion (the last step of a move of everything) is signed and waits for the server. */
    DELETION_WAITING,

    /**
     * A change of the vault waits on this device that it cannot read (a frame that does not parse, or a kept record of
     * the move that cannot be read), and it may be the vault's signed deletion: this device cannot tell, so the vault is
     * closed as if it were, and the line says that it may be.
     */
    DELETION_MAY_BE_WAITING,
}

/** How a save or a delete ended. */
enum class Written {
    /** The server answered and the reconcile pull ran (or only that pull is missing; a later sync trues up). */
    APPLIED,

    /** The server was unreachable; the write sits in a DURABLE queue and [ItemEngine.items] already shows it. */
    QUEUED,

    /**
     * The server refused it for now because the session ended (`401`): the write sits in a DURABLE queue, already shown,
     * and goes at the next sign-in (design §4.4).
     */
    KEPT_SESSION_ENDED,

    /** The server asked this device to wait (`429`): the write sits in a DURABLE queue, already shown, and goes later by itself. */
    KEPT_TOO_MANY_REQUESTS,

    /** The server had a fault (`5xx`): the write sits in a DURABLE queue, already shown, and goes when the server answers again. */
    KEPT_SERVER_FAULT,
    ;

    /** Not on the server yet: kept on this device to be sent later. */
    val waits: Boolean get() = this != APPLIED

    companion object {
        /**
         * How a write the failure [why] left in a DURABLE queue waits there: no answer, the session's end, a rate limit or
         * a fault of the server. Null for any other failure, which is said as the failure it is.
         */
        fun keptFor(why: ItemFailure): Written? = when {
            why is ItemFailure.Unreachable -> QUEUED
            why !is ItemFailure.Refused -> null
            why.status == 401 -> KEPT_SESSION_ENDED
            why.status == 429 || why.code == io.silencelen.andvari.core.model.wire.WireErrors.RATE_LIMITED -> KEPT_TOO_MANY_REQUESTS
            why.status >= 500 -> KEPT_SERVER_FAULT
            else -> null
        }
    }
}

class SavedItem(val itemId: String, val outcome: Written)

/**
 * An import that did not land whole ([ItemEngine.importAll]): [saved] of its items the server took; [keptToSend] sealed
 * and kept in a DURABLE queue, sent at a later sync ([kept] says how they wait, null when none do); [notSaved] neither
 * (never sealed, or taken out of a queue that dies with the session: nothing of them is sent later).
 */
class ImportStopped internal constructor(val saved: Int, val keptToSend: Int, val notSaved: Int, val kept: Written?)

/**
 * One completed sync cycle. [quota] is the account's own use and limits as this cycle's pull served them (spec 03 §14.4):
 * null when the server sent none or sent something that cannot be meters. [QuotaCheck.room] reads it.
 */
class SyncReport(val rev: Long, val full: Boolean, val quota: io.silencelen.andvari.core.model.wire.QuotaUse? = null)

/** A vault the account may read, for pickers, badges and the sharing screens. */
data class VaultView(
    val vaultId: String,
    /** `personal` or `shared`, DERIVED from the account genesis, never the served label (spec 02 §4). */
    val type: String,
    val name: String,
    val role: String,
    val standing: VaultStanding,
    val writable: Boolean,
    /** Set while the app interface holds the vault closed for writing on this device; [writable] is then false. */
    val closedFor: VaultClosedReason? = null,
)

/** One vault in the holding area, for the "Recently removed" surface. */
data class HeldVaultView(
    val vaultId: String,
    /** Decrypted on each read when the trust engine still offers the key; never stored. */
    val name: String?,
    /** A [VaultDeparture.code]. */
    val reason: String,
    val itemCount: Int,
    val parkedCount: Int,
    val expungeAt: Long,
    /** True while the held items can still be read and copied out on this device. */
    val readable: Boolean,
    /**
     * This account owned the vault when it left this device (its own grant said `owner`): a `deleted` or `purged`
     * departure is then the account's own delete, not "its owner's".
     */
    val ownedHere: Boolean = false,
    /**
     * The account was added to the vault again and this device holds an invitation it can answer now: the copy does not
     * open for that reason ([VaultKeySource.heldClosedAsMemberAgain]), until it accepts, the invitation ends or the day
     * comes. False for a copy closed for any other reason.
     */
    val addedAgain: Boolean = false,
)

/**
 * A restore ([restored] true) or a delete for good of [itemId] that the server answered as done, kept in the account's
 * cache until the next whole read of the trash checks it, so that a lock between the two does not lose the check.
 * [deletedAt] is the server's time of the deletion the device acted on; [seenLive] says whether this device was then
 * served the item live again (a restore that was stored). Together they tell a restore the server never stored (the
 * same deletion is listed, and the item was never served live) from a later deletion by another device or member.
 */
data class TrashActionDone(val itemId: String, val restored: Boolean, val deletedAt: Long, val seenLive: Boolean)

/**
 * One shared vault this account owned and deleted, in its grace (spec 03 §11.2): a row of the owner's "Recently
 * deleted" list. Restoring it is the owner's signed `restore`, a vault-log action, not the item engine's.
 */
data class DeletedVault(
    val vaultId: String,
    /** Decrypted with the key this device still holds for the vault; null when it holds none (the served wrap is never opened). */
    val name: String?,
    val deletedAt: Long,
    /** The end of the grace as the server served it; 0 where it served none (no day is known then). */
    val purgeAt: Long,
    /** The `delete` entry's id as served (`b64_16`): a hint for the restore, which the vault-log engine checks itself. */
    val deleteId: String,
    /** True when this device's verified log says the vault was deleted by its owner ([VaultDeparture.DELETED]). */
    val verified: Boolean,
)

/**
 * A notice the engine raises for the UI. Field names follow the old `LifecycleNotice`, so the notice copy keyed on
 * [kind] moves over unchanged.
 */
data class ItemNotice(
    val id: String,
    val vaultId: String,
    val vaultName: String,
    val kind: String,
    /** How many rows the notice is about (writes dropped, rows refused, edits parked). */
    val count: Int? = null,
    /** `write-rejected`: the server's reason for the first dropped row. `bad-id`: where the ids came from. */
    val reason: String? = null,
    /** [ITEM_BROUGHT_BACK] or [WRITE_DENIED] about one item: its name; null for several, or where it is not known. */
    val itemName: String? = null,
) {
    companion object {
        /**
         * Changes of this device brought back items that had been deleted elsewhere (the server's answer to a put over a
         * deletion, spec 03 §5): one notice per vault, [count] of them, and no copy was made.
         */
        const val ITEM_BROUGHT_BACK = "item-brought-back"

        /** Queue rows the server could never apply were dropped (spec 03 §5 `rejected`, and a refused batch bisected to a row). */
        const val WRITE_REJECTED = "write-rejected"

        /**
         * Changes of this device the server denied for good (the account may no longer write to the vault) were undone
         * here: one notice per vault, [count] items, and [itemName] when it is one. Raised beside a write the server
         * applied as well as at a sync; never for the change a write's own answer says it was refused.
         */
        const val WRITE_DENIED = "write-denied"

        /** The server sent an item under another vault than the one this device holds it in (spec 02 §7.2 INV-HOME). */
        const val WRONG_VAULT = "wrong-vault"

        /** The server sent rows whose ids are not UUIDs; they were dropped at the pull (spec 05 R18). */
        const val BAD_ID = "bad-id"

        /**
         * Edits recovered after a vault came back were refused (the role changed meanwhile). [ItemNotice.reason] says why
         * the vault had gone: [DELETED], [REMOVED] or [LEFT] (a held copy's reason), or [WITHHELD] (the server took it
         * away with no verified reason).
         */
        const val REPLAY_DENIED = "replay-denied"

        /** A vault left for a VERIFIED reason and moved to the holding area: `removed`, `left`, `deleted`, `purged`. */
        const val REMOVED = "removed"
        const val LEFT = "left"
        const val DELETED = "deleted"
        const val PURGED = "purged"

        /** The server stopped serving a vault with no verified reason: the copy stays, read-only (spec 02 §10.6). */
        const val WITHHELD = "withheld"

        /** A vault came back from the holding area. */
        const val RESTORED = "restored"

        /** A vault's metadata was served with an older `metaV` than this device holds: the newer one was kept. */
        const val META_REPLAY = "meta-replay"

        /** The server answered a sync with an older state than this device has seen (spec 05 T1): nothing was applied. */
        const val ROLLBACK = "rollback"

        /**
         * A sync answer claimed the personal vault away (named it removed, left or deleted, left it out of a whole
         * snapshot, or served it under another key). A personal vault has no members (design §3.10), so none of that can
         * be genuine: the vault, its key, its rows and its saves were kept unchanged.
         */
        const val PERSONAL_KEPT = "personal-kept"
    }
}

/**
 * A lock (or the end of the session) overtook a write before this device kept it: of the change, only the first [kept]
 * items were sealed and queued here (0 for a single save); nothing of the rest was sealed, queued or sent, and nothing
 * of it will be. It is still the lock ([io.silencelen.andvari.core.crypto.KeysGoneException]), so every caller that
 * answers a lock as "locked" goes on doing so; the content uses it to tell the person at the next unlock.
 */
class LockedBeforeKept(val kept: Int = 0) :
    io.silencelen.andvari.core.crypto.KeysGoneException("the vault locked before this change was kept: nothing more of it was sealed")

/** What copying a held vault's items into the personal vault came to: items copied, and files the server no longer handed over. */
class HeldRescue(val copied: Int, val filesLeftOut: Int)

/**
 * One item of a vault this device holds to bring into another vault ([ItemEngine.bringHeldInto]): [itemId] as it is
 * held, and [replaces], the copy an earlier run made of it in the target vault, which the new copy replaces (null when
 * there is none), with [replacesAtRev], the revision of that copy the replacement was decided against (the revision the
 * earlier run made it at: [HeldCopied.madeRev]). The earlier copy is deleted only while it stands at exactly that
 * revision with no change of this device waiting for it, and the deletion is sent at that revision, so a change made
 * since, here or by anyone else, keeps it ([HeldDeleted.KEPT_CHANGED]). A pick that names no revision deletes nothing
 * ([HeldDeleted.KEPT_NO_REVISION]).
 */
class HeldPick(val itemId: String, val replaces: String?, val replacesAtRev: Long? = null)

/**
 * What [ItemEngine.bringHeldInto] made of one [HeldPick]: [madeItemId], the copy in the target vault of [itemId] at
 * [rev] (made now, or found made by an earlier run), [filesLeftOut] of its files the server no longer handed over, and
 * [earlierKept]: the earlier copy it named was left in place on purpose (live, in the target vault, nothing sent for it);
 * name it no more. [keptBecause] says why ([HeldDeleted.KEPT_CHANGED]: changed in the target since, here or elsewhere,
 * or no longer there; [HeldDeleted.KEPT_REFUSED]: its deletion was denied or rejected; [HeldDeleted.KEPT_NO_REVISION]:
 * the pick named no revision to delete it at); null when [earlierKept] is false. False when no earlier copy was named,
 * or when it is gone. [madeRev] is the revision this device holds of the copy as the run made or found it (null when it
 * does not hold it): what a later pick that replaces this copy names as [HeldPick.replacesAtRev]. [deletedThere]: an
 * earlier run made this copy and it was deleted in the target since (by anyone there): it is not made again and is no
 * copy now, so it is never counted as copied; [madeRev] is then null.
 */
class HeldCopied(
    val itemId: String,
    val rev: Long,
    val madeItemId: String,
    val filesLeftOut: Int,
    val earlierKept: Boolean,
    val keptBecause: String? = null,
    val madeRev: Long? = null,
    val deletedThere: Boolean = false,
)

/**
 * A [HeldPick] that [ItemEngine.bringHeldInto] did not copy because the person deleted it on this device and that
 * deletion is still waiting ([ItemEngine.waitingDeletions]): [itemId] at [rev], the revision the deletion was made on.
 * [earlier] is the earlier copy the pick named (null: none). It was deleted from the target, its envelope kept so it is
 * in the target's trash, unless [earlierKept]: it was changed there since (someone's change is never deleted for a
 * copy) or the server denied its deletion; name it no more either way. A second run says the same and deletes nothing more.
 * [keptBecause] says which, so each has a sentence of its own: [KEPT_CHANGED] (changed there since, or no longer in the
 * target), [KEPT_REFUSED] (the server denied or rejected the deletion), [KEPT_NO_REVISION] (the pick named no revision
 * of the earlier copy, [HeldPick.replacesAtRev], and nothing is deleted without one); null when [earlierKept] is false.
 */
class HeldDeleted(val itemId: String, val rev: Long, val earlier: String?, val earlierKept: Boolean, val keptBecause: String? = null) {
    companion object {
        /** The earlier copy was changed in the target since (or is no longer there): someone's change is never deleted for a copy. */
        const val KEPT_CHANGED = "changed"

        /** The server denied or rejected the earlier copy's deletion. */
        const val KEPT_REFUSED = "refused"

        /** The pick named no revision of the earlier copy ([HeldPick.replacesAtRev]): nothing is deleted without one. */
        const val KEPT_NO_REVISION = "no-revision"
    }
}

/** A newly attached file awaiting upload: the item's [AttachmentRef] and the plaintext bytes. */
class NewAttachment(val ref: AttachmentRef, val data: ByteArray)

/** One attachment of a move or copy: a fresh id and a fresh file key, minted once. */
@kotlinx.serialization.Serializable
data class MovedAttachment(val oldId: String, val newId: String, val newFileKey: String, val name: String, val size: Long)

/**
 * A move or copy of one item into another vault, minted ONCE (a fresh item id, fresh attachment ids and file keys).
 * A retry re-runs the SAME plan and converges on the server's mutation dedup; a fresh plan would duplicate.
 * [sourceRev] is the rev of the content copied, so the delete leg catches a source that changed meanwhile.
 * Serializable so an unfinished move can be kept, sealed, across a lock.
 */
@kotlinx.serialization.Serializable
data class MovePlan(
    val planId: String,
    val sourceItemId: String,
    val sourceVaultId: String,
    val sourceRev: Long,
    val targetVaultId: String,
    val targetItemId: String,
    /** True for a move (copy, then delete the source); false for a copy. */
    val deleteSource: Boolean,
    val attachments: List<MovedAttachment>,
)
