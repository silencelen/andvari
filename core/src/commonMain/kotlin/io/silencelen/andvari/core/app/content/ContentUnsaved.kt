package io.silencelen.andvari.core.app.content

import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized

/** What [ContentState.notice] is about, so an app can tell its notices apart without reading the sentence. */
enum class ContentNoticeKind {
    /** Something the person asked for went well ("Synced.", moved, copied, restored, deleted for good). */
    DONE,

    /** The change waits on this device and is sent when the server can be reached. */
    QUEUED,

    /** A refusal or failure of an intent whose screen had already gone. */
    REFUSED,

    /** A save with files that was cut short: finished now, finished in part, or not yet. */
    KEPT_SAVE,

    /** What this device keeps for later (kept saves, unfinished moves, the automatic saves) could not be read or carried over. */
    RECORDS,

    /** What a lock cut short before it finished, said at the next unlock: [ContentState.lockCut] lists each. */
    LOCK,

    /**
     * A restore from the trash or a delete for good that the server answered as done and did not perform: the next read
     * of the trash still lists the item. Said once; a warning, not a success.
     */
    NOT_DONE_ON_SERVER,

    /**
     * An item restored or deleted for good on this device is in the trash again, after a later deletion by another
     * device or member: said as what is so, once, accusing nobody.
     */
    IN_TRASH_AGAIN,
}

/** What a lock cut short ([LockCut.kind]). */
enum class LockCutKind {
    /** A save not kept on this device ([io.silencelen.andvari.core.client.items.LockedBeforeKept]). [LockCut.name]: the item. */
    SAVE,

    /** An import the lock stopped: [LockCut.done] items saved of [LockCut.total]. */
    CSV_IMPORT,

    /** A copy of a held vault's items into a vault ([VaultContent.bringHeldItemsInto]): at least [LockCut.done] of [LockCut.total] copied, from [LockCut.name] into [LockCut.target]. */
    VAULT_COPY,

    /** A move of the item [LockCut.name] into [LockCut.target] that may not have finished. */
    MOVE,

    /** A copy of the one item [LockCut.name] into [LockCut.target] that may not have finished. */
    ITEM_COPY,

    /** A delete of the item [LockCut.name] that may not have finished. */
    ITEM_DELETE,

    /** The file [LockCut.name] was being added to an editor's item and was not. */
    FILE,

    /** A restore of [LockCut.name] from the trash that may not have finished. */
    RESTORE,

    /** Putting back an earlier version of [LockCut.name], not done. */
    VERSION,

    /**
     * A copy of a vault's items into the personal vault ([VaultContent.saveVaultItemsToPersonal]): at least [LockCut.done]
     * of [LockCut.total] copied, from [LockCut.name] into [LockCut.target]. Copying again copies every item again, the
     * ones already copied too, so its line never says that a second run makes no duplicates.
     */
    PERSONAL_COPY,
}

/**
 * One thing a lock cut short, as the next unlock's content says it ([ContentState.lockCut], with
 * [ContentNoticeKind.LOCK]). Names are labels (an item's name cut to a line, a file's safe name, a vault's name as this
 * device knows it), never a secret.
 */
class LockCut internal constructor(
    val kind: LockCutKind,
    val name: String,
    /** The vault written into, for COPY, MOVE and COPY_ITEM; "" otherwise. */
    val target: String,
    /** COPY and IMPORT: how many were done (at least), of [total]; 0 otherwise. */
    val done: Int,
    val total: Int,
) {
    /** The sentence for this one ([ContentState.notice] joins them). */
    val line: String get() = ContentCopy.lockCut(this)
}

/**
 * Changes the person made that a lock overtook before this device kept them
 * ([io.silencelen.andvari.core.client.items.LockedBeforeKept]): a plain save (no files) not yet sealed, and the batches
 * of an import a lock stopped; and work a lock cut short before it finished (a copy into a vault with its counts, a move,
 * a delete, a file being added, a restore). Keeping them would need a seal the lock has taken away, and the screen that
 * would have been told has gone, so the next unlock's content says it instead ([ContentState.notice], of kind
 * [ContentNoticeKind.LOCK], each in [ContentState.lockCut]).
 *
 * Held in this process's memory only, never written anywhere: an item's name (never a secret of it), a file's or a
 * vault's name, and counts. One per account at one server ([ContentStores]), so another account never sees it; gone
 * when the app is, said once, and dropped with the account's other kept records ([ContentStores.drop]).
 */
class UnsavedAtLock internal constructor() {
    private val lock = SynchronizedObject()
    /** The items whose save was not kept, by item ([save]'s key), each with its label: items are counted, not names. */
    private val names = LinkedHashMap<String, String>()
    private var unkeyed = 0
    private var importKept = 0
    private var importLost = 0
    private val cuts = ArrayList<LockCut>()

    /**
     * A save of the item named [name] was not kept. [item] tells items apart (its id, or a new item's minted id): two
     * items with the same name, or two with no name, are two changes; a second save of the same item is one. Null: an
     * item this content cannot name by id, counted on its own.
     */
    internal fun save(name: String, item: String? = null) = synchronized(lock) {
        names[item ?: "unkeyed|${unkeyed++}"] = ItemText.label(name)
    }

    /** An import kept [kept] of its items and not [lost] more. */
    internal fun import(kept: Int, lost: Int) = synchronized(lock) {
        importKept += kept
        importLost += lost
    }

    /** Work of [kind] a lock cut short ([LockCut]). */
    internal fun cut(kind: LockCutKind, name: String, target: String = "", done: Int = 0, total: Int = 0) = synchronized(lock) {
        val label = if (kind == LockCutKind.FILE) name else ItemText.label(name)
        cuts += LockCut(kind, label, target, done, total)
    }

    /** What to tell the person, once, and each thing in it: null when nothing was lost or cut short. */
    internal fun taken(): Taken? = synchronized(lock) {
        if (names.isEmpty() && importLost == 0 && cuts.isEmpty()) return@synchronized null
        val all = ArrayList<LockCut>()
        names.values.forEach { all += LockCut(LockCutKind.SAVE, it, "", 0, 0) }
        if (importLost > 0) all += LockCut(LockCutKind.CSV_IMPORT, "", "", importKept, importKept + importLost)
        all += cuts
        val said = listOf(ContentCopy.unsavedAtLock(names.values.toList(), importKept, importLost)).filter { it.isNotEmpty() } + cuts.map { it.line }
        names.clear()
        importKept = 0
        importLost = 0
        cuts.clear()
        Taken(said.joinToString(" "), all)
    }

    /** [taken]'s sentence alone. */
    internal fun take(): String? = taken()?.text

    internal fun clear() = synchronized(lock) {
        names.clear()
        importKept = 0
        importLost = 0
        cuts.clear()
    }

    internal class Taken(val text: String, val cuts: List<LockCut>)
}
