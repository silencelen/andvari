package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.ItemRefusal
import io.silencelen.andvari.core.client.items.VaultClosedReason
import io.silencelen.andvari.core.client.items.Written
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

/**
 * What the vault's content says. The sentences the old controller and `HouseholdCopy` said are kept word for word
 * (several are pinned byte-equal with the web client); they are copied here, not referenced, because those files go
 * with the old stack. A sentence marked NEW has no old twin: the old stack had no such state.
 */
object ContentCopy {
    // ---- kept word for word ----

    const val UNREACHABLE = "Can't reach the andvari server — check your connection (and your VPN, if your server is private), then try again."
    const val SOMETHING_WENT_WRONG = "Something went wrong — please try again."
    const val SERVER_PROBLEM = "The server had a problem answering — try again in a moment."
    const val SESSION_EXPIRED = "Session expired — sign in again."
    const val TOO_MANY_REQUESTS = "Too many requests — please wait a bit and try again."
    const val UPGRADE_REQUIRED = "This andvari server requires a newer version of the app — update andvari, then try again."
    const val SAVE_OFFLINE = "Offline — your save is queued and will finish when you're connected."
    const val SAVE_FAILED_OFFLINE = "Offline — this couldn't be saved. Try again when you're connected."
    const val SAVE_REJECTED_ATTACHMENT = "The server refused this save — an attachment it references is no longer there. Remove that attachment, then save again."
    const val SAVE_FAILED = "Could not save — try again."
    const val ITEM_CHANGED_VAULTS = "This item changed vaults; reopen it."
    const val NO_PERSONAL_VAULT = "Choose a vault for this item."
    const val SYNC_OFFLINE = "Can't reach the server right now — showing what's synced on this device."
    const val SYNC_FAILED = "Sync didn't finish — please try again."
    const val SYNCED = "Synced."
    const val NAME_REQUIRED = "Give the login a name."
    const val CARD_NAME_REQUIRED = "Give the card a name."
    const val NOTE_NAME_REQUIRED = "Give the note a name."
    const val TOTP_INVALID = "That one-time code key isn't valid base32 or an otpauth:// link."
    const val ITEM_GONE = "This item is no longer here."
    const val CARD_EXPIRY_INVALID = "That expiry date can't be read. Use a month and a year, like 07 and 2031."
    const val CARD_NUMBER_TOO_LONG = "A card number has at most 19 digits. Check the number."
    const val CARD_NUMBER_UNUSUAL = "This number doesn't pass the usual check for card numbers. You can still save it."
    const val READ_ONLY = "You can only view this vault, so this can't be changed here."
    const val VAULT_NOT_WRITABLE = "You can't add items to that vault."
    const val MOVE_DENIED = "You don't have permission to add items to that vault, so nothing was moved."
    const val MOVE_CHANGED = "This item changed while it was being moved. Review it and try again."
    const val MOVE_RETRY = "That didn't finish. Try again: it won't make a duplicate."
    const val TRASH_RESTORED = "Item restored."
    const val TRASH_PURGED = "Item deleted for good."
    /** A deleted shared vault whose name this device cannot read (it holds no key for it). */
    const val DELETED_VAULT_UNNAMED = "Shared vault"
    const val TRASH_GONE = "That item is no longer in the trash. Open the trash again."
    const val TRASH_UNREADABLE = "No readable version of this item is left, so it can only be deleted for good."

    /** NEW: the server's deleted-items list did not come to an end ([io.silencelen.andvari.core.client.items.ItemTransport.TRASH_INCOMPLETE]). */
    const val TRASH_LIST_INCOMPLETE = "The server's list of deleted items couldn't be read to the end, so it isn't shown. Try again later, and tell your admin if it keeps happening."
    const val TRASH_EXPLANATION = "Deleted items are kept for 30 days, then removed automatically. " +
        "Restoring brings the item back, but not its attachments — those were permanently removed when the item was deleted." +
        " \"Delete forever\" removes one now."
    const val HISTORY_GONE = "That version is no longer listed. Open the history again."
    const val VERSION_RESTORED = "Restored that version. The one it replaced is in the history."
    const val FILE_GONE = "This file is no longer in the item."
    const val FILE_READ_FAILED = "Couldn't read that file — try choosing it again."
    val FILE_TOO_LARGE_TO_OPEN =
        "This file is larger than ${io.silencelen.andvari.core.app.AttachmentRules.size(io.silencelen.andvari.core.app.AttachmentRules.MAX_FILE_BYTES)}, more than this app opens. Open it in andvari on a computer."
    const val STALE_META ="This vault changed somewhere else — reload and try the rename again."
    const val NOT_VAULT_OWNER = "Only the vault's owner can do that."

    /** `quota_exceeded` (spec 03 §14.4): the shared vaults' approved line ([io.silencelen.andvari.core.app.CopyKey.OWNER_OUT_OF_SPACE]). */
    const val OUT_OF_SPACE = "This vault's owner is out of space on this server."

    /**
     * A large copy the check before it stopped ([SpaceVerdict.NOT_ENOUGH]): the approved refusal line, then which limit and by
     * how much ([SpaceCheck.line]). It starts with [OUT_OF_SPACE], so [isOutOfSpace] reads it as a refusal for space.
     */
    fun outOfSpace(check: SpaceCheck): String = OUT_OF_SPACE + (check.line?.let { " " + it.english } ?: "")

    /** A failure sentence that is a refusal for space, whichever line about whose space follows it. */
    fun isOutOfSpace(message: String): Boolean = message.startsWith(OUT_OF_SPACE)
    const val WRONG_VAULT_NOTICE = "The server sent an item under the wrong vault. andvari kept the item where it was and ignored the other copy. Tell your admin — the server may be misbehaving."
    const val BAD_ID_NOTICE = "The server sent records with malformed ids. andvari ignored them and kept your vaults as they were. Tell your admin — the server may be misbehaving."

    // ---- NEW: states the old stack did not have ----

    /** NEW. Design §4.4: the server's card chain forked on this device; the vault is readable and nothing can be saved. */
    const val SERVER_STOPPED = "This server is stopped on this device, so nothing can be saved. What you see is this device's copy."

    /** NEW. Spec 05 T1: a sync answered with an older state than this device has seen. */
    const val ROLLBACK = "The server sent an older copy of your vault than this device has already seen, so andvari kept what it has. Tell your admin — the server may be misbehaving."

    /**
     * NEW: changes a lock overtook before this device kept them ([UnsavedAtLock]).
     * [names] are the items whose save was lost, one entry per item (already cut to a label; blank for an item with no
     * name): two items of the same name are two changes. [importKept] and [importLost] what an import the lock stopped
     * came to.
     */
    fun unsavedAtLock(names: List<String>, importKept: Int, importLost: Int): String {
        val parts = ArrayList<String>()
        if (names.isNotEmpty()) {
            val shown = names.take(3).map { if (it.isBlank()) Slot("an item with no name", named = false) else said(it) }
            val more = names.size - shown.size
            parts += when {
                more > 0 -> fillNames(CopyKey.UNSAVED_AT_LOCK_MORE, shown[0], shown[1], shown[2], number(more))
                shown.size == 3 -> fillNames(CopyKey.UNSAVED_AT_LOCK_THREE, shown[0], shown[1], shown[2])
                shown.size == 2 -> fillNames(CopyKey.UNSAVED_AT_LOCK_TWO, shown[0], shown[1])
                else -> fillNames(CopyKey.UNSAVED_AT_LOCK_ONE, shown[0])
            }
        }
        if (importLost > 0) {
            // [importKept] can be 1: a batch the server refuses as too large is split, and single items land on their own.
            parts += when {
                importKept == 1 && importLost == 1 -> fillNames(CopyKey.LOCK_CUT_IMPORT_KEPT_ONE_LOST_ONE)
                importKept == 1 -> fillNames(CopyKey.LOCK_CUT_IMPORT_KEPT_ONE_LOST_MANY, number(importLost))
                importLost == 1 -> fillNames(CopyKey.LOCK_CUT_IMPORT_KEPT_MANY_LOST_ONE, number(importKept))
                else -> fillNames(CopyKey.LOCK_CUT_IMPORT_KEPT_MANY_LOST_MANY, number(importKept), number(importLost))
            }
        }
        return parts.joinToString(" ")
    }

    /**
     * An import cut short with nothing of it kept to send: [saved] items are on the server and [notSaved] are not, and
     * those are not sent later. [why] the refusal's own sentence when the import cannot simply be tried again (it comes
     * first), null when Retry imports the rest. Null when [saved] or [notSaved] is 0: the plain line says it then.
     */
    fun importStopped(saved: Int, notSaved: Int, why: String?): String? {
        if (saved <= 0 || notSaved <= 0) return null
        val counts = when {
            saved == 1 && notSaved == 1 -> fillNames(CopyKey.IMPORT_STOPPED_SAVED_ONE_NOT_ONE)
            saved == 1 -> fillNames(CopyKey.IMPORT_STOPPED_SAVED_ONE_NOT_MANY, number(notSaved))
            notSaved == 1 -> fillNames(CopyKey.IMPORT_STOPPED_SAVED_MANY_NOT_ONE, number(saved))
            else -> fillNames(CopyKey.IMPORT_STOPPED_SAVED_MANY_NOT_MANY, number(saved), number(notSaved))
        }
        return if (why != null) "$why $counts" else counts + " " + fillNames(CopyKey.IMPORT_RETRY_THE_REST)
    }

    /**
     * What a save or a deletion kept on this device to be sent later says ([Written.waits]): no answer is the queued line,
     * and a refusal for now says why it waits and when it goes. Null when it was not kept (it reached the server).
     */
    fun kept(how: io.silencelen.andvari.core.client.items.Written): String? = when (how) {
        io.silencelen.andvari.core.client.items.Written.APPLIED -> null
        io.silencelen.andvari.core.client.items.Written.QUEUED -> SAVE_OFFLINE
        io.silencelen.andvari.core.client.items.Written.KEPT_SESSION_ENDED -> fillNames(CopyKey.SAVE_KEPT_SESSION_ENDED)
        io.silencelen.andvari.core.client.items.Written.KEPT_TOO_MANY_REQUESTS -> fillNames(CopyKey.SAVE_KEPT_TOO_MANY)
        io.silencelen.andvari.core.client.items.Written.KEPT_SERVER_FAULT -> fillNames(CopyKey.SAVE_KEPT_SERVER_FAULT)
    }

    /**
     * NEW (placeholder). An import that is done, [n] items added to [vault], whose items the list shows only after the
     * next sync (the last pull got no answer): it says when they show, and not to import the file again before then.
     */
    fun importDoneListedLater(n: Int, vault: String): String {
        val into = if (vault.isBlank()) Slot("a vault", named = false) else Slot(vault, named = true)
        return if (n == 1) fillNames(CopyKey.IMPORT_DONE_LISTED_LATER_ONE, into) else fillNames(CopyKey.IMPORT_DONE_LISTED_LATER, number(n), into)
    }

    /** An import cut short whose [kept] items wait on this device, sent later as [how] says ([Written.keptFor]). */
    fun importKept(kept: Int, how: io.silencelen.andvari.core.client.items.Written): String =
        if (how == io.silencelen.andvari.core.client.items.Written.KEPT_SESSION_ENDED) counted(kept, CopyKey.IMPORT_KEPT_UNTIL_SIGN_IN_ONE, CopyKey.IMPORT_KEPT_UNTIL_SIGN_IN_MANY)
        else counted(kept, CopyKey.IMPORT_KEPT_ONE, CopyKey.IMPORT_KEPT_MANY)

    /** A number in a slot: plain words, never quoted. */
    private fun number(n: Int) = Slot(n.toString(), named = false)

    /** [one] when [n] is 1, else [many] with {0} the number. */
    private fun counted(n: Int, one: CopyKey, many: CopyKey) = if (n == 1) fillNames(one) else fillNames(many, number(n))

    /**
     * Restores ([restored] true) and deletes for good the server answered as done that the next read of the trash shows
     * did not happen, by the item's name where this device knows it (null: it does not).
     */
    fun trashNotDone(missed: List<Pair<Boolean, String?>>): String = missed.joinToString(" ") { (restored, name) ->
        fillNames(if (restored) CopyKey.TRASH_RESTORE_NOT_DONE else CopyKey.TRASH_PURGE_NOT_DONE, trashItem(name))
    }

    /** Items restored or deleted for good here that a later deletion put in the trash again, by name where known. */
    fun trashInAgain(names: List<String?>): String = names.joinToString(" ") { fillNames(CopyKey.TRASH_IN_AGAIN, trashItem(it)) }

    private fun trashItem(name: String?): Slot = when {
        name == null -> Slot("an item", named = false)
        name.isBlank() -> Slot("an item with no name", named = false)
        else -> Slot(ItemText.label(name), named = true)
    }

    /** What goes into one slot of a sentence: a name someone chose ([named]), or the plain words that stand where none is known. */
    internal class Slot(val text: String, val named: Boolean)

    private fun said(text: String) = Slot(text, named = true)

    /**
     * Fills [key]'s slots where some hold names. A sentence that has its words quotes a name's slot itself (“{0}”), so a
     * name goes in as it is and is quoted once, by the sentence. Where no name is known, the plain words stand there and
     * the sentence's quotes around that slot go: "an item with no name" is not a name to quote. A key that still awaits
     * its words has no quotes in its gloss, and both kinds go in as they are. One pass over the template, as
     * [CopyKey.fill] makes it, so a name that itself reads "{0}" is copied and never filled in again.
     */
    internal fun fillNames(key: CopyKey, vararg slots: Slot): String {
        val t = key.english
        val out = StringBuilder(t.length + 32)
        var i = 0
        while (i < t.length) {
            val quoted = t[i] == '“' && i + 1 < t.length && t[i + 1] == '{'
            val open = if (quoted) i + 1 else i
            val close = if (t[open] == '{') t.indexOf('}', open) else -1
            val slot = (if (close > open + 1) t.substring(open + 1, close).toIntOrNull() else null)?.let { slots.getOrNull(it) }
            if (slot == null) {
                out.append(t[i])
                i++
                continue
            }
            val closed = quoted && close + 1 < t.length && t[close + 1] == '”'
            if (closed && !slot.named) {
                out.append(slot.text)
                i = close + 2
            } else {
                if (quoted) out.append('“')
                out.append(slot.text)
                i = close + 1
            }
        }
        return out.toString()
    }

    /** What a lock cut short, one sentence ([LockCut.line]); SAVE and IMPORT are said by [unsavedAtLock]. */
    fun lockCut(c: LockCut): String {
        fun q(s: String) = if (s.isBlank()) Slot("an item with no name", named = false) else Slot(s, named = true)
        fun v(s: String) = if (s.isBlank()) Slot("a vault", named = false) else Slot(s, named = true)
        fun f(s: String) = if (s.isBlank()) Slot("a file with no name", named = false) else Slot(s, named = true)
        return when (c.kind) {
            LockCutKind.SAVE -> unsavedAtLock(listOf(c.name), 0, 0)
            LockCutKind.CSV_IMPORT -> unsavedAtLock(emptyList(), c.done, c.total - c.done)
            LockCutKind.VAULT_COPY ->
                if (c.done == 1) fillNames(CopyKey.LOCK_CUT_COPY_ONE, v(c.name), v(c.target), number(c.total))
                else fillNames(CopyKey.LOCK_CUT_COPY, v(c.name), v(c.target), said(c.done.toString()), said(c.total.toString()))
            LockCutKind.PERSONAL_COPY ->
                if (c.done == 1) fillNames(CopyKey.LOCK_CUT_COPY_TO_PERSONAL_ONE, v(c.name), v(c.target), number(c.total))
                else fillNames(CopyKey.LOCK_CUT_COPY_TO_PERSONAL, v(c.name), v(c.target), said(c.done.toString()), said(c.total.toString()))
            LockCutKind.MOVE -> fillNames(CopyKey.LOCK_CUT_MOVE, q(c.name), v(c.target))
            LockCutKind.ITEM_COPY -> fillNames(CopyKey.LOCK_CUT_COPY_ITEM, q(c.name), v(c.target))
            LockCutKind.ITEM_DELETE -> fillNames(CopyKey.LOCK_CUT_DELETE, q(c.name))
            LockCutKind.FILE -> fillNames(CopyKey.LOCK_CUT_FILE, f(c.name))
            LockCutKind.RESTORE -> fillNames(CopyKey.LOCK_CUT_RESTORE, q(c.name))
            LockCutKind.VERSION -> fillNames(CopyKey.LOCK_CUT_VERSION, q(c.name))
        }
    }

    /**
     * A save or upload refused for space (`quota_exceeded`): the approved line, then whose space it is, as the shared
     * vaults' rows say it (approved entries 27 and 28): [yours] for the personal vault and a vault this account owns.
     */
    fun outOfSpaceWhose(yours: Boolean): String =
        OUT_OF_SPACE + " " + (if (yours) CopyKey.OWNER_OUT_OF_SPACE_YOURS else CopyKey.OWNER_OUT_OF_SPACE_THEIRS).english

    /** NEW: a sync answer claimed the personal vault away; nothing changed. */
    const val PERSONAL_KEPT = "The server said your personal vault was taken away. A personal vault belongs to you alone and can't be removed, so andvari kept it on this device, unchanged. Tell your admin — the server may be misbehaving."

    /** NEW. Spec 03 §5 `denied`: the server refused this device's own changes in a vault that is still this account's. */
    fun denied(count: Int): String =
        if (count == 1) "The server refused one of your changes — your access to that vault may have changed. Reopen the item to see what it holds now."
        else "The server refused $count of your changes — your access to that vault may have changed. Reopen those items to see what they hold now."

    /** NEW. The vault is not open on this device (not accepted, removed, or never verified here). */
    const val VAULT_NOT_OPEN = "That vault isn't open on this device."

    /** NEW. A move whose copy landed and whose original could not be deleted. */
    const val SOURCE_KEPT = "The copy was made, but the original couldn't be deleted, so the item is in both vaults."

    /** NEW. Spec 02 §6: an attachment that failed its own checks. */
    const val ATTACHMENT_DAMAGED = "This attachment is damaged and can't be opened."

    // ---- moves, copies and the holding area ----

    const val VAULT_NAME_REQUIRED = "Give the vault a name."
    const val COPY_RUNNING = "Wait for the copy into your personal vault to finish first."

    /** The target vault of a move, by name, or the plain words ([CopyKey.NAME_THE_OTHER_VAULT]) when it cannot be read. */
    private fun targetVault(name: String?) = name?.takeIf { it.isNotBlank() }?.let(::said) ?: Slot(CopyKey.NAME_THE_OTHER_VAULT.english, named = false)

    /** The vault an item is in, by name, or the plain words ([CopyKey.NAME_ITS_VAULT]). */
    private fun itsVault(name: String?) = name?.takeIf { it.isNotBlank() }?.let(::said) ?: Slot(CopyKey.NAME_ITS_VAULT.english, named = false)

    /** An item of a move's lines, by name, or the plain words ([CopyKey.NAME_THIS_ITEM]) when it has none. */
    private fun movedItem(name: String?) = name?.takeIf { it.isNotBlank() }?.let(::said) ?: Slot(CopyKey.NAME_THIS_ITEM.english, named = false)

    /** [target] null or blank: a vault whose name this device cannot read, said in plain words, unquoted. */
    fun moved(target: String?) = fillNames(CopyKey.ITEM_MOVED_TO, targetVault(target))
    fun copied(target: String?) = fillNames(CopyKey.ITEM_COPIED_TO, targetVault(target))
    fun copiedToPersonal(count: Int) = counted(count, CopyKey.COPIED_TO_PERSONAL_ONE, CopyKey.COPIED_TO_PERSONAL_MANY)

    /** NEW. A held vault's items copied out; [filesLeftOut] files the server no longer hands over. */
    fun copiedOutOfHeld(count: Int, filesLeftOut: Int) =
        counted(count, CopyKey.COPIED_OUT_OF_HELD_ONE, CopyKey.COPIED_OUT_OF_HELD_MANY) + filesNotHandedOver(filesLeftOut)

    /**
     * [VaultContent.bringHeldItemsInto] with files the server no longer handed over: said by this content, never silently.
     * [target] null or blank: a vault whose name this device cannot read, said as "a vault", unquoted.
     */
    fun broughtInto(target: String?, count: Int, filesLeftOut: Int): String {
        val into = target?.takeIf { it.isNotBlank() }?.let(::said) ?: Slot("a vault", named = false)
        val line = if (count == 1) fillNames(CopyKey.BROUGHT_INTO_ONE, into) else fillNames(CopyKey.BROUGHT_INTO_MANY, number(count), into)
        return line + filesNotHandedOver(filesLeftOut)
    }

    private fun filesNotHandedOver(filesLeftOut: Int) =
        if (filesLeftOut == 0) "" else " " + counted(filesLeftOut, CopyKey.FILES_NOT_HANDED_OVER_ONE, CopyKey.FILES_NOT_HANDED_OVER_MANY)

    /** NEW. A move whose copy landed and whose original stayed; a name that cannot be read is said in plain words. */
    fun inBothVaults(name: String?, target: String?, source: String?) =
        fillNames(CopyKey.ITEM_IN_BOTH_VAULTS, movedItem(name), targetVault(target), itsVault(source))

    /**
     * An export saved (the old `ExportCopy` sentences, word for word when [folder] is named). A picker that names no
     * folder (Android's document picker) passes "" and the sentence leaves the folder out: "Saved “x.csv”: 3 logins…".
     */
    fun csvSaved(fileName: String, folder: String, logins: Int): String =
        exportSaved(fileName, folder, counted(logins, CopyKey.EXPORT_CSV_HOLDS_ONE, CopyKey.EXPORT_CSV_HOLDS_MANY))

    fun backupSaved(fileName: String, folder: String, items: Int, vaults: Int, files: Int): String {
        val i = Slot(counted(items, CopyKey.COUNT_ITEMS_ONE, CopyKey.COUNT_ITEMS_MANY), named = false)
        val v = Slot(counted(vaults, CopyKey.COUNT_VAULTS_ONE, CopyKey.COUNT_VAULTS_MANY), named = false)
        val holds = if (files > 0) {
            fillNames(CopyKey.EXPORT_BACKUP_HOLDS_FILES, i, v, Slot(counted(files, CopyKey.COUNT_FILES_ONE, CopyKey.COUNT_FILES_MANY), named = false))
        } else {
            fillNames(CopyKey.EXPORT_BACKUP_HOLDS, i, v)
        }
        return exportSaved(fileName, folder, holds)
    }

    /** "Saved “file” to folder: …", the folder left out where the picker names none. */
    private fun exportSaved(fileName: String, folder: String, holds: String): String {
        val what = Slot(holds, named = false)
        return if (folder.isBlank()) fillNames(CopyKey.EXPORT_SAVED, said(fileName), what)
        else fillNames(CopyKey.EXPORT_SAVED_TO, said(fileName), Slot(folder.trim(), named = false), what)
    }

    /** What a try says when an earlier try's copy is already in the target (the old `VaultMoves.alreadyCopiedLine`). */
    fun alreadyCopied(item: String?, target: String?, changedSince: Boolean): String =
        fillNames(if (changedSince) CopyKey.ITEM_ALREADY_COPIED_CHANGED else CopyKey.ITEM_ALREADY_COPIED, movedItem(item), targetVault(target))

    /** NEW. What this device keeps about unfinished moves could not be read: nothing was done. */
    const val MOVES_UNREADABLE =
        "andvari couldn't read what this device keeps about moves that did not finish, so nothing was moved or copied and nothing was changed. Try again in a moment."

    /** NEW. The kept saves with files could not be read: nothing was saved, removed or changed. */
    const val KEPT_SAVES_UNREADABLE =
        "andvari couldn't read the saves with files this device keeps, so nothing was saved and nothing kept was removed. Try again in a moment."

    /** NEW. The list of automatic saves (or the extensions' queue) could not be read. */
    const val SAVES_LIST_UNREADABLE =
        "andvari couldn't read the logins captured for it on this device, or its list of automatic saves, so nothing was saved, undone or removed. Try again in a moment."

    // ---- kept saves with files (the old `AttachmentCopy`, word for word) ----

    const val FILE_NOT_SET_ASIDE = "This file could not be set aside for the save. Try again."
    const val KEPT_SAVE_DONE = "A save with files that was cut short is done."
    const val KEPT_SAVES_DONE = "saves with files that were cut short are done."

    fun savedWithoutFiles(name: String, why: String) = fillNames(CopyKey.KEPT_SAVE_WITHOUT_FILES, said(name), said(why))

    fun savedLater(name: String) = fillNames(CopyKey.KEPT_SAVE_LATER, said(name))

    /** A kept save that could not be finished now, for [why]: one whose session the server ended waits for the next sign-in. */
    fun savedLater(name: String, why: ItemFailure): String =
        if (why is ItemFailure.Refused && Written.keptFor(why) == Written.KEPT_SESSION_ENDED) fillNames(CopyKey.KEPT_SAVE_LATER_SIGN_IN, said(name))
        else savedLater(name)

    /** NEW (placeholder). A change refused while this device's copy is being removed for the server's policy. */
    val COPY_BEING_REMOVED: String get() = fillNames(CopyKey.SAVE_COPY_BEING_REMOVED)

    /** NEW (placeholder). The state's line while this device's copy is being removed for the server's policy (not a refusal). */
    val REMOVING_LINE: String get() = fillNames(CopyKey.POLICY_COPY_BEING_REMOVED)

    /** NEW (placeholder). A save already in the copy when its removal began: the policy's one try sends it (not "not made"). */
    val IN_POLICY_ATTEMPT: String get() = fillNames(CopyKey.SAVE_IN_POLICY_ATTEMPT)

    /** NEW (placeholder). A change into a shared vault whose deletion stands: refused on the device before anything is queued. */
    val VAULT_DELETED_READ_ONLY: String get() = fillNames(CopyKey.SAVE_VAULT_DELETED)

    /** NEW (placeholder). Caught logins the account could not open were removed: [n] of them, or an unknown number (n < 1). */
    fun capturesUnreadable(n: Int): String =
        if (n < 1) fillNames(CopyKey.CAPTURES_UNREADABLE_REMOVED)
        else counted(n, CopyKey.CAPTURES_UNREADABLE_REMOVED_ONE, CopyKey.CAPTURES_UNREADABLE_REMOVED_MANY)

    /** NEW (placeholder). The reason a kept save is let go when a file set aside for it is no longer on this device. */
    val KEPT_FILE_NOT_ON_DEVICE: String get() = fillNames(CopyKey.KEPT_FILE_NOT_ON_DEVICE)

    /**
     * A kept save let go for good, for [why] (a sentence): it says that andvari stopped trying and names what was lost, the
     * new item ([newItem]) or the changes, and the [files] new files added with it.
     */
    fun keptSaveGivenUp(name: String, newItem: Boolean, files: Int, why: String): String =
        fillNames(
            if (newItem) CopyKey.KEPT_SAVE_GIVEN_UP_NEW else CopyKey.KEPT_SAVE_GIVEN_UP_EDIT,
            said(name), said(why), Slot(counted(files, CopyKey.COUNT_FILES_ONE, CopyKey.COUNT_FILES_MANY), named = false),
        )

    fun filesOnly(name: String, removalsNotKept: Boolean) =
        fillNames(if (removalsNotKept) CopyKey.KEPT_SAVE_FILES_ONLY_REMOVALS_KEPT else CopyKey.KEPT_SAVE_FILES_ONLY, said(name))

    /** Round-10 review 3: what an earlier version kept on this device and this one could not carry over, counted. */
    fun earlierRecords(count: Int) =
        (if (count == 1) "One thing an earlier version of andvari kept on this device" else "$count things an earlier version of andvari kept on this device") +
            " (a save with files that was cut short, a move that did not finish, or an entry in the list of automatic saves) could not be carried over to this version, so " +
            (if (count == 1) "it was" else "they were") + " removed. Check that your recent changes are there, and make again any that are missing."

    /** NEW. "Remove from this device" on a vault that is still open to this account. */
    const val STILL_YOURS = "This vault is still open to you. To stop having it, leave it under Shared vaults."

    /**
     * NEW. The holding area's line for a vault, by why it left (design §3.11). [addedAgain]: the account was added to it
     * again and this device holds an invitation it can answer now, so its copy does not open; the line then says so, with
     * the vault's name ([vaultName], the plain words where it is not known here) and the day, in place of the reason and
     * the kept-until sentence. The day is named in [zone], this device's time zone as the content hands it in.
     */
    fun heldLine(
        reason: String, expungeAtMs: Long, ownedHere: Boolean = false, addedAgain: Boolean = false, vaultName: String = "",
        zone: TimeZone = TimeZone.UTC,
    ): String {
        if (addedAgain) {
            // The name comes from the server's invitation: one safe line, whatever a caller hands in (ItemText.label).
            val name = ItemText.label(vaultName)
            val vault = if (name.isEmpty()) Slot("a vault", named = false) else said(name)
            return fillNames(CopyKey.HELD_ADDED_AGAIN, vault, said(day(expungeAtMs, zone)))
        }
        val kept = said(fillNames(CopyKey.HELD_KEPT_UNTIL, said(day(expungeAtMs, zone))))
        val key = when (reason) {
            // The account's own delete is never "its owner's": it is the owner.
            ItemNotice.DELETED -> if (ownedHere) CopyKey.HELD_DELETED_BY_YOU else CopyKey.HELD_DELETED_BY_OWNER
            ItemNotice.PURGED -> if (ownedHere) CopyKey.HELD_PURGED_BY_YOU else CopyKey.HELD_PURGED_BY_OWNER
            ItemNotice.LEFT -> CopyKey.HELD_LEFT
            else -> CopyKey.HELD_ACCESS_REMOVED
        }
        return fillNames(key, kept)
    }

    // ---- failures ----

    /** What the failure is about, for the one row that differs: no answer from the server. */
    enum class During { SAVE, SYNC, OTHER }

    /** The sentence for [why]; never raw server or exception text. */
    fun forFailure(why: ItemFailure, during: During): String = when (why) {
        is ItemFailure.Unreachable -> when (during) {
            During.SAVE -> SAVE_FAILED_OFFLINE
            During.SYNC -> SYNC_OFFLINE
            During.OTHER -> UNREACHABLE
        }
        is ItemFailure.Refused -> forRefusal(why.code, why.status, during)
        is ItemFailure.Rollback -> ROLLBACK
        ItemFailure.Halted -> SERVER_STOPPED
        is ItemFailure.NotAllowed -> forRefusal(why.reason)
        is ItemFailure.Denied -> denied(why.count)
        is ItemFailure.Corrupt -> if (why.what == io.silencelen.andvari.core.client.items.ItemTransport.TRASH_INCOMPLETE) TRASH_LIST_INCOMPLETE else ATTACHMENT_DAMAGED
    }

    /** This device refused before anything was sent. */
    fun forRefusal(reason: ItemRefusal): String = when (reason) {
        ItemRefusal.NO_PERSONAL_VAULT -> NO_PERSONAL_VAULT
        ItemRefusal.VAULT_NOT_OPEN -> VAULT_NOT_OPEN
        ItemRefusal.VAULT_READ_ONLY -> READ_ONLY
        ItemRefusal.ITEM_GONE -> ITEM_GONE
        ItemRefusal.ITEM_CHANGED_VAULTS, ItemRefusal.EDIT_UNBOUND -> ITEM_CHANGED_VAULTS
        ItemRefusal.ITEM_CHANGED -> MOVE_CHANGED
        ItemRefusal.COPY_DENIED -> MOVE_DENIED
        ItemRefusal.COPY_UNCONFIRMED -> MOVE_RETRY
        ItemRefusal.SOURCE_DELETE_DENIED -> SOURCE_KEPT
        ItemRefusal.BAD_ID -> SOMETHING_WENT_WRONG
        ItemRefusal.VAULT_CLOSED_FOR_WRITING -> closedForWriting(VaultClosedReason.DELETION_WAITING)
    }

    /** A change refused because the app interface closed the vault for writing on this device, for [reason]. */
    fun closedForWriting(reason: VaultClosedReason): String = when (reason) {
        VaultClosedReason.DELETION_WAITING -> CopyKey.VAULT_CLOSED_DELETION_WAITING.fill(emptyList())
        VaultClosedReason.DELETION_MAY_BE_WAITING -> CopyKey.VAULT_CLOSED_DELETION_MAY_BE_WAITING.fill(emptyList())
    }

    /** The server's refusal, by its code first and its status after (the item-plane rows of `HouseholdCopy.apiCopy`). */
    fun forRefusal(code: String, status: Int, during: During): String = when (code) {
        "unknown_attachment", "attachment_mismatch" -> SAVE_REJECTED_ATTACHMENT
        "vault_deleted" -> "This vault was deleted. The owner can restore it for a few more days."
        "vault_gone" -> "The restore window has passed — this vault's data has been erased."
        "vault_state_changed" -> "This vault changed since you tried that — reload and try again."
        "stale_meta" -> STALE_META
        "not_vault_owner" -> NOT_VAULT_OWNER
        "quota_exceeded" -> OUT_OF_SPACE
        "rate_limited" -> TOO_MANY_REQUESTS
        "upgrade_required" -> UPGRADE_REQUIRED
        else -> when {
            status == 426 -> UPGRADE_REQUIRED
            status == 401 -> SESSION_EXPIRED
            status == 403 -> "You don't have permission to do that."
            status == 404 -> "The server couldn't find that — it may have been removed on another device."
            status == 409 -> "That changed somewhere else — sync, then try again."
            status == 410 -> "That's no longer available — it may have expired or been removed."
            status == 413 -> "The server refused that upload — it may be too large, or storage may be full."
            status == 429 -> TOO_MANY_REQUESTS
            status >= 500 -> if (during == During.SYNC) SYNC_FAILED else SERVER_PROBLEM
            status == 400 -> "The server couldn't accept that request — try again, and update andvari if it keeps happening."
            during == During.SAVE -> SAVE_FAILED
            during == During.SYNC -> SYNC_FAILED
            else -> SOMETHING_WENT_WRONG
        }
    }

    // ---- notices ----

    /**
     * What a notice of the item engine says, and whether it is a warning. The kinds the old `LifecycleNoticeCopy` knew
     * keep its sentences; `withheld`, `purged`, `meta-replay` and `rollback` are NEW.
     */
    fun notice(n: ItemNotice): Pair<String, Boolean> {
        val name = if (n.vaultName.isBlank()) Slot("a vault", named = false) else Slot(n.vaultName, named = true)
        val count = n.count ?: 0
        return when (n.kind) {
            ItemNotice.DELETED -> Pair(
                fillNames(CopyKey.NOTICE_VAULT_DELETED, name) +
                    (if (count > 1) " " + fillNames(CopyKey.NOTICE_EDITS_KEPT_MANY, said(count.toString()))
                    else if (count == 1) " " + fillNames(CopyKey.NOTICE_EDITS_KEPT_ONE) else ""),
                false,
            )
            ItemNotice.PURGED -> Pair(fillNames(CopyKey.NOTICE_VAULT_PURGED, name), false)
            ItemNotice.REMOVED -> Pair(fillNames(CopyKey.NOTICE_ACCESS_REMOVED, name), false)
            ItemNotice.LEFT -> Pair(fillNames(CopyKey.NOTICE_LEFT, name), false)
            ItemNotice.RESTORED -> Pair(fillNames(CopyKey.NOTICE_RESTORED, name), false)
            ItemNotice.ITEM_BROUGHT_BACK -> Pair(
                if (count <= 1) fillNames(CopyKey.NOTICE_ITEM_BROUGHT_BACK_ONE, n.itemName?.takeIf { it.isNotBlank() }?.let(::said) ?: Slot("an item", named = false), name)
                else fillNames(CopyKey.NOTICE_ITEM_BROUGHT_BACK_MANY, said(count.toString()), name),
                false,
            )
            ItemNotice.WITHHELD -> Pair(fillNames(CopyKey.NOTICE_WITHHELD, name), true)
            // "…while the vault was deleted" only where it was: a vault the server took away with no verified reason, or
            // one the account is a member of again after a removal or a departure, has a line of its own.
            ItemNotice.REPLAY_DENIED -> Pair(
                if (n.reason == ItemNotice.DELETED) {
                    if (count == 1) fillNames(CopyKey.NOTICE_REPLAY_DENIED_ONE, name)
                    else fillNames(CopyKey.NOTICE_REPLAY_DENIED_MANY, said(count.toString()), name)
                } else {
                    if (count == 1) fillNames(CopyKey.NOTICE_REPLAY_DENIED_BACK_ONE, name)
                    else fillNames(CopyKey.NOTICE_REPLAY_DENIED_BACK_MANY, said(count.toString()), name)
                },
                false,
            )
            ItemNotice.WRITE_REJECTED -> Pair(writeRejected(count, name, n.reason), true)
            ItemNotice.WRITE_DENIED -> Pair(writeDenied(count, n.itemName, n.vaultName), true)
            ItemNotice.WRONG_VAULT -> Pair(WRONG_VAULT_NOTICE, true)
            ItemNotice.BAD_ID -> Pair(BAD_ID_NOTICE, true)
            ItemNotice.META_REPLAY -> Pair(
                "The server sent an older name for one of your vaults than this device has already seen, so andvari kept the newer one. Tell your admin — the server may be misbehaving.",
                true,
            )
            ItemNotice.ROLLBACK -> Pair(ROLLBACK, true)
            ItemNotice.PERSONAL_KEPT -> Pair(PERSONAL_KEPT, true)
            else -> Pair(fillNames(CopyKey.NOTICE_SOMETHING_CHANGED, name), true)
        }
    }

    /**
     * The notice of [count] items whose change the server denied for good and which were undone on this device
     * ([ItemNotice.WRITE_DENIED]): [CopyKey.NOTICE_WRITE_DENIED_ONE] names the item ([itemName]; "an item" where it is
     * not known), [CopyKey.NOTICE_WRITE_DENIED_MANY] counts them; both name the vault ([vaultName]).
     */
    fun writeDenied(count: Int, itemName: String?, vaultName: String): String {
        val vault = if (vaultName.isBlank()) Slot("a vault", named = false) else Slot(vaultName, named = true)
        return if (count <= 1) fillNames(CopyKey.NOTICE_WRITE_DENIED_ONE, itemName?.takeIf { it.isNotBlank() }?.let(::said) ?: Slot("an item", named = false), vault)
        else fillNames(CopyKey.NOTICE_WRITE_DENIED_MANY, said(count.toString()), vault)
    }

    private fun writeRejected(count: Int, vault: Slot, reason: String?): String {
        val (one, many) = when (reason) {
            "unknown_attachment", "attachment_mismatch" -> CopyKey.NOTICE_WRITE_REJECTED_ATTACHMENT_ONE to CopyKey.NOTICE_WRITE_REJECTED_ATTACHMENT_MANY
            "item_attachment_quota", "body_too_large" -> CopyKey.NOTICE_WRITE_REJECTED_TOO_LARGE_ONE to CopyKey.NOTICE_WRITE_REJECTED_TOO_LARGE_MANY
            else -> CopyKey.NOTICE_WRITE_REJECTED_ONE to CopyKey.NOTICE_WRITE_REJECTED_MANY
        }
        return if (count == 1) fillNames(one, vault) else fillNames(many, said(count.toString()), vault)
    }

    private val MONTHS = listOf("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December")

    /**
     * "November 19": the day of the instant [ms] in [zone]. A line of Recently removed names the day in this device's
     * time zone, which the content takes from its host ([ContentHost.timeZone]) and hands in; the default, UTC, is only
     * for callers that name no zone.
     */
    fun day(ms: Long, zone: TimeZone = TimeZone.UTC): String {
        val date = Instant.fromEpochMilliseconds(ms).toLocalDateTime(zone).date
        return "${MONTHS[date.monthNumber - 1]} ${date.dayOfMonth}"
    }
}

/**
 * The line under an item's history ([ContentState.history]) when it has no earlier versions: its own key
 * ([CopyKey.ITEM_HISTORY_EMPTY]), never the empty vault's "Nothing here yet.". Null when there are versions to list.
 */
val io.silencelen.andvari.core.app.ItemHistoryView.emptyLine: CopyKey?
    get() = if (versions.isEmpty()) CopyKey.ITEM_HISTORY_EMPTY else null
