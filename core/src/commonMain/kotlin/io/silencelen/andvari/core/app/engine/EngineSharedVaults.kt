package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.client.items.VaultClosedReason
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.ContactRow
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.MemberRow
import io.silencelen.andvari.core.app.MembersScreen
import io.silencelen.andvari.core.app.MoveEverythingScreen
import io.silencelen.andvari.core.app.MoveFinished
import io.silencelen.andvari.core.app.MoveKept
import io.silencelen.andvari.core.app.MoveMemberRow
import io.silencelen.andvari.core.app.MoveStage
import io.silencelen.andvari.core.app.MoveStop
import io.silencelen.andvari.core.app.content.ContentCopy
import io.silencelen.andvari.core.app.content.SpaceCheck
import io.silencelen.andvari.core.app.content.SpaceVerdict
import io.silencelen.andvari.core.app.OwnershipOfferRow
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.SharedVaultRow
import io.silencelen.andvari.core.app.SharedVaultsApi
import io.silencelen.andvari.core.app.UncomparedShareWarning
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AdoptionRefusal
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.app.WaitingChange
import io.silencelen.andvari.core.app.WaitingKind
import io.silencelen.andvari.core.app.WaitingKnown
import io.silencelen.andvari.core.app.WaitingNotice
import io.silencelen.andvari.core.app.WaitingResult
import io.silencelen.andvari.core.app.WaitingUndo
import io.silencelen.andvari.core.client.log.FoundKind
import io.silencelen.andvari.core.client.log.HeldFinding
import io.silencelen.andvari.core.client.log.HeldKind
import io.silencelen.andvari.core.client.log.HeldKnown
import io.silencelen.andvari.core.client.log.HeldLook
import io.silencelen.andvari.core.client.log.HeldRepost
import io.silencelen.andvari.core.client.log.HeldWithdrawal
import io.silencelen.andvari.core.client.log.LetGo
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.ServerGrant
import io.silencelen.andvari.core.client.log.ServerGrants
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.log.VerifiedVaultState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.trust.MemberRole
import io.silencelen.andvari.core.trust.VaultLogVerdict
import kotlinx.coroutines.launch

/**
 * Shared vaults (design §3) on the vault-log engine ([EngineVault.logs]): the rows with the state of their history,
 * members, the log actions, incoming vaults and the ways out of a vault whose history does not check out.
 *
 * Everything a row says comes from the log this device verified ([StoredVaultLogs.status]) and from the adoption rules
 * ([StoredVaultLogs.adoption]); the server's rows only say which vaults to look at. A vault this device holds no key
 * for is looked at again after every sync ([refresh]): the outcome is what makes it an incoming prompt, a "connect
 * first" row or a refused key.
 */
/** A day, by the engine's clock: a change held longer is not sent again and is given up (design §3.7). */
private const val HELD_DAY_MS = 24L * 60 * 60 * 1000

internal class EngineSharedVaults(private val app: EngineAppApi) : SharedVaultsApi, io.silencelen.andvari.core.app.MoveNotes,
    io.silencelen.andvari.core.app.WaitingChanges {
    /** The last adoption outcome of each vault this device holds no key for (none for a vault it adopted). */
    private val adoptions = HashMap<String, Adoption>()

    /** The prompt shown for each incoming vault, the same object while its `add` is the same. */
    private val incoming = HashMap<String, AccountPrompt.IncomingVault>()

    /** Vaults a save or a share was refused for space in (§7.4), this session. */
    private val outOfSpace = HashSet<String>()

    private var membersOf: String? = null

    /**
     * The server's member list for the open Members screen, as last read ([readGrants]): the server's word, shown only
     * against the verified head it was read at, and dropped with the screen.
     */
    private var grantsRead: ServerGrants? = null
    private var warning: UncomparedShareWarning? = null
    private var moveOf: String? = null
    private var moveRemoving: String? = null
    private var moveTicks = HashMap<String, Boolean>()
    private var moveProgress: Triple<Boolean, Int, Int> = Triple(false, 0, 0)
    private var moveFinished: MoveFinished? = null

    /** The last run's check for space when it found the account short (shown on the move's screen). */
    private var moveSpace: SpaceCheck? = null

    /**
     * Moves this device started and has not finished, by the old vault's id, as read this opening: a second run carries
     * on from where the first stopped (the same new vault; items copied and members added are not done again). Each one
     * is kept on the device ([MoveRecord], per account and old vault), so a lock or a restart does not drop it; it goes
     * when the move ends or the account's data leaves the device ([dropMoves]).
     */
    private val moveRuns = HashMap<String, MoveRun>()

    /** The old vaults whose kept record this opening looked for (found or not). */
    private val runsLooked = HashSet<String>()

    /** The old vaults whose kept record could not be read this opening: no move of them runs (it could make a second new vault). */
    private val runsUnreadable = HashSet<String>()

    /** The first screen's offers to finish a move the person put off until the next unlock ([unfinishedMoveLater]). */
    private val movesPutOff = HashSet<String>()

    private class MoveRun(var name: String, val plannedId: String) {
        var removed = false
        var newVaultId: String? = null

        /**
         * The old vault's `delete` was signed and sent, and the server has not confirmed it yet: the old vault still exists
         * (the server did not store the change), and the next run looks at what the server holds before anything else.
         */
        var deleteSent = false

        /** The old vault's verified head the held delete followed: a later stored head means its place was taken. */
        var deleteAtSeq = -1L

        /** What was copied, by item and the revision copied: a later revision is not copied yet. */
        val copied = HashMap<String, Long>()

        /** Each copied item's copy in the new vault, by the original's id: a later revision replaces it (decided on 16 November 2026). */
        val copies = HashMap<String, String>()

        /** Copies in the new vault that a later revision replaced, still to be deleted there. */
        val stale = LinkedHashSet<String>()
        val added = HashSet<String>()
        var stop: MoveStop? = null

        /**
         * Half-made new vaults of earlier runs that hold someone the present plan does not add:
         * they hold only copies, and are deleted once this run has finished.
         */
        val discard = ArrayList<String>()

        /** [MoveRecord.storedOutside]. */
        var storedOutside = false

        /** [MoveRecord.deletionsCarried]. */
        var deletionsCarried = 0

        /** [MoveRecord.deletionsKept]. */
        var deletionsKept = 0

        /** Each copy's revision when the move made it, by the original's id ([MoveCopy.copyRev]). */
        val copyRevs = HashMap<String, Long>()

        /** [stale] copies' revisions when the move made them: each is deleted only at that revision ([MoveRecord.staleRevs]). */
        val staleRevs = HashMap<String, Long>()

        /** Copies this move deleted in its new vault (they lie in its trash: the move's own, [MoveRecord.staleDeleted]). */
        val staleDeleted = LinkedHashSet<String>()

        /** What the move made in each half-made vault of [discard] ([MoveRecord.discardMade]); one with none is never deleted. */
        val discardMade = HashMap<String, HalfMade>()

        /** Earlier copies kept beside a newer one: changed in the new vault since the move made them, or no revision known. */
        var keptBesideChanged = 0
        var keptBesideNoRevision = 0

        /** Earlier copies kept beside a newer one because the server refused their deletion. */
        var keptBesideRefused = 0

        /** Items not copied again because their copy was deleted in the new vault since ([MoveRecord.deletedThere]). */
        var deletedThere = 0

        /** Everything this run made in its new vault, as a later run judges it once that vault is half-made. */
        fun madeHere(): HalfMade = HalfMade(
            copies.entries.associate { (orig, copy) -> copy to copyRevs[orig] } + stale.associateWith { staleRevs[it] },
            staleDeleted.toList(),
        )

        /** [itemId]'s copy is replaced by a newer one: the earlier copy is to be deleted at the revision it was made at. */
        fun replaced(itemId: String) {
            val earlier = copies.remove(itemId)
            val rev = copyRevs.remove(itemId)
            if (earlier == null) return
            stale += earlier
            if (rev != null) staleRevs[earlier] = rev
        }

        /** Record [copyId] as [itemId]'s copy, at the revision [v] holds of it now (it was just made). */
        fun copyMade(v: EngineVault, itemId: String, copyId: String) {
            copies[itemId] = copyId
            val rev = v.items.items().firstOrNull { it.itemId == copyId }?.rev
            if (rev != null) copyRevs[itemId] = rev else copyRevs.remove(itemId)
        }

        fun record() = MoveRecord(plannedId, newVaultId, removed, deleteSent, deleteAtSeq,
            copied.mapValues { (id, rev) -> MoveCopy(rev, copies[id], copyRevs[id]?.takeIf { copies[id] != null }) }, stale.toList(), added.sorted(), discard.toList(),
            storedOutside, deletionsCarried, deletionsKept, staleRevs.filterKeys { it in stale }, staleDeleted.toList(),
            discardMade.filterKeys { it in discard }, keptBesideChanged, keptBesideNoRevision, keptBesideRefused, deletedThere)

        companion object {
            fun of(r: MoveRecord, name: String) = MoveRun(name, r.plannedId).also { run ->
                run.newVaultId = r.newVaultId
                run.removed = r.removed
                run.deleteSent = r.deleteSent
                run.deleteAtSeq = r.deleteAtSeq
                r.copied.forEach { (id, c) ->
                    run.copied[id] = c.rev
                    c.copyId?.let { run.copies[id] = it }
                    c.copyRev?.let { run.copyRevs[id] = it }
                }
                run.stale += r.stale
                run.added += r.added
                run.discard += r.discard
                run.storedOutside = r.storedOutside
                run.deletionsCarried = r.deletionsCarried
                run.deletionsKept = r.deletionsKept
                run.staleRevs += r.staleRevs
                run.staleDeleted += r.staleDeleted
                run.discardMade += r.discardMade
                run.keptBesideChanged = r.keptBesideChanged
                run.keptBesideNoRevision = r.keptBesideNoRevision
                run.keptBesideRefused = r.keptBesideRefused
                run.deletedThere = r.deletedThere
            }
        }
    }

    private fun moveKey(v: EngineVault, from: String) = "$MOVE_PREFIX${v.origin}|${v.userId}|$from"

    /**
     * The run of [from] this device keeps, read once per opening; null when none is kept. A record the device state
     * cannot read now marks [from] in [runsUnreadable]; one that reads but does not decode is not this version's, and goes.
     */
    private fun runFor(v: EngineVault, from: String): MoveRun? {
        moveRuns[from]?.let { return it }
        if (!runsLooked.add(from)) return null
        val text = try {
            app.engine.state.get(moveKey(v, from))
        } catch (e: Exception) {
            runsUnreadable += from
            return null
        } ?: return null
        val record = runCatching { moveJson.decodeFromString(MoveRecord.serializer(), text) }.getOrNull()
        if (record == null) {
            runCatching { app.engine.state.set(moveKey(v, from), null) }
            return null
        }
        // No name is kept: the new vault's own name once it is made, otherwise the one typed for the next run.
        val name = record.newVaultId?.let { id -> v.content.state.vaults.firstOrNull { it.vaultId == id }?.name }.orEmpty()
        val run = MoveRun.of(record, name)
        if (run.deleteSent && !run.storedOutside) run.stop = MoveStop(MoveStage.DELETE_OLD_VAULT, name, run.copied.size, run.copied.size, VaultActionResult.SENT_PENDING, CopyKey.MOVE_DELETE_UNCONFIRMED)
        moveRuns[from] = run
        return run
    }

    /** Keep [run] on the device, as it stands now. */
    private fun keepRun(v: EngineVault, from: String, run: MoveRun) {
        runCatching { app.engine.state.set(moveKey(v, from), moveJson.encodeToString(MoveRecord.serializer(), run.record())) }
    }

    /** The move of [from] ended: the run goes, here and on the device. */
    private fun dropRun(v: EngineVault, from: String) {
        moveRuns.remove(from)
        runCatching { app.engine.state.set(moveKey(v, from), null) }
        // No deletion of this move waits any more (stored, or the vault is gone from this device).
        if (!v.closed && ownMark(v.items.closedForWriting(from))) v.content.markVaultClosedForWriting(from, null)
    }

    /** The line for [row]'s panel and the first screen while a move of it is unfinished ([SharedVaultRow.unfinishedMove]). */
    private fun unfinishedLine(v: EngineVault, vaultId: String, oldName: String?): io.silencelen.andvari.core.app.CopyLine? {
        val run = runFor(v, vaultId)?.takeIf { !it.storedOutside } ?: return null
        val newName = newNameOf(v, run)
        return io.silencelen.andvari.core.app.CopyLine.of(if (run.deleteSent) CopyKey.MOVE_DELETE_WAITING else CopyKey.MOVE_UNFINISHED, oldName.orEmpty(), newName)
    }

    /** The first screen's offers to finish a move ([io.silencelen.andvari.core.app.AccountSnapshot.unfinishedMoves]). */
    fun unfinishedMoves(rows: List<SharedVaultRow>): List<io.silencelen.andvari.core.app.UnfinishedVaultMove> {
        if (vault() == null) return emptyList()
        return rows.mapNotNull { row ->
            val line = row.unfinishedMove ?: return@mapNotNull null
            if (row.vaultId in movesPutOff || row.vaultId == moveOf) return@mapNotNull null
            io.silencelen.andvari.core.app.UnfinishedVaultMove(row, line.key == CopyKey.MOVE_DELETE_WAITING, line)
        }
    }

    override fun unfinishedMoveLater(move: io.silencelen.andvari.core.app.UnfinishedVaultMove) {
        if (vault() == null) return
        movesPutOff += move.vault.vaultId
        app.publish()
    }

    private fun newNameOf(v: EngineVault, run: MoveRun): String =
        run.newVaultId?.let { id -> v.content.state.vaults.firstOrNull { it.vaultId == id }?.name } ?: run.name

    // ---- a move's deletion stored outside the move (a server holds the signed deletion and stores it later) ----

    /** The old vault whose move is running now ([moveEverything]): only that run sees its own deletion stored. */
    private var runOf: String? = null

    /** What each stored-outside notice counts, (added, changed), by old vault, this opening: read again after a copy. */
    private val lateCounts = HashMap<String, Pair<Int, Int>>()

    /** The line after a copy, by old vault, this opening. */
    private val lateCopied = HashMap<String, io.silencelen.andvari.core.app.CopyLine>()

    private val storedNotices = HashMap<String, io.silencelen.andvari.core.app.MoveStoredNotice>()

    /** The vaults a kept move record may be about: the rows' and the holding area's. */
    private fun recordIds(v: EngineVault): Set<String> {
        val ids = LinkedHashSet<String>()
        ids += v.rows.vaultIds()
        v.content.state.held.forEach { ids += it.vaultId }
        ids -= v.personalVaultId
        return ids
    }

    /**
     * After a completed sync: a move whose deletion was signed and waiting, and whose old vault this device now sees
     * deleted (or in the holding area), while no run of that move is going on, had its deletion stored outside the move.
     * It is not the person's quiet departure: the record says so, and the notice below counts what changed after the copies.
     */
    private fun seeStoredOutside(v: EngineVault) {
        val held = v.content.state.held.mapTo(HashSet()) { it.vaultId }
        for (id in recordIds(v)) {
            if (id == runOf) continue
            val run = runFor(v, id) ?: continue
            // Restored by its owner after the deletion was stored (decided on 2026-11-17): a live vault again, never the
            // old vault of a move. The record ends there; what was copied stays where it is, and the notice goes. Only a log
            // this device verified, holding no deletion, says so: one it withholds judgement on (a server serving an older
            // state of it), or one that failed, never ends the record, its notice or what it still carries.
            val restored = (v.logs.status(id) as? VaultLogStatus.Verified)?.state?.let { it.deletedId == null } == true
            if (run.storedOutside && !deleteStored(v, id) && id !in held && restored) {
                dropRun(v, id)
                storedNotices.remove(id)
                lateCounts.remove(id)
                lateCopied.remove(id)
                continue
            }
            if (!run.deleteSent || run.storedOutside) continue
            if (!deleteStored(v, id) && id !in held && v.logs.status(id) !is VaultLogStatus.Purged) continue
            run.storedOutside = true
            run.stop = null
            keepRun(v, id, run)
            lateCounts.remove(id)
            if (moveOf == id && !moveProgress.first) closeMoveEverything()
        }
        // A notice whose vault this device no longer holds at all (its holding days are over): nothing is left to copy.
        val ids = recordIds(v)
        for ((id, run) in moveRuns.entries.toList()) if (run.storedOutside && id !in ids) dropRun(v, id)
        // The finishing run carries the person's own waiting deletions, without a question (decided on 2026-11-17), each at
        // the revision the move made its copy at ([carryOwnDeletions]), in the vault's own scope.
        for ((id, run) in moveRuns.entries.toList()) {
            if (!run.storedOutside || deletionPicks(v, id, run).isEmpty() || id in carrying) continue
            app.scope.launch { if (carryOwnDeletions(v, id, run)) app.publish() }
        }
    }

    /** What this device holds of [oldId] that the move's record does not hold as copied: (added, changed). */
    private fun lateOf(v: EngineVault, oldId: String, run: MoveRun): Pair<Int, Int> = lateCounts.getOrPut(oldId) {
        val heldNow = lateItems(v, oldId, run)
        heldNow.count { it.itemId !in run.copied } to heldNow.count { it.itemId in run.copied }
    }

    /**
     * The items of [oldId] this device holds (in the holding area, or still open) added or changed after their copy,
     * and those with a change that was waiting to be sent when the vault closed (the item engine kept it back, and it
     * is carried as the item's newest content).
     */
    private fun lateItems(v: EngineVault, oldId: String, run: MoveRun): List<io.silencelen.andvari.core.client.VaultItem> {
        val heldNow = v.items.heldItems(oldId).ifEmpty { v.items.items().filter { it.vaultId == oldId } }
        val waiting = v.items.waitingChanges(oldId)
        // The person's own deletion that waited when the vault closed is neither added nor changed: it is carried by
        // itself ([carryOwnDeletions]), without a question (decided on 2026-11-17).
        val deleted = v.items.waitingDeletions(oldId)
        return heldNow.filter { it.itemId !in deleted && (run.copied[it.itemId] != it.rev || it.itemId in waiting) }.sortedBy { it.itemId }
    }

    /**
     * The person's own waiting deletions of [oldId] whose item has a copy in the new vault, as picks for the content's copy
     * of held items: each names the copy and the revision the move made it at ([MoveRun.copyRevs]; none known: null). The
     * content deletes the copy only at that revision, decided against the copy as the server holds it when the deletion
     * is sent, and keeps it at any other (changed elsewhere since, or a change of it still waiting here) or with no
     * revision named; the answer goes through [recordDeleted] (carried, or kept and counted). Nothing is ever deleted at a
     * revision this device did not record.
     */
    private fun deletionPicks(v: EngineVault, oldId: String, run: MoveRun): List<io.silencelen.andvari.core.client.items.HeldPick> =
        v.items.waitingDeletions(oldId).filter { it in run.copies }.sorted()
            .map { io.silencelen.andvari.core.client.items.HeldPick(it, run.copies[it], run.copyRevs[it]) }

    /**
     * The finishing run carries the person's own waiting deletions of [oldId] into the new vault without a question
     * (decided on 2026-11-17), each at its recorded revision ([deletionPicks]). Answers whether anything was settled.
     */
    private suspend fun carryOwnDeletions(v: EngineVault, oldId: String, run: MoveRun): Boolean {
        val target = run.newVaultId ?: return false
        val picks = deletionPicks(v, oldId, run)
        if (picks.isEmpty() || !carrying.add(oldId)) return false
        try {
            val b = app.unlessLocked(null) { app.working { v.content.bringHeldItemsInto(oldId, target, picks) } } ?: return false
            if (v.closed || vault() == null) return false
            recordDeleted(v, oldId, run, b)
            lateCounts.remove(oldId)
            return b.deleted.isNotEmpty()
        } finally {
            carrying -= oldId
        }
    }

    /** The old vaults whose deletions are being carried now: one carry at a time each. */
    private val carrying = HashSet<String>()

    /** An earlier copy the content kept beside its newer one, counted by why ([io.silencelen.andvari.core.client.items.HeldDeleted]). */
    private fun keptBeside(run: MoveRun, why: String?) {
        when (why) {
            io.silencelen.andvari.core.client.items.HeldDeleted.KEPT_NO_REVISION -> run.keptBesideNoRevision++
            io.silencelen.andvari.core.client.items.HeldDeleted.KEPT_REFUSED -> run.keptBesideRefused++
            else -> run.keptBesideChanged++
        }
    }

    /**
     * What the content's copy of held items said of an item it found deleted (the person's own waiting deletion, picked by
     * [deletionPicks] at its recorded revision): its copy goes from the record. Only a deletion whose earlier copy really went counts as
     * carried; one with no earlier copy named, or whose deletion was kept
     * ([io.silencelen.andvari.core.client.items.HeldDeleted.earlierKept]), counts as kept: the copy stays live, and the
     * notice says how many.
     */
    private fun recordDeleted(v: EngineVault, oldId: String, run: MoveRun, b: io.silencelen.andvari.core.app.content.HeldBrought) {
        if (b.deleted.isEmpty()) return
        for (d in b.deleted) {
            run.copied[d.itemId] = d.rev
            run.copies.remove(d.itemId)
            run.copyRevs.remove(d.itemId)
            if (d.earlier == null || d.earlierKept) run.deletionsKept++ else run.deletionsCarried++
        }
        keepRun(v, oldId, run)
    }

    /** [io.silencelen.andvari.core.app.AccountSnapshot.movesStoredOutside]. */
    fun movesStoredOutside(): List<io.silencelen.andvari.core.app.MoveStoredNotice> {
        val v = vault() ?: return emptyList()
        val out = ArrayList<io.silencelen.andvari.core.app.MoveStoredNotice>()
        for (id in recordIds(v).sorted()) {
            val run = runFor(v, id)?.takeIf { it.storedOutside } ?: continue
            val oldName = v.content.state.held.firstOrNull { it.vaultId == id }?.name?.ifEmpty { null }
                ?: v.content.state.vaults.firstOrNull { it.vaultId == id }?.name.orEmpty()
            val newName = newNameOf(v, run)
            val (added, changed) = lateOf(v, id, run)
            val target = run.newVaultId
            val canCopy = added + changed > 0 && target != null && v.content.vaultsForNewItems().any { it.vaultId == target }
            val line = if (added + changed > 0) io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_STORED_OUTSIDE, oldName, newName, added.toString(), changed.toString())
                else io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_STORED_OUTSIDE_NOTHING_LATE, oldName, newName)
            val copiedLine = lateCopied[id]
            val carried = run.deletionsCarried
            val kept = run.deletionsKept
            val beside = listOf(CopyKey.MOVE_KEPT_BESIDE_CHANGED to run.keptBesideChanged, CopyKey.MOVE_KEPT_BESIDE_NO_REVISION to run.keptBesideNoRevision,
                CopyKey.MOVE_KEPT_BESIDE_REFUSED to run.keptBesideRefused).filter { it.second > 0 }
            val there = run.deletedThere
            val shown = storedNotices[id]?.takeIf {
                it.oldName == oldName && it.intoName == newName && it.added == added && it.changed == changed && it.canCopy == canCopy &&
                    it.copiedLine == copiedLine && it.deletionsCarried == carried && it.deletionsKept == kept && it.deletedThere == there &&
                    it.keptBesideLines.map { l -> l.key to l.values.first().toInt() } == beside
            }
            val carriedLine = if (carried > 0) io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_STORED_DELETIONS_CARRIED, carried.toString(), newName) else null
            val keptLine = if (kept > 0) io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_STORED_DELETIONS_KEPT, kept.toString(), newName) else null
            val besideLines = beside.map { (key, n) -> io.silencelen.andvari.core.app.CopyLine.of(key, n.toString(), newName) }
            val thereLine = if (there > 0) io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_STORED_DELETED_THERE, there.toString(), newName) else null
            out += shown ?: io.silencelen.andvari.core.app.MoveStoredNotice(id, oldName, target, newName, added, changed, canCopy, line, copiedLine, carried, carriedLine,
                kept, keptLine, besideLines, there, thereLine)
                .also { storedNotices[id] = it }
        }
        return out
    }

    override suspend fun bringLateIntoMove(notice: io.silencelen.andvari.core.app.MoveStoredNotice): VaultActionResult {
        val v = vault() ?: return VaultActionResult.STALE
        if (storedNotices[notice.oldVaultId] !== notice) return VaultActionResult.STALE
        val oldId = notice.oldVaultId
        val run = runFor(v, oldId)?.takeIf { it.storedOutside } ?: return VaultActionResult.STALE
        val target = run.newVaultId ?: return VaultActionResult.NOT_ALLOWED
        if (v.content.vaultsForNewItems().none { it.vaultId == target }) return VaultActionResult.READ_ONLY
        // The finishing run's carry of the person's deletions is under way: one call at a time over the same items.
        if (oldId in carrying) return VaultActionResult.STALE
        var copied = 0
        fun done(r: VaultActionResult): VaultActionResult {
            lateCounts.remove(oldId)
            if (copied > 0) lateCopied[oldId] = io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_STORED_COPIED, copied.toString(), newNameOf(v, run))
            app.publish()
            return r
        }
        // Every item with its files, through the content's own copy of held items: each file is re-sealed under a fresh key,
        // a changed item replaces its earlier copy only once the new one is confirmed, and a second run copies nothing.
        // The person's own waiting deletions are carried with the late items, each at the revision the move made its
        // copy at ([deletionPicks]); a copy changed since, or of no known revision, is kept and counted.
        val picks = deletionPicks(v, oldId, run) +
            lateItems(v, oldId, run).map { io.silencelen.andvari.core.client.items.HeldPick(it.itemId, run.copies[it.itemId], run.copyRevs[it.itemId]) }
        if (picks.isNotEmpty()) {
            val b = app.unlessLocked(null) { app.working { v.content.bringHeldItemsInto(oldId, target, picks) } } ?: return VaultActionResult.STALE
            if (v.closed || vault() == null) return VaultActionResult.STALE
            recordDeleted(v, oldId, run, b)
            for (c in b.made) {
                val earlier = run.copies[c.itemId]
                run.copied[c.itemId] = c.rev
                // Answered as found while this device holds no copy of it: its copy was deleted in the new vault since (by
                // anyone there). It is not made again, and never counted as copied (the engine tells it by a field of its own).
                if (c.deletedThere) {
                    run.copies.remove(c.itemId)
                    run.copyRevs.remove(c.itemId)
                    run.deletedThere++
                    keepRun(v, oldId, run)
                    continue
                }
                // A second run answers the copy already recorded: it is the live copy, never one to delete.
                if (earlier != c.madeItemId) {
                    run.copyMade(v, c.itemId, c.madeItemId)
                    // The call deleted the earlier copy itself, or kept it on purpose (changed since, its deletion
                    // denied, or no revision of it known): either way it is no longer this move's to delete.
                    if (earlier != null) {
                        run.stale -= earlier
                        if (c.earlierKept) keptBeside(run, c.keptBecause)
                    }
                }
                keepRun(v, oldId, run)
                copied++
            }
            when (val r = b.result) {
                is ActionResult.Ok -> {}
                is ActionResult.NotDone -> return done(VaultActionResult.STALE)
                else -> return done(if (r is ActionResult.Failed && ContentCopy.isOutOfSpace(r.message)) VaultActionResult.OUT_OF_SPACE else VaultActionResult.FAILED)
            }
        }
        for (old in run.stale.toList()) {
            when (dropStale(v, oldId, old, run)) {
                null -> return VaultActionResult.STALE
                false -> return done(VaultActionResult.FAILED)
                true -> {}
            }
        }
        v.afterLogAction()
        return done(VaultActionResult.DONE)
    }

    /**
     * [old], an earlier copy in the new vault that a newer copy replaced, is deleted only at the revision the move made it
     * at ([MoveRun.staleRevs]), and only while no change of it waits on this device: the content's deletion sends the
     * revision this device holds, checked here to be that one. Changed since (here or elsewhere), or of no known revision,
     * it is kept beside the newer copy and counted ([MoveRun.keptBesideChanged], [MoveRun.keptBesideNoRevision]); gone
     * already, there is nothing to delete. Answers true when [old] is settled, false when its deletion failed (it stays
     * to be deleted), null when a lock overtook it.
     */
    private suspend fun dropStale(v: EngineVault, from: String, old: String, run: MoveRun): Boolean? {
        val copy = v.items.item(old)
        val at = run.staleRevs[old]
        when {
            copy == null -> {}
            at == null -> run.keptBesideNoRevision++
            copy.rev != at || old in v.items.waitingChanges(copy.vaultId) -> run.keptBesideChanged++
            else -> {
                val r = v.content.deleteItem(old)
                if (v.closed || vault() == null) return null
                if (r !is ActionResult.Ok) return false
                run.staleDeleted += old
            }
        }
        run.stale -= old
        run.staleRevs.remove(old)
        keepRun(v, from, run)
        return true
    }

    override fun dismissMoveStored(notice: io.silencelen.andvari.core.app.MoveStoredNotice) {
        val v = vault() ?: return
        if (storedNotices[notice.oldVaultId] !== notice) return
        storedNotices.remove(notice.oldVaultId)
        lateCopied.remove(notice.oldVaultId)
        lateCounts.remove(notice.oldVaultId)
        dropRun(v, notice.oldVaultId)
        app.publish()
    }

    /** Who the present plan of [screen] adds to the new vault: every remaining member, or on a frozen or failed vault those ticked. */
    private fun planAdds(screen: MoveEverythingScreen): Set<String> =
        (if (screen.sourceStays) screen.members.filter { it.ticked } else screen.members).mapTo(HashSet()) { it.userId }

    /**
     * A stopped run may be carried on only while every member its half-made new vault holds (as
     * its verified log says, and as the run counted) is among the people the present plan adds. Removing someone from
     * the new vault would not take back the key they were given, so otherwise the move starts a fresh vault.
     */
    private fun resumable(v: EngineVault, run: MoveRun, adds: Set<String>): Boolean {
        val id = run.newVaultId ?: return (run.added - adds).isEmpty()
        val held = verifiedState(v.logs.status(id))?.members?.keys ?: return false
        return ((held - me(v)) + run.added).all { it in adds }
    }
    private var refreshing = false
    private var syncSeen = false

    /** The session ended, moved or locked: nothing of this account's screens or outcomes is kept. */
    fun ended() {
        adoptions.clear()
        // The notes stay at rest; the next opening reads them again.
        notes.clear()
        notesOf = null
        incoming.clear()
        outOfSpace.clear()
        membersOf = null
        grantsRead = null
        warning = null
        warningForLink = null
        moveOf = null
        moveRemoving = null
        moveTicks.clear()
        moveProgress = Triple(false, 0, 0)
        moveFinished = null
        moveSpace = null
        // The runs stay kept on the device ([MoveRecord]): the next opening reads them again.
        moveRuns.clear()
        runsLooked.clear()
        runsUnreadable.clear()
        movesPutOff.clear()
        lateCounts.clear()
        lateCopied.clear()
        storedNotices.clear()
        refreshing = false
        syncSeen = false
    }

    private fun vault(): EngineVault? = app.vault?.takeIf { !it.closed && app.phase == AppPhase.UNLOCKED }

    /** The name of the open invitation to [vaultId], as its prompt shows it; null where none is known now. */
    internal fun openInvitationName(vaultId: String): String? = (adoptions[vaultId] as? Adoption.AskAccept)?.vaultName

    // ---- a vault whose deletion is signed and waiting is closed for writing by the content (design §3.13) ----

    /**
     * An opening is composed: before anything runs in it, every old vault whose kept move signed the deletion and waits
     * is closed for writing through the content's own call, with its reason. The marks are kept in the cache as well;
     * this covers a record kept by a version that did not set them.
     */
    fun composed(v: EngineVault) {
        for (id in signedDeletions(app.engine.state, v.origin, v.userId)) {
            if (v.items.closedForWriting(id) == null) v.content.markVaultClosedForWriting(id, VaultClosedReason.DELETION_WAITING)
        }
        // And a kept move whose old vault holds a change a lock may have overtaken after its signature (moveDeleteWaiting).
        for (id in recordIds(v)) {
            val why = waitingReason(v, id) ?: continue
            if (v.items.closedForWriting(id) == null) v.content.markVaultClosedForWriting(id, why)
        }
    }

    /**
     * Design §3.13 (rule of 2026-11-17): from the moment the old vault's deletion by "Move everything" is signed, the
     * content closes that vault for writing, with [VaultClosedReason.DELETION_WAITING] ([closeForDeletion], before the
     * signature); it is opened again only when that deletion is no longer waiting: refused for good, dropped because
     * another change took its place, or stored (the vault is then deleted, and a later restore of it is the deletion
     * withdrawn). A mark of that reason with no waiting deletion behind it goes here; marks of other reasons are not
     * this code's.
     */
    private fun closeWaiting(v: EngineVault, only: String? = null) {
        if (v.closed) return
        for (id in only?.let(::listOf) ?: recordIds(v)) {
            // The move running now sets and clears its own vault's mark around its signature (it passes [only]).
            if (only == null && id == runOf) continue
            val why = waitingReason(v, id)
            val mark = v.items.closedForWriting(id)
            if (why != null && (mark == null || (ownMark(mark) && mark != why))) v.content.markVaultClosedForWriting(id, why)
            else if (why == null && ownMark(mark)) v.content.markVaultClosedForWriting(id, null)
        }
    }

    /** The move is about to sign [from]'s deletion: the vault is closed for writing first, so nothing goes in after the signature. */
    private fun closeForDeletion(v: EngineVault, from: String) {
        v.content.markVaultClosedForWriting(from, VaultClosedReason.DELETION_WAITING)
    }

    // ---- looking at the vaults again after a sync ----

    /**
     * The content published a new state: when a sync has just finished, the vaults this device holds no key for are
     * looked at again (in the vault's own scope, so a lock stops it).
     */
    fun contentChanged() {
        val v = vault() ?: return
        val syncing = v.content.state.syncing
        if (syncing) {
            syncSeen = true
            return
        }
        if (!syncSeen) return
        syncSeen = false
        pruneOwnDepartures(v)
        seeStoredOutside(v)
        // A deletion stored (outside the move or in it) or no longer waiting opens the vault's mark; one still waiting keeps it.
        closeWaiting(v)
        // Nothing here re-posts a change that waits. A completed sync runs the general re-send ([settleWaiting]), which never
        // sends a deletion that waits for the person's word nor a move's own deletion (the move re-posts that itself, after
        // it looked at the log and copied what is new), and never an addition whose contact changed; the log engine also
        // re-posts a vault's held change before its next action on that vault.
        v.launch { refresh() }
    }

    /** Run the adoption rules for every shared vault this device holds no key for, and keep what they answered. */
    suspend fun refresh() {
        val v = vault() ?: return
        if (refreshing) return
        refreshing = true
        var adopted = false
        try {
            for (id in v.rows.vaultIds()) {
                if (id == v.personalVaultId) continue
                if (v.logs.adoptionSettled(id)) {
                    adoptions.remove(id)
                    continue
                }
                if (v.logs.status(id) is VaultLogStatus.Unknown) continue
                val a = v.logs.adoption(id)
                if (v.closed) return
                adoptions[id] = a
                if (a is Adoption.Adopted) adopted = true
            }
        } finally {
            refreshing = false
        }
        // A key adopted here (a self-wrap another device of the account posted): its items come with the next sync.
        if (adopted) v.afterLogAction()
        app.publish()
        readGrants()
    }

    /**
     * Read the server's member list for the open Members screen (design §3.11): when it opens, after a change to its vault
     * and after a sync. In the vault's scope, so a lock stops it; an answer for a screen no longer open is dropped.
     */
    private fun readGrants() {
        val v = vault() ?: return
        val id = membersOf ?: return
        v.launch {
            val r = v.logs.serverGrants(id)
            if (v.closed || membersOf != id) return@launch
            grantsRead = r
            app.publish()
        }
    }

    // ---- what the snapshot shows ----

    private fun me(v: EngineVault) = v.userId

    private fun personName(v: EngineVault, userId: String, key: String): PersonName = when {
        userId == me(v) -> PersonName.You()
        else -> v.contacts.currentFor(userId, key)?.labelText?.let { PersonName.Contact(it) } ?: PersonName.Unverified(null)
    }

    private fun roleOf(literal: String?): RoleInVault? = when (literal) {
        "owner" -> RoleInVault.OWNER
        "writer" -> RoleInVault.WRITER
        "reader" -> RoleInVault.READER
        else -> null
    }

    private fun verifiedState(st: VaultLogStatus): VerifiedVaultState? = when (st) {
        is VaultLogStatus.Unknown -> null
        is VaultLogStatus.Verified -> st.state
        is VaultLogStatus.Failed -> st.lastGood
        is VaultLogStatus.Withheld -> st.state
        is VaultLogStatus.Frozen -> st.state
        is VaultLogStatus.Purged -> st.state
        is VaultLogStatus.Removed -> st.state
    }

    private fun logState(st: VaultLogStatus): VaultLogState = when (st) {
        is VaultLogStatus.Unknown -> VaultLogState.NOT_CHECKED_YET
        is VaultLogStatus.Verified -> VaultLogState.VERIFIED
        is VaultLogStatus.Failed -> VaultLogState.FAILED
        is VaultLogStatus.Withheld -> VaultLogState.WITHHELD
        is VaultLogStatus.Frozen -> VaultLogState.FROZEN
        is VaultLogStatus.Purged -> VaultLogState.PURGED
        is VaultLogStatus.Removed -> VaultLogState.REMOVED
    }

    /** A signed change for [vaultId] is sent and not yet acknowledged (the engine's durable pending-append record). */
    private fun changeWaiting(v: EngineVault, vaultId: String): Boolean =
        app.engine.state.get(StoredVaultLogs.recordKey(me(v), vaultId, "pending")) != null

    /**
     * The change the log engine holds for [vaultId] is a deletion. This device signed it, and the held record keeps the
     * signed frame in the clear (a log entry is signed, not sealed), so its kind is read, after a lock too. A rename or a
     * member's change that waits is not a deletion. A record whose frame cannot be read counts as one (the safer reading:
     * nothing is signed over a deletion that may be waiting).
     */
    private fun deletionWaiting(v: EngineVault, vaultId: String): Boolean = heldDeletion(v, vaultId) != false

    /** [deletionWaiting] told apart: true, a deletion; false, none held or another kind; null, a frame this device cannot read. */
    private fun heldDeletion(v: EngineVault, vaultId: String): Boolean? {
        val text = app.engine.state.get(StoredVaultLogs.recordKey(me(v), vaultId, "pending")) ?: return false
        val frame = runCatching {
            (kotlinx.serialization.json.Json.parseToJsonElement(text) as kotlinx.serialization.json.JsonObject)["frame"]
                ?.let { (it as kotlinx.serialization.json.JsonPrimitive).content }
        }.getOrNull() ?: return null
        val entry = runCatching { io.silencelen.andvari.core.trust.VaultLog.parse(app.crypto, Bytes.fromB64(frame)).valueOrNull()?.entry }.getOrNull()
            ?: return null
        return entry is io.silencelen.andvari.core.trust.LogEntry.Delete
    }

    private fun row(v: EngineVault, id: String): SharedVaultRow? {
        val adoption = adoptions[id]
        if (adoption is Adoption.Declined) return null
        val st = v.logs.status(id)
        val s = verifiedState(st)
        val content = v.content.state
        val held = content.held.firstOrNull { it.vaultId == id }
        var log = logState(st)
        var name: String? = content.vaults.firstOrNull { it.vaultId == id }?.name ?: held?.name?.ifEmpty { null }
        var owner: PersonName? = s?.let { personName(v, it.owner, it.ownerKey) }
        var sharedBy: PersonName.Unverified? = null
        var senderToConfirm: ContactRow? = null
        when (adoption) {
            is Adoption.ConnectFirst -> {
                // The sender is the owner who signed the `add`; a contact of this account not current here is confirmed, not connected.
                val sender = s?.owner
                val contact = sender?.let { v.store.local().contacts[it] }
                if (contact != null) {
                    log = VaultLogState.CONFIRM_FIRST
                    senderToConfirm = app.contactsFlow.rowFor(sender)
                } else {
                    log = VaultLogState.CONNECT_FIRST
                }
                sharedBy = PersonName.Unverified(adoption.serverName)
                name = null
                owner = null
            }
            is Adoption.AskAccept -> name = adoption.vaultName
            is Adoption.Refused -> when (adoption.reason) {
                AdoptionRefusal.KEY_COMMIT_MISMATCH, AdoptionRefusal.GRANT_REFUSED, AdoptionRefusal.RECORD_GENESIS_MISMATCH,
                AdoptionRefusal.RECORD_AHEAD, AdoptionRefusal.RECORD_FORK,
                -> {
                    if (st is VaultLogStatus.Verified) log = VaultLogState.KEY_REFUSED
                    name = null
                }
                AdoptionRefusal.WRAP_UNOPENABLE, AdoptionRefusal.NO_KEY -> {
                    if (st is VaultLogStatus.Verified) log = VaultLogState.KEY_MISSING
                    name = null
                }
                AdoptionRefusal.LOG_NOT_VERIFIED, AdoptionRefusal.NOT_A_MEMBER -> {}
            }
            else -> {}
        }
        if (log == VaultLogState.NOT_CHECKED_YET) owner = null
        val deleted = st is VaultLogStatus.Verified && st.state.deletedId != null
        // The server's grace end when it sent one for this very `delete` (display only). Where it sent none the row carries
        // no day: this device's own estimate is handed to no screen (a server may keep a deleted vault for a shorter time).
        val purgeAt = if (deleted) (v.logs.serverGraceEnd(id)?.purgeAt ?: 0L) else 0L
        val pending = s?.pending
        val offer = pending?.takeIf { log == VaultLogState.VERIFIED }?.let {
            OwnershipOfferRow(personName(v, it.to, it.toKey), it.to == me(v), it.expiresAt)
        }
        val role = s?.members?.get(me(v))?.role?.let(::roleOf)
        // The same rule as openMove's, so the row's offer and the intent never disagree.
        val canMove = role == RoleInVault.OWNER &&
            (log == VaultLogState.VERIFIED || log == VaultLogState.FROZEN || log == VaultLogState.FAILED) &&
            (!deleted || runFor(v, id)?.let { it.deleteSent && !it.storedOutside } == true) && v.logs.copyOutAllowed(id) && verifiedState(st) != null
        val waiting = moveDeleteWaiting(v, id)
        return SharedVaultRow(
            vaultId = id,
            name = name,
            role = role,
            log = log,
            owner = owner,
            sharedBy = sharedBy,
            senderToConfirm = senderToConfirm,
            historyHint = st is VaultLogStatus.Verified && st.itemHintUnresolved,
            ownerOutOfSpace = id in outOfSpace,
            purgeAtMs = purgeAt,
            heldUntilMs = if (log == VaultLogState.PURGED || log == VaultLogState.REMOVED) held?.expungeAtMs ?: 0L else 0L,
            removedByOwner = st is VaultLogStatus.Removed && st.byOwner,
            offer = offer,
            changeWaiting = changeWaiting(v, id),
            // A vault whose deletion stands takes no change (the content refuses each with a line of its own): never writable,
            // whether or not the server sent a day for its end; a restore makes it writable again at once.
            writable = v.logs.writeAllowed(id) && !deleted && !app.content.isNullOrStopped() && !waiting,
            canSaveElsewhere = v.logs.copyOutAllowed(id),
            canRemoveFromDevice = held != null || log == VaultLogState.FROZEN || log == VaultLogState.FAILED || log == VaultLogState.WITHHELD,
            unfinishedMove = unfinishedLine(v, id, name),
            canMoveEverything = canMove,
            readOnlyLine = if (waiting && v.logs.writeAllowed(id)) {
                io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_WAITING_READ_ONLY, name.orEmpty(), runFor(v, id)?.let { newNameOf(v, it) }.orEmpty())
            } else null,
            deleted = deleted,
            waiting = waitingOf(v, id, s, name),
            frozenMoveClose = frozenMoveLine(v, id, name),
        )
    }

    private fun io.silencelen.andvari.core.app.content.VaultContent?.isNullOrStopped(): Boolean = this == null || state.serverStopped

    /** The shared vaults this account holds or is offered, by name (a vault with none last), the personal vault left out. */
    fun rows(): List<SharedVaultRow> {
        val v = vault() ?: return emptyList()
        val ids = LinkedHashSet<String>()
        ids += v.rows.vaultIds()
        v.content.state.held.forEach { ids += it.vaultId }
        ids -= v.personalVaultId
        return ids.mapNotNull { row(v, it) }.sortedWith(compareBy({ it.name == null }, { it.name?.lowercase() }, { it.vaultId }))
    }

    // ---- §3.7: a change to a shared vault that waits ([io.silencelen.andvari.core.app.WaitingChanges]) ----

    /** [SharedVaultRow.waiting]: [id]'s held change, settled first by the log engine (nothing sent); a move's own steps are the move's. */
    private fun waitingOf(v: EngineVault, id: String, s: VerifiedVaultState?, name: String?): WaitingChange? {
        val c = v.logs.heldChange(id) ?: return null
        if (c.movesOwn) return null
        val kind = waitingKindOf(c.kind)
        // Asked only after this opening's look at this very deletion (by its entry's hash) that sent nothing, only within its
        // day, and never for one the server's answer called stored: neither "delete it now" nor "keep the vault" is offered.
        val asks = kind == WaitingKind.DELETION && c.waitsForWord && c.known != HeldKnown.STORED_BY_SERVERS_WORD && c.hash in v.askedForWord &&
            app.engine.clock() - c.heldSince < HELD_DAY_MS
        // A change of role: the role the member holds in the log as verified here, which a withdrawal keeps.
        val roleBack = if (kind == WaitingKind.ROLE) c.names?.let { s?.members?.get(it)?.role }?.let(::roleOf) else null
        return WaitingChange(id, kind, namedIn(v, c.names, c.memberKey), roleOf(c.role), c.heldSince, knownOf(c.known), c.requestOut, c.withdrawable, asks, name,
            memberId = c.names, roleBack = roleBack, heldHash = c.hash, opening = v.opening)
    }

    private fun waitingKindOf(k: HeldKind): WaitingKind = when (k) {
        HeldKind.ADD -> WaitingKind.ADD
        HeldKind.REMOVE -> WaitingKind.REMOVE
        HeldKind.ROLE -> WaitingKind.ROLE
        HeldKind.OFFER -> WaitingKind.OFFER
        HeldKind.DELETE -> WaitingKind.DELETION
        HeldKind.CREATE, HeldKind.LEAVE, HeldKind.CANCEL, HeldKind.ACCEPT, HeldKind.RESTORE, HeldKind.OTHER -> WaitingKind.OTHER
    }

    private fun knownOf(k: HeldKnown): WaitingKnown = when (k) {
        HeldKnown.STORED_BY_SERVERS_WORD -> WaitingKnown.SERVER_SAYS_STORED
        HeldKnown.NOT_STORED -> WaitingKnown.NOT_STORED
        HeldKnown.CANNOT_TELL -> WaitingKnown.CANNOT_TELL
    }

    /**
     * The member a held change (or a finding about one) names, only by the key the change names them by ([key]: an
     * addition's or an offer's own key; a removal's or a role change's member's key in the log as verified here): a
     * contact this account still holds, with exactly that key, current here, is named by its label; otherwise unverified,
     * never by a contact's other key nor by one removed (the same contact the log engine compares before a re-send).
     */
    private fun namedIn(v: EngineVault, userId: String?, key: String?): PersonName? {
        if (userId == null) return null
        if (userId == me(v)) return PersonName.You()
        if (key == null || v.store.local().contacts[userId]?.identityPub != key) return PersonName.Unverified(null)
        return personName(v, userId, key)
    }

    /**
     * After a completed sync of [v] (so also after every log action): the general re-send (it never sends a deletion that
     * waits for the person's word, nor a change a day old, which it gives up after a read), then, for each deletion that
     * waits for the person's word, the look in its log that sends nothing; only a deletion still held after a read that
     * reached the server is asked about, and the record of that look is kept by the deletion's own entry (its hash), so a
     * later deletion of the same vault gets a look of its own. What no longer waits is let go of from that record. Not
     * while a move runs: the move sends its own steps itself.
     */
    internal suspend fun settleWaiting(v: EngineVault) {
        if (v.closed || runOf != null) return
        app.unlessLocked(Unit) {
            v.logs.resendHeld()
            for (c in v.logs.heldChanges()) {
                if (!c.waitsForWord || c.movesOwn || c.known == HeldKnown.STORED_BY_SERVERS_WORD) continue
                if (app.engine.clock() - c.heldSince >= HELD_DAY_MS || c.hash in v.askedForWord) continue
                val look = v.logs.lookHeld(c.vaultId)
                // Kept only for the very deletion the look found still held; nothing else is marked looked at.
                if (look is HeldLook.StillHeld && look.readReached && look.change.hash == c.hash) v.askedForWord += c.hash
            }
            // Only what still waits for the person's word, within its day, keeps its mark of a look.
            val waiting = v.logs.heldChanges().filter {
                it.waitsForWord && !it.movesOwn && it.known != HeldKnown.STORED_BY_SERVERS_WORD && app.engine.clock() - it.heldSince < HELD_DAY_MS
            }.mapTo(HashSet()) { it.hash }
            v.askedForWord.retainAll(waiting)
        }
        if (!v.closed) app.publish()
    }

    /** The notices on show, by finding id, so a snapshot that says the same hands the same notice. */
    private val waitingShown = HashMap<String, WaitingNotice>()

    /** [io.silencelen.andvari.core.app.AccountSnapshot.waitingNotices], named from [rows] (the vault's name now). */
    fun waitingNotices(rows: List<SharedVaultRow>): List<WaitingNotice> {
        val v = vault() ?: return emptyList()
        val out = v.logs.heldFindings().map { f ->
            val name = rows.firstOrNull { it.vaultId == f.vaultId }?.name
                ?: v.content.state.held.firstOrNull { it.vaultId == f.vaultId }?.name?.ifEmpty { null }
            val (key, found) = noticeOf(f, v.logs.status(f.vaultId))
            // An undo acts on the member the notice names, by account id; a change of role is changed back to the role the
            // member held when this device let go of it, and is offered only where that role is known.
            val roleBack = if (found == WaitingUndo.CHANGE_ROLE_BACK) roleOf(f.roleBefore) else null
            val undo = if (found == WaitingUndo.CHANGE_ROLE_BACK && roleBack == null) null else found
            val line = io.silencelen.andvari.core.app.CopyLine.of(key, name ?: CopyKey.WAITING_UNNAMED_VAULT.english)
            waitingShown[f.id]?.takeIf { it.line.key == key && it.line.values == line.values && it.undo == undo }
                ?: WaitingNotice(f.id, f.vaultId, waitingKindOf(f.change), namedIn(v, f.names, f.memberKey), line, undo, memberId = f.names, roleBack = roleBack)
                    .also { waitingShown[f.id] = it }
        }
        waitingShown.keys.retainAll(out.map { it.noticeId }.toSet())
        return out
    }

    /** A notice's line and undo, by what was found and, for a deletion found made, by what the vault reads here now ([st]). */
    private fun noticeOf(f: HeldFinding, st: VaultLogStatus): Pair<CopyKey, WaitingUndo?> {
        // A deletion found made offers the restore only while the vault still reads deleted here; restored since, its line
        // says so; in any other state here, no restore is offered from this device.
        fun deletion(key: CopyKey): Pair<CopyKey, WaitingUndo?> = when {
            st is VaultLogStatus.Verified && st.state.deletedId != null -> key to WaitingUndo.RESTORE_VAULT
            st is VaultLogStatus.Verified -> CopyKey.WAITING_FOUND_DELETED_RESTORED_SINCE to null
            else -> CopyKey.WAITING_FOUND_DELETED_NO_RESTORE to null
        }
        return when (f.what) {
            FoundKind.MADE -> deletion(CopyKey.WAITING_FOUND_DELETED)
            FoundKind.MADE_AFTER_ALL -> when {
                f.letGo == LetGo.HALF_MADE -> deletion(CopyKey.WAITING_FOUND_HALF_MADE_DELETED)
                // "That you withdrew" only of a deletion the person withdrew; one given up says that.
                f.change == HeldKind.DELETE && f.letGo == LetGo.WITHDRAWN -> deletion(CopyKey.WAITING_FOUND_DELETED_AFTER_ALL)
                f.change == HeldKind.DELETE -> deletion(CopyKey.WAITING_FOUND_GIVEN_UP_DELETED_AFTER_ALL)
                else -> CopyKey.WAITING_FOUND_MADE_AFTER_ALL to when (f.change) {
                    HeldKind.ADD -> WaitingUndo.REMOVE_MEMBER
                    HeldKind.REMOVE -> WaitingUndo.ADD_MEMBER
                    HeldKind.ROLE -> WaitingUndo.CHANGE_ROLE_BACK
                    HeldKind.OFFER -> WaitingUndo.CANCEL_OFFER
                    else -> null
                }
            }
            else -> otherNotice(f) to null
        }
    }

    private fun otherNotice(f: HeldFinding): CopyKey = when (f.what) {
        FoundKind.NOT_MADE -> if (f.final) CopyKey.WAITING_FOUND_NOT_MADE else CopyKey.WAITING_FOUND_NOT_MADE_YET
        FoundKind.GIVEN_UP -> when {
            // Refused at a re-send while an earlier send may have stored it: refused and cannot tell, never "a day".
            f.code != null && !f.final -> CopyKey.WAITING_FOUND_REFUSED_CANNOT_TELL
            f.final -> CopyKey.WAITING_GIVEN_UP_NOT_MADE
            f.absentAtRead -> CopyKey.WAITING_GIVEN_UP_ABSENT
            else -> CopyKey.WAITING_GIVEN_UP_CANNOT_TELL
        }
        FoundKind.PLACE_TAKEN -> CopyKey.WAITING_FOUND_PLACE_TAKEN
        FoundKind.REFUSED -> CopyKey.WAITING_FOUND_REFUSED
        FoundKind.CONTACT_CHANGED -> if (f.final) CopyKey.WAITING_FOUND_CONTACT_CHANGED_NOT_MADE else CopyKey.WAITING_FOUND_CONTACT_CHANGED
        // Said by [noticeOf] itself.
        FoundKind.MADE, FoundKind.MADE_AFTER_ALL -> CopyKey.WAITING_FOUND_MADE_AFTER_ALL
    }

    override fun dismissWaitingNotice(notice: WaitingNotice) {
        val v = vault() ?: return
        if (waitingShown[notice.noticeId] !== notice) return
        v.logs.findingShown(notice.noticeId)
        waitingShown.remove(notice.noticeId)
        app.publish()
    }

    override suspend fun withdrawWaiting(change: WaitingChange): WaitingResult {
        val v = vault() ?: return WaitingResult.STALE
        // Drawn in another opening (before a lock, a sign-out or a switch of account): stale, and nothing is withdrawn.
        if (change.opening !== v.opening) return WaitingResult.STALE
        val id = change.vaultId
        // A vault frozen at the read that showed its server contradicting itself takes no act, and says so.
        if (v.logs.status(id) is VaultLogStatus.Frozen) return WaitingResult.FROZEN
        // The log engine withdraws only the change this was drawn for: it compares the hash with the change held now in the
        // same step as the drop, and the opening is compared again here with no wait before that step.
        val r = app.unlessLocked(null) { app.working { if (vault() !== v || v.closed) null else v.logs.withdraw(id, change.heldHash) } }
        v.askedForWord -= change.heldHash
        app.publish()
        // The words follow the record as the engine acted on it, never what was drawn.
        return when (r) {
            null -> WaitingResult.STALE
            is HeldWithdrawal.Withdrawn -> {
                val deletion = r.change.kind == HeldKind.DELETE
                val notMade = r.known == HeldKnown.NOT_STORED
                // The person's own deletion that will not be made: its quiet departure is not expected any more.
                if (deletion && notMade && !v.closed) v.departureRefused(id)
                when {
                    deletion && notMade -> WaitingResult.KEPT_NOT_DELETED
                    deletion -> WaitingResult.KEPT_MAY_BE_DELETED
                    notMade -> WaitingResult.WITHDRAWN_NOT_MADE
                    else -> WaitingResult.WITHDRAWN_MAY_BE_MADE
                }
            }
            is HeldWithdrawal.Kept -> when (r.reason) {
                // Another change waits for the vault now: the row the person acted on is stale.
                HeldWithdrawal.NOT_THIS_CHANGE -> WaitingResult.STALE
                HeldWithdrawal.NOTHING_HELD -> if (v.logs.status(id) is VaultLogStatus.Frozen) WaitingResult.FROZEN else WaitingResult.NOTHING_WAITING
                HeldWithdrawal.FIRST_REQUEST_OUT -> WaitingResult.STILL_SENDING
                HeldWithdrawal.NOT_WITHDRAWABLE, HeldWithdrawal.NOT_A_DELETION -> WaitingResult.NOT_OFFERED
                HeldWithdrawal.RECORD_UNREADABLE -> WaitingResult.RECORD_UNREADABLE
                HeldWithdrawal.STORED_BY_SERVERS_WORD -> WaitingResult.SERVER_SAYS_STORED
                else -> WaitingResult.FAILED
            }
        }
    }

    override suspend fun deleteWaitingNow(change: WaitingChange): WaitingResult {
        val v = vault() ?: return WaitingResult.STALE
        // Drawn in another opening (before a lock, a sign-out or a switch of account): stale, and nothing is sent.
        if (change.opening !== v.opening) return WaitingResult.STALE
        val id = change.vaultId
        if (v.logs.status(id) is VaultLogStatus.Frozen) return WaitingResult.FROZEN
        // As every other act on the vault: refused while a move of it runs or the move's own deletion of it waits.
        if (runOf == id || moveDeleteWaiting(v, id)) return WaitingResult.MOVE_IN_PROGRESS
        val held = v.logs.heldChange(id) ?: return if (v.logs.status(id) is VaultLogStatus.Frozen) WaitingResult.FROZEN else WaitingResult.NOTHING_WAITING
        // Another change waits for the vault now (a later deletion, say): the question the person answered is stale.
        if (held.hash != change.heldHash) return WaitingResult.STALE
        // Only the deletion the person was asked about, after this opening's look at that very deletion; never a move's own,
        // never one not looked at, never one the server's answer called stored (it is not asked about).
        if (held.kind != HeldKind.DELETE || !held.waitsForWord || held.movesOwn || held.known == HeldKnown.STORED_BY_SERVERS_WORD ||
            held.hash !in v.askedForWord
        ) return WaitingResult.NOT_OFFERED
        if (app.engine.clock() - held.heldSince >= HELD_DAY_MS) {
            // The day ran out between the question and the tap: nothing is sent, and the general re-send gives it up.
            v.askedForWord -= held.hash
            app.unlessLocked(Unit) { app.working { v.logs.resendHeld() } }
            app.publish()
            return WaitingResult.DELETE_GIVEN_UP
        }
        v.beforeDeparture(id)
        // The log engine sends only the deletion this was drawn for (compared in the same step as the send); the opening is
        // compared again here with no wait before that step.
        val r = app.unlessLocked(null) { app.working { if (vault() !== v || v.closed) null else v.logs.repostHeld(id, held.hash) } }
        v.askedForWord -= held.hash
        val out = when (r) {
            null -> WaitingResult.STALE
            HeldRepost.NotThisChange -> WaitingResult.STALE
            // Refused at this send while an earlier send may have stored it: given up, and whether it was made cannot be told.
            is HeldRepost.RefusedCannotTell -> WaitingResult.DELETE_REFUSED_CANNOT_TELL
            is HeldRepost.Stored -> WaitingResult.DELETED
            HeldRepost.Dropped -> WaitingResult.DELETE_DID_NOT_HAPPEN
            HeldRepost.NothingHeld -> WaitingResult.NOTHING_WAITING
            // Still held: no answer settled it, and it is asked about again after the next look. Given up meanwhile (nothing
            // held): the finding says what became of it.
            HeldRepost.Waiting -> if (v.logs.heldChange(id) != null) WaitingResult.DELETE_STILL_WAITING else WaitingResult.NOTHING_WAITING
            is HeldRepost.Refused ->
                if (r.code == StoredVaultLogs.VAULT_FROZEN || v.logs.status(id) is VaultLogStatus.Frozen) WaitingResult.FROZEN else WaitingResult.DELETE_REFUSED
        }
        // The quiet departure stays expected only where the deletion was made or may be: deleted, still waiting, or refused at
        // a send while an earlier send may have stored it. A lock that cut the act off keeps it for the next opening to settle.
        val mayBeMade = out == WaitingResult.DELETED || out == WaitingResult.DELETE_STILL_WAITING || out == WaitingResult.DELETE_REFUSED_CANNOT_TELL
        if (!v.closed && !mayBeMade && r != null) v.departureRefused(id)
        if (out == WaitingResult.DELETED && !v.closed) v.afterLogAction()
        app.publish()
        return out
    }

    /** [SharedVaultRow.frozenMoveClose]: a move of [id] whose own deletion was sent, stopped because the old vault froze. */
    private fun frozenMoveLine(v: EngineVault, id: String, name: String?): io.silencelen.andvari.core.app.CopyLine? {
        val run = runFor(v, id)?.takeIf { it.deleteSent && !it.storedOutside } ?: return null
        if (v.logs.status(id) !is VaultLogStatus.Frozen || runOf == id) return null
        return io.silencelen.andvari.core.app.CopyLine.of(CopyKey.MOVE_FROZEN_CLOSE, newNameOf(v, run), name.orEmpty(), run.copied.size.toString())
    }

    override fun closeFrozenMove(vault: SharedVaultRow): VaultActionResult {
        val v = vault() ?: return VaultActionResult.STALE
        val id = vault.vaultId
        if (frozenMoveLine(v, id, null) == null) return VaultActionResult.STALE
        // This device's record of the move and its mark of a waiting deletion go; nothing is sent, and nothing the log
        // engine holds is touched (the freeze dropped the deletion already): the old vault stays frozen and read-only here.
        dropRun(v, id)
        if (moveOf == id) closeMoveEverything()
        app.publish()
        return VaultActionResult.DONE
    }

    /** The incoming vaults (§3.6 `AskAccept`), each asked once until it is answered. */
    fun prompts(): List<AccountPrompt> {
        if (vault() == null) return emptyList()
        val out = ArrayList<AccountPrompt>()
        for ((id, a) in adoptions.entries.sortedBy { it.key }) {
            if (a !is Adoption.AskAccept) {
                incoming.remove(id)
                continue
            }
            val shown = incoming[id]?.takeIf { it.addSeq == a.addSeq && it.from == a.ownerLabel && it.vaultName == a.vaultName }
            out += shown ?: AccountPrompt.IncomingVault(id, a.ownerLabel, a.vaultName, a.addSeq).also { incoming[id] = it }
        }
        return out
    }

    fun members(): MembersScreen? {
        val v = vault() ?: return null
        val id = membersOf ?: return null
        val row = rows().firstOrNull { it.vaultId == id } ?: return null
        val s = verifiedState(v.logs.status(id)) ?: return null
        // The server's member list, only as read against this very verified head (design §3.11): the server's word, for
        // the line on the screen. It feeds no decision here: every intent treats the person as the log says.
        val read = (grantsRead as? ServerGrants.Read)?.takeIf { it.vaultId == id && it.headSeq == s.headSeq && it.headHash == s.headHash }
        val list = s.members.values.mapNotNull { m ->
            val role = roleOf(m.role) ?: return@mapNotNull null
            val gone = m.userId != me(v) && read?.of(m.userId) == ServerGrant.NO_GRANT_AS_SERVER_SAYS
            MemberRow(id, m.userId, personName(v, m.userId, m.key), role, deletedByOperator = gone)
        }.sortedWith(compareBy({ it.role != RoleInVault.OWNER }, { it.who !is PersonName.You }, { label(it.who) }, { it.userId }))
        val st = v.logs.status(id)
        return MembersScreen(row, list, st is VaultLogStatus.Verified && st.itemHintUnresolved, s.owner == me(v) && row.writable)
    }

    private fun label(p: PersonName): String = when (p) {
        is PersonName.Contact -> p.label.lowercase()
        is PersonName.Unverified -> p.serverName.orEmpty().lowercase()
        is PersonName.You -> ""
    }

    fun shareWarning(): UncomparedShareWarning? = if (vault() == null) null else warning

    fun moving(): MoveEverythingScreen? {
        val v = vault() ?: return null
        val id = moveOf ?: return null
        val row = rows().firstOrNull { it.vaultId == id } ?: return null
        val s = verifiedState(v.logs.status(id)) ?: return null
        val sourceStays = row.log == VaultLogState.FROZEN || row.log == VaultLogState.FAILED
        fun memberRow(userId: String, key: String, roleLiteral: String, ticked: (Boolean) -> Boolean): MoveMemberRow {
            // Added from this device only as a contact current here whose codes were compared: the move cannot show an
            // uncompared share's own warning (§6.7 step 8), so such a member is named before the person starts.
            val canBeAdded = v.contacts.currentFor(userId, key) != null && app.contactsFlow.rowFor(userId)?.compared == true
            val role = MemberRole.fromLiteral(roleLiteral) ?: MemberRole.WRITER
            return MoveMemberRow(userId, personName(v, userId, key), role, ticked(canBeAdded) && canBeAdded, canBeAdded)
        }
        val removing = moveRemoving?.let { r -> s.members[r]?.let { m -> memberRow(m.userId, m.key, m.role) { false } } }
        // The remaining members: not this account, not the owner, not the one the remove dialog is about.
        val members = s.members.values.filter { it.userId != me(v) && it.userId != moveRemoving && it.role != "owner" }.map { m ->
            // A vault in good standing adds every remaining member again; a frozen or failed one only those ticked (FS-R3).
            memberRow(m.userId, m.key, m.role) { can -> if (sourceStays) moveTicks[m.userId] ?: false else can }
        }.sortedWith(compareBy({ label(it.who) }, { it.userId }))
        val unreadable = unreadableIn(v, id)
        val kept = when {
            sourceStays -> MoveKept.SOURCE_STAYS
            members.any { !it.canBeAdded } -> MoveKept.MEMBER_CANNOT_BE_ADDED
            unreadable > 0 -> MoveKept.UNREADABLE_ITEMS
            else -> null
        }
        val (running, copied, total) = moveProgress
        val run = runFor(v, id)
        val stop = run?.stop
        val adds = (if (sourceStays) members.filter { it.ticked } else members).mapTo(HashSet()) { it.userId }
        // A run stopped because the old vault froze offers no fresh start: the old vault is read-only here for good.
        val fresh = run != null && !running && !run.deleteSent && stop?.line != CopyKey.MOVE_OLD_VAULT_FROZEN && !resumable(v, run, adds)
        return MoveEverythingScreen(
            row, sourceStays, members, shortOfSpace = id in outOfSpace || stop?.result == VaultActionResult.OUT_OF_SPACE, running = running,
            copied = copied, total = total, removing = removing, ticksOffered = sourceStays, unreadable = unreadable, oldVaultKept = kept,
            whatMoves = CopyKey.MOVE_ONLY_LIVE_ITEMS, stopped = stop, finished = moveFinished,
            startsFresh = if (fresh) CopyKey.MOVE_STARTS_FRESH else null,
            space = moveSpace,
        )
    }

    /** Live items of [vaultId] this device holds but cannot read: "Move everything" cannot copy them. */
    private fun unreadableIn(v: EngineVault, vaultId: String): Int {
        val readable = v.items.items().filter { it.vaultId == vaultId }.mapTo(HashSet()) { it.itemId }
        return v.items.liveItemIdsIn(vaultId).count { it !in readable }
    }

    private fun keptLine(kept: MoveKept): CopyKey = when (kept) {
        MoveKept.SOURCE_STAYS -> CopyKey.MOVE_KEPT_SOURCE_STAYS
        MoveKept.MEMBER_CANNOT_BE_ADDED -> CopyKey.MOVE_KEPT_NOT_ADDED
        MoveKept.UNREADABLE_ITEMS -> CopyKey.MOVE_KEPT_UNREADABLE
    }

    // ---- intents ----

    private fun result(r: AppendOutcome): VaultActionResult = when (r) {
        is AppendOutcome.Appended -> VaultActionResult.DONE
        is AppendOutcome.Pending -> VaultActionResult.SENT_PENDING
        is AppendOutcome.VaultReadOnly -> VaultActionResult.READ_ONLY
        is AppendOutcome.HeadMoved -> VaultActionResult.CHANGED_MEANWHILE
        is AppendOutcome.ClockAhead -> VaultActionResult.CLOCK_AHEAD
        is AppendOutcome.NotAllowed -> when (r.reason) {
            "not_compared" -> VaultActionResult.NEEDS_UNCOMPARED_WARNING
            "not_a_current_contact" -> VaultActionResult.NOT_A_CONTACT_HERE
            "not_authorized" -> VaultActionResult.NOT_OWNER
            // A change signed before is still waiting: nothing else is signed for the vault until it is settled, and this one
            // was neither signed nor sent. A step of a running move keeps the move's own answer (its stop says what waits).
            "append_pending" -> if (runOf == null) VaultActionResult.OTHER_CHANGE_WAITS else VaultActionResult.SENT_PENDING
            "origin_stopped" -> VaultActionResult.FAILED
            MOVE_DELETE_WAITING_REASON -> VaultActionResult.MOVE_DELETE_WAITING
            // The head the caller checked is not the head any more: nothing was signed; read again.
            StoredVaultLogs.LOG_MOVED_ON -> VaultActionResult.CHANGED_MEANWHILE
            StoredVaultLogs.NIL_USER_ID -> VaultActionResult.NOT_ALLOWED
            else -> VaultActionResult.NOT_ALLOWED
        }
        is AppendOutcome.Refused -> when (r.code) {
            "offer_expired" -> VaultActionResult.OFFER_EXPIRED
            "not_connected" -> VaultActionResult.NOT_CONNECTED
            "member_limit" -> VaultActionResult.MEMBER_LIMIT
            "quota_exceeded" -> VaultActionResult.OUT_OF_SPACE
            "rate_limited" -> VaultActionResult.RATE_LIMITED
            "update_required", "client_too_old" -> VaultActionResult.UPDATE_REQUIRED
            "not_vault_owner" -> VaultActionResult.NOT_OWNER
            else -> VaultActionResult.FAILED
        }
    }

    /** The row on show for [vaultId], or null when none is (the intent is stale). */
    private fun shown(vaultId: String): SharedVaultRow? = app.snapshot.account?.vaults?.firstOrNull { it.vaultId == vaultId }

    /**
     * While a move's deletion of [vaultId] is signed and not known to be stored, this device signs nothing else on that
     * vault's log: every other road to the log (the person's "delete it now" among them) is refused before anything is
     * signed or sent, with [VaultActionResult.MOVE_DELETE_WAITING], and only the move's own run goes on. A kept record
     * that cannot be read counts as waiting (the safer reading: nothing is signed over a deletion that may be waiting).
     */
    internal fun moveDeleteWaiting(vaultId: String): Boolean {
        val v = vault() ?: return false
        return moveDeleteWaiting(v, vaultId)
    }

    private fun moveDeleteWaiting(v: EngineVault, vaultId: String): Boolean = waitingReason(v, vaultId) != null

    /**
     * Why [vaultId] is closed for writing by a move's deletion, or null when none waits ([moveDeleteWaiting]):
     * [VaultClosedReason.DELETION_WAITING] when the move's deletion is known to be signed and waiting;
     * [VaultClosedReason.DELETION_MAY_BE_WAITING] when this device only cannot rule it out (a held change whose frame it
     * cannot read, or a kept move record it cannot read).
     */
    private fun waitingReason(v: EngineVault, vaultId: String): VaultClosedReason? {
        if (deleteStored(v, vaultId)) return null
        val run = runFor(v, vaultId)
        if (vaultId in runsUnreadable) return VaultClosedReason.DELETION_MAY_BE_WAITING
        if (run == null || run.storedOutside) return null
        if (run.deleteSent) return VaultClosedReason.DELETION_WAITING
        // A lock can overtake the move's deletion after its signature, before the record learns it was sent: a deletion the
        // log engine holds for the old vault of a move not yet finished is that deletion. Any other held change (a rename,
        // a member's change) is not, and closes nothing.
        return when (heldDeletion(v, vaultId)) {
            true -> VaultClosedReason.DELETION_WAITING
            null -> VaultClosedReason.DELETION_MAY_BE_WAITING
            false -> null
        }
    }

    /** A mark this code sets ([waitingReason]): it clears only these, never a mark of another reason. */
    private fun ownMark(mark: VaultClosedReason?): Boolean =
        mark == VaultClosedReason.DELETION_WAITING || mark == VaultClosedReason.DELETION_MAY_BE_WAITING

    /**
     * Sign [action] on [vaultId]'s log. A `leave` or `delete` tells the item engine first, so the vault goes quietly;
     * after any change the engine re-reads its keys at a sync. [byMove] only for the move's own steps on its old vault:
     * every other caller is refused while that vault's deletion waits ([moveDeleteWaiting]). [expectHead]: the entry is
     * signed only over that very head (the log engine compares it with no wait before the signature); another head
     * answers CHANGED_MEANWHILE with nothing signed.
     */
    private suspend fun act(
        vaultId: String?, action: LogAction, departing: Boolean = false, byMove: Boolean = false,
        expectHead: io.silencelen.andvari.core.trust.Checkpoint? = null,
    ): Pair<VaultActionResult, AppendOutcome?> {
        val v = vault() ?: return VaultActionResult.STALE to null
        if (!byMove && vaultId != null && moveDeleteWaiting(v, vaultId)) return VaultActionResult.MOVE_DELETE_WAITING to null
        if (app.content?.state?.removingLine != null) return VaultActionResult.REMOVING_COPY to null
        if (app.content.isNullOrStopped()) return VaultActionResult.FAILED to null
        if (departing && vaultId != null) v.beforeDeparture(vaultId)
        // A lock during the append's waits: the log engine signed and sent nothing more, and the intent
        // answers STALE.
        val r = app.unlessLocked(null) { app.working { v.logs.append(vaultId, action, expectHead) } }
        if (r == null || v.closed) return VaultActionResult.STALE to null
        // The person's own delete or leave did not happen (the server refused it, or nothing was signed and no held one of
        // it was stored meanwhile): the quiet departure expected above is withdrawn, so a later one, by anyone, is said.
        if (departing && vaultId != null && (r is AppendOutcome.Refused ||
                (r is AppendOutcome.NotAllowed && !deleteStored(v, vaultId) && v.logs.status(vaultId) !is VaultLogStatus.Removed))) {
            v.departureRefused(vaultId)
        }
        // The person's own departure, sent without an answer: kept on this device, so whichever later opening sees the
        // server store it takes it quietly, as this one would.
        if (departing && vaultId != null && r is AppendOutcome.Pending) noteOwnDeparture(app.engine.state, v.origin, me(v), vaultId)
        if (r is AppendOutcome.Appended || r is AppendOutcome.Pending) v.afterLogAction()
        if (r is AppendOutcome.Refused && r.code == "quota_exceeded" && vaultId != null) outOfSpace += vaultId
        app.publish()
        if (vaultId != null && vaultId == membersOf) readGrants()
        return result(r) to r
    }

    private fun ownerOnly(row: SharedVaultRow): VaultActionResult? = if (row.role != RoleInVault.OWNER) VaultActionResult.NOT_OWNER else null

    override suspend fun createVault(name: String): VaultActionResult {
        if (vault() == null) return VaultActionResult.STALE
        if (name.isBlank()) return VaultActionResult.NOT_ALLOWED
        return act(null, LogAction.Create(name.trim())).first
    }

    override suspend fun renameVault(vault: SharedVaultRow, name: String): VaultActionResult {
        val v = vault() ?: return VaultActionResult.STALE
        val row = shown(vault.vaultId) ?: return VaultActionResult.STALE
        ownerOnly(row)?.let { return it }
        // A rename is a write of the vault's own record: refused like any change while its deletion waits.
        if (moveDeleteWaiting(v, row.vaultId)) return VaultActionResult.MOVE_DELETE_WAITING
        if (!row.writable) return VaultActionResult.READ_ONLY
        if (name.isBlank()) return VaultActionResult.NOT_ALLOWED
        val r = app.working { v.content.renameSharedVault(row.vaultId, name.trim()) }
        app.publish()
        return contentResult(r)
    }

    private fun contentResult(r: ActionResult): VaultActionResult = when (r) {
        is ActionResult.Ok -> VaultActionResult.DONE
        is ActionResult.NotDone -> if (vault() == null) VaultActionResult.STALE else VaultActionResult.FAILED
        else -> VaultActionResult.FAILED
    }

    override suspend fun openMembers(vault: SharedVaultRow): VaultActionResult {
        val v = vault() ?: return VaultActionResult.STALE
        shown(vault.vaultId) ?: return VaultActionResult.STALE
        if (verifiedState(v.logs.status(vault.vaultId)) == null) return VaultActionResult.NOT_ALLOWED
        membersOf = vault.vaultId
        grantsRead = null
        app.publish()
        readGrants()
        return VaultActionResult.DONE
    }

    override fun closeMembers() {
        membersOf = null
        grantsRead = null
        app.publish()
    }

    override suspend fun addMember(screen: MembersScreen, contact: ContactRow, role: MemberRole): VaultActionResult {
        val v = vault() ?: return VaultActionResult.STALE
        if (membersOf != screen.vault.vaultId) return VaultActionResult.STALE
        val row = shown(screen.vault.vaultId) ?: return VaultActionResult.STALE
        ownerOnly(row)?.let { return it }
        // Refused before the uncompared warning too: nothing is offered that would only be refused after it.
        if (moveDeleteWaiting(v, row.vaultId)) return VaultActionResult.MOVE_DELETE_WAITING
        val now = app.contactsFlow.rowFor(contact.userId) ?: return VaultActionResult.NOT_A_CONTACT_HERE
        if (!now.currentHere) return VaultActionResult.NOT_A_CONTACT_HERE
        if (!now.compared) {
            // §6.7 step 8 (T-B2): nothing is shared until the person confirms exactly this share.
            warning = UncomparedShareWarning(row.vaultId, row.name.orEmpty(), now.userId, now.label, role)
            warningForLink = null
            app.publish()
            return VaultActionResult.NEEDS_UNCOMPARED_WARNING
        }
        if (v.closed) return VaultActionResult.STALE
        return act(row.vaultId, LogAction.Add(now.userId, role.literal)).first
    }

    override suspend fun confirmUncomparedShare(warning: UncomparedShareWarning): VaultActionResult {
        if (vault() == null) return VaultActionResult.STALE
        if (this.warning !== warning) return VaultActionResult.STALE
        this.warning = null
        // A share waiting on a link goes through the link's own record (§6.10), so it leaves the link's waiting list.
        warningForLink?.let { share ->
            warningForLink = null
            return app.linksFlow.release(share)
        }
        return act(warning.vaultId, LogAction.Add(warning.userId, warning.role.literal, releaseUncompared = true)).first
    }

    override fun cancelUncomparedShare(warning: UncomparedShareWarning) {
        if (this.warning !== warning) return
        this.warning = null
        warningForLink = null
        app.publish()
    }

    /** The waiting link share the warning on show is for ([io.silencelen.andvari.core.app.LinksApi.releaseShare]); null for a Members screen add. */
    private var warningForLink: io.silencelen.andvari.core.app.PendingShareRow? = null

    /** §6.7 step 8 for a share waiting on a link: the warning first, and nothing is shared until it is confirmed. */
    fun warnForLinkShare(share: io.silencelen.andvari.core.app.PendingShareRow) {
        warning = UncomparedShareWarning(share.vaultId, share.vaultName, share.userId, share.label, share.role)
        warningForLink = share
        app.publish()
    }

    /** What a log append came to, as an intent's result. */
    internal fun resultOf(r: AppendOutcome): VaultActionResult = result(r)

    private fun memberOnShow(member: MemberRow): Boolean =
        membersOf == member.vaultId && members()?.members?.any { it.userId == member.userId } == true

    override suspend fun changeRole(member: MemberRow, role: MemberRole): VaultActionResult {
        if (vault() == null || !memberOnShow(member)) return VaultActionResult.STALE
        val row = shown(member.vaultId) ?: return VaultActionResult.STALE
        ownerOnly(row)?.let { return it }
        return act(member.vaultId, LogAction.Role(member.userId, role.literal)).first
    }

    override suspend fun removeMember(member: MemberRow): VaultActionResult {
        if (vault() == null || !memberOnShow(member)) return VaultActionResult.STALE
        val row = shown(member.vaultId) ?: return VaultActionResult.STALE
        ownerOnly(row)?.let { return it }
        return act(member.vaultId, LogAction.Remove(member.userId)).first
    }

    override suspend fun leaveVault(vault: SharedVaultRow): VaultActionResult {
        if (vault() == null) return VaultActionResult.STALE
        val row = shown(vault.vaultId) ?: return VaultActionResult.STALE
        if (moveDeleteWaiting(row.vaultId)) return VaultActionResult.MOVE_DELETE_WAITING
        if (row.role == RoleInVault.OWNER) return VaultActionResult.NOT_ALLOWED
        return act(row.vaultId, LogAction.Leave, departing = true).first
    }

    override suspend fun offerOwnership(member: MemberRow): VaultActionResult {
        if (vault() == null || !memberOnShow(member)) return VaultActionResult.STALE
        val row = shown(member.vaultId) ?: return VaultActionResult.STALE
        ownerOnly(row)?.let { return it }
        return act(member.vaultId, LogAction.Offer(member.userId, OFFER_MS)).first
    }

    override suspend fun cancelOffer(vault: SharedVaultRow): VaultActionResult {
        if (vault() == null) return VaultActionResult.STALE
        val row = shown(vault.vaultId) ?: return VaultActionResult.STALE
        if (moveDeleteWaiting(row.vaultId)) return VaultActionResult.MOVE_DELETE_WAITING
        val offer = row.offer ?: return VaultActionResult.NOT_ALLOWED
        if (row.role != RoleInVault.OWNER && !offer.toMe) return VaultActionResult.NOT_OWNER
        return act(row.vaultId, LogAction.Cancel).first
    }

    override suspend fun acceptOwnership(vault: SharedVaultRow): VaultActionResult {
        if (vault() == null) return VaultActionResult.STALE
        val row = shown(vault.vaultId) ?: return VaultActionResult.STALE
        if (moveDeleteWaiting(row.vaultId)) return VaultActionResult.MOVE_DELETE_WAITING
        if (row.offer?.toMe != true) return VaultActionResult.NOT_ALLOWED
        return act(row.vaultId, LogAction.Accept).first
    }

    override suspend fun deleteVault(vault: SharedVaultRow): VaultActionResult {
        if (vault() == null) return VaultActionResult.STALE
        val row = shown(vault.vaultId) ?: return VaultActionResult.STALE
        ownerOnly(row)?.let { return it }
        return act(row.vaultId, LogAction.Delete, departing = true).first
    }

    override suspend fun restoreVault(vault: SharedVaultRow): VaultActionResult {
        if (vault() == null) return VaultActionResult.STALE
        val row = shown(vault.vaultId) ?: return VaultActionResult.STALE
        ownerOnly(row)?.let { return it }
        if (moveDeleteWaiting(row.vaultId)) return VaultActionResult.MOVE_DELETE_WAITING
        if (!row.deleted) return VaultActionResult.NOT_ALLOWED
        return restored(act(row.vaultId, LogAction.Restore).first)
    }

    override suspend fun restoreDeletedVault(vault: io.silencelen.andvari.core.app.DeletedVaultView): VaultActionResult {
        if (vault() == null) return VaultActionResult.STALE
        val list = app.content?.state?.deletedVaults ?: return VaultActionResult.STALE
        if (list.none { it === vault }) return VaultActionResult.STALE
        // The row, when the vault is still listed among the shared vaults, says who may; otherwise the log decides.
        shown(vault.vaultId)?.let { row -> ownerOnly(row)?.let { return it } }
        return restored(act(vault.vaultId, LogAction.Restore).first)
    }

    /** After a restore the content syncs, then an open "Recently deleted" list is read again (the vault left it). */
    private fun restored(r: VaultActionResult): VaultActionResult {
        val v = vault() ?: return r
        if (r == VaultActionResult.DONE) v.launch {
            v.content.syncQuietly()
            if (v.content.state.deletedVaults != null) v.content.openDeletedVaults()
        }
        return r
    }

    private suspend fun answer(prompt: AccountPrompt.IncomingVault, accept: Boolean): VaultActionResult {
        val v = vault() ?: return VaultActionResult.STALE
        if (incoming[prompt.vaultId] !== prompt) return VaultActionResult.STALE
        val ask = adoptions[prompt.vaultId] as? Adoption.AskAccept ?: return VaultActionResult.STALE
        if (app.content?.state?.removingLine != null) return VaultActionResult.REMOVING_COPY
        if (app.content.isNullOrStopped()) return VaultActionResult.FAILED
        if (moveDeleteWaiting(v, prompt.vaultId)) return VaultActionResult.MOVE_DELETE_WAITING
        // A decline signs a `leave`: the item engine is told first, so the vault goes quietly.
        if (!accept) v.beforeDeparture(prompt.vaultId)
        val r = app.unlessLocked(null) { app.working { v.logs.answerIncoming(ask, accept) } }
        if (r == null || v.closed) return VaultActionResult.STALE
        incoming.remove(prompt.vaultId)
        // A decline whose leave was not recorded: the quiet departure expected above is withdrawn.
        if (!accept && r !is Adoption.Declined) v.departureRefused(prompt.vaultId)
        if (r is Adoption.Adopted) adoptions.remove(prompt.vaultId) else adoptions[prompt.vaultId] = r
        v.afterLogAction()
        app.publish()
        return when {
            accept && r is Adoption.Adopted -> VaultActionResult.DONE
            // The decline is recorded for the account; its `leave` (so the owner sees it) may still wait for an answer,
            // and is then not reported as stored.
            !accept && r is Adoption.Declined -> if (changeWaiting(v, prompt.vaultId)) VaultActionResult.SENT_PENDING else VaultActionResult.DONE
            // The log moved meanwhile (a new `add`, a removal): what it answers now is shown instead.
            r is Adoption.AskAccept -> VaultActionResult.CHANGED_MEANWHILE
            else -> VaultActionResult.FAILED
        }
    }

    override suspend fun acceptIncoming(prompt: AccountPrompt.IncomingVault): VaultActionResult = answer(prompt, true)

    override suspend fun declineIncoming(prompt: AccountPrompt.IncomingVault): VaultActionResult = answer(prompt, false)

    override suspend fun saveItemsElsewhere(vault: SharedVaultRow, toVaultId: String?): VaultActionResult {
        val v = vault() ?: return VaultActionResult.STALE
        val row = shown(vault.vaultId) ?: return VaultActionResult.STALE
        if (!row.canSaveElsewhere && row.heldUntilMs == 0L) return VaultActionResult.NOT_ALLOWED
        // GAP: the content copies a whole vault into the personal vault only; another destination is not offered yet.
        if (toVaultId != null && toVaultId != v.personalVaultId) return VaultActionResult.FAILED
        val r = app.working { v.content.saveVaultItemsToPersonal(row.vaultId) }
        app.publish()
        return contentResult(r)
    }

    override fun removeFromThisDevice(vault: SharedVaultRow) {
        val v = vault() ?: return
        val row = shown(vault.vaultId) ?: return
        if (!row.canRemoveFromDevice) return
        v.content.removeFromDevice(row.vaultId)
        app.publish()
    }

    override suspend fun openMoveEverything(vault: SharedVaultRow): VaultActionResult {
        if (vault() == null) return VaultActionResult.STALE
        val row = shown(vault.vaultId) ?: return VaultActionResult.STALE
        return openMove(row, null)
    }

    override suspend fun openMoveEverythingRemoving(member: MemberRow): VaultActionResult {
        val v = vault() ?: return VaultActionResult.STALE
        if (!memberOnShow(member)) return VaultActionResult.STALE
        val row = shown(member.vaultId) ?: return VaultActionResult.STALE
        if (member.userId == me(v) || member.role == RoleInVault.OWNER) return VaultActionResult.NOT_ALLOWED
        // A remove on the old log while its deletion waits: refused; the waiting move is finished from its own offer.
        if (moveDeleteWaiting(v, row.vaultId)) return VaultActionResult.MOVE_DELETE_WAITING
        return openMove(row, member.userId)
    }

    /**
     * Offered as the web offers it: to the vault's owner, on a vault that is
     * verified, frozen or failed, not deleted, and whose items this device can copy out.
     */
    private fun openMove(row: SharedVaultRow, removing: String?): VaultActionResult {
        val v = vault() ?: return VaultActionResult.STALE
        if (moveProgress.first) return VaultActionResult.STALE
        ownerOnly(row)?.let { return it }
        val offered = row.log == VaultLogState.VERIFIED || row.log == VaultLogState.FROZEN || row.log == VaultLogState.FAILED
        // A run whose old-vault delete was sent without an answer may be opened again on that vault even once the server
        // stored the delete meanwhile: moving again finishes it (the run's last steps).
        val finishing = runFor(v, row.vaultId)?.let { it.deleteSent && !it.storedOutside } == true
        if (!offered || (row.deleted && !finishing) || !row.canSaveElsewhere) return VaultActionResult.NOT_ALLOWED
        if (verifiedState(v.logs.status(row.vaultId)) == null) return VaultActionResult.NOT_ALLOWED
        moveOf = row.vaultId
        moveRemoving = removing
        moveTicks = HashMap()
        moveFinished = null
        moveSpace = null
        moveProgress = Triple(false, runFor(v, row.vaultId)?.copied?.size ?: 0, 0)
        app.publish()
        return VaultActionResult.DONE
    }

    override fun closeMoveEverything() {
        if (moveProgress.first) return
        moveOf = null
        moveRemoving = null
        moveTicks.clear()
        moveFinished = null
        moveSpace = null
        app.publish()
    }

    override fun tickMember(screen: MoveEverythingScreen, member: MoveMemberRow, ticked: Boolean) {
        if (moveOf != screen.vault.vaultId || !member.canBeAdded || moveProgress.first) return
        // Ticks only on a frozen or failed vault (§3.13): a vault in good standing adds every remaining member.
        if (moving()?.ticksOffered != true) return
        moveTicks[member.userId] = ticked
        app.publish()
    }

    /**
     * §3.13, in the design's order and as the web runs it: the removed member's `remove` on the old log (from the remove
     * dialog, on a vault in good standing); a new vault; every live item copied into it (the list read again until
     * nothing new is left); the remaining members added with the role they hold now (on a frozen or failed vault, only
     * those ticked); and the old vault deleted, only on a vault in good standing with every member added and every item
     * copied. Nothing is ever in neither vault: the old one is untouched until that last step.
     *
     * A stop at any step is said on the screen ([MoveEverythingScreen.stopped]), and the next run carries on from it. A
     * lock that overtakes a step is the intent's own STALE (each step signs under the key guard and sends nothing after
     * the wipe), and drops the run.
     */
    override suspend fun moveEverything(screen: MoveEverythingScreen, name: String): VaultActionResult {
        if (vault() == null) return VaultActionResult.STALE
        if (moveOf != screen.vault.vaultId || moveProgress.first || runOf != null) return VaultActionResult.STALE
        runOf = screen.vault.vaultId
        try {
            return runMove(screen, name)
        } finally {
            runOf = null
        }
    }

    private suspend fun runMove(screen: MoveEverythingScreen, name: String): VaultActionResult {
        val v = vault() ?: return VaultActionResult.STALE
        val from = screen.vault.vaultId
        // A kept record that cannot be read now: no run, since one made without it could make a second new vault.
        val earlier = runFor(v, from)
        if (from in runsUnreadable) return VaultActionResult.FAILED
        // The deletion was stored outside the move: the move is over; what changed after the copies is the notice's.
        if (earlier?.storedOutside == true) {
            closeMoveEverything()
            return VaultActionResult.DONE
        }
        // A carried-on run first reads the old vault's log (nothing is posted), so the plan's members
        // are those of the log as it stands now.
        if (earlier != null && !settled(v, from)) return VaultActionResult.STALE
        // That read can freeze the old vault (its server named the move's own deletion stored where another entry stands),
        // and the freeze drops the held deletion. The move looks for that first: it says the old vault is frozen and stops
        // read-only; it does not clear its mark of a waiting deletion as if the deletion had ended, and no fresh start is
        // offered (the old vault is read-only here for good, and nothing more is sent on its log).
        if (earlier != null && earlier.deleteSent && v.logs.status(from) is VaultLogStatus.Frozen) {
            earlier.stop = MoveStop(MoveStage.DELETE_OLD_VAULT, earlier.name, earlier.copied.size, earlier.copied.size,
                VaultActionResult.READ_ONLY, CopyKey.MOVE_OLD_VAULT_FROZEN)
            keepRun(v, from, earlier)
            moveProgress = Triple(false, earlier.copied.size, earlier.copied.size)
            app.publish()
            return VaultActionResult.READ_ONLY
        }
        // The held delete's place was taken (another stored change stands where it would have gone) or nothing waits any
        // more and it was not stored: it can never be stored, and the log engine drops it by its own rule. The run goes on
        // as an ordinary run, with the members read again above, and signs a new delete only when every condition of
        // §3.13 holds (decided on 16 November 2026).
        if (earlier != null && earlier.deleteSent && !deleteStored(v, from)) {
            val head = verifiedState(v.logs.status(from))?.headSeq ?: -1L
            if (head > earlier.deleteAtSeq || !changeWaiting(v, from)) {
                earlier.deleteSent = false
                earlier.stop = null
                keepRun(v, from, earlier)
                // That deletion no longer waits: the old vault is open for writing again until a new one is signed.
                closeWaiting(v, from)
            }
        }
        val plan = moving() ?: return VaultActionResult.STALE
        val adds = planAdds(plan)
        val prior = runFor(v, from)
        val newName = prior?.name?.ifEmpty { null } ?: name.trim()
        if (newName.isEmpty()) return VaultActionResult.NOT_ALLOWED
        // A run whose old-vault delete is in flight is always carried on: its adds are done, and nothing is made afresh
        // while that delete may still be stored.
        val run = if (prior != null && (prior.deleteSent || resumable(v, prior, adds))) {
            prior.also { it.name = newName }
        } else if (prior != null && screen.startsFresh == null) {
            // The members changed since the run's adds (its held delete was dropped above): the person is told before a
            // fresh vault is made (MoveEverythingScreen.startsFresh), and the next run makes it.
            prior.stop = MoveStop(MoveStage.ADD_MEMBERS, prior.name.ifEmpty { newName }, prior.copied.size, prior.copied.size, VaultActionResult.CHANGED_MEANWHILE, CopyKey.MOVE_STOPPED)
            app.publish()
            return VaultActionResult.CHANGED_MEANWHILE
        } else {
            // F1: the half-made new vault holds someone this plan does not add: a fresh vault with a fresh key, and the
            // half-made one deleted once this run has finished (said before the start: MoveEverythingScreen.startsFresh).
            MoveRun(newName, Bytes.uuidV4FromBytes(app.crypto.randomBytes(16))).also { fresh ->
                if (prior != null) {
                    // Each half-made vault keeps beside it what the move made there, for the read before its deletion.
                    fresh.discard += prior.discard
                    fresh.discardMade += prior.discardMade
                    prior.newVaultId?.let {
                        fresh.discard += it
                        fresh.discardMade[it] = prior.madeHere()
                    }
                }
                moveRuns[from] = fresh
            }
        }
        run.stop = null
        moveFinished = null
        keepRun(v, from, run)
        var total = run.copied.size

        fun stop(stage: MoveStage, result: VaultActionResult, line: CopyKey = CopyKey.MOVE_STOPPED): VaultActionResult {
            // A lock ended the session: the intent is stale; the run stays kept on the device as far as it got.
            if (vault() == null || result == VaultActionResult.STALE) return VaultActionResult.STALE
            run.stop = MoveStop(stage, run.name, run.copied.size, total, result, line)
            keepRun(v, from, run)
            moveProgress = Triple(false, run.copied.size, total)
            app.publish()
            return result
        }

        // The check for space, before anything is signed or sent (design §3.13, spec 03 §14.4; the content's one call): a
        // fresh sync, then the items not copied yet (on a carried-on run, an item copied at the revision it has now
        // counts as copied) with their files, plus the new vault while it is not made. Short: nothing is done, and the
        // screen says which limit and by how much. Short only on the file sizes items state, or unknown (no use and
        // limits served, or the check could not be made): the move goes on and the server decides.
        val revNow = v.items.items().filter { it.vaultId == from }.associate { it.itemId to it.rev }
        val copiedNow = run.copied.filter { (id, rev) -> revNow[id] == rev }.keys.toList()
        val space = v.content.spaceForMoveEverything(from, if (run.newVaultId == null) run.name else null, copiedNow)
        if (v.closed || vault() == null) return VaultActionResult.STALE
        moveSpace = space?.takeIf { it.verdict == SpaceVerdict.NOT_ENOUGH || it.verdict == SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES }
        if (space?.verdict == SpaceVerdict.NOT_ENOUGH) {
            total = run.copied.size + v.items.items().count { it.vaultId == from && it.itemId !in copiedNow }
            return stop(if (run.newVaultId == null) MoveStage.CREATE_VAULT else MoveStage.TRANSFER_ITEMS, VaultActionResult.OUT_OF_SPACE)
        }

        // A carried-on run first looks at what the server holds (a change of an earlier run sent without an answer is
        // re-posted byte for byte and the log read again), and only then decides what is left to send.
        if (prior === run) {
            run.newVaultId?.let { if (!settled(v, it)) return VaultActionResult.STALE }
            for (half in run.discard) if (!settled(v, half)) return VaultActionResult.STALE
        }
        // The old vault's log was read before the plan (posting nothing). Its delete stored meanwhile:
        // the move is finished, and only now is the old vault deleted. (A delete whose place was taken was dropped above;
        // one that can still be stored waits: the run copies what is new or changed first, and re-posts it last.)
        if (run.deleteSent && deleteStored(v, from)) return finishMove(run, from, null, emptyList(), total)

        // 0. The member the remove dialog is about, removed on the old log first (never on a frozen or failed vault).
        val removing = moveRemoving
        if (!run.removed && removing != null && !plan.sourceStays && verifiedState(v.logs.status(from))?.members?.containsKey(removing) == true) {
            val r = act(from, LogAction.Remove(removing), byMove = true).first
            // A remove sent and not yet acknowledged has not happened yet: the move waits for it.
            if (r != VaultActionResult.DONE) return stop(MoveStage.REMOVE_MEMBER, r)
        }
        run.removed = true
        keepRun(v, from, run)
        // The old vault's head the plan's members were checked at (after this run's own remove): the delete is signed
        // only over that head. Another stored change after it makes the run stop and the next run read again.
        val checked = verifiedState(v.logs.status(from))?.let { it.headSeq to it.headHash }

        // 0b. Half-made vaults an earlier run left (F1), each dealt with before this run makes or copies anything, so a move
        //     that removes a member never leaves them holding copies unsaid. Each is read first ([readHalfMade]): holding
        //     only what the move made, at the revisions it made them, it is deleted (the old vault still holds everything
        //     meanwhile), and it counts as gone only once the server stored its delete; holding anything else, it is not
        //     deleted and stays a vault of its own, and the person is told its name ([MoveNote]). A held deletion of it from
        //     an earlier try is re-posted only after that read.
        for (half in run.discard.toList()) {
            if (vault() == null) return VaultActionResult.STALE
            if (deleteStored(v, half)) {
                run.discard -= half
                run.discardMade.remove(half)
                continue
            }
            val read = readHalfMade(v, half, run.discardMade[half])
            if (read == HalfRead.Locked) return VaultActionResult.STALE
            // Frozen on this device: it can never be deleted from here, so it is kept as a vault of its own with a note, and
            // the move goes on without it. Nothing of it is sent.
            if (v.logs.status(half) is VaultLogStatus.Frozen) {
                halfMadeFrozen(v, from, run, half, removing)
                continue
            }
            val readAt = when (read) {
                HalfRead.Locked -> return VaultActionResult.STALE
                // Not read: nothing is deleted and nothing is said of what it holds; it stays due for the next run.
                HalfRead.Unread -> return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.FAILED, CopyKey.MOVE_DISCARD_UNREAD)
                is HalfRead.Other -> {
                    // A deletion of it that an earlier try signed and the log engine still holds is dropped, unsent, by the
                    // engine's own call, which remembers it where it may already be stored (a later read that finds it says
                    // so in a line of its own). Kept, it would wait for a word that deletes a vault holding other items.
                    if (changeWaiting(v, half)) {
                        val dropped = app.unlessLocked(null) { app.working { v.logs.dropHalfMade(half) } } ?: return VaultActionResult.STALE
                        if (vault() == null || v.closed) return VaultActionResult.STALE
                        // Its first request is still out: nothing dropped yet; the next run drops it.
                        if (dropped is HeldWithdrawal.Kept && dropped.reason == HeldWithdrawal.FIRST_REQUEST_OUT) {
                            return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.SENT_PENDING)
                        }
                    }
                    // The note is kept at rest before the vault leaves the move's record: a lock or a close in between
                    // never leaves a kept vault (and a member who still holds it) unnamed.
                    halfMadeKept(v, from, half, read.foreign, removing)
                    run.discard -= half
                    run.discardMade.remove(half)
                    keepRun(v, from, run)
                    continue
                }
                is HalfRead.OnlyCopies -> read.readAt
            }
            // A held change of it is re-posted now, after the read and signing nothing, only where it is the move's own
            // deletion; stored, it is its delete. A change that is not the move's (the person's own deletion waits for their
            // word) is not sent by the move: the run stops until it is settled.
            if (changeWaiting(v, half)) {
                val mine = v.logs.heldChange(half)
                if (mine != null && !mine.movesOwn) {
                    return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.SENT_PENDING, CopyKey.MOVE_OTHER_CHANGE_WAITING)
                }
                val held = (if (mine == null) heldUnread(v, half) else app.unlessLocked(null) { app.working { v.logs.repostHeld(half, mine.hash) } })
                    ?: return VaultActionResult.STALE
                if (vault() == null || v.closed || held == HeldRepost.NotThisChange) return VaultActionResult.STALE
                if (held is HeldRepost.Stored || held is HeldRepost.Dropped) v.afterLogAction()
                if (deleteStored(v, half)) {
                    run.discard -= half
                    run.discardMade.remove(half)
                    continue
                }
                if (held is HeldRepost.Waiting || held is HeldRepost.RefusedCannotTell) {
                    return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.SENT_PENDING, CopyKey.MOVE_DISCARD_UNCONFIRMED)
                }
                if (held is HeldRepost.Refused && held.code == StoredVaultLogs.VAULT_FROZEN) {
                    halfMadeFrozen(v, from, run, half, removing)
                    continue
                }
                // Refused because an item moved after its read point: dropped, nothing stored; this run's read is newer,
                // and the deletion below names it.
            }
            // Not verified here: it cannot be deleted from this device now, and it is not forgotten either.
            val h = verifiedState(v.logs.status(half)) ?: return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.FAILED)
            // The move's own deletion, naming the point up to which the read above saw its items: where any item of it moved
            // since, the server refuses it, nothing is stored or held, and the next run reads it again.
            val (r, outcome) = act(half, LogAction.DeleteVault(movesOwn = true, itemsAtMost = readAt), departing = true,
                expectHead = io.silencelen.andvari.core.trust.Checkpoint(h.headSeq, h.headHash))
            when {
                // Its held delete re-posted and stored first makes the new entry refused locally: the stored one counts.
                r == VaultActionResult.DONE || deleteStored(v, half) -> {
                    run.discard -= half
                    run.discardMade.remove(half)
                    keepRun(v, from, run)
                }
                // Frozen by what this deletion's own answer or read found: kept, as above; nothing more of it is sent.
                v.logs.status(half) is VaultLogStatus.Frozen -> halfMadeFrozen(v, from, run, half, removing)
                outcome is AppendOutcome.Pending -> return stop(MoveStage.DELETE_OLD_VAULT, r, CopyKey.MOVE_DISCARD_UNCONFIRMED)
                outcome is AppendOutcome.Refused && outcome.code == WireErrors.VAULT_ITEMS_MOVED ->
                    return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.CHANGED_MEANWHILE)
                else -> return stop(MoveStage.DELETE_OLD_VAULT, r)
            }
        }

        // 1. The new vault, made once, under the id this run chose: asked again for that id, the log engine re-posts a
        //    genesis it still holds byte for byte, answers one it verified as made, and signs one only when it holds
        //    nothing for it (an earlier genesis the server refused). Never two vaults for one run.
        if (run.newVaultId == null) {
            val (made, outcome) = act(null, LogAction.Create(run.name, run.plannedId))
            when (outcome) {
                is AppendOutcome.Appended -> run.newVaultId = outcome.state.vaultId
                AppendOutcome.Pending -> return stop(MoveStage.CREATE_VAULT, VaultActionResult.SENT_PENDING)
                else -> return stop(MoveStage.CREATE_VAULT, made)
            }
            keepRun(v, from, run)
        }
        val target = run.newVaultId ?: return stop(MoveStage.CREATE_VAULT, VaultActionResult.FAILED)
        // The new vault's key is used once the engine has re-read its keys.
        v.content.syncQuietly()
        if (v.closed) return VaultActionResult.STALE
        if (v.content.vaultsForNewItems().none { it.vaultId == target }) return stop(MoveStage.CREATE_VAULT, VaultActionResult.FAILED)

        // 2. Every live item, copied (never moved: the originals stay until the old vault is deleted). Items that arrive
        //    meanwhile are copied too: the list is read again after each pass.
        for (pass in 0 until MOVE_PASSES) {
            // An item new since its copy, or at a later revision than the one copied (F2), is copied (again).
            val left = v.items.items().filter { it.vaultId == from && run.copied[it.itemId] != it.rev }.sortedBy { it.itemId }
            total = run.copied.size + left.count { it.itemId !in run.copied }
            moveProgress = Triple(true, run.copied.size, total)
            app.publish()
            if (left.isEmpty()) break
            for (item in left) {
                val itemId = item.itemId
                // Copied before, and this device does not know which item its copy is: a second copy would stand beside
                // the first, so the run stops here (the old vault keeps everything).
                if (itemId in run.copied && itemId !in run.copies) return stop(MoveStage.TRANSFER_ITEMS, VaultActionResult.FAILED)
                // The copy's id is the one item the copy adds to the new vault (the item engine keeps it at once).
                val before = v.items.items().filter { it.vaultId == target }.mapTo(HashSet()) { it.itemId }
                val r = v.content.moveOrCopyItem(itemId, target, move = false)
                if (v.closed || vault() == null) return VaultActionResult.STALE
                when {
                    r is ActionResult.Ok -> {
                        val made = v.items.items().filter { it.vaultId == target && it.itemId !in before }.map { it.itemId }
                        // A later revision replaces its earlier copy, never stands beside it (decided on 16 November 2026): the new
                        // copy is made first, so the item is never in neither vault, and the earlier one is deleted below.
                        run.replaced(itemId)
                        made.singleOrNull()?.let { run.copyMade(v, itemId, it) }
                        run.copied[itemId] = item.rev
                        keepRun(v, from, run)
                    }
                    // Deleted meanwhile: it is in the old vault's trash, which stays with the old vault.
                    r is ActionResult.Failed && r.message == ContentCopy.ITEM_GONE -> total--
                    r is ActionResult.Failed && ContentCopy.isOutOfSpace(r.message) -> return stop(MoveStage.TRANSFER_ITEMS, VaultActionResult.OUT_OF_SPACE)
                    else -> return stop(MoveStage.TRANSFER_ITEMS, VaultActionResult.FAILED)
                }
                moveProgress = Triple(true, run.copied.size, total)
                app.publish()
            }
            v.content.syncQuietly()
            if (v.closed) return VaultActionResult.STALE
        }
        // 2b. Earlier copies a later revision replaced go from the new vault (into its trash), before the old vault is
        //     touched, each only at the revision the move made it at ([dropStale]). One that cannot be deleted now stops
        //     the run, and the next run deletes it.
        for (old in run.stale.toList()) {
            when (dropStale(v, from, old, run)) {
                null -> return VaultActionResult.STALE
                false -> return stop(MoveStage.TRANSFER_ITEMS, VaultActionResult.FAILED)
                true -> {}
            }
        }
        // Still arriving after the last pass: the old vault is not deleted under them; the next run carries on.
        if (changedSinceCopied(v, from, run)) return stop(MoveStage.TRANSFER_ITEMS, VaultActionResult.CHANGED_MEANWHILE)

        // 3. The remaining members, each with the role they hold now. One this device cannot add is named, not added.
        val notAdded = ArrayList<MoveMemberRow>()
        for (m in if (plan.sourceStays) plan.members.filter { it.ticked } else plan.members) {
            if (m.userId in run.added || verifiedState(v.logs.status(target))?.members?.containsKey(m.userId) == true) {
                run.added += m.userId
                continue
            }
            if (!m.canBeAdded) {
                notAdded += m
                continue
            }
            // Signed as the move's own: held, it is sent again and given up after a day like any addition, never withdrawn.
            val (r, outcome) = act(target, LogAction.Add(m.userId, m.role.literal, movesOwn = true))
            // An earlier run's add that was kept and re-posted first (§3.7) may have added them already: the log refuses a
            // second add, and once read again shows the first. That is the add.
            if (outcome is AppendOutcome.NotAllowed && outcome.reason == VaultLogVerdict.PRECONDITION.code) {
                app.unlessLocked(null) { app.working { v.logs.refresh(target, null, null, force = true) } }
                if (vault() == null) return VaultActionResult.STALE
                if (verifiedState(v.logs.status(target))?.members?.containsKey(m.userId) == true) {
                    run.added += m.userId
                    continue
                }
            }
            when (r) {
                VaultActionResult.DONE -> run.added += m.userId
                VaultActionResult.NEEDS_UNCOMPARED_WARNING, VaultActionResult.NOT_A_CONTACT_HERE -> notAdded += m
                else -> return stop(MoveStage.ADD_MEMBERS, r)
            }
        }

        keepRun(v, from, run)

        // 3b. The new vault's members as its log, read again now, says the server holds them.
        //     Only an add the server stored counts; nobody the plan does not add is there. Otherwise the run stops at the
        //     adds (an add counted but not stored is sent again by the next run), and the old vault is not deleted.
        app.unlessLocked(null) { app.working { v.logs.refresh(target, null, null, force = true) } }
        if (vault() == null || v.closed) return VaultActionResult.STALE
        val inNew = verifiedState(v.logs.status(target))?.members?.keys?.minus(me(v))
            ?: return stop(MoveStage.ADD_MEMBERS, VaultActionResult.FAILED)
        val notStored = run.added - inNew
        if (notStored.isNotEmpty()) {
            run.added -= notStored
            return stop(MoveStage.ADD_MEMBERS, VaultActionResult.FAILED)
        }
        if (inNew.any { it !in adds }) return stop(MoveStage.ADD_MEMBERS, VaultActionResult.NOT_ALLOWED)

        // 4. The old vault, deleted into its grace: only on a vault in good standing with nothing left behind.
        val unreadable = unreadableIn(v, from)
        val kept = when {
            plan.sourceStays -> MoveKept.SOURCE_STAYS
            notAdded.isNotEmpty() -> MoveKept.MEMBER_CANNOT_BE_ADDED
            unreadable > 0 -> MoveKept.UNREADABLE_ITEMS
            else -> null
        }
        // 4b. The old vault: counted as deleted only once the server stored its delete. Sent without an answer, the delete
        //     is kept and re-posted byte for byte (§3.7), the run is kept, and the screen says the old vault still exists.
        if (kept == null) {
            // F2: the old vault read once more after the adds: anything new there, or changed since its copy, keeps it.
            v.content.syncQuietly()
            if (v.closed || vault() == null) return VaultActionResult.STALE
            // The point up to which this read saw the old vault's items: its deletion names it, so the server refuses the
            // deletion where an item moved since (nothing is stored then, and the next run carries what is late).
            val readAt = v.itemsReadAt()
            if (changedSinceCopied(v, from, run)) return stop(MoveStage.TRANSFER_ITEMS, VaultActionResult.CHANGED_MEANWHILE)
            // A held change of the old vault is re-posted here, by the move alone and only now, byte
            // for byte, and nothing new is signed with it: stored, the move is finished; still unanswered, it waits; its
            // place taken by another stored change, it is dropped, and the check below makes the run read again. Only the
            // move's own deletion is re-posted: a change that is not the move's (the person's own deletion of this vault
            // waits for their word) is not sent by the move, and the run stops until it is settled.
            if (changeWaiting(v, from)) {
                val mine = v.logs.heldChange(from)
                if (mine != null && !mine.movesOwn) {
                    return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.SENT_PENDING, CopyKey.MOVE_OTHER_CHANGE_WAITING)
                }
                // The move's own delete, stored by this re-post: its departure is not news.
                if (run.deleteSent) v.beforeDeparture(from)
                val reposted = if (mine == null) heldUnread(v, from) else app.unlessLocked(null) { app.working { v.logs.repostHeld(from, mine.hash) } }
                if (reposted == null || vault() == null || v.closed || reposted == HeldRepost.NotThisChange) return VaultActionResult.STALE
                if (reposted is HeldRepost.Stored || reposted is HeldRepost.Dropped) v.afterLogAction()
                app.publish()
                val held = repostResult(reposted)
                when {
                    deleteStored(v, from) -> return finishMove(run, from, null, notAdded, total)
                    // Frozen: the server's own answer named the deletion stored where the verified log holds another entry.
                    // Nothing more is sent, nothing is said of the change, and the old vault is read-only here for good: the
                    // stop says so (never "failed"), and the vault is not opened for writing again (the freeze keeps it shut;
                    // only the move's own mark of a deletion that waits goes, since none waits now). Checked before a change
                    // that waits, so a record the freeze left is never said as a deletion still waiting.
                    reposted is HeldRepost.Refused && reposted.code == StoredVaultLogs.VAULT_FROZEN -> {
                        run.deleteSent = false
                        keepRun(v, from, run)
                        closeWaiting(v, from)
                        return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.READ_ONLY, CopyKey.MOVE_OLD_VAULT_FROZEN)
                    }
                    changeWaiting(v, from) -> {
                        if (!run.deleteSent) return stop(MoveStage.DELETE_OLD_VAULT, held)
                        return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.SENT_PENDING, CopyKey.MOVE_DELETE_UNCONFIRMED)
                    }
                    // Refused because an item of the old vault moved after the deletion's read point: nothing was stored and
                    // nothing is held; the old vault stays, open for writing again, and moving again carries what is late.
                    reposted is HeldRepost.Refused && reposted.code == WireErrors.VAULT_ITEMS_MOVED -> {
                        run.deleteSent = false
                        keepRun(v, from, run)
                        closeWaiting(v, from)
                        return stop(MoveStage.TRANSFER_ITEMS, VaultActionResult.CHANGED_MEANWHILE)
                    }
                    // Refused for good: the held change is dropped, and nothing new is signed in this run.
                    held == VaultActionResult.FAILED -> {
                        run.deleteSent = false
                        keepRun(v, from, run)
                        // The deletion was refused for good: the old vault is open for writing again.
                        closeWaiting(v, from)
                        return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.FAILED)
                    }
                    else -> {
                        // Its place was taken by another stored change: that deletion can never be stored. The vault stays
                        // closed only if this run signs a new one ([closeForDeletion] below).
                        run.deleteSent = false
                        keepRun(v, from, run)
                        closeWaiting(v, from)
                    }
                }
            }
            // The members were checked at [checked]: the delete is signed only over that very head, read again now. Any
            // other stored change since (a member added, removed or given another role meanwhile) makes the run stop, and
            // the next run reads the old vault's log again before it signs anything.
            if (!settled(v, from)) return VaultActionResult.STALE
            // This read too can freeze the old vault: then nothing is signed, the stop says the old vault is frozen, and no
            // mark of a waiting deletion is cleared as if a deletion had ended.
            if (v.logs.status(from) is VaultLogStatus.Frozen) {
                return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.READ_ONLY, CopyKey.MOVE_OLD_VAULT_FROZEN)
            }
            val now = verifiedState(v.logs.status(from))?.let { it.headSeq to it.headHash }
            if (now == null || now != checked) return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.CHANGED_MEANWHILE)
            // Signed only over that head: the log engine compares it with no wait before the signature, so a change stored
            // by another device between this check and the delete makes the run read again (CHANGED_MEANWHILE).
            // Closed for writing first (design §3.13): from the signature on, nothing more is put into the old vault here.
            closeForDeletion(v, from)
            // The move's own deletion (never sent by the general re-send, never withdrawn one by one), naming the read point.
            val (r, outcome) = act(from, LogAction.DeleteVault(movesOwn = true, itemsAtMost = readAt), departing = true, byMove = true,
                expectHead = io.silencelen.andvari.core.trust.Checkpoint(now.first, now.second))
            // A lock overtook the deletion (perhaps after its signature): nothing more is read under the wiped keys, and the
            // old vault's mark stays; the next opening finds the held change (moveDeleteWaiting) and keeps the vault closed.
            if (v.closed || vault() == null) return VaultActionResult.STALE
            when {
                // Stored (the held one re-posted and stored makes the new entry refused locally: the stored one counts).
                r == VaultActionResult.DONE || deleteStored(v, from) -> {
                    // The old vault's row says deleted at once: where this device's verified log does not show the stored
                    // deletion yet, it is read again now (a read only; nothing is sent), so the finished move never leaves
                    // the row reading as a live vault until the next sync.
                    if (!deleteStored(v, from)) settled(v, from)
                }
                outcome is AppendOutcome.Pending -> {
                    // Signed and waiting for the server, and it cannot be taken back (point 2): never "kept", never "deleted".
                    run.deleteSent = true
                    run.deleteAtSeq = verifiedState(v.logs.status(from))?.headSeq ?: -1L
                    return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.SENT_PENDING, CopyKey.MOVE_DELETE_UNCONFIRMED)
                }
                // An item of the old vault moved after the read: refused, nothing stored, nothing held. The old vault stays,
                // open for writing again, and moving again carries what is late.
                outcome is AppendOutcome.Refused && outcome.code == WireErrors.VAULT_ITEMS_MOVED -> {
                    closeWaiting(v, from)
                    return stop(MoveStage.TRANSFER_ITEMS, VaultActionResult.CHANGED_MEANWHILE)
                }
                else -> {
                    // Nothing waits: not signed (the head moved, a refusal before the signature) or refused for good.
                    closeWaiting(v, from)
                    // The old vault froze here (at the read that showed a contradiction, or at this append): the stop says so,
                    // as at a re-send refused for the freeze; it stays read-only.
                    if (v.logs.status(from) is io.silencelen.andvari.core.client.log.VaultLogStatus.Frozen) {
                        return stop(MoveStage.DELETE_OLD_VAULT, VaultActionResult.READ_ONLY, CopyKey.MOVE_OLD_VAULT_FROZEN)
                    }
                    return stop(MoveStage.DELETE_OLD_VAULT, r)
                }
            }
        }
        return finishMove(run, from, kept, notAdded, total)
    }

    /**
     * What a re-post of the old vault's held change byte for byte (the log engine's own re-post call, which signs nothing;
     * only the move re-posts it, after its own read of the log) comes to for the run. Stored: DONE (the move is finished
     * when it was the delete); its place taken by another stored change: DONE too, the held frame is dropped by the log's
     * own rule and the run reads the log again before it signs anything; no answer, or a refusal where an earlier send may
     * have stored it: SENT_PENDING; refused for good: FAILED; another change held than the one read: STALE.
     */
    private fun repostResult(r: HeldRepost): VaultActionResult {
        return when (r) {
            is HeldRepost.Stored, HeldRepost.NothingHeld, HeldRepost.Dropped -> VaultActionResult.DONE
            HeldRepost.Waiting, is HeldRepost.RefusedCannotTell -> VaultActionResult.SENT_PENDING
            is HeldRepost.Refused -> VaultActionResult.FAILED
            HeldRepost.NotThisChange -> VaultActionResult.STALE
        }
    }

    /**
     * Where a held record exists for [vaultId] but [VaultLogEngine.heldChange] reports none (its record cannot be read, or
     * it settled against what this device verified): nothing is sent, and the answer is the one the re-post would give.
     */
    private fun heldUnread(v: EngineVault, vaultId: String): HeldRepost = if (changeWaiting(v, vaultId)) HeldRepost.Waiting else HeldRepost.NothingHeld

    /** The move is done: the run is forgotten, here and on the device; the screen closes when the old vault was deleted, and says why it was kept otherwise. */
    private fun finishMove(run: MoveRun, from: String, kept: MoveKept?, notAdded: List<MoveMemberRow>, total: Int): VaultActionResult {
        vault()?.let { keptBesideNote(it, from, run) }
        vault()?.let { dropRun(it, from) } ?: moveRuns.remove(from)
        moveProgress = Triple(false, run.copied.size, total)
        if (kept == null) {
            moveOf = null
            moveRemoving = null
            moveTicks.clear()
        } else {
            moveFinished = MoveFinished(run.name, run.copied.size, kept, notAdded.map { it.who }, keptLine(kept))
        }
        app.publish()
        return VaultActionResult.DONE
    }

    /**
     * What the server holds for [vaultId], read before a carried-on run sends anything: the log is
     * read again, and nothing is posted. A held change is re-posted only by the run's own next action on that vault.
     * False when a lock overtook it.
     */
    private suspend fun settled(v: EngineVault, vaultId: String): Boolean {
        app.unlessLocked(null) { app.working { v.logs.refresh(vaultId, null, null, force = true) } }
        return vault() != null && !v.closed
    }

    /** What a read of a half-made vault found ([readHalfMade]). */
    private sealed class HalfRead {
        /**
         * Every item in it, live or in its trash, is a copy the move made, at the revision it made it. [readAt]: the sync
         * `rev` of the read that decided it, named beside its deletion so the server refuses it where an item moved since.
         */
        class OnlyCopies(val readAt: Long) : HalfRead()

        /** [foreign] items in it the move did not make (null: no record of what the move made there, so none can be told). */
        class Other(val foreign: Int?) : HalfRead()

        /** The read failed: nothing is decided, and nothing is said of what it holds. */
        object Unread : HalfRead()

        /** A lock overtook the read. */
        object Locked : HalfRead()
    }

    /**
     * Before any road deletes [half], a vault an earlier, stopped run of the move made: its log is read again, then a fresh
     * sync and the account's trash, so the read starts after the deletion is due (never a pull already held). What counts
     * as not the move's: a live item that is not one of [made]'s copies or stands at another revision than the one the move
     * made it at (a copy of no known revision too), a change of an item in it still waiting here, an item this device holds
     * there but cannot read, and a row in its trash that the move itself did not put there. A sync or a trash that cannot be
     * read is [HalfRead.Unread].
     *
     * Known gap (the server's): between this read and the deletion's commit a member's save can still land; the server
     * names only the log's head in a deletion, never the items. So "holds only copies" is said of the read, never of the
     * stored deletion.
     */
    private suspend fun readHalfMade(v: EngineVault, half: String, made: HalfMade?): HalfRead {
        if (!settled(v, half)) return HalfRead.Locked
        val synced = v.content.syncQuietly()
        if (v.closed || vault() == null) return HalfRead.Locked
        if (synced !is ActionResult.Ok) return HalfRead.Unread
        // The point up to which this read saw the vault's items: what is judged below is what stood there.
        val readAt = v.itemsReadAt()
        val trash = v.items.deletedItems()
        if (v.closed || vault() == null) return HalfRead.Locked
        val rows = (trash as? io.silencelen.andvari.core.client.items.ItemResult.Ok)?.value ?: return HalfRead.Unread
        if (made == null) return HalfRead.Other(null)
        val live = v.items.items().filter { it.vaultId == half }
        val readable = live.mapTo(HashSet()) { it.itemId }
        val waiting = v.items.waitingChanges(half)
        val unreadable = v.items.liveItemIdsIn(half).count { it !in readable }
        val changed = live.count { item -> made.copies[item.itemId].let { at -> at == null || at != item.rev } || item.itemId in waiting }
        val trashed = rows.count { it.vaultId == half && it.itemId !in made.trashed }
        val foreign = unreadable + changed + trashed
        return if (foreign == 0) HalfRead.OnlyCopies(readAt) else HalfRead.Other(foreign)
    }

    /**
     * [half] holds items the move did not make: it is not deleted, it stays a vault of its own, and the person is told its
     * name; where the run removes a member who holds it, also that they still hold it and what is in it (section of the
     * move that cuts a member off for good).
     */
    private fun halfMadeKept(v: EngineVault, from: String, half: String, foreign: Int?, removing: String?) {
        val lines = ArrayList<LineAtRest>()
        lines += if (foreign == null) LineAtRest(CopyKey.MOVE_HALF_MADE_KEPT_CANNOT_TELL.name, listOf(null))
            else LineAtRest(CopyKey.MOVE_HALF_MADE_KEPT.name, listOf(null, foreign.toLong()))
        val holds = removing?.let { verifiedState(v.logs.status(half))?.members?.get(it) }
        if (holds != null) lines += LineAtRest(CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS.name, listOf(null))
        addNote(v, NoteAtRest(from, half, lines, holds?.userId, holds?.key))
        app.publish()
    }

    /**
     * [half] is frozen on this device: no deletion of it can ever be sent from here, so a move that waited on it would never
     * finish. It is kept as a vault of its own, the person is told so (and, where the run removes a member who holds it,
     * that they still do), and it leaves the move's record: the run goes on with its new vault. One note per vault: a note
     * already kept for it is not made again. The note is at rest before the vault leaves the record.
     */
    private fun halfMadeFrozen(v: EngineVault, from: String, run: MoveRun, half: String, removing: String?) {
        val noted = notesFor(v).any { n -> n.atRest.vault == half && n.atRest.lines.any { it.key == CopyKey.MOVE_HALF_MADE_FROZEN.name } }
        if (!noted) {
            val lines = arrayListOf(LineAtRest(CopyKey.MOVE_HALF_MADE_FROZEN.name, listOf(null)))
            val holds = removing?.let { verifiedState(v.logs.status(half))?.members?.get(it) }
            if (holds != null) lines += LineAtRest(CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS.name, listOf(null))
            addNote(v, NoteAtRest(from, half, lines, holds?.userId, holds?.key))
            app.publish()
        }
        run.discard -= half
        run.discardMade.remove(half)
        keepRun(v, from, run)
    }

    /**
     * [io.silencelen.andvari.core.app.AccountSnapshot.moveNotes]: kept at rest per account ([NOTES_PREFIX]) until the person
     * dismisses each, across a lock and a restart, as ids, key names and numbers only ([NoteAtRest]); in memory, the
     * account's notes as last read or written, each with the [io.silencelen.andvari.core.app.MoveNote] last shown of it.
     */
    private val notes = ArrayList<KeptNote>()

    /** A note as kept at rest, and as last shown ([shownNote] fills in its names); null: not shown since it was read. */
    private class KeptNote(val atRest: NoteAtRest) {
        var shown: io.silencelen.andvari.core.app.MoveNote? = null
    }

    /** Whose notes [notes] holds (`<origin>|<userId>`); null: not read yet. */
    private var notesOf: String? = null

    private fun notesKey(v: EngineVault) = "$NOTES_PREFIX${v.origin}|${v.userId}"

    /** [notes], read from the device for [v]'s account where they are another's or not read yet. */
    private fun notesFor(v: EngineVault): List<KeptNote> {
        val of = "${v.origin}|${v.userId}"
        if (notesOf != of) {
            notes.clear()
            val text = runCatching { app.engine.state.get(notesKey(v)) }.getOrNull()
            val kept = text?.let { runCatching { moveJson.decodeFromString(kotlinx.serialization.builtins.ListSerializer(NoteAtRest.serializer()), it) }.getOrNull() }
            kept?.forEach { notes += KeptNote(it) }
            notesOf = of
        }
        return notes
    }

    /** [notes] as they stand, at rest for [v]'s account (none: the record goes). */
    private fun keepNotes(v: EngineVault) {
        val text = if (notes.isEmpty()) null
            else moveJson.encodeToString(kotlinx.serialization.builtins.ListSerializer(NoteAtRest.serializer()), notes.map { it.atRest })
        runCatching { app.engine.state.set(notesKey(v), text) }
    }

    /** [note] is added, at rest first, then in memory. */
    private fun addNote(v: EngineVault, note: NoteAtRest) {
        notesFor(v)
        notes += KeptNote(note)
        keepNotes(v)
    }

    /**
     * [kept] as the person reads it now: the vault's name from the opened content, the member as this device shows that
     * person now ([personName]: a contact renamed since reads by its present name). While the opened content does not hold
     * the vault (not read yet since the opening, or no longer this account's), the note is not shown and stays at rest as
     * it is. The same object as last time while nothing it shows changed.
     */
    private fun shownNote(v: EngineVault, kept: KeptNote): io.silencelen.andvari.core.app.MoveNote? {
        val n = kept.atRest
        val name = n.vault?.let { id -> v.content.state.vaults.firstOrNull { it.vaultId == id }?.name }
        if (name == null) {
            kept.shown = null
            return null
        }
        // Only the move's own lines, each in its own shape; any other line in the record is left out (an edited record
        // could otherwise make the place of the notes say any sentence of the app). The member is named only beside the
        // line that names them, and only as this device knows that person.
        val lines = n.lines.mapNotNull { l ->
            val key = NOTE_LINES.firstOrNull { it.name == l.key } ?: return@mapNotNull null
            if (!noteLineShaped(key, l.values, n.memberId != null && n.memberKey != null)) return@mapNotNull null
            io.silencelen.andvari.core.app.CopyLine(key, l.values.map { it?.toString() ?: name })
        }
        if (lines.isEmpty()) {
            kept.shown = null
            return null
        }
        val member = if (lines.none { it.key == CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS || it.key == CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS }) null
            else personName(v, n.memberId!!, n.memberKey!!)
        val last = kept.shown
        if (last != null && last.lines.map { it.key to it.values } == lines.map { it.key to it.values } && said(last.member) == said(member)) return last
        return io.silencelen.andvari.core.app.MoveNote(n.old, n.vault, lines, member).also { kept.shown = it }
    }

    private fun said(p: PersonName?): String? = when (p) {
        is PersonName.Contact -> "contact|" + p.label
        is PersonName.Unverified -> "unverified|" + p.serverName
        is PersonName.You -> "you"
        null -> null
    }

    fun moveNotes(): List<io.silencelen.andvari.core.app.MoveNote> {
        val v = vault() ?: return emptyList()
        return notesFor(v).mapNotNull { shownNote(v, it) }
    }

    override fun dismissMoveNote(note: io.silencelen.andvari.core.app.MoveNote) {
        val v = vault() ?: return
        notesFor(v)
        if (notes.removeAll { it.shown === note }) {
            keepNotes(v)
            app.publish()
        }
    }

    /**
     * After a run that finished: the earlier copies it kept beside a newer one, and why, said once ([MoveNote]); the new
     * vault's name is filled in when the note is read.
     */
    private fun keptBesideNote(v: EngineVault, from: String, run: MoveRun) {
        val lines = ArrayList<LineAtRest>()
        if (run.keptBesideChanged > 0) lines += LineAtRest(CopyKey.MOVE_KEPT_BESIDE_CHANGED.name, listOf(run.keptBesideChanged.toLong(), null))
        if (run.keptBesideNoRevision > 0) lines += LineAtRest(CopyKey.MOVE_KEPT_BESIDE_NO_REVISION.name, listOf(run.keptBesideNoRevision.toLong(), null))
        if (run.keptBesideRefused > 0) lines += LineAtRest(CopyKey.MOVE_KEPT_BESIDE_REFUSED.name, listOf(run.keptBesideRefused.toLong(), null))
        val into = run.newVaultId
        if (lines.isNotEmpty() && into != null) addNote(v, NoteAtRest(from, into, lines))
    }

    /** [vaultId]'s verified log holds a standing `delete` (or its tombstone): the server stored it. Only the owner deletes. */
    private fun deleteStored(v: EngineVault, vaultId: String): Boolean = when (val st = v.logs.status(vaultId)) {
        is VaultLogStatus.Verified -> st.state.deletedId != null
        is VaultLogStatus.Purged -> true
        else -> false
    }

    /**
     * After a completed sync: an own departure whose change is no longer waiting, and which this device has either
     * seen leave or will never see leave (the change was refused), is forgotten.
     */
    private fun pruneOwnDepartures(v: EngineVault) {
        val state = app.engine.state
        val ids = ownDepartures(state, v.origin, me(v))
        if (ids.isEmpty()) return
        val open = v.content.state.vaults.mapTo(HashSet()) { it.vaultId }
        val keep = ids.filter { id ->
            val departed = deleteStored(v, id) || v.logs.status(id) is VaultLogStatus.Removed
            changeWaiting(v, id) || (departed && id in open)
        }
        if (keep.size != ids.size) writeOwnDepartures(state, v.origin, me(v), keep)
    }

    /** A live item of [from] that is new since the run's copies, or at another revision than the one copied (F2). */
    private fun changedSinceCopied(v: EngineVault, from: String, run: MoveRun): Boolean =
        v.items.items().any { it.vaultId == from && run.copied[it.itemId] != it.rev }

    companion object {
        /**
         * This account's own `delete` and `leave` entries sent without an answer yet, by vault id, kept on this device: the
         * item engine of every later opening is told to expect that vault's departure, so a delete the server stores only
         * after a lock is never shown to the person as "deleted by its owner" (nor their own leave as news).
         */
        private fun ownDeparturesKey(origin: String, userId: String) = "ovh.app.own-departures|$origin|$userId"

        /** The key an earlier version kept the record under: by user id alone (not per server). */
        private fun legacyOwnDeparturesKey(userId: String) = "ovh.app.own-departures|$userId"

        private fun parseIds(text: String?): List<String> = text?.split(',')?.filter { it.isNotEmpty() }.orEmpty()

        /**
         * [userId]'s own departures at [origin]. A record under the user id alone (an earlier version's) is taken over by
         * the first server that reads it, once, and removed.
         */
        internal fun ownDepartures(state: io.silencelen.andvari.core.client.DeviceState, origin: String, userId: String): List<String> {
            val ids = parseIds(state.get(ownDeparturesKey(origin, userId)))
            val legacy = parseIds(state.get(legacyOwnDeparturesKey(userId)))
            if (legacy.isEmpty()) return ids
            writeOwnDepartures(state, origin, userId, ids + legacy)
            state.set(legacyOwnDeparturesKey(userId), null)
            return (ids + legacy).distinct().sorted()
        }

        private fun writeOwnDepartures(state: io.silencelen.andvari.core.client.DeviceState, origin: String, userId: String, ids: Collection<String>) =
            state.set(ownDeparturesKey(origin, userId), ids.distinct().sorted().joinToString(",").ifEmpty { null })

        internal fun noteOwnDeparture(state: io.silencelen.andvari.core.client.DeviceState, origin: String, userId: String, vaultId: String) {
            val ids = ownDepartures(state, origin, userId)
            if (vaultId !in ids) writeOwnDepartures(state, origin, userId, ids + vaultId)
        }

        /** The record of [userId]'s own departures at [origin] goes with the account's data (and one under the id alone). */
        internal fun dropOwnDepartures(state: io.silencelen.andvari.core.client.DeviceState, origin: String, userId: String) {
            runCatching { state.set(ownDeparturesKey(origin, userId), null) }
            runCatching { state.set(legacyOwnDeparturesKey(userId), null) }
        }

        /** An ownership offer's life: [io.silencelen.andvari.core.app.OwnershipOffer.LIFE_MS], 14 days (at most 14 days, §3.3). */
        const val OFFER_MS: Long = io.silencelen.andvari.core.app.OwnershipOffer.LIFE_MS

        /** How many times "Move everything" reads the old vault's list again for items that arrived meanwhile (as the web). */
        const val MOVE_PASSES = 3

        /**
         * The prefix of the kept move records, `<prefix><origin>|<userId>|<old vault id>`: per origin, so they go with a
         * followed move and with "Forget this server" (registered with the pin store), and per account, so they go with
         * the account's data ([dropMoves]).
         */
        const val MOVE_PREFIX = "ovh.app.move|"

        /** The refusal of a log action on a vault whose move deletion waits ([moveDeleteWaiting]), as an append outcome. */
        internal const val MOVE_DELETE_WAITING_REASON = "move_delete_waiting"

        private val moveJson = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }

        /**
         * The old vaults whose kept move (by [userId] at [origin]) signed the deletion and is waiting for the server, read
         * from the device state alone: what an opening closes for writing before anything else runs ([composed]).
         */
        internal fun signedDeletions(state: io.silencelen.andvari.core.client.DeviceState, origin: String, userId: String): List<String> {
            val prefix = "$MOVE_PREFIX$origin|$userId|"
            val keys = runCatching { state.keys() }.getOrNull() ?: return emptyList()
            return keys.filter { it.startsWith(prefix) }.mapNotNull { k ->
                val text = runCatching { state.get(k) }.getOrNull() ?: return@mapNotNull null
                val r = runCatching { moveJson.decodeFromString(MoveRecord.serializer(), text) }.getOrNull() ?: return@mapNotNull null
                if (r.deleteSent && !r.storedOutside) k.removePrefix(prefix) else null
            }
        }

        /**
         * How many "Move everything" runs [userId] at [origin] keeps on this device unfinished, from the device state alone: every
         * kept record but one whose old vault's deletion was seen stored (that move is over). A record that cannot be read
         * is counted: what it stands for cannot be told finished.
         */
        internal fun unfinishedMoves(state: io.silencelen.andvari.core.client.DeviceState, origin: String, userId: String): Int {
            val prefix = "$MOVE_PREFIX$origin|$userId|"
            val keys = runCatching { state.keys() }.getOrNull() ?: return 0
            return keys.filter { it.startsWith(prefix) }.count { k ->
                val text = runCatching { state.get(k) }.getOrNull() ?: return@count false
                runCatching { moveJson.decodeFromString(MoveRecord.serializer(), text) }.getOrNull()?.storedOutside != true
            }
        }

        /** Every move [userId] at [origin] kept on this device goes (its data left the device). */
        internal fun dropMoves(state: io.silencelen.andvari.core.client.DeviceState, origin: String, userId: String) {
            val prefix = "$MOVE_PREFIX$origin|$userId|"
            runCatching { state.set("$NOTES_PREFIX$origin|$userId", null) }
            val keys = runCatching { state.keys() }.getOrNull() ?: return
            for (k in keys) if (k.startsWith(prefix)) runCatching { state.set(k, null) }
        }

        /**
         * `<prefix><origin>|<userId>`: the account's move notes not yet dismissed ([io.silencelen.andvari.core.app.MoveNote]),
         * a JSON list of [NoteAtRest]: vault ids, the lines' key names and numbers, and a member as the account's id and
         * public key; never a name. A record of its server and account: it goes with them.
         */
        const val NOTES_PREFIX = "ovh.app.movenotes|"

        /** The only lines a move's note says ([NoteAtRest]): a half-made vault kept, who still holds it, copies kept beside. */
        private val NOTE_LINES = listOf(CopyKey.MOVE_HALF_MADE_KEPT, CopyKey.MOVE_HALF_MADE_KEPT_CANNOT_TELL, CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS,
            CopyKey.MOVE_HALF_MADE_FROZEN, CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS, CopyKey.MOVE_KEPT_BESIDE_CHANGED, CopyKey.MOVE_KEPT_BESIDE_NO_REVISION, CopyKey.MOVE_KEPT_BESIDE_REFUSED)

        /**
         * [values] (null: the vault's name) are [key]'s own shape, as the move writes it: the vault's name and a count above
         * 0; the vault's name alone (the member's line only with a member); a count above 0 and the vault's name.
         */
        private fun noteLineShaped(key: CopyKey, values: List<Long?>, member: Boolean): Boolean = when (key) {
            CopyKey.MOVE_HALF_MADE_KEPT -> values.size == 2 && values[0] == null && (values[1] ?: 0L) > 0L
            CopyKey.MOVE_HALF_MADE_KEPT_CANNOT_TELL, CopyKey.MOVE_HALF_MADE_FROZEN -> values.size == 1 && values[0] == null
            CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS, CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS -> member && values.size == 1 && values[0] == null
            CopyKey.MOVE_KEPT_BESIDE_CHANGED, CopyKey.MOVE_KEPT_BESIDE_NO_REVISION, CopyKey.MOVE_KEPT_BESIDE_REFUSED ->
                values.size == 2 && (values[0] ?: 0L) > 0L && values[1] == null
            else -> false
        }
    }
}

/**
 * A "Move everything" this device started and has not finished, kept on the device per account and old vault so that a
 * lock or a restart carries it on (decided on 16 November 2026): the new vault, each item copied with the revision copied and its
 * copy, who was added, half-made vaults to delete. Ids and numbers only: no name and nothing of any item's content.
 */
@kotlinx.serialization.Serializable
internal class MoveRecord(
    val plannedId: String,
    val newVaultId: String? = null,
    val removed: Boolean = false,
    val deleteSent: Boolean = false,
    val deleteAtSeq: Long = -1L,
    val copied: Map<String, MoveCopy> = emptyMap(),
    val stale: List<String> = emptyList(),
    val added: List<String> = emptyList(),
    val discard: List<String> = emptyList(),
    /**
     * The old vault's deletion was seen stored outside a run of the move (a server may store a signed deletion whenever
     * it likes): the move is over, and what remains is the notice of what changed after the copies, and its copy step.
     */
    val storedOutside: Boolean = false,
    /** How many of the person's own deletions that waited when the old vault closed were carried into the new vault. */
    val deletionsCarried: Int = 0,
    /**
     * How many of those deletions were NOT carried: the item's copy in the new vault was changed there since the move made
     * it (the later change is the later word), or the server refused the copy's deletion. The copy stays live.
     */
    val deletionsKept: Int = 0,
    /** Each [stale] copy's revision when the move made it: it is deleted only at that one (none: kept beside, never deleted). */
    val staleRevs: Map<String, Long> = emptyMap(),
    /** The copies this move deleted in its new vault: they lie in that vault's trash, and are the move's own there. */
    val staleDeleted: List<String> = emptyList(),
    /**
     * What an earlier run made in each half-made vault of [discard]: kept beside the deletion it is due, so the vault is
     * deleted only after a read shows it holds nothing else. A vault with none (a record kept before it was) is never deleted.
     */
    val discardMade: Map<String, HalfMade> = emptyMap(),
    /** Earlier copies kept beside a newer one: changed in the new vault since the move made them. */
    val keptBesideChanged: Int = 0,
    /** Earlier copies kept beside a newer one: no revision of the earlier copy is known, so it is never deleted. */
    val keptBesideNoRevision: Int = 0,
    /** Earlier copies kept beside a newer one: the server refused their deletion. */
    val keptBesideRefused: Int = 0,
    /** Items whose copy was deleted in the new vault since (by anyone there): not made again, never counted as copied. */
    val deletedThere: Int = 0,
)

/**
 * What a run made in its new vault, for when a later run finds that vault half-made: each live copy with the revision the
 * move made it at (null: not known, so the copy is not judged the move's), and the copies the move itself deleted there.
 */
@kotlinx.serialization.Serializable
internal class HalfMade(val copies: Map<String, Long?> = emptyMap(), val trashed: List<String> = emptyList())

/**
 * One item copied by a move: the revision copied, its copy's id in the new vault, and the revision that copy had when the
 * move made it ([copyRev]; null in a record kept before it was recorded): a later revision of the copy is a change made
 * in the new vault since.
 */
@kotlinx.serialization.Serializable
internal class MoveCopy(val rev: Long, val copyId: String? = null, val copyRev: Long? = null)

/**
 * A [io.silencelen.andvari.core.app.MoveNote] at rest ([EngineSharedVaults.NOTES_PREFIX]). Ids, key names and numbers
 * only, never a name (a vault's name, or a person's as this device or the server shows them, is content and would stay
 * readable on a locked device): the old vault, the vault the note is about ([vault]), each line, and the member it names
 * as the account's id and public key ([memberId], [memberKey]). The names are filled in when the note is read with the
 * account open.
 */
@kotlinx.serialization.Serializable
internal class NoteAtRest(
    val old: String,
    val vault: String? = null,
    val lines: List<LineAtRest> = emptyList(),
    val memberId: String? = null,
    val memberKey: String? = null,
)

/**
 * One line of a [NoteAtRest]: its [io.silencelen.andvari.core.app.CopyKey]'s name, and its values in order, each a number
 * or null where the line names the note's vault (filled in with that vault's name when read). A line whose key this build
 * does not know is left out when read.
 */
@kotlinx.serialization.Serializable
internal class LineAtRest(val key: String, val values: List<Long?> = emptyList())
