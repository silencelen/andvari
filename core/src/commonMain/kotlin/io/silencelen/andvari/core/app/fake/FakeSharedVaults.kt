package io.silencelen.andvari.core.app.fake

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.ContactRow
import io.silencelen.andvari.core.app.MemberRow
import io.silencelen.andvari.core.app.MembersScreen
import io.silencelen.andvari.core.app.MoveEverythingScreen
import io.silencelen.andvari.core.app.MoveMemberRow
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.SharedVaultRow
import io.silencelen.andvari.core.app.SharedVaultsApi
import io.silencelen.andvari.core.app.UncomparedShareWarning
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.trust.MemberRole

/** Shared vaults of the signed-in account, in the fake: the ten log actions and the ways out of a bad history. */
internal class FakeSharedVaults(private val app: FakeAppApi) : SharedVaultsApi, io.silencelen.andvari.core.app.MoveNotes,
    io.silencelen.andvari.core.app.WaitingChanges {
    private fun vault(s: FakeSession, vaultId: String): FakeVault? = s.account.vaults.firstOrNull { it.vaultId == vaultId && it.vaultId !in s.hidden }

    // ---- a change that waits, as the engine plays it (§3.7) ----

    /** What this device must tell about changes it let go of or sent again, by account, kept until dismissed (as the engine keeps its findings). */
    internal val waitingFound = HashMap<String, MutableList<FakeWaitingFinding>>()

    internal fun foundOf(s: FakeSession): MutableList<FakeWaitingFinding> = waitingFound.getOrPut(s.server.origin + "|" + s.account.userId) { ArrayList() }

    private var findingSeq = 0

    internal fun found(s: FakeSession, v: FakeVault, kind: io.silencelen.andvari.core.app.WaitingKind, memberId: String?, key: io.silencelen.andvari.core.app.CopyKey,
        undo: io.silencelen.andvari.core.app.WaitingUndo?) {
        // As the engine: a change of role is changed back to the role the member holds while it waits (the change not made here).
        val roleBack = if (kind == io.silencelen.andvari.core.app.WaitingKind.ROLE) memberId?.let { id -> v.members.firstOrNull { it.userId == id }?.role } else null
        foundOf(s) += FakeWaitingFinding("finding-${++findingSeq}", v.vaultId, kind, memberId, key, undo, roleBack)
    }

    /** [SharedVaultRow.waiting], as the engine draws it. */
    internal fun waitingRow(s: FakeSession, v: FakeVault): io.silencelen.andvari.core.app.WaitingChange? {
        val w = v.waiting ?: return null
        val member = w.memberId?.let { id -> v.members.firstOrNull { it.userId == id }?.let { app.nameOf(s, it) } ?: io.silencelen.andvari.core.app.PersonName.Unverified(null) }
        val kind = w.kind
        val stored = w.known == io.silencelen.andvari.core.app.WaitingKnown.SERVER_SAYS_STORED
        val withdrawable = kind != io.silencelen.andvari.core.app.WaitingKind.OTHER && !w.firstOut && !stored
        // As the engine: a deletion the server says it has is never asked about.
        val asks = kind == io.silencelen.andvari.core.app.WaitingKind.DELETION && w.looked && !stored && app.nowMs - w.sinceMs < FakeScript.DAY
        val roleBack = if (kind == io.silencelen.andvari.core.app.WaitingKind.ROLE) w.memberId?.let { id -> v.members.firstOrNull { it.userId == id }?.role } else null
        return io.silencelen.andvari.core.app.WaitingChange(v.vaultId, kind, member, w.role, w.sinceMs, w.known, w.firstOut, withdrawable, asks,
            v.name.takeIf { v.log == VaultLogState.VERIFIED || v.log == VaultLogState.FROZEN },
            memberId = w.memberId, roleBack = roleBack, heldHash = w.id, opening = app.opening)
    }

    /** [io.silencelen.andvari.core.app.AccountSnapshot.waitingNotices], each the same object while it says the same. */
    fun waitingNotices(s: FakeSession): List<io.silencelen.andvari.core.app.WaitingNotice> = foundOf(s).map { f ->
        val v = s.account.vaults.firstOrNull { it.vaultId == f.vaultId }
        val name = v?.name?.takeIf { v.log == VaultLogState.VERIFIED || v.log == VaultLogState.FROZEN } ?: io.silencelen.andvari.core.app.CopyKey.WAITING_UNNAMED_VAULT.english
        val member = f.memberId?.let { id -> v?.members?.firstOrNull { it.userId == id }?.let { app.nameOf(s, it) } ?: io.silencelen.andvari.core.app.PersonName.Unverified(null) }
        // As the engine: a deletion found made offers the restore only while the vault still reads deleted here.
        val (key, undo) = when {
            f.undo != io.silencelen.andvari.core.app.WaitingUndo.RESTORE_VAULT -> f.key to f.undo
            v != null && v.purgeAtMs > 0L -> f.key to f.undo
            v != null && v.log == VaultLogState.VERIFIED -> io.silencelen.andvari.core.app.CopyKey.WAITING_FOUND_DELETED_RESTORED_SINCE to null
            else -> io.silencelen.andvari.core.app.CopyKey.WAITING_FOUND_DELETED_NO_RESTORE to null
        }
        val roleBack = if (undo == io.silencelen.andvari.core.app.WaitingUndo.CHANGE_ROLE_BACK) f.roleBack else null
        val offered = if (undo == io.silencelen.andvari.core.app.WaitingUndo.CHANGE_ROLE_BACK && roleBack == null) null else undo
        f.shown?.takeIf { it.line.values == listOf(name) && it.line.key == key && it.undo == offered } ?: io.silencelen.andvari.core.app.WaitingNotice(f.id, f.vaultId, f.kind, member,
            io.silencelen.andvari.core.app.CopyLine.of(key, name), offered, memberId = f.memberId, roleBack = roleBack).also { f.shown = it }
    }

    /** True where [change] was drawn in this opening for the very change [v] holds now; false where it is stale. */
    private fun drawnNow(v: FakeVault, change: io.silencelen.andvari.core.app.WaitingChange): Boolean =
        change.opening === app.opening && v.waiting?.id == change.heldHash

    override fun dismissWaitingNotice(notice: io.silencelen.andvari.core.app.WaitingNotice) {
        val s = app.session ?: return
        if (foundOf(s).removeAll { it.shown === notice }) app.publish()
    }

    override suspend fun withdrawWaiting(change: io.silencelen.andvari.core.app.WaitingChange): io.silencelen.andvari.core.app.WaitingResult {
        val s = app.session ?: return io.silencelen.andvari.core.app.WaitingResult.STALE
        val v = vault(s, change.vaultId) ?: return io.silencelen.andvari.core.app.WaitingResult.STALE
        app.injected<io.silencelen.andvari.core.app.WaitingResult>()?.let { return it }
        // As the engine: drawn in another opening, stale; nothing is withdrawn.
        if (change.opening !== app.opening) return io.silencelen.andvari.core.app.WaitingResult.STALE
        if (v.log == VaultLogState.FROZEN) return io.silencelen.andvari.core.app.WaitingResult.FROZEN
        val w = v.waiting ?: return io.silencelen.andvari.core.app.WaitingResult.NOTHING_WAITING
        // As the engine: another change waits now than the one drawn; stale, nothing is withdrawn.
        if (!drawnNow(v, change)) return io.silencelen.andvari.core.app.WaitingResult.STALE
        if (w.firstOut) return io.silencelen.andvari.core.app.WaitingResult.STILL_SENDING
        if (w.known == io.silencelen.andvari.core.app.WaitingKnown.SERVER_SAYS_STORED) return io.silencelen.andvari.core.app.WaitingResult.SERVER_SAYS_STORED
        if (w.kind == io.silencelen.andvari.core.app.WaitingKind.OTHER) return io.silencelen.andvari.core.app.WaitingResult.NOT_OFFERED
        v.waiting = null
        v.changeWaiting = false
        val deletion = w.kind == io.silencelen.andvari.core.app.WaitingKind.DELETION
        val notMade = w.known == io.silencelen.andvari.core.app.WaitingKnown.NOT_STORED
        // As the engine: one that may be made is read for at once; an honest server that does not hold it is "not made yet".
        if (!notMade) found(s, v, w.kind, w.memberId, io.silencelen.andvari.core.app.CopyKey.WAITING_FOUND_NOT_MADE_YET, null)
        app.publish()
        return when {
            deletion && notMade -> io.silencelen.andvari.core.app.WaitingResult.KEPT_NOT_DELETED
            deletion -> io.silencelen.andvari.core.app.WaitingResult.KEPT_MAY_BE_DELETED
            notMade -> io.silencelen.andvari.core.app.WaitingResult.WITHDRAWN_NOT_MADE
            else -> io.silencelen.andvari.core.app.WaitingResult.WITHDRAWN_MAY_BE_MADE
        }
    }

    override suspend fun deleteWaitingNow(change: io.silencelen.andvari.core.app.WaitingChange): io.silencelen.andvari.core.app.WaitingResult {
        val s = app.session ?: return io.silencelen.andvari.core.app.WaitingResult.STALE
        val v = vault(s, change.vaultId) ?: return io.silencelen.andvari.core.app.WaitingResult.STALE
        app.injected<io.silencelen.andvari.core.app.WaitingResult>()?.let { return it }
        if (change.opening !== app.opening) return io.silencelen.andvari.core.app.WaitingResult.STALE
        if (v.log == VaultLogState.FROZEN) return io.silencelen.andvari.core.app.WaitingResult.FROZEN
        // As the engine: not while a move of the vault runs or the move's own deletion of it waits.
        if (v.moveDeleteWaiting || (s.moving?.vault === v && s.moving?.running == true)) return io.silencelen.andvari.core.app.WaitingResult.MOVE_IN_PROGRESS
        val w = v.waiting ?: return io.silencelen.andvari.core.app.WaitingResult.NOTHING_WAITING
        if (!drawnNow(v, change)) return io.silencelen.andvari.core.app.WaitingResult.STALE
        if (w.kind != io.silencelen.andvari.core.app.WaitingKind.DELETION || !w.looked ||
            w.known == io.silencelen.andvari.core.app.WaitingKnown.SERVER_SAYS_STORED
        ) return io.silencelen.andvari.core.app.WaitingResult.NOT_OFFERED
        if (app.nowMs - w.sinceMs >= FakeScript.DAY) {
            // As the engine: nothing is sent; the general re-send gives it up after a read that cannot tell.
            v.waiting = null
            v.changeWaiting = false
            found(s, v, w.kind, null, io.silencelen.andvari.core.app.CopyKey.WAITING_GIVEN_UP_CANNOT_TELL, null)
            app.publish()
            return io.silencelen.andvari.core.app.WaitingResult.DELETE_GIVEN_UP
        }
        if (app.script.deleteNowGetsNoAnswer) {
            w.looked = false
            app.publish()
            return io.silencelen.andvari.core.app.WaitingResult.DELETE_STILL_WAITING
        }
        v.waiting = null
        v.changeWaiting = false
        v.purgeAtMs = app.nowMs + 30 * FakeScript.DAY
        app.publish()
        return io.silencelen.andvari.core.app.WaitingResult.DELETED
    }

    override fun closeFrozenMove(vault: SharedVaultRow): VaultActionResult {
        val s = app.session ?: return VaultActionResult.STALE
        val v = vault(s, vault.vaultId) ?: return VaultActionResult.STALE
        if (v.log != VaultLogState.FROZEN || !v.moveDeleteWaiting || v.moveUnfinishedInto == null) return VaultActionResult.STALE
        // As the engine: the record of the move and its mark go; nothing is sent and the vault stays frozen.
        v.moveUnfinishedInto = null
        v.moveDeleteWaiting = false
        s.movesStopped.remove(v.vaultId)
        if (s.moving?.vault === v) s.moving = null
        app.publish()
        return VaultActionResult.DONE
    }

    /** [SharedVaultRow.frozenMoveClose], as the engine says it: a move whose deletion was sent, stopped on a frozen old vault. */
    internal fun frozenMoveLine(s: FakeSession, v: FakeVault): io.silencelen.andvari.core.app.CopyLine? {
        val into = v.moveUnfinishedInto ?: return null
        if (v.log != VaultLogState.FROZEN || !v.moveDeleteWaiting || s.moving?.running == true) return null
        val copied = s.movesStopped[v.vaultId]?.copied ?: s.moving?.takeIf { it.vault === v }?.copied ?: 0
        return io.silencelen.andvari.core.app.CopyLine.of(io.silencelen.andvari.core.app.CopyKey.MOVE_FROZEN_CLOSE, into, v.name, copied.toString())
    }

    // ---- a move's notes, as the engine keeps them ----

    private fun notesOf(s: FakeSession): MutableList<FakeMoveNote> = app.moveNotesKept.getOrPut(s.server.origin + "|" + s.account.userId) { ArrayList() }

    /**
     * [io.silencelen.andvari.core.app.AccountSnapshot.moveNotes]: each note as the person reads it now (the vault's name and
     * the member as this device shows them now); a note whose vault the account does not hold is not listed and stays kept.
     * The same object while nothing it shows changed.
     */
    fun moveNotes(s: FakeSession): List<io.silencelen.andvari.core.app.MoveNote> = app.moveNotesKept[s.server.origin + "|" + s.account.userId].orEmpty().mapNotNull { n ->
        val vault = s.account.vaults.firstOrNull { it.vaultId == n.vaultId }
        if (vault == null) {
            n.shown = null
            return@mapNotNull null
        }
        val holder = n.memberId?.let { id -> vault.members.firstOrNull { it.userId == id } }
        val lines = n.lines.filter { holder != null || (it.first != io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS && it.first != io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS) }
            .map { (key, values) -> io.silencelen.andvari.core.app.CopyLine.of(key, *values.map { it?.toString() ?: vault.name }.toTypedArray()) }
        val member = holder?.let { app.nameOf(s, it) }
        val said = lines.map { it.key to it.values }.toString() + "|" + when (member) {
            is io.silencelen.andvari.core.app.PersonName.Contact -> "contact:" + member.label
            is io.silencelen.andvari.core.app.PersonName.Unverified -> "unverified:" + member.serverName
            else -> member?.let { "you" }
        }
        n.shown?.takeIf { n.shownSaid == said } ?: io.silencelen.andvari.core.app.MoveNote(n.oldVaultId, n.vaultId, lines, member).also {
            n.shown = it
            n.shownSaid = said
        }
    }

    override fun dismissMoveNote(note: io.silencelen.andvari.core.app.MoveNote) {
        val s = app.session ?: return
        if (notesOf(s).removeAll { it.shown === note }) app.publish()
    }

    /** What a finishing run of [move] into [made] tells, as the script plays it ([FakeScript.nextMoveKeepsHalfMade], [FakeScript.nextMoveKeptBeside]). */
    private fun leaveNotes(s: FakeSession, move: FakeMove, made: FakeVault, removing: FakeMember?) {
        val script = app.script
        val foreign = script.nextMoveKeepsHalfMade
        if (foreign != 0) {
            script.nextMoveKeepsHalfMade = 0
            // The earlier try's half-made vault stays a vault of its own, with what it holds and everyone who has it.
            val half = s.account.addVault(made.name, RoleInVault.OWNER).also { it.itemCount = foreign ?: 1 }
            if (removing != null) half.members += removing
            val lines = ArrayList<Pair<io.silencelen.andvari.core.app.CopyKey, List<Int?>>>()
            lines += if (foreign == null) io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_KEPT_CANNOT_TELL to listOf(null)
                else io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_KEPT to listOf(null, foreign)
            if (removing != null) lines += io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS to listOf(null)
            notesOf(s) += FakeMoveNote(move.vault.vaultId, half.vaultId, lines, removing?.userId)
        }
        if (script.nextMoveHalfMadeFrozen) {
            script.nextMoveHalfMadeFrozen = false
            // The earlier try's half-made vault is frozen here: kept as a vault of its own, read-only here, nothing of it sent.
            val half = s.account.addVault(made.name, RoleInVault.OWNER).also {
                it.itemCount = 1
                it.log = VaultLogState.FROZEN
            }
            if (removing != null) half.members += removing
            val lines = ArrayList<Pair<io.silencelen.andvari.core.app.CopyKey, List<Int?>>>()
            lines += io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_FROZEN to listOf(null)
            if (removing != null) lines += io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS to listOf(null)
            notesOf(s) += FakeMoveNote(move.vault.vaultId, half.vaultId, lines, removing?.userId)
        }
        val beside = script.nextMoveKeptBeside ?: return
        script.nextMoveKeptBeside = null
        val lines = listOf(
            io.silencelen.andvari.core.app.CopyKey.MOVE_KEPT_BESIDE_CHANGED to beside.changed,
            io.silencelen.andvari.core.app.CopyKey.MOVE_KEPT_BESIDE_NO_REVISION to beside.noRevision,
            io.silencelen.andvari.core.app.CopyKey.MOVE_KEPT_BESIDE_REFUSED to beside.refused,
        ).filter { it.second > 0 }.map { (key, n) -> key to listOf<Int?>(n, null) }
        if (lines.isNotEmpty()) notesOf(s) += FakeMoveNote(move.vault.vaultId, made.vaultId, lines, null)
    }

    /**
     * Why an entry cannot be signed on [vault] now, or null. A `leave` is the one entry a vault that is deleted,
     * frozen or failed still takes; everything else needs a history that verifies.
     */
    fun refusal(vault: FakeVault, owner: Boolean): VaultActionResult? {
        if (app.script.clockAhead) return VaultActionResult.CLOCK_AHEAD
        // As the engine: while a move's deletion of this vault waits, nothing else is signed on its log.
        if (vault.moveDeleteWaiting) return VaultActionResult.MOVE_DELETE_WAITING
        if (vault.log != VaultLogState.VERIFIED) return VaultActionResult.READ_ONLY
        if (owner && vault.role != RoleInVault.OWNER) return VaultActionResult.NOT_OWNER
        // As the engine: while a change of this vault waits, nothing else is signed or sent for it.
        if (vault.waiting != null) return VaultActionResult.OTHER_CHANGE_WAITS
        if (app.script.appendGetsNoAnswer) {
            // Signed, sent, and no answer: the entry waits, and the vault's row says so until it is acknowledged (§3.7).
            app.script.appendGetsNoAnswer = false
            vault.changeWaiting = true
            app.publish()
            return VaultActionResult.SENT_PENDING
        }
        return null
    }

    /** The `add` itself, once every rule allowed it. */
    fun add(vault: FakeVault, contact: FakeContact, role: MemberRole) {
        if (vault.members.any { it.userId == contact.userId }) return
        vault.addMember(contact.label, if (role == MemberRole.READER) RoleInVault.READER else RoleInVault.WRITER, contact)
        vault.seq++
    }

    override suspend fun createVault(name: String): VaultActionResult = app.act { s ->
        if (app.script.clockAhead) return VaultActionResult.CLOCK_AHEAD
        if (app.script.noSpaceForVaults) return VaultActionResult.OUT_OF_SPACE
        s.account.addVault(name, RoleInVault.OWNER)
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun renameVault(vault: SharedVaultRow, name: String): VaultActionResult = app.act { s ->
        val found = vault(s, vault.vaultId) ?: return VaultActionResult.STALE
        if (found.moveDeleteWaiting && found.role == RoleInVault.OWNER) return VaultActionResult.MOVE_DELETE_WAITING
        if (found.log != VaultLogState.VERIFIED || found.purgeAtMs > 0L) return VaultActionResult.READ_ONLY
        if (found.role != RoleInVault.OWNER) return VaultActionResult.NOT_OWNER
        if (name.isBlank()) return VaultActionResult.NOT_ALLOWED
        found.name = name.trim()
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun openMembers(vault: SharedVaultRow): VaultActionResult = app.act { s ->
        val found = vault(s, vault.vaultId) ?: return VaultActionResult.STALE
        // A vault nothing was decrypted of has no member list to show.
        if (!app.vaultRow(s, found).canSaveElsewhere) return VaultActionResult.NOT_ALLOWED
        s.membersOf = found.vaultId
        app.publish()
        VaultActionResult.DONE
    }

    override fun closeMembers() {
        app.session?.membersOf = null
        app.publish()
    }

    override suspend fun addMember(screen: MembersScreen, contact: ContactRow, role: MemberRole): VaultActionResult = app.act { s ->
        if (app.snapshot.account?.members !== screen) return VaultActionResult.STALE
        val found = vault(s, screen.vault.vaultId) ?: return VaultActionResult.STALE
        refusal(found, owner = true)?.let { return it }
        val person = s.account.contacts.firstOrNull { it.userId == contact.userId }
        // Only a contact that counts on this device can be given a vault's key (§3.6, §6.9).
        if (person == null || person.userId !in s.currentContacts) return VaultActionResult.NOT_A_CONTACT_HERE
        if (found.members.any { it.userId == person.userId }) return VaultActionResult.NOT_ALLOWED
        if (!person.compared) {
            s.warning = FakeWarning(found, person, role, fromLink = false)
            app.publish()
            return VaultActionResult.NEEDS_UNCOMPARED_WARNING
        }
        add(found, person, role)
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun confirmUncomparedShare(warning: UncomparedShareWarning): VaultActionResult = app.act { s ->
        val pending = s.warning ?: return VaultActionResult.STALE
        if (app.snapshot.account?.shareWarning !== warning) return VaultActionResult.STALE
        refusal(pending.vault, owner = true)?.let { return it }
        add(pending.vault, pending.contact, pending.role)
        if (pending.fromLink) pending.contact.waitingShares.removeAll { it.vaultId == pending.vault.vaultId }
        s.warning = null
        app.publish()
        VaultActionResult.DONE
    }

    override fun cancelUncomparedShare(warning: UncomparedShareWarning) {
        val s = app.session ?: return
        if (app.snapshot.account?.shareWarning !== warning) return
        s.warning = null
        app.publish()
    }

    override suspend fun changeRole(member: MemberRow, role: MemberRole): VaultActionResult = app.act { s ->
        val found = vault(s, member.vaultId) ?: return VaultActionResult.STALE
        refusal(found, owner = true)?.let { return it }
        val who = found.members.firstOrNull { it.userId == member.userId } ?: return VaultActionResult.STALE
        if (who.role == RoleInVault.OWNER) return VaultActionResult.NOT_ALLOWED
        who.role = if (role == MemberRole.READER) RoleInVault.READER else RoleInVault.WRITER
        if (found.offer?.toUserId == who.userId) found.offer = null
        found.seq++
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun removeMember(member: MemberRow): VaultActionResult = app.act { s ->
        val found = vault(s, member.vaultId) ?: return VaultActionResult.STALE
        refusal(found, owner = true)?.let { return it }
        val who = found.members.firstOrNull { it.userId == member.userId } ?: return VaultActionResult.STALE
        if (who.role == RoleInVault.OWNER) return VaultActionResult.NOT_ALLOWED
        found.members -= who
        if (found.offer?.toUserId == who.userId) found.offer = null
        found.seq++
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun leaveVault(vault: SharedVaultRow): VaultActionResult = app.act { s ->
        val found = vault(s, vault.vaultId) ?: return VaultActionResult.STALE
        if (app.script.clockAhead) return VaultActionResult.CLOCK_AHEAD
        if (found.moveDeleteWaiting) return VaultActionResult.MOVE_DELETE_WAITING
        if (found.role == RoleInVault.OWNER || found.role == null) return VaultActionResult.NOT_ALLOWED
        found.members.removeAll { it.userId == s.account.userId }
        found.role = null
        found.offer = null
        found.log = VaultLogState.REMOVED
        found.removedByOwner = false
        found.heldUntilMs = app.nowMs + 30 * FakeScript.DAY
        if (s.membersOf == found.vaultId) s.membersOf = null
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun offerOwnership(member: MemberRow): VaultActionResult = app.act { s ->
        val found = vault(s, member.vaultId) ?: return VaultActionResult.STALE
        refusal(found, owner = true)?.let { return it }
        val who = found.members.firstOrNull { it.userId == member.userId } ?: return VaultActionResult.STALE
        val pending = found.offer?.takeIf { it.expiresAtMs > app.nowMs }
        if (who.role == RoleInVault.OWNER || found.purgeAtMs > 0L || pending != null) return VaultActionResult.NOT_ALLOWED
        found.offer = FakeOffer(who.userId, app.nowMs + io.silencelen.andvari.core.app.OwnershipOffer.LIFE_MS)
        found.seq++
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun cancelOffer(vault: SharedVaultRow): VaultActionResult = app.act { s ->
        val found = vault(s, vault.vaultId) ?: return VaultActionResult.STALE
        if (app.script.clockAhead) return VaultActionResult.CLOCK_AHEAD
        if (found.moveDeleteWaiting) return VaultActionResult.MOVE_DELETE_WAITING
        if (found.log != VaultLogState.VERIFIED) return VaultActionResult.READ_ONLY
        val pending = found.offer?.takeIf { it.expiresAtMs > app.nowMs } ?: return VaultActionResult.NOT_ALLOWED
        // The owner withdraws it, or the person it was made to declines it; nobody else can.
        if (found.role != RoleInVault.OWNER && pending.toUserId != s.account.userId) return VaultActionResult.NOT_ALLOWED
        found.offer = null
        found.seq++
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun acceptOwnership(vault: SharedVaultRow): VaultActionResult = app.act { s ->
        val found = vault(s, vault.vaultId) ?: return VaultActionResult.STALE
        if (app.script.clockAhead) return VaultActionResult.CLOCK_AHEAD
        if (found.moveDeleteWaiting) return VaultActionResult.MOVE_DELETE_WAITING
        if (found.log != VaultLogState.VERIFIED) return VaultActionResult.READ_ONLY
        val pending = found.offer
        if (pending == null || pending.toUserId != s.account.userId) return VaultActionResult.NOT_ALLOWED
        if (pending.expiresAtMs <= app.nowMs) {
            found.offer = null
            app.publish()
            return VaultActionResult.OFFER_EXPIRED
        }
        // The vault's bytes count against the new owner from here on.
        if (app.script.noSpaceForVaults) return VaultActionResult.OUT_OF_SPACE
        found.members.filter { it.role == RoleInVault.OWNER }.forEach { it.role = RoleInVault.WRITER }
        found.members.firstOrNull { it.userId == s.account.userId }?.role = RoleInVault.OWNER
        found.role = RoleInVault.OWNER
        found.offer = null
        found.seq++
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun deleteVault(vault: SharedVaultRow): VaultActionResult = app.act { s ->
        val found = vault(s, vault.vaultId) ?: return VaultActionResult.STALE
        refusal(found, owner = true)?.let { return it }
        if (found.purgeAtMs > 0L) return VaultActionResult.NOT_ALLOWED
        // Members stay in the log and keep read access to it; a restore brings them back (B3).
        found.purgeAtMs = app.nowMs + 7 * FakeScript.DAY
        found.offer = null
        found.seq++
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun restoreVault(vault: SharedVaultRow): VaultActionResult = app.act { s ->
        val found = vault(s, vault.vaultId) ?: return VaultActionResult.STALE
        refusal(found, owner = true)?.let { return it }
        if (found.purgeAtMs == 0L) return VaultActionResult.NOT_ALLOWED
        found.purgeAtMs = 0L
        found.seq++
        app.publish()
        VaultActionResult.DONE
    }

    /** As the engine: an entry of the content's "Recently deleted" list on show, then the same `restore`, then the list is read again. */
    override suspend fun restoreDeletedVault(vault: io.silencelen.andvari.core.app.DeletedVaultView): VaultActionResult {
        val content = app.content ?: return VaultActionResult.STALE
        if (content.state.deletedVaults?.none { it === vault } != false) return VaultActionResult.STALE
        val r = app.act { s ->
            // The engine's log refuses a vault it holds no record of; the fake's world is its log.
            val found = vault(s, vault.vaultId) ?: return VaultActionResult.FAILED
            refusal(found, owner = true)?.let { return it }
            if (found.purgeAtMs == 0L) return VaultActionResult.NOT_ALLOWED
            found.purgeAtMs = 0L
            found.seq++
            app.publish()
            VaultActionResult.DONE
        }
        if (r == VaultActionResult.DONE) content.openDeletedVaults()
        return r
    }

    /** The vault a prompt is about, while the prompt still stands for the `add` it names. */
    private fun incoming(s: FakeSession, prompt: AccountPrompt.IncomingVault): FakeVault? {
        if (app.currentPrompts().none { it === prompt }) return null
        return s.account.vaults.firstOrNull { it.vaultId == prompt.vaultId && it.incomingFrom != null && it.incomingAddSeq == prompt.addSeq }
    }

    override suspend fun acceptIncoming(prompt: AccountPrompt.IncomingVault): VaultActionResult = app.act { s ->
        val found = incoming(s, prompt) ?: return VaultActionResult.STALE
        // Recorded once for the account, for this `add` alone: a later `add` asks again (FS-R6).
        found.incomingFrom = null
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun declineIncoming(prompt: AccountPrompt.IncomingVault): VaultActionResult = app.act { s ->
        val found = incoming(s, prompt) ?: return VaultActionResult.STALE
        if (app.script.clockAhead) return VaultActionResult.CLOCK_AHEAD
        // A decline hides the vault on every device of the account and signs a `leave`, so the owner sees it.
        found.incomingFrom = null
        found.members.removeAll { it.userId == s.account.userId }
        found.role = null
        s.hidden += found.vaultId
        app.publish()
        VaultActionResult.DONE
    }

    override suspend fun saveItemsElsewhere(vault: SharedVaultRow, toVaultId: String?): VaultActionResult = app.act { s ->
        val found = vault(s, vault.vaultId) ?: return VaultActionResult.STALE
        if (!app.vaultRow(s, found).canSaveElsewhere) return VaultActionResult.NOT_ALLOWED
        // It writes only under the destination's key, so the source's state does not matter; the destination's does.
        if (toVaultId != null) {
            val target = vault(s, toVaultId) ?: return VaultActionResult.STALE
            if (!app.vaultRow(s, target).writable) return VaultActionResult.READ_ONLY
            if (target.ownerOutOfSpace) return VaultActionResult.OUT_OF_SPACE
            target.itemCount += found.itemCount
        }
        app.publish()
        VaultActionResult.DONE
    }

    override fun removeFromThisDevice(vault: SharedVaultRow) {
        val s = app.session ?: return
        val found = vault(s, vault.vaultId) ?: return
        if (!app.vaultRow(s, found).canRemoveFromDevice) return
        // A local act: the server is told nothing.
        s.hidden += found.vaultId
        if (s.membersOf == found.vaultId) s.membersOf = null
        app.publish()
    }

    override suspend fun openMoveEverything(vault: SharedVaultRow): VaultActionResult = app.act { s ->
        val found = vault(s, vault.vaultId) ?: return VaultActionResult.STALE
        openMove(s, found, null)
    }

    override suspend fun openMoveEverythingRemoving(member: MemberRow): VaultActionResult = app.act { s ->
        val found = vault(s, member.vaultId) ?: return VaultActionResult.STALE
        val who = found.members.firstOrNull { it.userId == member.userId } ?: return VaultActionResult.STALE
        if (who.userId == s.account.userId || who.role == RoleInVault.OWNER) return VaultActionResult.NOT_ALLOWED
        if (found.moveDeleteWaiting) return VaultActionResult.MOVE_DELETE_WAITING
        openMove(s, found, who.userId)
    }

    /** As the engine: the owner's only, on a verified, frozen or failed vault that is not deleted. */
    private fun openMove(s: FakeSession, found: FakeVault, removing: String?): VaultActionResult {
        if (s.moving?.running == true) return VaultActionResult.STALE
        if (found.role != RoleInVault.OWNER) return VaultActionResult.NOT_OWNER
        val offered = found.log == VaultLogState.VERIFIED || found.log == VaultLogState.FROZEN || found.log == VaultLogState.FAILED
        if (!offered || found.purgeAtMs != 0L) return VaultActionResult.NOT_ALLOWED
        val stays = found.log != VaultLogState.VERIFIED
        if (stays && !app.vaultRow(s, found).canSaveElsewhere) return VaultActionResult.NOT_ALLOWED
        // A move that stopped earlier carries on: the same new vault, what it copied.
        val earlier = (s.moving?.takeIf { it.vault === found && (it.made != null || it.runName != null) } ?: s.movesStopped[found.vaultId])?.takeIf { it.finished == null }
        s.movesStopped.remove(found.vaultId)
        // On a frozen or failed vault nobody is ticked: the last verified list may predate a removal (FS-R3).
        // A run stopped before its first step (short of space) still owes the removal the person chose.
        s.moving = FakeMove(found, sourceStays = stays, short = app.script.noSpaceForVaults, removing = removing ?: earlier?.removing).also { m ->
            if (earlier != null) {
                m.made = earlier.made
                m.runName = earlier.runName
                m.copied = earlier.copied
                m.stop = earlier.stop
            }
        }
        app.publish()
        return VaultActionResult.DONE
    }

    override fun closeMoveEverything() {
        val s = app.session ?: return
        val move = s.moving ?: return
        if (move.running) return
        // A stopped run is remembered so a later move of the same vault carries on.
        if ((move.made != null || move.runName != null) && move.finished == null) s.movesStopped[move.vault.vaultId] = move
        s.moving = null
        app.publish()
    }

    override fun tickMember(screen: MoveEverythingScreen, member: MoveMemberRow, ticked: Boolean) {
        val s = app.session ?: return
        val move = s.moving ?: return
        if (app.snapshot.account?.moving !== screen || move.running) return
        // Ticks only on a frozen or failed vault (§3.13): a vault in good standing adds every remaining member.
        if (!move.sourceStays) return
        val who = move.vault.members.firstOrNull { it.userId == member.userId } ?: return
        val addable = who.contact?.userId?.let { it in s.currentContacts } == true
        if (ticked && addable) move.ticked += who.userId else move.ticked -= who.userId
        app.publish()
    }

    override suspend fun bringLateIntoMove(notice: io.silencelen.andvari.core.app.MoveStoredNotice): VaultActionResult = app.act { s ->
        if (app.snapshot.account?.movesStoredOutside?.any { it === notice } != true) return VaultActionResult.STALE
        val old = vault(s, notice.oldVaultId) ?: return VaultActionResult.STALE
        val into = s.account.vaults.firstOrNull { it.name == old.storedOutsideInto } ?: return VaultActionResult.NOT_ALLOWED
        // Added items land as new copies; a changed one replaces its earlier copy.
        into.itemCount += old.lateAdded
        old.lateCopied = old.lateAdded + old.lateChanged
        old.lateAdded = 0
        old.lateChanged = 0
        app.publish()
        VaultActionResult.DONE
    }

    override fun dismissMoveStored(notice: io.silencelen.andvari.core.app.MoveStoredNotice) {
        val s = app.session ?: return
        if (app.snapshot.account?.movesStoredOutside?.any { it === notice } != true) return
        s.account.vaults.firstOrNull { it.vaultId == notice.oldVaultId }?.storedOutsideInto = null
        app.publish()
    }

    override fun unfinishedMoveLater(move: io.silencelen.andvari.core.app.UnfinishedVaultMove) {
        val s = app.session ?: return
        if (app.snapshot.account?.unfinishedMoves?.any { it === move } != true) return
        s.movesPutOff += move.vault.vaultId
        app.publish()
    }

    override suspend fun moveEverything(screen: MoveEverythingScreen, name: String): VaultActionResult {
        val before = app.session
        val move = before?.moving
        if (move == null || app.snapshot.account?.moving !== screen || move.running) return VaultActionResult.STALE
        if (move.made == null && move.runName == null && name.isBlank()) return VaultActionResult.NOT_ALLOWED
        move.running = true
        move.stop = null
        move.finished = null
        app.publish()
        try {
            return app.act { s ->
                if (app.script.clockAhead) return VaultActionResult.CLOCK_AHEAD
                val copyable = move.vault.itemCount - move.vault.unreadable
                // The check for space runs before anything is signed or sent, as the engine's does: when short, no vault
                // is made and nothing is copied (a carried-on run whose vault exists stops before its next copy).
                if (move.short) {
                    // What the engine's check for space would show: the items limit, and by how much.
                    val room = (copyable / 2).toLong()
                    val by = copyable - room
                    move.space = io.silencelen.andvari.core.app.content.SpaceCheck(
                        io.silencelen.andvari.core.app.content.SpaceVerdict.NOT_ENOUGH, io.silencelen.andvari.core.app.content.SpaceFor.MOVE_EVERYTHING, null,
                        listOf(io.silencelen.andvari.core.app.content.SpaceShortfall(io.silencelen.andvari.core.model.wire.QuotaName.ITEMS, 100 - room, 100, copyable.toLong(), by)),
                        io.silencelen.andvari.core.app.CopyLine.of(io.silencelen.andvari.core.app.CopyKey.SPACE_SHORT_ITEMS, "100", by.toString()),
                    )
                    val stage = if (move.made == null) io.silencelen.andvari.core.app.MoveStage.CREATE_VAULT else io.silencelen.andvari.core.app.MoveStage.TRANSFER_ITEMS
                    if (move.made == null) move.runName = move.runName ?: name.trim()
                    move.stop = io.silencelen.andvari.core.app.MoveStop(stage, move.made?.name ?: move.runName.orEmpty(), move.copied, copyable,
                        VaultActionResult.OUT_OF_SPACE, io.silencelen.andvari.core.app.CopyKey.MOVE_STOPPED)
                    move.vault.moveUnfinishedInto = move.made?.name ?: move.runName.orEmpty()
                    return VaultActionResult.OUT_OF_SPACE
                }
                val stopAt = app.script.nextMoveStop
                if (stopAt != null) app.script.nextMoveStop = null
                // As the engine's carried-on run whose first read finds the old vault frozen while the move's deletion waited
                // (the freeze drops that deletion): the run stops there, before anything else, read-only, with the line that the
                // old vault is frozen; it clears no mark of a waiting deletion and offers no fresh start. So does every later run.
                if (stopAt == FakeScript.MoveStopAt.OLD_VAULT_FROZEN) move.vault.log = VaultLogState.FROZEN
                if (move.vault.log == VaultLogState.FROZEN && move.vault.moveDeleteWaiting) {
                    move.stop = io.silencelen.andvari.core.app.MoveStop(io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, move.made?.name ?: move.runName.orEmpty(),
                        move.copied, move.copied, VaultActionResult.READ_ONLY, io.silencelen.andvari.core.app.CopyKey.MOVE_OLD_VAULT_FROZEN)
                    return VaultActionResult.READ_ONLY
                }
                // As the engine's run whose re-send of the move's waiting deletion is refused because the old vault is frozen:
                // nothing more is sent, the old vault stays frozen and read-only, and the stop says that it is frozen.
                if (stopAt == FakeScript.MoveStopAt.OLD_VAULT_FROZEN_AT_RESEND) {
                    move.vault.log = VaultLogState.FROZEN
                    move.vault.moveDeleteWaiting = false
                    app.fakeContent?.markVaultClosedForWriting(move.vault.vaultId, null)
                    move.stop = io.silencelen.andvari.core.app.MoveStop(io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, move.made?.name ?: move.runName.orEmpty(),
                        move.copied, move.copied, VaultActionResult.READ_ONLY, io.silencelen.andvari.core.app.CopyKey.MOVE_OLD_VAULT_FROZEN)
                    return VaultActionResult.READ_ONLY
                }
                // The member the remove dialog is about, removed on the old log first (never on a frozen or failed vault).
                val removing = move.removing?.let { r -> move.vault.members.firstOrNull { it.userId == r } }
                if (removing != null && !move.sourceStays) {
                    move.vault.members -= removing
                    move.vault.seq++
                    move.removedMember = removing
                }
                // As the engine's step for the half-made vaults of an earlier try, before the new vault is made: one changed
                // after its read stops the run with nothing copied yet, and the next run reads it again.
                if (stopAt == FakeScript.MoveStopAt.HALF_MADE_CHANGED_AFTER_READ) {
                    move.runName = move.runName ?: move.made?.name ?: name.trim()
                    val into = move.made?.name ?: move.runName.orEmpty()
                    move.stop = io.silencelen.andvari.core.app.MoveStop(io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, into, 0, 0,
                        VaultActionResult.CHANGED_MEANWHILE, io.silencelen.andvari.core.app.CopyKey.MOVE_STOPPED)
                    move.vault.moveUnfinishedInto = into
                    return VaultActionResult.CHANGED_MEANWHILE
                }
                val made = move.made ?: s.account.addVault(move.runName ?: name.trim(), RoleInVault.OWNER).also {
                    it.itemCount = 0
                    move.made = it
                }
                move.copied = copyable
                made.itemCount = copyable
                val remaining = move.vault.members.filter { it.userId != s.account.userId && it.role != RoleInVault.OWNER && it.userId != move.removing }
                val toAdd = if (move.sourceStays) remaining.filter { it.userId in move.ticked } else remaining
                val notAdded = ArrayList<FakeMember>()
                for (member in toAdd) {
                    val contact = member.contact?.takeIf { it.userId in s.currentContacts }
                    if (contact == null) {
                        notAdded += member
                        continue
                    }
                    if (made.members.none { it.userId == member.userId }) add(made, contact, if (member.role == RoleInVault.READER) MemberRole.READER else MemberRole.WRITER)
                }
                val kept = when {
                    move.sourceStays -> io.silencelen.andvari.core.app.MoveKept.SOURCE_STAYS
                    notAdded.isNotEmpty() -> io.silencelen.andvari.core.app.MoveKept.MEMBER_CANNOT_BE_ADDED
                    move.vault.unreadable > 0 -> io.silencelen.andvari.core.app.MoveKept.UNREADABLE_ITEMS
                    else -> null
                }
                // As the engine's step that deletes the old vault: a change of it that is not the move's waits (the run sends
                // nothing of it and stops); an item of it moved after the move's read (the server refused the deletion, nothing
                // is stored or held, and the old vault is open for writing again).
                if (kept == null && app.script.moveOtherChangeWaiting) {
                    move.stop = io.silencelen.andvari.core.app.MoveStop(io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, made.name, move.copied, copyable,
                        VaultActionResult.SENT_PENDING, io.silencelen.andvari.core.app.CopyKey.MOVE_OTHER_CHANGE_WAITING)
                    move.vault.moveUnfinishedInto = made.name
                    return VaultActionResult.SENT_PENDING
                }
                if (kept == null && stopAt == FakeScript.MoveStopAt.OLD_VAULT_CHANGED_AFTER_READ) {
                    move.stop = io.silencelen.andvari.core.app.MoveStop(io.silencelen.andvari.core.app.MoveStage.TRANSFER_ITEMS, made.name, move.copied, copyable,
                        VaultActionResult.CHANGED_MEANWHILE, io.silencelen.andvari.core.app.CopyKey.MOVE_STOPPED)
                    move.vault.moveUnfinishedInto = made.name
                    move.vault.moveDeleteWaiting = false
                    app.fakeContent?.markVaultClosedForWriting(move.vault.vaultId, null)
                    return VaultActionResult.CHANGED_MEANWHILE
                }
                if (kept == null && app.script.moveDeleteUnanswered) {
                    // The old vault's delete went without an answer: it still exists, and moving again finishes the move.
                    move.stop = io.silencelen.andvari.core.app.MoveStop(io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, made.name, move.copied, copyable,
                        VaultActionResult.SENT_PENDING, io.silencelen.andvari.core.app.CopyKey.MOVE_DELETE_UNCONFIRMED)
                    move.vault.moveUnfinishedInto = made.name
                    move.vault.moveDeleteWaiting = true
                    // As the engine: the content's own mark closes the old vault for writing while its deletion waits.
                    app.fakeContent?.markVaultClosedForWriting(move.vault.vaultId, io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING)
                    return VaultActionResult.SENT_PENDING
                }
                move.vault.moveUnfinishedInto = null
                move.vault.moveDeleteWaiting = false
                app.fakeContent?.markVaultClosedForWriting(move.vault.vaultId, null)
                leaveNotes(s, move, made, removing ?: move.removedMember)
                if (kept == null) {
                    // A vault in good standing with nothing left behind is deleted once its items are out.
                    move.vault.purgeAtMs = app.nowMs + 7 * FakeScript.DAY
                    move.vault.seq++
                    s.moving = null
                } else {
                    // A frozen one stays where it is with nothing signed on its log; any other kept vault keeps what it holds.
                    val line = when (kept) {
                        io.silencelen.andvari.core.app.MoveKept.SOURCE_STAYS -> io.silencelen.andvari.core.app.CopyKey.MOVE_KEPT_SOURCE_STAYS
                        io.silencelen.andvari.core.app.MoveKept.MEMBER_CANNOT_BE_ADDED -> io.silencelen.andvari.core.app.CopyKey.MOVE_KEPT_NOT_ADDED
                        io.silencelen.andvari.core.app.MoveKept.UNREADABLE_ITEMS -> io.silencelen.andvari.core.app.CopyKey.MOVE_KEPT_UNREADABLE
                    }
                    move.finished = io.silencelen.andvari.core.app.MoveFinished(made.name, move.copied, kept, notAdded.map { app.nameOf(s, it) }, line)
                }
                app.publish()
                VaultActionResult.DONE
            }
        } finally {
            move.running = false
            app.publish()
        }
    }
}

/**
 * A change to a shared vault that waits, as the stand-in holds it ([FakeVault.waiting]): what it is, whom it names, since
 * when, and what is known of it. [id] stands for the hash of its signed entry: a screen's object names it, and an act on an
 * object drawn for another change (or in another opening) is stale.
 */
internal class FakeWaiting(
    val kind: io.silencelen.andvari.core.app.WaitingKind,
    val memberId: String?,
    val role: RoleInVault?,
    val sinceMs: Long,
    var known: io.silencelen.andvari.core.app.WaitingKnown,
) {
    val id: String = "waiting-${++made}"

    private companion object {
        var made = 0
    }

    /** Its first request is still out: it cannot be withdrawn until that ends. */
    var firstOut = false

    /** A deletion that waits for the person's word, found still waiting by a look in the log (nothing sent): it is asked about. */
    var looked = false
}

/** A finding as this device keeps it until the person dismisses its notice: the line's key, and the act that undoes it. */
internal class FakeWaitingFinding(
    val id: String,
    val vaultId: String,
    val kind: io.silencelen.andvari.core.app.WaitingKind,
    val memberId: String?,
    val key: io.silencelen.andvari.core.app.CopyKey,
    val undo: io.silencelen.andvari.core.app.WaitingUndo?,
    /** For a change of role: the role the member held when it was let go of ([io.silencelen.andvari.core.app.WaitingNotice.roleBack]). */
    val roleBack: RoleInVault? = null,
) {
    var shown: io.silencelen.andvari.core.app.WaitingNotice? = null
}

/**
 * A move's note as this device keeps it ([FakeAppApi.moveNotesKept]): about the move of [oldVaultId], concerning [vaultId];
 * each line's values are numbers, null standing for the vault's name when read; [memberId]: the member who still holds it.
 */
internal class FakeMoveNote(
    val oldVaultId: String,
    val vaultId: String,
    val lines: List<Pair<io.silencelen.andvari.core.app.CopyKey, List<Int?>>>,
    val memberId: String?,
) {
    /** The note last shown, and what it said; in memory only. */
    var shown: io.silencelen.andvari.core.app.MoveNote? = null
    var shownSaid: String? = null
}
