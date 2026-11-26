package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CopyLine
import io.silencelen.andvari.core.app.PolicyWipeNotice
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.items.CopyDeletion
import io.silencelen.andvari.core.client.items.WireItemTransport
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.session.KeptPolicy
import io.silencelen.andvari.core.client.session.PolicyWipeMarks
import io.silencelen.andvari.core.model.wire.ItemUpload
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.WireErrors
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withTimeoutOrNull

/**
 * One lock that every wipe of a copy on this device takes (a sign-out, forgetting the server, an account deletion, the
 * switch that keeps data on the device turned off, the settling at a start, the policy's run). One account is open at a
 * time on a device, so one lock serves every copy. The policy's run [hold]s it for its whole length; a wipe that cannot
 * wait (it is not suspending) takes it [now] when it is free, and otherwise is made by the holder as it lets go, so it
 * never removes a copy under a run that is counting it. A sign-out waits for it ([idle]) before it starts.
 */
internal class WipeLock {
    private val mutex = Mutex()
    private val after = ArrayList<() -> Unit>()

    /** True while a run holds the lock. */
    val held: Boolean get() = mutex.isLocked

    /** [body] under the lock: at once when it is free, else when the holder lets go (before anyone else takes it). */
    fun now(body: () -> Unit) {
        if (!mutex.tryLock()) {
            after += body
            return
        }
        try {
            body()
        } finally {
            release()
        }
    }

    /** [body] holding the lock for its whole length. */
    suspend fun <T> hold(body: suspend () -> T): T {
        mutex.lock()
        try {
            return body()
        } finally {
            release()
        }
    }

    /** Wait until no run holds the lock. */
    suspend fun idle() {
        mutex.lock()
        release()
    }

    private fun release() {
        try {
            while (after.isNotEmpty()) {
                val b = after.removeAt(0)
                try {
                    b()
                } catch (e: Exception) {
                    // A wipe that failed is the caller's own to say; the lock is let go all the same.
                }
            }
        } finally {
            mutex.unlock()
        }
    }
}

/**
 * The server's policy forbids the offline copy (decided on 2026-11-17: "Try once to send what waits, then wipe as
 * specified; say afterwards how many could not be sent"). The road, from the reading to the notice:
 *
 * 1. Every road that records a policy calls [recorded] ([io.silencelen.andvari.core.client.session.KeptPolicies.onRecorded]).
 *    A forbidding policy sets the mark that a wipe is owed for each copy of that server this device may hold; a policy
 *    that allows ends the marks not yet made (the copy is used again). Nothing is removed there.
 * 2. A composition over an owed copy opens it as it is, halted: nothing new is taken in and a change is refused with its
 *    own line ([EngineVault.wipeOwed]); nothing is synced or pulled.
 * 3. The run ([run]), once per copy at a time under the [lock]: the count is taken from the copy first (a part that
 *    cannot be read is "cannot tell"); one pass through what waits with the kept session of the copy's own account,
 *    checked at each request, [wholeMs] for the whole and [requestMs] for each request; the outcomes per change.
 * 4. The count is kept with the mark; then the wipe; the mark ends only once the copy is gone ([PolicyWipeMarks]), and
 *    the notice waits for the person ([notice], [dismiss]).
 */
internal class EnginePolicyWipe(private val app: EngineAppApi) {
    val lock = WipeLock()

    /** The whole attempt's limit and each request's (sixty and thirty seconds; tests shorten them). */
    var wholeMs = 60_000L
    var requestMs = 30_000L

    /** The run in progress, if any (tests wait for it). */
    var running: Job? = null
        private set

    private val marks: PolicyWipeMarks get() = PolicyWipeMarks(app.engine.state)

    /** The marks' writes, under one short lock: a policy is recorded on whichever thread read it, the rest on main. */
    private val marksLock = kotlinx.atomicfu.locks.SynchronizedObject()
    private fun <T> marking(body: PolicyWipeMarks.() -> T): T = kotlinx.atomicfu.locks.synchronized(marksLock) { marks.body() }

    /** A wipe is owed for this copy and its run has not counted it yet: a composition opens it halted for the run. */
    fun owed(origin: String, userId: String): Boolean = marks.mark(origin, userId)?.let { it.count == null } == true

    /**
     * A wipe is owed for this copy, counted or not: from the policy's record until the copy is gone and its count taken
     * ([io.silencelen.andvari.core.app.AppSnapshot.policyWipeOwed]). A store that throws on the read says false here (the
     * snapshot is never left unpublished); the run itself reads the same record and stops on it.
     */
    fun marked(origin: String, userId: String): Boolean = runCatching { marks.mark(origin, userId) != null }.getOrDefault(false)

    /** The copy was counted and its wipe was not made yet: it is never opened again. */
    fun counted(origin: String, userId: String): Boolean = marks.mark(origin, userId)?.count != null

    /**
     * Step 1: a policy was recorded for [origin], by whichever read, on the thread that read it. The marks are written
     * here at once (a process that ends after the record keeps them); only the start of the run hops to the main thread.
     */
    fun recorded(origin: String, kept: KeptPolicy, couldHoldCopy: Boolean) {
        if (kept.offlineCacheAllowed) {
            // Lifted: what was owed and not made ends; the copy is used again. A notice of a copy already gone stays.
            marking { for (mark in marks().filter { it.origin == origin }) end(mark.origin, mark.userId) }
            // The snapshot's answer whether a removal is owed follows the record at once.
            app.scope.launch { app.publish() }
            return
        }
        // A copy can be at rest here only where the policy kept before allowed one (or could not be read) and the
        // platform consents to keeping one: anywhere else there is nothing at rest to wipe.
        if (couldHoldCopy && app.engine.keepsAtRest()) {
            val held = app.heldCopies()
            marking { for ((o, u) in held) if (o == origin) owe(o, u) }
        }
        // The open vault of such a copy is closed to new changes at once, and the run starts.
        app.scope.launch {
            startIfOwed()
            app.publish()
        }
    }

    /** At an opening and after a policy was recorded: the run for the open account's copy, when its wipe is owed. */
    fun startIfOwed() {
        if (running?.isActive == true) return
        val s = app.keeper.session ?: return
        if (!owed(s.origin, s.userId)) return
        val v = app.vault?.takeIf { !it.closed && it.origin == s.origin && it.userId == s.userId }
        if (app.phase == AppPhase.UNLOCKED) {
            // Not composed yet (a copy kept closed for a policy that could not be read): its composition starts the run.
            if (v == null) return
            // The open vault over this copy takes nothing new from now on (a vault held in memory is not the copy at rest).
            if (v.keptAtRest && !v.wipeOwed) v.closeForWipe()
        } else if (!s.endedByServer) {
            // Locked: the next opening runs it. A session its server ended sends nothing, so its wipe needs no opening.
            return
        }
        running = app.scope.launch { run(s.origin, s.userId) }
    }

    /** What the run read from the copy before anything was sent or removed. */
    private class Read(
        val pending: List<io.silencelen.andvari.core.model.Mutation>, val notSendable: Int, val cannotTell: Boolean, val unopened: Boolean, val moves: Int,
        val kept: List<io.silencelen.andvari.core.app.content.ContentController.KeptChange>,
        /** The item engine's push that was out when the run began (the opening's own sync, say): its rows are its own. */
        val out: io.silencelen.andvari.core.client.items.ItemEngine.Outbound?,
        /** The open content over the copy, if any. */
        val content: io.silencelen.andvari.core.app.content.EngineVaultContent?,
    )

    /** Step 3 and 4. */
    private suspend fun run(origin: String, userId: String) = lock.hold {
        if (!owed(origin, userId)) return@hold
        val read = readCopy(origin, userId)
        var sent = 0
        var unsure = 0
        var notSent = read.notSendable
        // Who sends what, from the moment the policy is recorded: the item engine is halted then, so it sends nothing more.
        // A push of its that was already out keeps its rows until it ends: answered (taken or refused), they are counted by
        // that answer and not sent again; ended without an answer, or not answered within one request's limit, they still
        // wait and get this run's one try with the rest, in the queue's order (the server takes a change once). A push the
        // halt stopped before it left gives its rows back to this run. Every other row that waits is this run's own.
        val out = read.out
        val outRows = if (out == null) emptyList() else read.pending.filter { it.mutationId in out.mutationIds }
        var rows = if (outRows.isEmpty()) read.pending else read.pending.filter { it.mutationId !in out!!.mutationIds }
        // The request out is waited for (its rows not judged yet).
        var outOpen = outRows.isNotEmpty()
        // Rows whose earlier request ended without an answer: it may have arrived, so such a row is "not sent" only where
        // the server answered, for that row, that it did not take it; anything else not seen taken may or may not have.
        val doubtful = HashSet<String>()
        fun notTaken(ms: List<io.silencelen.andvari.core.model.Mutation>) {
            for (m in ms) if (m.mutationId in doubtful) unsure++ else notSent++
        }
        var reached = 0
        var inFlight = 0
        // The pass ended before what remains (no answer, a refusal that is not of the changes as sent, an ended session).
        var stopped = false
        val kept = read.kept
        var keptReached = 0
        var keptInFlight = false
        val transport = WireItemTransport(app.clientFor(origin), null)
        withTimeoutOrNull(wholeMs) {
            if (outOpen) {
                // The request out comes first in the pass: its answer, as the engine settled it, within one request's limit.
                val answer = withTimeoutOrNull(requestMs) { out!!.await() }
                currentCoroutineContext().ensureActive()
                outOpen = false
                when {
                    // It never left: its rows are this run's own, in order.
                    answer is WireResult.NoAnswer && answer.neverLeft -> rows = read.pending
                    // Out, and no answer in time (or it ended without one): its rows get this run's one try, in order.
                    answer == null || answer is WireResult.NoAnswer -> {
                        rows = read.pending
                        outRows.mapTo(doubtful) { it.mutationId }
                    }
                    answer is WireResult.Refused -> {
                        notSent += outRows.size
                        if (answer.status != 400 && answer.status != 413) stopped = true
                    }
                    answer is WireResult.Ok -> {
                        val byId = answer.value.results.associateBy { it.mutationId }
                        for (m in outRows) if (taken(m.op, byId[m.mutationId])) sent++ else notSent++
                    }
                }
            }
            while (!stopped && reached < rows.size) {
                // Each request with the kept session of this copy's own account, checked now: an ended one sends nothing
                // more. So is whether the server is stopped here (a fork another call found meanwhile stops the pass).
                if (!app.sessionOf(origin, userId) || app.serverStoppedFor(origin)) {
                    stopped = true
                    break
                }
                val chunk = rows.subList(reached, minOf(rows.size, reached + BATCH))
                inFlight = chunk.size
                val answer = withTimeoutOrNull(requestMs) { transport.push(chunk.map { it.wire() }) }
                // The app interface closed meanwhile (the process ends): nothing is counted or removed; the mark stays,
                // and the next opening runs the attempt again from the start (a transport may answer a cancel as no answer).
                currentCoroutineContext().ensureActive()
                inFlight = 0
                reached += chunk.size
                if (answer is WireResult.NoAnswer && answer.neverLeft) {
                    // The request never left this device (no connection was made): not sent, and the pass ends.
                    notTaken(chunk)
                    stopped = true
                    break
                }
                when (answer) {
                    null, is WireResult.NoAnswer -> {
                        // Sent, no answer in time: neither sent nor lost. The run ends at the first such request.
                        unsure += chunk.size
                        stopped = true
                        break
                    }
                    is WireResult.Refused -> {
                        notTaken(chunk)
                        // A batch the server refused as sent (400, 413) is not tried again; any other refusal ends the run.
                        if (answer.status != 400 && answer.status != 413) {
                            stopped = true
                            break
                        }
                    }
                    is WireResult.Ok -> {
                        val byId = answer.value.results.associateBy { it.mutationId }
                        for (m in chunk) if (taken(m.op, byId[m.mutationId])) sent++ else notSent++
                    }
                }
            }
            // Then each kept save, as one more change of the same pass: its files first, then its item. One that cannot
            // be sent as it was made is not sent; a refusal of it as sent goes on to the next; anything else ends the pass.
            while (!stopped && keptReached < kept.size) {
                if (!app.sessionOf(origin, userId) || app.serverStoppedFor(origin)) break
                val k = kept[keptReached]
                val put = k.put
                if (put == null) {
                    notSent++
                    keptReached++
                    continue
                }
                var filesUp = true
                for ((fileId, body) in k.files) {
                    if (!app.sessionOf(origin, userId) || app.serverStoppedFor(origin)) {
                        stopped = true
                        break
                    }
                    val up = withTimeoutOrNull(requestMs) { transport.uploadAttachment(fileId, k.itemId, k.vaultId, body) }
                    currentCoroutineContext().ensureActive()
                    if (up is WireResult.Ok || (up is WireResult.Refused && up.code == WireErrors.ATTACHMENT_ID_TAKEN)) continue
                    filesUp = false
                    // A file the server refused as sent: this save is not sent, and the pass goes on. No answer to a file,
                    // or any other refusal: the item was not sent, and the pass ends there.
                    if (!(up is WireResult.Refused && (up.status == 400 || up.status == 413))) stopped = true
                    break
                }
                if (stopped) break
                if (!filesUp) {
                    notSent++
                    keptReached++
                    continue
                }
                keptInFlight = true
                val answer = withTimeoutOrNull(requestMs) { transport.push(listOf(put)) }
                currentCoroutineContext().ensureActive()
                keptInFlight = false
                keptReached++
                when {
                    answer is WireResult.NoAnswer && answer.neverLeft -> {
                        notSent++
                        stopped = true
                    }
                    answer == null || answer is WireResult.NoAnswer -> {
                        unsure++
                        stopped = true
                    }
                    answer is WireResult.Refused -> {
                        notSent++
                        if (answer.status != 400 && answer.status != 413) stopped = true
                    }
                    answer is WireResult.Ok -> if (taken(put.op, answer.value.results.firstOrNull { it.mutationId == put.mutationId })) sent++ else notSent++
                }
            }
            // The write or sync whose request was out answers what became of it (made, or not, or not known) before the copy
            // goes, as it would have while this run sent that request itself; within one request's limit.
            if (out != null) read.content?.let { c -> withTimeoutOrNull(requestMs) { c.settled() } }
        }
        currentCoroutineContext().ensureActive()
        // The policy was lifted while the attempt ran (a later read allows the copy): nothing is wiped or said on the
        // strength of the old policy; the copy is used again.
        if (app.policies.get(origin)?.offlineCacheAllowed == true) {
            marking { end(origin, userId) }
            val v = app.vault?.takeIf { !it.closed && it.origin == origin && it.userId == userId && it.wipeOwed }
            if (v != null) {
                app.closeVaultForWipe()
                if (app.phase == AppPhase.UNLOCKED) app.reopenAfterWipe()
            }
            app.publish()
            return@hold
        }
        // The whole limit struck with a request out: that request's changes may or may not have arrived.
        if (outOpen) unsure += outRows.size
        unsure += inFlight
        reached += inFlight
        // Not reached: not sent, except a row whose earlier request ended without an answer (it may have arrived).
        notTaken(rows.subList(minOf(reached, rows.size), rows.size))
        // A kept save's item out when the limit struck may or may not have arrived; one whose files were still going up,
        // and every one not reached, was not sent.
        if (keptInFlight) {
            unsure++
            keptReached++
        }
        notSent += kept.size - keptReached
        val count = PolicyWipeMarks.Count(notSent, unsure, read.cannotTell, 0, read.unopened, read.moves)
        // The count is kept before anything is removed.
        marking { counted(origin, userId, count) }
        wipe(origin, userId)
    }

    /**
     * The copy as it is, before anything is sent: the queue in order, what waits that is not sent (held as refused,
     * parked with a held vault, kept saves not finished), and whether a part could not be read.
     */
    private fun readCopy(origin: String, userId: String): Read {
        val open = app.vault?.takeIf { !it.closed && it.origin == origin && it.userId == userId }
        // The open vault is over the copy (its cache is the file) or owed to this run (its content holds the kept records).
        val v = open?.takeIf { it.keptAtRest || it.wipeOwed }
        // The engine's push out now, read BEFORE the queue: the engine is halted, so no push of its leaves after this, and
        // one that is answered meanwhile has settled its rows out of the queue read below (they are then not counted here).
        val outNow = v?.items?.outbound()
        var cannotTell = false
        val q: QueuedCarry? = if (v != null && v.keptAtRest) {
            runCatching { v.queued() }.getOrNull()
        } else {
            val files = app.engine.cacheFiles
            if (files == null) {
                QueuedCarry(origin, userId, emptyList(), emptyList(), emptyList())
            } else {
                var cache: VaultCache? = null
                try {
                    cache = files.open(EngineVault.cacheName(app, origin, userId), userId)
                    QueuedCarry(origin, userId, cache.pending(), cache.stagedDenied(), cache.heldVaults())
                } catch (e: Exception) {
                    null
                } finally {
                    runCatching { cache?.close() }
                }
            }
        }
        if (q == null) cannotTell = true
        val pending = q?.pending.orEmpty().distinctBy { it.mutationId }
        val staged = q?.staged.orEmpty().map { it.mutationId }.toSet()
        val parked = q?.held.orEmpty().flatMap { it.parked }.map { it.mutationId }.toSet()
        val rows = pending.filter { it.mutationId !in staged && it.mutationId !in parked }
        val notSendable = (staged + parked).size
        // Saves kept to be finished (a lock cut them short): part of the copy, and of the attempt, each one more change of
        // the pass (its files first, then its item), sealed now while the account is open.
        val kept = if (v != null) v.content.keptChangesForAttempt() else null
        // Without the open content the kept saves cannot be read (they are sealed to the account): cannot tell, only where
        // a record of them is there (found without opening it). The known numbers are kept beside it.
        if (kept == null && app.mayHoldKeptRecords(origin, userId)) cannotTell = true
        // "Move everything" runs not finished: their records go with the copy, so each is counted on its own.
        val moves = EngineSharedVaults.unfinishedMoves(app.engine.state, origin, userId)
        val out = outNow?.takeIf { o -> rows.any { it.mutationId in o.mutationIds } }
        return Read(rows, notSendable, cannotTell, q == null, moves, kept.orEmpty(), out, v?.content)
    }

    /**
     * The wipe of a counted copy: the vault over it closes (it is composed again in memory, empty, while the account is
     * open), then its cache file and every kept record go. The mark ends and the notice is set only once the cache file is
     * gone; otherwise the mark stays and the wipe is tried again at the next start. Needs no key: works locked.
     */
    private fun wipe(origin: String, userId: String) {
        val v = app.vault?.takeIf { !it.closed && it.origin == origin && it.userId == userId && (it.keptAtRest || it.wipeOwed) }
        if (v != null) app.closeVaultForWipe()
        val gone = app.dropCopyLocked(origin, userId)
        val count = marks.mark(origin, userId)?.count
        if (gone && count != null) {
            marks.gone(origin, userId, count)
            marking { end(origin, userId) }
        }
        if (v != null && app.phase == AppPhase.UNLOCKED) app.reopenAfterWipe()
        app.publish()
    }

    /** At a start: a counted copy whose wipe was not made is wiped now, while the kept policy still forbids it. */
    fun atStart() {
        for (m in marks.marks()) {
            if (m.count == null) continue
            val p = app.policies.get(m.origin)
            when {
                p == null -> {}
                p.offlineCacheAllowed -> marking { end(m.origin, m.userId) }
                else -> lock.now {
                    if (app.dropCopyLocked(m.origin, m.userId)) {
                        marks.gone(m.origin, m.userId, m.count)
                        marking { end(m.origin, m.userId) }
                    }
                }
            }
        }
    }

    /** A followed move carried the copy of [userId] from [from] to [to]: what is owed or said of it follows it. */
    fun moved(from: String, to: String, userId: String, partly: Boolean) = marking { moved(from, to, userId, partly) }

    /** The account's server dropped this device's account by the person's own act: its mark goes with its copy. */
    fun forget(origin: String, userId: String) = marking { end(origin, userId) }

    /** The account was deleted on this device, or forgotten with its server: nothing of it stays, its notice neither. */
    fun forgetNotice(origin: String, userId: String) = marks.dismiss(origin, userId)

    /** The person forgot the server at [origin]: every notice of an account there goes. */
    fun forgetNoticesAt(origin: String) = marks.dropNoticesAt(origin)

    /** A wipe of the person's own act waits behind the run: kept durably first ([PolicyWipeMarks.ownWipeWaits]). */
    fun ownWipeWaits(origin: String, userId: String, why: CopyDeletion) = marks.ownWipeWaits(origin, userId, why.name)

    fun ownWipeMade(origin: String, userId: String) = marks.ownWipeMade(origin, userId)

    /** At a start: the own wipes a stop left waiting behind a run, each with its act, to be made now. */
    fun ownWipesLeft(): List<Triple<String, String, CopyDeletion>> = marks.ownWipes().mapNotNull { (o, u, w) ->
        // An act this build does not know is a sign-out's wipe: the copy goes, which every own act does.
        Triple(o, u, CopyDeletion.entries.firstOrNull { it.name == w && it != CopyDeletion.POLICY_FORBIDS_OFFLINE_COPY } ?: CopyDeletion.SIGNED_OUT)
    }

    private var shown: PolicyWipeNotice? = null

    /**
     * The notices the screens may show now: inside an account, only that account's own; where no account is signed in
     * on this device, any. Another person's session neither reads a notice nor puts it away.
     */
    private fun visible(): List<PolicyWipeMarks.Gone> {
        val all = marks.notices()
        val s = if (app.keeperReady) app.keeper.session else null
        return if (s == null) all else all.filter { it.origin == s.origin && it.userId == s.userId }
    }

    /** [io.silencelen.andvari.core.app.AppSnapshot.policyWipe]: the first notice not dismissed, the same object while it stands. */
    fun notice(): PolicyWipeNotice? {
        val g = visible().firstOrNull()
        if (g == null) {
            shown = null
            return null
        }
        val name = app.labelFor(g.origin)?.name?.takeIf { it.isNotBlank() } ?: g.origin
        val s = shown
        val c = g.count
        if (s != null && shownFor == g.origin to g.userId && s.serverName == name && s.notSent == c.notSent && s.unsure == c.unsure &&
            s.cannotTell == c.cannotTell && s.unopened == c.unopened && s.unfinishedMoves == c.moves
        ) return s
        shownFor = g.origin to g.userId
        return PolicyWipeNotice(g.origin, name, c.notSent, c.unsure, c.cannotTell, c.unopened, c.moves).also { shown = it }
    }

    /** The account whose notice [shown] is. */
    private var shownFor: Pair<String, String>? = null

    fun dismiss(notice: PolicyWipeNotice) {
        // Only the notice on show, and only where it may be shown now (never from another account's session).
        if (notice !== shown || notice() !== notice) return
        val (o, u) = shownFor ?: return
        marks.dismiss(o, u)
        shown = null
        shownFor = null
        app.publish()
    }

    /** [io.silencelen.andvari.core.app.AppSnapshot.closedForPolicy]'s line, while the open account's kept policy cannot be read. */
    fun closedLine(): CopyLine? {
        if (app.phase != AppPhase.UNLOCKED && app.phase != AppPhase.LOCKED) return null
        val s = app.keeper.session ?: return null
        if (!app.policies.unreadable(s.origin)) return null
        return closed ?: CopyLine.of(CopyKey.POLICY_UNREADABLE_COPY_CLOSED).also { closed = it }
    }

    private var closed: CopyLine? = null

    /**
     * Whether the server took a change of [op] by its result [r]: a put over a newer version is stored (the displaced one
     * stays in the item's history); a deletion over a newer edit is not made; a refusal is not taken; a status this client
     * does not know removes the row in the ordinary drain: taken. No conflict copy is made during the attempt.
     */
    private fun taken(op: String, r: io.silencelen.andvari.core.model.wire.MutationResult?): Boolean = when {
        r == null -> false
        r.status == MutationStatus.APPLIED -> true
        r.status == MutationStatus.CONFLICT -> op != MutationOp.DELETE
        r.status == MutationStatus.REJECTED || r.status == MutationStatus.DENIED -> false
        else -> true
    }

    private fun io.silencelen.andvari.core.model.Mutation.wire() = io.silencelen.andvari.core.model.wire.Mutation(
        mutationId, op, itemId, vaultId, baseItemRev, item?.let { ItemUpload(it.formatVersion, it.attachmentIds, it.blob) },
    )

    companion object {
        /** Changes per request of the attempt (the server's batch limit is larger). */
        const val BATCH = 100
    }
}
