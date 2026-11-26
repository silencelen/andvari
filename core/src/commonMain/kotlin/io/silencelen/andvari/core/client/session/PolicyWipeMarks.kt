package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.DeviceState

/**
 * The marks a server's policy that forbids the offline copy leaves on this device, in device state, apart from the copy
 * itself (decided on 2026-11-17: "try once to send what waits, then wipe as specified; say afterwards how many could not
 * be sent"). Each names one copy: an account at a server.
 *
 * - **Owed:** a forbidding policy was recorded for the copy's server while the copy may be at rest here. From then on
 *   only the policy's run removes anything of it; a stop in the middle leaves the mark, and the next opening runs the
 *   attempt again from the start.
 * - **Counted:** the run has counted the copy (the numbers below) and its wipe is due; a wipe that could not be made
 *   keeps this mark and is tried again at each start while the kept policy still forbids.
 * - **Notice:** the copy is gone; the numbers wait for the person to read and dismiss them. Nothing of the content is
 *   kept: numbers only.
 *
 * A policy that allows the copy again ends an owed or counted mark (the copy is used again). A notice stays until it is
 * dismissed.
 */
class PolicyWipeMarks(private val state: DeviceState) {
    /** What the run counted from a copy before anything of it was removed. */
    class Count(
        /** Changes that could not be sent (refused, never reached, held as refused, parked, kept saves not finished). */
        val notSent: Int,
        /** Changes whose request went out and got no answer in time: they may or may not have arrived. */
        val unsure: Int,
        /** Part of the copy could not be read: how many were lost cannot be told (never said as none). */
        val cannotTell: Boolean,
        /**
         * Always 0 now: logins the phone caught are not part of the copy and stay until answered (decided on 2026-11-18).
         * The slot stays in the kept record, so records written before read as they did.
         */
        val captures: Int = 0,
        /**
         * With [cannotTell]: the copy itself could not be opened (its queue was not read). False where only kept records
         * could not be read (saves kept to be finished): then what the queue held is known and in [notSent].
         */
        val unopened: Boolean = false,
        /**
         * "Move everything" runs this device started and had not finished: each stands half-done at the server, and its
         * record on this device goes with the copy. The changes they queued are in the other numbers.
         */
        val moves: Int = 0,
    ) {
        internal fun text(): String = "$notSent|$unsure|${if (cannotTell) 1 else 0}|$captures|${if (unopened) 1 else 0}|$moves"

        internal companion object {
            fun parse(parts: List<String>): Count? {
                if (parts.size < 4) return null
                val n = parts[0].toIntOrNull() ?: return null
                val u = parts[1].toIntOrNull() ?: return null
                val c = parts[3].toIntOrNull() ?: return null
                // A record written before the fifth field: "cannot tell" then meant the copy could not be opened.
                val unopened = if (parts.size > 4) parts[4] == "1" else parts[2] == "1"
                // A record written before the sixth field counted no unfinished move.
                val moves = if (parts.size > 5) parts[5].toIntOrNull() ?: return null else 0
                return Count(n, u, parts[2] == "1", c, unopened && parts[2] == "1", moves)
            }
        }
    }

    /** One mark: the copy, and the count once the run has taken it (null while only owed). */
    class Mark(val origin: String, val userId: String, val count: Count?)

    /** One notice: the copy that is gone, and what its run counted. */
    class Gone(val origin: String, val userId: String, val count: Count)

    fun marks(): List<Mark> = lines(MARKS_KEY).mapNotNull { p ->
        if (p.size < 3) null else Mark(p[0], p[1], if (p[2] == OWED) null else Count.parse(p.drop(3)))
    }

    fun mark(origin: String, userId: String): Mark? = marks().firstOrNull { it.origin == origin && it.userId == userId }

    /** A wipe is owed for [userId] at [origin]; a mark already there (owed or counted) stays as it is. */
    fun owe(origin: String, userId: String) {
        if (mark(origin, userId) != null) return
        setMarks(marks() + Mark(origin, userId, null))
    }

    /** The run counted the copy, before removing anything: the count is kept with the mark. */
    fun counted(origin: String, userId: String, count: Count) {
        setMarks(marks().filterNot { it.origin == origin && it.userId == userId } + Mark(origin, userId, count))
    }

    /** The mark of the copy goes (its wipe was made, or its policy was lifted). */
    fun end(origin: String, userId: String) {
        setMarks(marks().filterNot { it.origin == origin && it.userId == userId })
    }

    /** Every notice not dismissed yet. */
    fun notices(): List<Gone> = lines(NOTICES_KEY).mapNotNull { p ->
        if (p.size < 2) null else Count.parse(p.drop(2))?.let { Gone(p[0], p[1], it) }
    }

    /** The copy is gone: its count waits for the person ([dismiss]). */
    fun gone(origin: String, userId: String, count: Count) {
        val rest = notices().filterNot { it.origin == origin && it.userId == userId }
        setNotices(rest + Gone(origin, userId, count))
    }

    fun dismiss(origin: String, userId: String) {
        setNotices(notices().filterNot { it.origin == origin && it.userId == userId })
    }

    /** Every notice of an account at [origin] goes (the person forgot that server: nothing of it stays). */
    fun dropNoticesAt(origin: String) {
        setNotices(notices().filterNot { it.origin == origin })
    }

    /**
     * A wipe the person's own act calls for (a sign-out, forgetting the server, an account's deletion) waits behind the
     * policy's run: it is kept here, durably, before anything lets go of the account, so a stop meanwhile does not
     * forget it; the next start makes it ([ownWipes]). [why] is the act's name.
     */
    fun ownWipeWaits(origin: String, userId: String, why: String) {
        val rest = lines(OWN_KEY).filterNot { it.size >= 2 && it[0] == origin && it[1] == userId }
        setLines(OWN_KEY, rest + listOf(listOf(origin, userId, why)))
    }

    /** The waiting own wipe of [userId] at [origin] was made. */
    fun ownWipeMade(origin: String, userId: String) {
        val all = lines(OWN_KEY)
        val rest = all.filterNot { it.size >= 2 && it[0] == origin && it[1] == userId }
        if (rest.size != all.size) setLines(OWN_KEY, rest)
    }

    /**
     * A followed move took [userId]'s copy from [from] to [to] (its cache and kept records now go by the new address): its
     * mark, its notice and an own wipe waiting for it name the copy at [to] from now on. One already kept at [to] stays.
     * [partly]: part of the copy could not be carried and stays under the old address, so the mark stays there too.
     */
    fun moved(from: String, to: String, userId: String, partly: Boolean = false) {
        if (from == to) return
        mark(from, userId)?.let { m ->
            val rest = if (partly) marks() else marks().filterNot { it.origin == from && it.userId == userId }
            setMarks(if (rest.any { it.origin == to && it.userId == userId }) rest else rest + Mark(to, userId, m.count))
        }
        notices().firstOrNull { it.origin == from && it.userId == userId }?.let { g ->
            val rest = notices().filterNot { it.origin == from && it.userId == userId }
            setNotices(if (rest.any { it.origin == to && it.userId == userId }) rest else rest + Gone(to, userId, g.count))
        }
        val own = lines(OWN_KEY)
        if (own.any { it.size >= 2 && it[0] == from && it[1] == userId }) {
            val atTo = own.any { it.size >= 2 && it[0] == to && it[1] == userId }
            setLines(OWN_KEY, own.mapNotNull { l ->
                if (l.size >= 2 && l[0] == from && l[1] == userId) (if (atTo) null else listOf(to) + l.drop(1)) else l
            })
        }
    }

    /** The own wipes still waiting, as (origin, user id, the act's name). */
    fun ownWipes(): List<Triple<String, String, String>> = lines(OWN_KEY).mapNotNull { if (it.size < 3) null else Triple(it[0], it[1], it[2]) }

    private fun setLines(key: String, list: List<List<String>>) {
        state.set(key, list.joinToString("\n") { it.joinToString("|") }.ifEmpty { null })
    }

    private fun lines(key: String): List<List<String>> =
        state.get(key).orEmpty().split('\n').filter { it.isNotBlank() }.map { it.split('|') }

    private fun setMarks(list: List<Mark>) {
        state.set(MARKS_KEY, list.joinToString("\n") { m -> "${m.origin}|${m.userId}|" + (m.count?.let { "$COUNTED|${it.text()}" } ?: OWED) }.ifEmpty { null })
    }

    private fun setNotices(list: List<Gone>) {
        state.set(NOTICES_KEY, list.joinToString("\n") { "${it.origin}|${it.userId}|${it.count.text()}" }.ifEmpty { null })
    }

    companion object {
        const val MARKS_KEY = "ovh.policy.wipe"
        const val NOTICES_KEY = "ovh.policy.wiped"
        const val OWN_KEY = "ovh.policy.ownwipe"
        private const val OWED = "owed"
        private const val COUNTED = "counted"
    }
}
