package io.silencelen.andvari.core.app

/**
 * [AppSnapshot.policyWipe]: the server's policy forbids a copy of the vault on devices, so this device tried once to
 * send what waited in its copy and then removed the copy (decided on 2026-11-17). Shown only once the copy is gone, in
 * every phase (the lock screen too), as a notice above whatever screen is on show, until the person dismisses it
 * ([AppApi.dismissPolicyWipe]). It carries the server's name and numbers only, nothing of the content.
 *
 * Draw [lines] in order: the first says why the copy went and what was lost ("nothing", one, how many, or that it
 * cannot be told); a second, when there is one, says how many were sent with no answer in time. Logins the phone caught
 * are not part of the copy and are not counted here: they stay until the person answers them (decided on 2026-11-18).
 */
class PolicyWipeNotice internal constructor(
    /** The server whose policy it is (its address). */
    val origin: String,
    /** The server's name as this device knows it (its card's), or its address when it has none. */
    val serverName: String,
    /** Changes that could not be sent and are lost. */
    val notSent: Int,
    /** Changes that were sent with no answer in time: they may or may not have arrived. */
    val unsure: Int,
    /** Part of the copy could not be read: whether changes were lost cannot be told. Never said as "nothing lost". */
    val cannotTell: Boolean,
    /**
     * With [cannotTell]: the copy itself could not be opened to send what waited in it. False where only the saves kept
     * to be finished could not be read (then [notSent] counts what the copy's queue held, at least).
     */
    val unopened: Boolean = cannotTell,
    /**
     * "Move everything" runs this device started and had not finished when the copy went: each stands half-done at the
     * server, and its record on this device went with the copy. The changes they had queued are in the other numbers.
     */
    val unfinishedMoves: Int = 0,
) {
    /**
     * What the notice says, in order. Each line's values are {0} [notSent], {1} [serverName], {2} [unsure]; the moves'
     * line also {3} [unfinishedMoves]. A known number is never hidden behind "cannot tell": with [cannotTell] and [notSent] above 0 the
     * first line says "at least {0}, and more cannot be told". A last line, when there is one, says how many moves of
     * everything stand half-done.
     */
    val lines: List<CopyLine>
        get() {
            val v = arrayOf(notSent.toString(), serverName, unsure.toString())
            val first = when {
                cannotTell && notSent > 0 -> CopyKey.POLICY_COPY_REMOVED_AT_LEAST_LOST
                cannotTell && unopened -> CopyKey.POLICY_COPY_REMOVED_CANNOT_TELL
                cannotTell -> CopyKey.POLICY_COPY_REMOVED_KEPT_UNREAD
                notSent == 1 -> CopyKey.POLICY_COPY_REMOVED_ONE_LOST
                notSent > 1 -> CopyKey.POLICY_COPY_REMOVED_LOST
                unsure > 0 -> CopyKey.POLICY_COPY_REMOVED_NONE_KNOWN_LOST
                else -> CopyKey.POLICY_COPY_REMOVED_NOTHING_LOST
            }
            val second = when {
                unsure == 1 -> CopyKey.POLICY_COPY_REMOVED_UNSURE_ONE
                unsure > 1 -> CopyKey.POLICY_COPY_REMOVED_UNSURE
                else -> null
            }
            val moves = when {
                unfinishedMoves == 1 -> CopyKey.POLICY_COPY_REMOVED_MOVE_UNFINISHED_ONE
                unfinishedMoves > 1 -> CopyKey.POLICY_COPY_REMOVED_MOVES_UNFINISHED
                else -> null
            }
            // The moves' line alone carries the fourth value.
            return listOfNotNull(first, second).map { CopyLine.of(it, *v) } + listOfNotNull(moves).map { CopyLine.of(it, *v, unfinishedMoves.toString()) }
        }

    internal companion object {
        /** For the fake and the tests of the apps' screens. */
        fun of(origin: String, serverName: String, notSent: Int, unsure: Int, cannotTell: Boolean, unopened: Boolean = cannotTell, unfinishedMoves: Int = 0) =
            PolicyWipeNotice(origin, serverName, notSent, unsure, cannotTell, unopened, unfinishedMoves)
    }
}
