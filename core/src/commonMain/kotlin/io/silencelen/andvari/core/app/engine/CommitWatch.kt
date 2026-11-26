package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.session.SessionKeeper

/**
 * The session keeper as the recoveries' sink, unchanged in everything it answers, counting [notTaken]: a recovery's
 * engine ends a session unkept only after the server answered its commit with that session (the account could not be
 * opened from it: a fault while opening). So a stop that comes after such a call is a stop AFTER the commit, where the
 * new master password is in force and the old kit no longer works, and is never said as "nothing was committed".
 */
internal class CommitWatch(private val keeper: SessionKeeper) : SessionSink by keeper {
    /** How many sessions a commit's answer opened that this device did not take. */
    var notTaken: Long = 0L
        private set

    override suspend fun notTaken(origin: String, accessToken: String, refreshToken: String) {
        notTaken++
        keeper.notTaken(origin, accessToken, refreshToken)
    }
}
