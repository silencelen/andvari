package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.UpgradeRequiredException
import kotlinx.coroutines.CancellationException
import kotlinx.io.IOException

/**
 * Audit H10: what the first sync after a bind came back with. The session is already bound, so none
 * of these is an error screen: the user lands on the vault, the capture gate or the recovery reveal,
 * and this only decides what that screen also says.
 */
sealed interface FirstSync {
    data object Done : FirstSync

    /** Unreachable, or too slow for its bound: the vault shows what the cache holds. */
    data object Offline : FirstSync

    /** A 426: the blocking update screen takes over, as it does from any other sync. */
    data object UpgradeRequired : FirstSync

    /** The server answered and refused: the sync canon's sentence, over the landing. */
    data class Failed(val message: String) : FirstSync
}

/** The pure half of the first-sync landing. A cancelled scope is not a verdict and is rethrown; a bound's
 *  timeout is an IOException by then ([runBounded]), so it reads as offline. */
fun firstSyncOutcome(failure: Throwable?): FirstSync = when (failure) {
    null -> FirstSync.Done
    is CancellationException -> throw failure
    is UpgradeRequiredException -> FirstSync.UpgradeRequired
    is IOException -> FirstSync.Offline
    else -> FirstSync.Failed(HouseholdCopy.forSyncError(failure))
}

/**
 * Audit H10, the post-bind half of sign-in, unlock, quick unlock and enroll: the first sync, under its
 * own bound and outside any other, so a timeout here is an IOException that reads as offline. Never
 * throws a verdict (only a cancelled scope): the caller always goes on to land.
 */
suspend fun firstSyncAfterBind(sync: suspend () -> Unit): FirstSync {
    val failure = try {
        runBounded(BoundedOps.FLAT_MS) { sync() }
        null
    } catch (t: Throwable) {
        t
    }
    return firstSyncOutcome(failure)
}
