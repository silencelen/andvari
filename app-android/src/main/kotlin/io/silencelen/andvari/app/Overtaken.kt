package io.silencelen.andvari.app

import io.silencelen.andvari.core.crypto.KeysGoneException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * Work a lock overtook (the shared code's fix for keys used after a lock): once a lock or the end of the session
 * wipes the account's keys, the shared code refuses anything more built from them with [KeysGoneException]. Its intents
 * answer that as "not done" or STALE; an exception that reaches the app anyway is not a crash, not a failure and never a
 * wrong password: it is the lock. Each place where the app launches such work catches it here, logs nothing (not even
 * the exception's class: the work's kind would say what the person was doing), and treats it as the lock.
 */
internal object Overtaken {
    /** Whether [t], or one of its causes, is the shared code's "the keys are gone". */
    fun isLock(t: Throwable): Boolean {
        var c: Throwable? = t
        var depth = 0
        while (c != null && depth++ < 8) {
            if (c is KeysGoneException) return true
            c = c.cause
        }
        return false
    }

    /** [block]'s value, or [locked]'s when a lock overtook it. Anything else is not swallowed. */
    inline fun <T> orLocked(locked: () -> T, block: () -> T): T = try {
        block()
    } catch (t: Throwable) {
        if (!isLock(t)) throw t
        locked()
    }
}

/**
 * As [launch], for work on the open vault a lock can overtake: a [KeysGoneException] ends [block] and runs [onLock]
 * instead of crashing the app. A cancellation propagates as before. Anything else is a fault the app contains:
 * [onFault] runs (by default it is said above the screen, [io.silencelen.andvari.app.trust.AppFaults]),
 * nothing of the exception is kept, and the app goes on.
 */
internal fun CoroutineScope.launchOvertakable(
    onLock: () -> Unit = {},
    onFault: () -> Unit = { io.silencelen.andvari.app.trust.AppFaults.report(null) },
    block: suspend CoroutineScope.() -> Unit,
): Job = launch {
    try {
        block()
    } catch (t: Throwable) {
        when {
            Overtaken.isLock(t) -> onLock()
            io.silencelen.andvari.app.trust.Contained.isFault(t) -> onFault()
            else -> throw t
        }
    }
}
