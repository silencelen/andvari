package io.silencelen.andvari.core.app

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

/**
 * Bounds for the "a lock overtakes work" probes. A probe holds a request at its fake server and
 * waits: for the request to arrive, for the intent to answer after the lock. When the code under test throws inside a
 * coroutine instead (the engine's key lend refused, the request never came), the
 * wait used to last for ever and hung the whole test pass. Each wait now has a bound, and running past it fails the
 * probe with a sentence naming what it was waiting for.
 *
 * The bound is on the wall clock of the test's own event loop, so it holds only for a wait that suspends (every wait of
 * these probes does: a deferred, a job, a held request). A thread blocked outright is not covered.
 */
internal object ProbeBound {
    /** How long one wait of a probe may take. The probes' own work (a KDF at test cost, a few fake requests) takes well under a second. */
    const val WAIT_MS: Long = 20_000

    /** How long a whole probe may take, all its waits together. */
    const val PROBE_MS: Long = 120_000
}

/** Thrown when a probe waited past its bound: the message names the wait. */
class ProbeWaitedTooLong(message: String) : AssertionError(message)

/**
 * Wait for [what] (said as "the PUSH to reach the server", "the import to answer after the lock") at most [ms]; past it,
 * fail with [ProbeWaitedTooLong]. The block is cancelled, so whatever it started under this scope stops with it.
 */
internal suspend fun <T> waitFor(what: String, ms: Long = ProbeBound.WAIT_MS, block: suspend CoroutineScope.() -> T): T =
    try {
        withTimeout(ms, block)
    } catch (t: TimeoutCancellationException) {
        throw ProbeWaitedTooLong("the probe waited ${ms / 1000} s for $what, which never came (the code under test may have thrown inside a coroutine)")
    }

/**
 * A probe's body, as `runBlocking` but bounded as a whole by [ms]: a wait the probe did not name still fails, saying
 * the probe as a whole ran past its bound. Children the body launches end with it.
 */
internal fun boundedProbe(what: String = "the probe to finish", ms: Long = ProbeBound.PROBE_MS, body: suspend CoroutineScope.() -> Unit) {
    runBlocking<Unit> { waitFor(what, ms) { coroutineScope { body() } } }
}
