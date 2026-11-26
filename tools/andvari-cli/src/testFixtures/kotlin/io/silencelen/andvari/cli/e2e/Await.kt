package io.silencelen.andvari.cli.e2e

/**
 * Waiting, with a bound, for something that arrives after the call that caused it returned: a mail the server's sender
 * worker writes to the sink (it drains the outbox every 15 seconds, on wall-clock time), a line another thread prints, a
 * connection another thread accepts, a state another coroutine reaches. A test never looks once for such a thing, and
 * never sleeps a fixed time hoping it has come: it asks again every [POLL_MS] until it is there, or fails after a stated
 * bound with a message that says what was awaited and what was there instead.
 *
 * The bound is generous on purpose: on a busy machine (several builds at once) one worker pass can take many seconds,
 * and a bound that is merely enough on an idle machine is a test that fails for the machine. A wait that succeeds costs
 * only the time the thing took to come.
 */
object Await {
    /** The default bound: six of the mail worker's 15-second passes, with room for a loaded machine. */
    const val DEFAULT_MS = 90_000L

    /** How often a waiting test asks again. */
    const val POLL_MS = 50L

    /**
     * [probe]'s first non-null answer. When none came within [timeoutMs], an [AssertionError] naming [what] was awaited,
     * how long, and [there]: what was there instead.
     */
    fun <T : Any> until(what: String, timeoutMs: Long = DEFAULT_MS, there: () -> String, probe: () -> T?): T {
        val start = System.nanoTime()
        while (true) {
            probe()?.let { return it }
            val waited = (System.nanoTime() - start) / 1_000_000
            if (waited >= timeoutMs) throw timedOut(what, waited, timeoutMs, there)
            Thread.sleep(POLL_MS)
        }
    }

    /** [until] for a test running in a coroutine: it suspends between probes, so the work it waits on can run. */
    suspend fun <T : Any> untilSuspending(what: String, timeoutMs: Long = DEFAULT_MS, there: () -> String, probe: suspend () -> T?): T {
        val start = System.nanoTime()
        while (true) {
            probe()?.let { return it }
            val waited = (System.nanoTime() - start) / 1_000_000
            if (waited >= timeoutMs) throw timedOut(what, waited, timeoutMs, there)
            kotlinx.coroutines.delay(POLL_MS)
        }
    }

    private fun timedOut(what: String, waited: Long, timeoutMs: Long, there: () -> String): AssertionError {
        val instead = runCatching(there).getOrElse { "(could not be read: $it)" }
        return AssertionError("waited $waited ms (the bound is $timeoutMs ms) for $what; there instead: $instead")
    }
}
