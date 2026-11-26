package io.silencelen.andvari.core.app

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The probes' bound itself: a wait that never ends fails within its bound and names the wait. */
class ProbeBoundTest {
    @Test
    fun aWaitThatNeverEndsFailsWithinItsBoundSayingWhatItWaitedFor() {
        val e = assertFailsWith<ProbeWaitedTooLong> {
            boundedProbe {
                val never = CompletableDeferred<Unit>()
                // An intent that threw inside a coroutine: what the probe waits on never completes, and the intent's own
                // job waiting on it ends with the probe instead of keeping the test open.
                launch(start = CoroutineStart.UNDISPATCHED) { never.await() }
                waitFor("the PUSH request to reach the server", ms = 300) { never.await() }
            }
        }
        assertTrue(e.message!!.contains("the PUSH request to reach the server"), e.message)
    }

    @Test
    fun aProbeAsAWholeIsBoundedToo() {
        val e = assertFailsWith<ProbeWaitedTooLong> {
            boundedProbe("the probe to finish", ms = 300) { CompletableDeferred<Unit>().await() }
        }
        assertTrue(e.message!!.contains("the probe to finish"), e.message)
    }

    @Test
    fun aWaitThatEndsAnswersItsValue() = boundedProbe {
        assertEquals(7, waitFor("seven") { 7 })
    }
}
