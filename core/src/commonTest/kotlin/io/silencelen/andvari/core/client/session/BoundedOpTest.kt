package io.silencelen.andvari.core.client.session

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Audit H10: an op has a whole-call bound, so a silent server cannot hold the vault unlocked. */
class BoundedOpTest {
    @Test
    fun anAnsweredOpReturnsItsValue() = runBlocking {
        assertEquals(7, runBounded(1_000L) { 7 })
    }

    @Test
    fun aServerThatNeverAnswersTimesOutAsUnreachable() = runBlocking<Unit> {
        // The op must end near its bound, and read as a transport failure so the existing
        // "can't reach the server" mappings and offline branches apply.
        val started = kotlinx.datetime.Clock.System.now().toEpochMilliseconds()
        assertFailsWith<IOException> { runBounded(30L) { delay(60_000L); 1 } }
        assertTrue(kotlinx.datetime.Clock.System.now().toEpochMilliseconds() - started < 10_000L, "the bound ended the op")
    }

    @Test
    fun anOpsOwnFailurePassesThroughUnchanged() = runBlocking<Unit> {
        assertFailsWith<IllegalArgumentException> { runBounded(1_000L) { throw IllegalArgumentException("nope") } }
    }

    @Test
    fun cancellingTheCallerIsNotATimeout() = runBlocking<Unit> {
        var outcome: Throwable? = null
        val job = launch {
            try {
                runBounded(60_000L) { delay(60_000L); 1 }
            } catch (t: Throwable) {
                outcome = t
                throw t
            }
        }
        delay(20)
        job.cancelAndJoin()
        assertTrue(outcome is CancellationException, "a cancelled scope must not read as 'server unreachable': $outcome")
        assertFalse(outcome is IOException)
    }

    private fun assertFalse(condition: Boolean) = assertTrue(!condition)

    @Test
    fun theByteCarryingBoundIsScaledAndCapped() {
        assertEquals(BoundedOps.FLAT_MS, BoundedOps.attachmentMs(0L), "no bytes: the flat window")
        assertEquals(BoundedOps.FLAT_MS, BoundedOps.attachmentMs(-5L), "nonsense sizes cannot shrink the window")
        assertEquals(
            BoundedOps.FLAT_MS + BoundedOps.ATTACHMENT_MIN_BYTES_PER_SEC * 3 * 1000L / BoundedOps.ATTACHMENT_MIN_BYTES_PER_SEC,
            BoundedOps.attachmentMs(BoundedOps.ATTACHMENT_MIN_BYTES_PER_SEC * 3),
            "3 seconds of transfer at the slowest supported link",
        )
        val ceiling = BoundedOps.attachmentMs(BoundedOps.ATTACHMENT_CEILING_BYTES)
        assertEquals(ceiling, BoundedOps.attachmentMs(Long.MAX_VALUE), "a declared size cannot stretch the bound past the ceiling")
    }

    @Test
    fun anImportGetsOneWindowPerBatch() {
        assertEquals(BoundedOps.FLAT_MS, BoundedOps.importMs(0))
        assertEquals(BoundedOps.FLAT_MS * 2, BoundedOps.importMs(1))
        assertEquals(BoundedOps.FLAT_MS * 2, BoundedOps.importMs(200))
        assertEquals(BoundedOps.FLAT_MS * 3, BoundedOps.importMs(201))
    }

    @Test
    fun theRescueCopyHasAHardCeiling() {
        assertEquals(BoundedOps.FLAT_MS, BoundedOps.rescueCopyMs(0L, 0))
        assertEquals(BoundedOps.FLAT_MS * 4, BoundedOps.rescueCopyMs(0L, 3), "one flat window per item, on top of the byte budget")
        assertEquals(BoundedOps.RESCUE_COPY_CEILING_MS, BoundedOps.rescueCopyMs(0L, Int.MAX_VALUE, Long.MAX_VALUE), "co-members control the count: never overflow, never unbounded")
        assertEquals(BoundedOps.RESCUE_COPY_CEILING_MS, BoundedOps.rescueCopyMs(Long.MAX_VALUE, 100_000))
    }
}
