package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The tool never ends in a stack trace. Anything unexpected after the arguments are
 * accepted ends as one line that names its kind and no secret, with a non-zero exit and nothing produced.
 */
class AssistFaultTest {
    private val r = AssistRun()
    private val seedB64 = Bytes.toB64(r.seed)

    private fun nothingProduced(seen: AssistRun.Seen, what: String) {
        assertEquals(1, seen.status, "$what: $seen")
        assertEquals("Request code matches the request key.\n", seen.out.toString(), "$what: no answer, nothing after the first line: $seen")
        assertFalse("andvari-answer" in seen.out || "andvari-answer" in seen.err, "$what: $seen")
        assertFalse(seedB64 in seen.err || seedB64 in seen.out, "$what: the seed is never printed: $seen")
        assertFalse("\tat " in seen.err || "Exception in thread" in seen.err, "$what: no stack trace: $seen")
    }

    /** An exception thrown on purpose at each stage after the seed is read, its message carrying the seed. */
    @Test
    fun aFaultAtEachStageAfterTheSeed_endsInOneLineThatNamesItsKind_andNothingIsProduced() {
        for (stage in AssistStage.entries) {
            for (fault in listOf<Throwable>(IllegalStateException("seed $seedB64"), StackOverflowError("seed $seedB64"))) {
                val got = runWithFault(stage, fault)
                nothingProduced(got, "$stage ${fault::class.simpleName}")
                val last = got.err.lines().last { it.isNotEmpty() }
                assertEquals(unexpectedFault(stage, fault), last, "$stage: $got")
                assertTrue(last.startsWith("REFUSED (unexpected_fault): an unexpected fault (${fault::class.simpleName}) while ${stage.words}."), last)
                assertFalse("seed " in last, "the fault's message is never printed: $last")
            }
        }
    }

    /** The comparison's case, as it would now end if the statement's grammar failed after RECOVER was typed. */
    @Test
    fun theComparisonsFault_afterRecoverIsTyped_isOneLine() {
        val e = IllegalArgumentException("assisted-recovery statement is outside its grammar (non_canonical)")
        val got = runWithFault(AssistStage.ANSWER, e)
        nothingProduced(got, "answer")
        assertEquals(1, got.linesAsked, "RECOVER was typed: $got")
        assertEquals(
            "REFUSED (unexpected_fault): an unexpected fault (IllegalArgumentException) while making the answer. Nothing was produced: " +
                "no answer was printed and nothing was written. Run the command again; if it happens again, report this line.",
            got.err.lines().last { it.isNotEmpty() },
        )
    }

    @Test
    fun aSeedThatIsNotOne_isRefusedByName() {
        for (bad in listOf("not a seed", Bytes.toB64(ByteArray(31)), "")) {
            val got = r.run(r.args(), seedLine = bad)
            nothingProduced(got, bad)
            assertTrue(got.err.lines().last { it.isNotEmpty() }.startsWith("REFUSED (bad_seed)"), got.toString())
            assertEquals(0, got.linesAsked, got.toString())
        }
    }

    private fun runWithFault(stage: AssistStage, fault: Throwable): AssistRun.Seen {
        val seen = AssistRun.Seen()
        val lines = listOf("RECOVER ${r.member.userId.take(8)}").iterator()
        val io = AssistIo(
            readFile = { path, _ -> seen.filesRead += path;kotlinx.serialization.json.Json.encodeToString(io.silencelen.andvari.core.model.AdminEscrowDownload.serializer(), r.download).encodeToByteArray() },
            readSecret = { seen.secretsAsked++; seedB64 },
            readLine = { seen.linesAsked++; if (lines.hasNext()) lines.next() else null },
            out = { seen.out.append(it) },
            err = { seen.err.appendLine(it) },
            clock = { r.clock },
        )
        seen.status = runAssist(r.crypto, r.args(), io) { if (it == stage) throw fault }
        return seen
    }
}
