package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Every argument of the tool is checked exactly as given, before anything is
 * read or asked, and the value checked is the value used. An id, a key or a copy with white space around it is refused
 * by its name, with nothing read, nothing asked and nothing produced.
 */
class AssistArgumentsTest {
    private val r = AssistRun()

    private fun refusedBeforeAnything(seen: AssistRun.Seen, verdict: String, what: String) {
        assertEquals(1, seen.status, "$what: $seen")
        assertTrue(seen.err.startsWith("REFUSED ($verdict)"), "$what: $seen")
        assertEquals(emptyList(), seen.filesRead, "$what: nothing is read: $seen")
        assertEquals(0, seen.secretsAsked, "$what: the seed is not asked for: $seen")
        assertEquals(0, seen.linesAsked, "$what: nothing is asked: $seen")
        assertEquals("", seen.out.toString(), "$what: nothing is produced: $seen")
    }

    @Test
    fun theCommandLineAsGiven_producesTheAnswer() {
        val seen = r.run(r.args())
        assertEquals(0, seen.status, seen.toString())
        assertTrue(seen.out.lines().last { it.isNotEmpty() }.startsWith("andvari-answer:3:${r.requestId}:${r.rPub}:"), seen.toString())
    }

    @Test
    fun anIdAKeyOrACopyWithASpaceBeforeOrAfter_isRefusedByItsName_beforeAnythingIsReadOrAsked() {
        val copy = r.member.sealed
        for ((flag, value, verdict) in listOf(
            Triple("--instance", r.instanceId, "bad_instance"),
            Triple("--request", r.requestId, "bad_request_id"),
            Triple("--request-key", r.rPub, "bad_request_key"),
            Triple("--user", r.member.userId, "bad_user_id"),
            Triple("--copy", copy, "bad_copy"),
        )) {
            for (spaced in listOf(" $value", "$value ")) refusedBeforeAnything(r.run(r.args(flag to spaced)), verdict, "$flag '$spaced'")
        }
    }

    /** The identity file is the path exactly as typed; its copy is checked exactly as the server wrote it, before the seed. */
    @Test
    fun theIdentityFileIsThePathAsGiven_andItsCopyIsCheckedAsGiven_beforeTheSeed() {
        assertEquals(listOf(" f.json "), r.run(r.args("--identity-file" to " f.json ")).filesRead)
        r.download = r.member.download.copy(sealed = r.member.sealed + " ")
        val seen = r.run(r.args())
        assertEquals(1, seen.status, seen.toString())
        assertTrue(seen.err.startsWith("REFUSED (bad_copy)"), seen.toString())
        assertEquals(0, seen.secretsAsked, seen.toString())
        assertEquals("", seen.out.lines().drop(1).joinToString(""), seen.toString())
    }

    /** The other commands' keys and blobs: exactly as given. */
    @Test
    fun rotateFingerprintAndCanary_takeTheirKeysExactlyAsGiven() {
        val key = Bytes.toB64(r.request.publicKey)
        for (spaced in listOf(" $key", "$key ")) {
            assertFailsWith<RecoverRefused> { RotateCommand.parse(listOf("--instance", r.instanceId, "--to", spaced)) }
            assertTrue(assertFailsWith<RecoverRefused> { keyArg(spaced, "the public key") }.message!!.startsWith("REFUSED (bad_key)"))
            assertTrue(assertFailsWith<RecoverRefused> { blobArg(spaced, "the sealed canary") }.message!!.startsWith("REFUSED (bad_copy)"))
        }
        assertEquals(key, Bytes.toB64(RotateCommand.parse(listOf("--instance", r.instanceId, "--to", key)).toPub))
        assertEquals(key, Bytes.toB64(keyArg(key, "the public key")))
        assertFailsWith<RecoverRefused> { keyArg("$key=", "the public key") }
    }
}
