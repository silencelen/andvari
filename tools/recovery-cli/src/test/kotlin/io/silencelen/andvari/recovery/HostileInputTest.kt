package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.AdminEscrowDownload
import kotlinx.serialization.json.Json
import java.io.Reader
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * spec 04 §4, "The tool's inputs are hostile" (evening review B, F9): every file the tool reads has a limit it is never
 * read past, the JSON files refuse a key given twice and deep nesting, a typed or piped line is bounded, and none of it
 * ends in a stack trace or an out-of-memory error. Every seed and file here is made up by the test.
 */
class HostileInputTest {
    private val r = AssistRun()
    private val crypto = r.crypto

    /** An endless file: a reader that read it whole would never stop, or run out of memory. */
    private val endless = "/dev/zero"

    @Test
    fun aFile_isReadOnlyUpToItsLimit() {
        assertEquals(1024, assertFailsWith<ToolInput.TooLarge> { ToolInput.readFile(endless, 1024) }.cap)
        val f = kotlin.io.path.createTempFile("andvari-input").toFile()
        try {
            f.writeBytes(ByteArray(100) { 'a'.code.toByte() })
            assertEquals(100, ToolInput.readFile(f.path, 100).size, "exactly at the limit is read")
            assertFailsWith<ToolInput.TooLarge> { ToolInput.readFile(f.path, 99) }
        } finally {
            f.delete()
        }
    }

    private fun refusedBeforeAnySeed(s: AssistRun.Seen, name: String) {
        assertEquals(1, s.status, s.toString())
        assertTrue(s.err.lines().first { it.isNotEmpty() }.startsWith("REFUSED ($name)"), s.toString())
        assertEquals(0, s.secretsAsked, s.toString())
        assertTrue("Exception" !in s.err.toString() && "\tat " !in s.err.toString(), "no stack trace: $s")
    }

    /** `assist` whose files are made by [bytes]; an [endless] path is read through the tool's own bounded reader. */
    private fun assist(extra: List<String> = emptyList(), bytes: (String, Int) -> ByteArray): AssistRun.Seen {
        val seen = AssistRun.Seen()
        val io = AssistIo(
            readFile = { p, cap -> seen.filesRead += p; bytes(p, cap) },
            readSecret = { seen.secretsAsked++; Bytes.toB64(r.seed) },
            readLine = { seen.linesAsked++; null },
            out = { seen.out.append(it) },
            err = { seen.err.appendLine(it) },
            clock = { r.clock },
        )
        seen.status = runAssist(crypto, r.args() + extra, io)
        return seen
    }

    private val download = Json.encodeToString(AdminEscrowDownload.serializer(), r.member.download)

    @Test
    fun theIdentityFile_isBounded_andRefusesAKeyGivenTwice() {
        refusedBeforeAnySeed(assist { _, cap -> ToolInput.readFile(endless, cap) }, "bad_identity_file")
        // A caller's own reader that hands over more is held to the same limit.
        refusedBeforeAnySeed(assist { _, _ -> ByteArray(ToolInput.IDENTITY_FILE_MAX + 1) { ' '.code.toByte() } }, "bad_identity_file")
        // The same key twice: another account's id first, the right one last (the parser would keep the last silently).
        val twice = download.replaceFirst("{", "{\"userId\":\"99999999-9999-4999-8999-999999999999\",")
        refusedBeforeAnySeed(assist { _, _ -> twice.encodeToByteArray() }, "bad_identity_file")
        // Spelled with an escape, it is still the same key.
        val escaped = download.replaceFirst("{", "{\"user\\u0049d\":\"99999999-9999-4999-8999-999999999999\",")
        refusedBeforeAnySeed(assist { _, _ -> escaped.encodeToByteArray() }, "bad_identity_file")
        refusedBeforeAnySeed(assist { _, _ -> ("[".repeat(10_000) + "]".repeat(10_000)).encodeToByteArray() }, "bad_identity_file")
    }

    private val served = ServedInstance(crypto, r.instanceId).card(r.seed, 1_790_000_000_000L)

    private fun withInstance(file: (Int) -> ByteArray) = assist(listOf("--instance-file", "instance.json", "--card0-hash", served.card0Hash())) { p, cap ->
        if (p == "instance.json") file(cap) else download.encodeToByteArray()
    }

    @Test
    fun theInstanceFile_isBounded_refusesAKeyGivenTwice_deepNesting_andTooManyFrames() {
        refusedBeforeAnySeed(withInstance { cap -> ToolInput.readFile(endless, cap) }, "bad_instance_file")
        val good = served.json().decodeToString()
        // A second "cards" list after the genuine one: the one the parser would keep.
        val twice = good.dropLast(1) + ",\"cards\":[]}"
        refusedBeforeAnySeed(withInstance { twice.encodeToByteArray() }, "bad_instance_file")
        refusedBeforeAnySeed(withInstance { (good.dropLast(1) + ",\"x\":" + "[".repeat(40) + "]".repeat(40) + "}").encodeToByteArray() }, "bad_instance_file")
        val frame = "\"" + Bytes.toB64(ByteArray(90) { 7 }) + "\""
        val many = "{\"cards\":[" + good.substringAfter("[").substringBefore("]") + "],\"rotations\":[" + List(ToolInput.ROTATIONS_MAX + 1) { frame }.joinToString(",") + "]}"
        val s = withInstance { many.encodeToByteArray() }
        refusedBeforeAnySeed(s, "bad_instance_file")
        assertTrue("65 rotations" in s.err, s.toString())
        // The genuine file still goes through: the seed is asked for (and the run stops later, at the confirmation no one typed).
        val genuine = withInstance { served.json() }
        assertEquals(1, genuine.secretsAsked, genuine.toString())
        assertTrue("it has not changed" in genuine.err && "REFUSED (not_confirmed)" in genuine.err, genuine.toString())
    }

    @Test
    fun theFleetChecksFiles_areBounded_andTheDumpRefusesAKeyGivenTwice() {
        fun fleet(files: (String, Int) -> ByteArray): String {
            val all = StringBuilder()
            val io = AssistIo(
                readFile = files, readSecret = { all.appendLine("ask"); null }, readLine = { null },
                out = { all.append(it) }, err = { all.appendLine(it) }, clock = { r.clock },
            )
            val status = runVerify(crypto, listOf("seed.txt", "dump.json"), io)
            assertEquals(1, status, all.toString())
            assertTrue("ask" !in all.lines() && "PASS" !in all && "\tat " !in all, all.toString())
            return all.toString()
        }
        val row = """{"userId":"${r.member.userId}","sealed":"${r.member.sealed}","fingerprint":null,"updatedAt":1,"encryptedIdentitySeed":"${r.member.download.encryptedIdentitySeed}","identityPub":"${r.member.download.identityPub}"}"""
        val seedFile = (Bytes.toB64(r.seed) + "\n").encodeToByteArray()
        assertTrue("REFUSED (bad_dump)" in fleet { p, cap -> if (p == "dump.json") ToolInput.readFile(endless, cap) else seedFile })
        assertTrue("REFUSED (bad_seed)" in fleet { p, cap -> if (p == "seed.txt") ToolInput.readFile(endless, cap) else "[$row]".encodeToByteArray() })
        // A row whose sealed copy is given twice: the parser would keep the second, unchecked by anyone.
        val twice = row.dropLast(1) + ",\"sealed\":\"AAAA\"}"
        val out = fleet { p, _ -> if (p == "dump.json") "[$twice]".encodeToByteArray() else seedFile }
        assertTrue("REFUSED (bad_dump)" in out && "\"sealed\" twice" in out, out)
    }

    @Test
    fun theJsonCheck_comparesDecodedKeys_perObject_andBoundsTheDepth() {
        assertNotNull(ToolInput.jsonProblem("""{"a":1,"a":2}"""))
        assertNotNull(ToolInput.jsonProblem("""{"a":1,"a":2}"""))
        assertNull(ToolInput.jsonProblem("""[{"a":1},{"a":2}]"""), "one key per object, not per file")
        assertNull(ToolInput.jsonProblem("""{"a":{"a":1},"b":"{{\"a\":1,\"a\":2}"}"""), "inside a string nothing is structure")
        assertNull(ToolInput.jsonProblem("[".repeat(ToolInput.JSON_DEPTH_MAX) + "]".repeat(ToolInput.JSON_DEPTH_MAX)))
        assertNotNull(ToolInput.jsonProblem("[".repeat(ToolInput.JSON_DEPTH_MAX + 1) + "]".repeat(ToolInput.JSON_DEPTH_MAX + 1)))
        assertNotNull(ToolInput.jsonProblem("""{"a":"open"""))
        assertNotNull(ToolInput.jsonProblem("""{"a\x":1}"""))
    }

    @Test
    fun aTypedLine_isBounded_andAnOverlongOneFailsWhatWasAsked() {
        // Ten million characters, then a line ending: what is kept is one more than the limit, so no grammar takes it.
        val huge = object : Reader() {
            var left = 10_000_000
            override fun read(cbuf: CharArray, off: Int, len: Int): Int {
                if (left < 0) return -1
                var n = 0
                while (n < len && left >= 0) {
                    cbuf[off + n] = if (left == 0) '\n' else 'A'
                    left--
                    n++
                }
                return n
            }
            override fun close() {}
        }
        assertEquals(ToolInput.LINE_MAX + 1, ToolInput.lineFrom(huge)!!.length)
        assertNull(ToolInput.lineFrom(huge), "then the end of the input")
        assertEquals("abc", ToolInput.lineFrom("abc\r\nnext".reader()))
        assertNull(readSeed("A".repeat(ToolInput.LINE_MAX + 1)))
    }
}
