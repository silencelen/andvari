package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.model.AdminEscrowDownload
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The layers, and what the specification's text left open: the command line reads what a person typed (space and tab from both
 * ends of a typed confirmation, and nothing else; spaces, tabs and dashes from the request code, its letters without
 * regard to case); the clock is checked with the arguments, before anything is read; a file is strict UTF-8; and every
 * refusal the tool can make has a name.
 */
class AssistReadingTest {
    private val r = AssistRun()

    private fun refused(seen: AssistRun.Seen, verdict: String, what: String) {
        assertEquals(1, seen.status, "$what: $seen")
        assertTrue(seen.err.lines().any { it.startsWith("REFUSED ($verdict)") }, "$what: $seen")
        assertTrue("andvari-answer" !in seen.out, "$what: nothing produced: $seen")
    }

    private fun refusedBeforeTheSeed(seen: AssistRun.Seen, verdict: String, what: String) {
        refused(seen, verdict, what)
        assertEquals(0, seen.secretsAsked, "$what: the seed is not asked for: $seen")
    }

    @Test
    fun aTypedConfirmation_losesSpaceAndTabAtBothEnds_andNothingElse() {
        val recover = "RECOVER ${r.member.userId.take(8)}"
        assertEquals(0, r.run(r.args(), listOf(" \t$recover\t ")).status)
        for (other in listOf(Char(0x0C), Char(0xA0), Char(0x0B))) {
            refused(r.run(r.args(), listOf("$recover$other")), "not_confirmed", "RECOVER + U+${other.code.toString(16)}")
        }
        // The unanchored acknowledgment, read the same way.
        val un = r.args().filter { it != "--identity-fp" && it != r.member.identityFp.take(32) } + "--no-identity-anchor"
        assertEquals(0, r.run(un, listOf("\t${Escrow.UNANCHORED_ACK} ", recover)).status)
        refused(r.run(un, listOf(Escrow.UNANCHORED_ACK + Char(0x0C), recover)), "unanchored_not_acknowledged", "acknowledgment + form feed")
    }

    @Test
    fun theRequestCode_losesSpacesTabsAndDashes_andItsCase_andNothingElse() {
        assertEquals(0, r.run(r.args("--request-code" to " " + r.code.uppercase().chunked(4).joinToString("-") + "\t")).status)
        for (bad in listOf(r.code + "\n", r.code.chunked(12).joinToString("\r"), r.code + Char(0xA0))) {
            val seen = r.run(r.args("--request-code" to bad))
            refusedBeforeTheSeed(seen, "request_code_mismatch", "code ${bad.map { it.code }}")
            assertEquals(emptyList(), seen.filesRead)
        }
    }

    @Test
    fun theClock_isCheckedWithTheArguments_beforeAnythingIsRead() {
        for (t in listOf(999_999_999_999L, 10_000_000_000_000L)) {
            r.clock = t
            val seen = r.run(r.args())
            refusedBeforeTheSeed(seen, "bad_clock", "clock $t")
            assertEquals(emptyList(), seen.filesRead, seen.toString())
            assertEquals("", seen.out.toString(), seen.toString())
        }
    }

    @Test
    fun anIdentityFileThatIsNotStrictUtf8_isRefusedBeforeTheSeed() {
        val json = Json.encodeToString(AdminEscrowDownload.serializer(), r.member.download)
        // A valid download with one byte that is not UTF-8 inside an extra field: a lenient decoder would replace it and go on.
        val head = json.dropLast(1) + ",\"note\":\""
        r.fileBytes = { head.encodeToByteArray() + byteArrayOf(0xFF.toByte()) + "\"}".encodeToByteArray() }
        refusedBeforeTheSeed(r.run(r.args()), "bad_identity_file", "a 0xFF byte")
    }

    @Test
    fun everyOtherRefusal_hasAName_andComesBeforeTheSeed() {
        val user = r.member.userId
        val cases = listOf(
            "unknown option" to (r.args("--instance" to "not-a-uuid") + "--frob") to "unknown_option",
            "--legacy" to (r.args() + "--legacy") to "legacy_refused",
            "two copies" to (r.args("--copy" to r.member.sealed) + r.member.sealed) to "more_than_one_copy",
            "--request with no value" to (r.args().filter { it != "--request" && it != r.requestId } + "--request") to "bad_request_id",
            "--user with no value" to (r.args().filter { it != "--user" && it != user } + "--user") to "bad_user_id",
            "--identity-file with no value" to (r.args().filter { it != "--identity-file" && it != "f.json" } + "--identity-file") to "identity_check_required",
        )
        for ((c, verdict) in cases) {
            val (what, args) = c
            val seen = r.run(args)
            refusedBeforeTheSeed(seen, verdict, what)
            assertEquals(emptyList(), seen.filesRead, "$what: $seen")
        }
        for ((what, file, verdict) in listOf(
            Triple("not a download", "{\"hello\":1}", "bad_identity_file"),
            Triple("another account's", Json.encodeToString(AdminEscrowDownload.serializer(), r.member.download.copy(userId = "22222222-2222-4222-8222-222222222222")), "identity_file_mismatch"),
            Triple("a 31-byte identityPub", Json.encodeToString(AdminEscrowDownload.serializer(), r.member.download.copy(identityPub = Bytes.toB64(ByteArray(31)))), "identity_check_failed"),
        )) {
            r.fileBytes = { file.encodeToByteArray() }
            refusedBeforeTheSeed(r.run(r.args()), verdict, what)
        }
        r.fileBytes = { throw java.io.FileNotFoundException("f.json") }
        refusedBeforeTheSeed(r.run(r.args()), "bad_identity_file", "a file that cannot be read")
    }
}
