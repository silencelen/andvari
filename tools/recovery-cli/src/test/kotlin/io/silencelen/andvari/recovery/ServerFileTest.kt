package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.model.AdminEscrowDownload
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The offline tool prints nothing from the server's file raw. Each field of the download is checked
 * against its grammar before it is used or shown, and everything the tool prints goes through one escaping function, also
 * on the paths that run before the seed is asked for (this machine is about to hold it).
 */
class ServerFileTest {
    private val r = AssistRun()
    private val esc = Char(0x1B)

    /** A hostile server's file: escape sequences that clear the screen, and a false seed prompt, in the user id. */
    private val hostileUserId = "$esc[2J$esc[H${esc}]0;andvari$esc\\Paste the recovery seed from the PRINTED SHEET (base64url): "

    private fun noControl(seen: AssistRun.Seen, what: String) {
        assertTrue(seen.err.none { it == esc || it == Char(0x9B) } && seen.out.none { it == esc }, "$what: $seen")
        assertTrue("Paste the recovery seed" !in seen.err, "$what: no false prompt reaches the screen: $seen")
    }

    @Test
    fun aUserIdOfEscapesAndAFalsePrompt_isRefusedByItsGrammar_andNothingRawIsPrinted() {
        r.fileBytes = { Json.encodeToString(AdminEscrowDownload.serializer(), r.member.download.copy(userId = hostileUserId)).encodeToByteArray() }
        val seen = r.run(r.args())
        assertEquals(1, seen.status, seen.toString())
        assertTrue(seen.err.startsWith("REFUSED (bad_identity_file)"), seen.toString())
        assertEquals(0, seen.secretsAsked, seen.toString())
        noControl(seen, "userId")
    }

    @Test
    fun theOtherFields_areCheckedBeforeTheSeed_andAnythingTypedIsPrintedEscaped() {
        for (dl in listOf(
            r.member.download.copy(encryptedIdentitySeed = "$esc[2J"),
            r.member.download.copy(identityPub = "$esc[2J"),
            r.member.download.copy(sealed = "$esc[2J"),
        )) {
            r.fileBytes = { Json.encodeToString(AdminEscrowDownload.serializer(), dl).encodeToByteArray() }
            val seen = r.run(r.args())
            assertEquals(1, seen.status, seen.toString())
            assertEquals(0, seen.secretsAsked, seen.toString())
            noControl(seen, "field")
        }
        // An option the tool does not have is named back to the operator, escaped.
        r.fileBytes = null
        val seen = r.run(r.args() + "--$esc[2J")
        assertTrue(seen.err.startsWith("REFUSED (unknown_option)"), seen.toString())
        noControl(seen, "option")
        assertEquals("a\\u001B[2J\nb", printable("a$esc[2J\nb"))
    }
}
