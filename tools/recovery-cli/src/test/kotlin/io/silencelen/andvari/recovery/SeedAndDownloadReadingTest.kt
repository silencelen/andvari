package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * spec 04 §4 step 1 and "Reading the identity file": a typed seed is read like everything else a person types (space and
 * tab removed from both ends, nothing else, then exactly 32 bytes of canonical base64url); a download is its four fields,
 * others ignored; a copy given in place of the download's leaves the download's own copy unread. Every seed here is a
 * made-up test seed.
 */
class SeedAndDownloadReadingTest {
    private val r = AssistRun()

    /** A made-up seed whose base64url uses both characters the other alphabet spells differently. */
    private val seed = ByteArray(32) { 0xFB.toByte() }
    private val text = Bytes.toB64(seed)

    @Test
    fun aTypedSeed_isTrimmedOfSpaceAndTabOnly_andMustBeCanonicalBase64url() {
        assertTrue('-' in text && '_' in text, text)
        for (ok in listOf(text, " $text", "$text\t", " \t$text \t ")) assertContentEquals(seed, readSeed(ok), "read: [$ok]")
        val refused = listOf(
            "$text\u00A0", "\u00A0$text", "$text=", text.replace('-', '+').replace('_', '/'), "$text\n", "$text\r", "$text\u000B", "${text.dropLast(1)} ${text.last()}",
        )
        for (bad in refused) assertNull(readSeed(bad), "bad_seed: [$bad]")
        // A seed file is one line: its line ending goes, then the same rule.
        assertContentEquals(seed, readSeedFile("$text\n"))
        assertContentEquals(seed, readSeedFile("$text\r\n"))
        assertContentEquals(seed, readSeedFile(text))
        assertNull(readSeedFile("$text\n\n"))
        assertNull(readSeedFile("$text\u00A0\n"))
    }

    @Test
    fun assist_refusesASeedWithANoBreakSpace_paddingOrTheOtherAlphabet_andReadsOneWithSpaces() {
        val good = Bytes.toB64(r.seed)
        for (bad in listOf("$good\u00A0", "$good=", good.replace('-', '+').replace('_', '/').let { if (it == good) "$good+" else it })) {
            val seen = r.run(r.args(), seedLine = bad)
            assertEquals(1, seen.status, seen.toString())
            assertTrue(seen.err.lines().last { it.isNotEmpty() }.startsWith("REFUSED (bad_seed)"), seen.toString())
            assertEquals(0, seen.linesAsked, seen.toString())
        }
        assertEquals(0, r.run(r.args(), seedLine = " \t$good\t ").status)
    }

    @Test
    fun aDownloadWithOtherFields_isStillADownload() {
        val d = r.member.download
        r.fileBytes = {
            """{"userId":"${d.userId}","sealed":"${d.sealed}","encryptedIdentitySeed":"${d.encryptedIdentitySeed}","identityPub":"${d.identityPub}","note":{"x":[1,2]},"legacySealed":null}""".encodeToByteArray()
        }
        assertEquals(0, r.run(r.args()).status)
    }

    @Test
    fun aCopyGivenInPlaceOfTheDownloads_leavesTheDownloadsOwnCopyUnread() {
        val d = r.member.download
        for (own in listOf("", ""","sealed":5""", ""","sealed":"not base64 at all"""", ""","sealed":null""")) {
            r.fileBytes = {
                """{"userId":"${d.userId}","encryptedIdentitySeed":"${d.encryptedIdentitySeed}","identityPub":"${d.identityPub}"$own}""".encodeToByteArray()
            }
            val seen = r.run(r.args("--copy" to d.sealed))
            assertEquals(0, seen.status, "[$own] $seen")
            // Without a copy in its place, the download's own must be there and be a copy.
            val alone = r.run(r.args())
            assertEquals(1, alone.status, "[$own] $alone")
            assertTrue(alone.err.startsWith("REFUSED (bad_identity_file)") || alone.err.startsWith("REFUSED (bad_copy)"), alone.toString())
        }
    }
}
