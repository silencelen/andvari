package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The recovery kit of design 2026-11-15 §10, graded off `recoverykit.json` from the independent oracle:
 * the grouped secret, the typed secret, the three-group confirmation (space, CR and LF anywhere in a
 * typed group ignored), what a valid challenge is, and the kit QR text composed and parsed, every row
 * through [gradeEvery]. The TypeScript twin (`web/src/crypto/trust/recoverykit.ts`) grades the same file.
 *
 * A kit text that does not parse is `bad_kit` (§2.4 "Small cases"). The parsers of this package answer
 * null for it and the flow names the verdict, as for a link that does not parse (`bad_link`); the
 * `qr.parse` rows name it in `expect.verdict`, which is graded exactly.
 */
class RecoveryKitVectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("recoverykit.json")

    @Test
    fun theFileHasTheSectionsThisSuiteGrades_andNoOther() {
        assertSections(v, "_about", "grouping", "typedSecret", "confirm", "groupChoice", "qr")
        assertSections(v.o("qr"), "maxLength", "compose", "parse")
    }

    private fun ints(row: JsonObject, key: String): List<Int> = row.getValue(key).jsonArray.map { it.jsonPrimitive.int }

    /** The verdict of a kit text: `ok`, or §2.4's `bad_kit` for one that does not parse. */
    private fun verdict(parsed: Any?): String = if (parsed != null) "ok" else "bad_kit"

    @Test
    fun grouping_elevenGroupsTenOfFourAndOneOfThree() {
        gradeEvery("recoverykit.grouping", v.rows("grouping")) { r ->
            val why = r.s("why")
            val secret = r.b64("secretB64")
            val groups = RecoveryKit.groups(secret)
            assertEquals(r.getValue("groups").jsonArray.strings(), groups, why)
            assertEquals(RecoveryKit.GROUPS, groups.size, why)
            assertEquals(List(10) { 4 } + 3, groups.map { it.length }, why)
            assertEquals(r.s("display"), RecoveryKit.displayForm(secret), why)
            // The display form is what a person types back.
            assertContentEquals(secret, RecoveryKit.parseSecret(r.s("display")), why)
        }
    }

    @Test
    fun typedSecret_spaceCrAndLfAreIgnoredAndNothingElse() {
        val rows = v.rows("typedSecret")
        var valid = 0
        gradeEvery("recoverykit.typedSecret", rows) { r ->
            val why = r.s("why")
            val expect = r.o("expect")
            val secret = RecoveryKit.parseSecret(r.s("input"))
            assertEquals(if (expect.bool("valid")) "ok" else "bad_kit", verdict(secret), why)
            if (secret != null) {
                valid++
                assertEquals(expect.s("secretB64"), Bytes.toB64(secret), why)
                assertEquals(32, secret.size, why)
            }
        }
        assertTrue(valid in 1 until rows.size, "the corpus has secrets that parse and texts that do not")
    }

    @Test
    fun confirm_theThreeGroupsExactlyAndInTheOrderAsked() {
        val rows = v.rows("confirm")
        var matched = 0
        gradeEvery("recoverykit.confirm", rows) { r ->
            val why = r.s("why")
            val matches = RecoveryKit.confirmMatches(r.b64("secretB64"), ints(r, "groups"), r.getValue("typed").jsonArray.strings())
            assertEquals(r.o("expect").bool("matches"), matches, why)
            if (matches) matched++
        }
        assertTrue(matched in 1 until rows.size, "the corpus has entries that match and entries that do not")
    }

    @Test
    fun groupChoice_aChallengeIsThreeDistinctNumbersFromOneToEleven() {
        val secret = v.rows("grouping").first().b64("secretB64")
        val all = RecoveryKit.groups(secret)
        gradeEvery("recoverykit.groupChoice", v.rows("groupChoice")) { r ->
            val why = r.s("why")
            val numbers = ints(r, "groups")
            assertEquals(r.bool("valid"), RecoveryKit.isGroupChoice(numbers), why)
            // The confirmation takes no other challenge: typing the right group for every number asked passes only a valid one.
            val typed = numbers.map { all.getOrNull(it - 1) ?: "" }
            assertEquals(r.bool("valid"), RecoveryKit.confirmMatches(secret, numbers, typed), why)
        }
        // What the CSPRNG draws is always a valid challenge, in ascending order.
        repeat(200) {
            val drawn = RecoveryKit.confirmGroups(crypto)
            assertTrue(RecoveryKit.isGroupChoice(drawn), "$drawn")
            assertEquals(drawn.sorted(), drawn)
        }
    }

    @Test
    fun qrCompose_isByteExact() {
        val qr = v.o("qr")
        assertEquals(qr.l("maxLength").toInt(), RecoveryKit.MAX_QR_LENGTH)
        gradeEvery("recoverykit.qr.compose", qr.rows("compose")) { r ->
            val why = r.s("why")
            val secret = r.b64("secretB64")
            val text = RecoveryKit.composeQr(r.s("origin"), r.s("card0Hash"), r.s("email"), secret)
            assertEquals(r.s("text"), text, why)
            assertTrue(text!!.length <= RecoveryKit.MAX_QR_LENGTH, why)
            // What compose makes, parse reads back.
            val kit = assertNotNull(RecoveryKit.parseQr(text), why)
            assertEquals(r.s("origin"), kit.origin, why)
            assertEquals(r.s("card0Hash"), kit.card0Hash, why)
            assertEquals(r.s("email"), kit.emailNorm, why)
            assertContentEquals(secret, kit.secret, why)
        }
    }

    @Test
    fun qrParse_isTotalAndCanonical() {
        val rows = v.o("qr").rows("parse")
        var valid = 0
        gradeEvery("recoverykit.qr.parse", rows) { r ->
            val why = r.s("why")
            val input = r.s("input")
            val expect = r.o("expect")
            val kit = RecoveryKit.parseQr(input)
            // expect.verdict names the verdict (ok or bad_kit); expect.valid says the same as a boolean.
            assertEquals(expect.s("verdict") == "ok", expect.bool("valid"), "$why: verdict and valid agree")
            assertEquals(expect.s("verdict"), verdict(kit), why)
            if (kit != null) {
                valid++
                assertEquals(expect.s("origin"), kit.origin, why)
                assertEquals(expect.s("card0Hash"), kit.card0Hash, why)
                assertEquals(expect.s("email"), kit.emailNorm, why)
                assertEquals(expect.s("secretB64"), Bytes.toB64(kit.secret), why)
                // The kit screen's scanner takes it, and no other scanner does (FS-B1).
                assertEquals(ScanPayload.KIT, ScanPayload.of(input), why)
                assertNull(LinkUrl.parse(input), why)
                assertNull(DeviceLinkUrl.parse(input), why)
            } else {
                assertNotEquals(ScanPayload.KIT, ScanPayload.of(input), why)
            }
        }
        assertTrue(valid in 1 until rows.size, "the corpus has kits that parse and texts that do not")
    }
}
