package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Kit rules of design 2026-11-15 §10 that `recoverykit.json` does not carry: that every group is equally
 * likely to be asked for, what white space a typed group may carry, the cap of 1,024 characters counted
 * after the strip, bytes outside ASCII inside the QR's parts, and what the composer refuses.
 */
class RecoveryKitRulesTest {
    private val crypto = createCryptoProvider()
    private val secret = ByteArray(32) { (0x21 + it * 7).toByte() }
    private val origin = "https://vault.example.org"
    private val card0Hash = "5c".repeat(32)
    private val email = "alice@example.com"

    /** A provider whose "random" bytes are the given blocks, in order; once they run out, bytes that end any draw. */
    private class Scripted(private val inner: CryptoProvider, vararg blocks: ByteArray) : CryptoProvider by inner {
        private val script = ArrayDeque(blocks.toList())
        var draws = 0

        override fun randomBytes(n: Int): ByteArray {
            draws++
            val block = script.removeFirstOrNull() ?: ByteArray(n) { it.toByte() }
            return block.copyOf(n)
        }
    }

    private fun block(vararg values: Int): ByteArray = ByteArray(16) { i -> (values.getOrNull(i) ?: values.last()).toByte() }

    @Test
    fun confirmGroups_everyGroupIsEquallyLikely() {
        // 253 = 11 * 23: bytes 0..252 give each of the eleven groups exactly 23 times, and 253..255 are drawn again.
        assertEquals((1..11).associateWith { 23 }, (0..252).groupingBy { it % 11 + 1 }.eachCount())

        for (first in 0..255) {
            // The first byte, then bytes that give groups 1, 2, 3 and 4.
            val drawn = RecoveryKit.confirmGroups(Scripted(crypto, block(first, 0, 1, 2, 3)))
            val expected = LinkedHashSet<Int>()
            if (first < 253) expected += first % 11 + 1
            for (filler in 1..4) if (expected.size < 3) expected += filler
            assertEquals(expected.sorted(), drawn, "first byte $first")
        }
        // The highest accepted byte gives group 11; the three above it are skipped, not folded onto groups 1 to 3.
        assertEquals(listOf(1, 2, 11), RecoveryKit.confirmGroups(Scripted(crypto, block(252, 253, 254, 255, 0, 1))))
        // A block that yields nothing, or too little, is followed by another draw.
        val twoDraws = Scripted(crypto, block(255), block(21, 21, 9, 9, 5))
        assertEquals(listOf(6, 10, 11), RecoveryKit.confirmGroups(twoDraws))
        assertEquals(2, twoDraws.draws)
        val threeDraws = Scripted(crypto, block(7), block(7, 255), block(8, 9))
        assertEquals(listOf(8, 9, 10), RecoveryKit.confirmGroups(threeDraws))
        assertEquals(3, threeDraws.draws)

        // With the real CSPRNG every group turns up, about as often as any other (3/11 of the draws each).
        val seen = IntArray(12)
        repeat(2200) { for (g in RecoveryKit.confirmGroups(crypto)) seen[g]++ }
        for (g in 1..11) assertTrue(seen[g] in 420..780, "group $g was asked for ${seen[g]} times in 2200 draws")
    }

    @Test
    fun confirm_aTypedGroupMayCarrySpacesAndLineBreaks_andNothingElse() {
        val groups = RecoveryKit.groups(secret)
        val asked = listOf(2, 7, 10)
        val right = asked.map { groups[it - 1] }
        fun confirm(typed: List<String>, numbers: List<Int> = asked) = RecoveryKit.confirmMatches(secret, numbers, typed)

        assertTrue(confirm(right))
        // Space, CR and LF are ignored, as in a typed secret: around a group, and inside it too (the twin does the same).
        assertTrue(confirm(listOf(" ${right[0]} ", "${right[1]}\r\n", "\n${right[2]}")))
        assertTrue(confirm(listOf(right[0].take(2) + " " + right[0].drop(2), right[1], right[2])))
        // A tab is not, nor any other character; and the comparison is exact and case-sensitive.
        assertFalse(confirm(listOf("${right[0]}\t", right[1], right[2])))
        assertFalse(confirm(listOf("${right[0]}.", right[1], right[2])))
        assertFalse(confirm(listOf(right[0] + Char(0xA0), right[1], right[2])))
        assertFalse(confirm(listOf(right[0].dropLast(1), right[1], right[2])))
        assertFalse(confirm(listOf("", right[1], right[2])))
        assertFalse(confirm(listOf(right[0], right[1], if (right[2] == right[2].lowercase()) right[2].uppercase() else right[2].lowercase())))
        // The order asked is the order typed; a sorted challenge is not required.
        assertTrue(confirm(listOf(right[2], right[0], right[1]), listOf(10, 2, 7)))
        assertFalse(confirm(listOf(right[2], right[0], right[1])))
        // The whole secret in one box is not three groups.
        assertFalse(confirm(listOf(RecoveryKit.displayForm(secret), right[1], right[2])))
        // The last group has three characters.
        assertEquals(3, groups[10].length)
        assertTrue(confirm(listOf(groups[0], groups[10], groups[5]), listOf(1, 11, 6)))
        assertFalse(confirm(listOf(groups[0], groups[10] + "A", groups[5]), listOf(1, 11, 6)))

        assertTrue(RecoveryKit.isGroupChoice(listOf(11, 1, 6)))
        assertFalse(RecoveryKit.isGroupChoice(emptyList()))
        assertFalse(RecoveryKit.isGroupChoice(listOf(1, 1, 1)))
        assertFalse(RecoveryKit.isGroupChoice(listOf(-1, 2, 3)))
        assertFalse(RecoveryKit.isGroupChoice(listOf(Int.MAX_VALUE, 2, 3)))
        // The secret is the app's own value: another length is the caller's mistake, not a typed one.
        assertFailsWith<IllegalArgumentException> { RecoveryKit.groups(ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKit.displayForm(ByteArray(33)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKit.confirmMatches(ByteArray(31), asked, right) }
    }

    @Test
    fun typedSecret_theDisplayFormRoundTrips_andTheResultIsTheCallersCopy() {
        val typed = RecoveryKit.displayForm(secret)
        assertEquals(53, typed.length, "43 characters and ten spaces")
        val parsed = assertNotNull(RecoveryKit.parseSecret(typed))
        assertContentEquals(secret, parsed)
        assertContentEquals(secret, RecoveryKit.parseSecret(typed.replace(" ", "\r\n")))
        assertNull(RecoveryKit.parseSecret(typed.replace(" ", "\t")), "a tab is not ignored")
        assertNull(RecoveryKit.parseSecret(typed.replace(" ", "-")), "a dash is base64url")
        assertNull(RecoveryKit.parseSecret(typed.dropLast(1)))
        // A kit QR text is not a typed secret, and a typed secret is not a kit QR text.
        val qr = assertNotNull(RecoveryKit.composeQr(origin, card0Hash, email, secret))
        assertNull(RecoveryKit.parseSecret(qr))
        assertNull(RecoveryKit.parseQr(typed))
    }

    @Test
    fun qr_theCapCountsAfterTheWhiteSpaceIsStripped() {
        val text = assertNotNull(RecoveryKit.composeQr(origin, card0Hash, email, secret))
        assertTrue(text.length < RecoveryKit.MAX_QR_LENGTH)
        // White space is removed before anything is measured: space, tab, CR and LF, wherever they stand.
        assertNotNull(RecoveryKit.parseQr(text + " ".repeat(RecoveryKit.MAX_QR_LENGTH)))
        assertNotNull(RecoveryKit.parseQr(text.chunked(7).joinToString("\r\n\t ")))
        // Any other character between the parts is part of the text.
        assertNull(RecoveryKit.parseQr(text + Char(0x0C)), "a form feed")
        assertNull(RecoveryKit.parseQr(text + Char(0xA0)), "a no-break space")
        assertNull(RecoveryKit.parseQr("$text:"))
        assertNull(RecoveryKit.parseQr(text.replace("andvari-kit:2:", "andvari-kit:2::")))
        // More than 1,024 characters after the strip is refused whatever it holds.
        assertNull(RecoveryKit.parseQr(text + "A".repeat(RecoveryKit.MAX_QR_LENGTH)))
        assertNull(RecoveryKit.parseQr("A".repeat(100_000)))
        assertNull(RecoveryKit.parseQr(""))
        assertNull(RecoveryKit.parseQr("andvari-kit:2:"))
        assertNull(RecoveryKit.parseQr("andvari-kit:2::::"))
    }

    @Test
    fun qr_bytesOutsideAsciiInsideAPartAreRefusedBeforeAnyDecoding() {
        val text = assertNotNull(RecoveryKit.composeQr(origin, card0Hash, email, secret))
        val o = Bytes.toB64(origin.encodeToByteArray())
        val e = Bytes.toB64(email.encodeToByteArray())
        fun withOrigin(bytes: ByteArray) = text.replace(":$o:", ":" + Bytes.toB64(bytes) + ":")
        fun withEmail(bytes: ByteArray) = text.replace(":$e:", ":" + Bytes.toB64(bytes) + ":")
        assertNotNull(RecoveryKit.parseQr(withOrigin(origin.encodeToByteArray())), "the replacement itself is sound")
        assertNotNull(RecoveryKit.parseQr(withEmail(email.encodeToByteArray())))

        // A byte-order mark in front of the origin: a decoder that drops it would accept the origin.
        val bom = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte())
        assertNull(RecoveryKit.parseQr(withOrigin(bom + origin.encodeToByteArray())))
        assertNull(RecoveryKit.parseQr(withEmail(bom + email.encodeToByteArray())))
        // Ill-formed UTF-8, a NUL, a line feed and DEL inside a part.
        for (extra in listOf(0xFF, 0x80, 0x00, 0x0A, 0x7F)) {
            assertNull(RecoveryKit.parseQr(withOrigin(origin.encodeToByteArray() + extra.toByte())), "origin with byte $extra")
            assertNull(RecoveryKit.parseQr(withEmail(email.encodeToByteArray() + extra.toByte())), "email with byte $extra")
        }
        // An address that is not already normal, though its bytes are ASCII.
        assertNull(RecoveryKit.parseQr(withEmail(" $email".encodeToByteArray())))
        assertNull(RecoveryKit.parseQr(withEmail(email.uppercase().encodeToByteArray())))
    }

    @Test
    fun compose_refusesWhatTheParserWouldRefuse_andHandsBackItsParts() {
        val text = assertNotNull(RecoveryKit.composeQr(origin, card0Hash, email, secret))
        assertEquals("andvari-kit:2:${Bytes.toB64(origin.encodeToByteArray())}:$card0Hash:${Bytes.toB64(email.encodeToByteArray())}:${Bytes.toB64(secret)}", text)
        assertFalse(text.any(TrustGrammar::isAsciiSpace))
        // A part outside its grammar.
        assertNull(RecoveryKit.composeQr("http://192.168.1.10", card0Hash, email, secret))
        assertNull(RecoveryKit.composeQr("$origin/", card0Hash, email, secret))
        assertNull(RecoveryKit.composeQr("https://vault.example.org:443", card0Hash, email, secret))
        assertNull(RecoveryKit.composeQr(origin, card0Hash.uppercase(), email, secret))
        assertNull(RecoveryKit.composeQr(origin, card0Hash.dropLast(1), email, secret))
        assertNull(RecoveryKit.composeQr(origin, "none", email, secret))
        assertNull(RecoveryKit.composeQr(origin, card0Hash, "Alice@example.com", secret))
        assertNull(RecoveryKit.composeQr(origin, card0Hash, " $email", secret))
        assertNull(RecoveryKit.composeQr(origin, card0Hash, "alice.example.com", secret))
        assertNull(RecoveryKit.composeQr(origin, card0Hash, email, secret.copyOf(31)))
        assertNull(RecoveryKit.composeQr(origin, card0Hash, email, secret.copyOf(33)))
        // White space inside the hash would be stripped by the parser: the text would not carry the part it was given.
        assertNull(RecoveryKit.composeQr(origin, card0Hash.take(10) + " " + card0Hash.drop(10), email, secret))
        assertNull(RecoveryKit.composeQr(origin, "$card0Hash\n", email, secret))
        assertNull(RecoveryKit.composeQr(origin, "$card0Hash:", email, secret))

        // A parsed kit holds its own copy of the secret, hands out copies, and can be wiped.
        val kit = assertNotNull(RecoveryKit.parseQr(text))
        assertEquals(origin, kit.origin)
        assertEquals(card0Hash, kit.card0Hash)
        assertEquals(email, kit.emailNorm)
        kit.secret.fill(0)
        assertContentEquals(secret, kit.secret)
        kit.wipe()
        assertContentEquals(ByteArray(32), kit.secret)
    }
}
