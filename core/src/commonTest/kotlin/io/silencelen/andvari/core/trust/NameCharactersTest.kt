package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * ONE list of the characters a name may not hold (spec 01 section 5.1, spec 03 section 0.1):
 * the shared code's test of one character ([TrustGrammar.isRefusedNameCodePoint]) is the list the `name` type refuses,
 * and the server's `text` type (display and device names, [TrustGrammar.isText]) refuses exactly the same, with spaces
 * allowed and up to 256 characters.
 */
class NameCharactersTest {
    private val v = vector("encodings.json")

    /** The server's list (`Grammar.isRefusedInText`), spelled out here on its own. */
    private fun onTheServersList(cp: Int): Boolean =
        cp in 0x0000..0x001F || cp in 0x007F..0x009F || cp == 0x00AD || cp == 0x061C || cp == 0x180E ||
            cp in 0x200B..0x200F || cp in 0x2028..0x202E || cp in 0x2060..0x2064 || cp in 0x2066..0x206F ||
            cp == 0xFEFF || cp in 0xFFF9..0xFFFB

    /** [cp] as UTF-16 text. */
    private fun text(cp: Int): String =
        if (cp < 0x10000) cp.toChar().toString()
        else charArrayOf((0xD800 + ((cp - 0x10000) shr 10)).toChar(), (0xDC00 + ((cp - 0x10000) and 0x3FF)).toChar()).concatToString()

    @Test fun theOneCharacterTestIsTheServersListOverEveryCodePoint() {
        var refused = 0
        for (cp in 0..0x10FFFF) {
            if (cp in 0xD800..0xDFFF) continue
            val r = TrustGrammar.isRefusedNameCodePoint(cp)
            assertEquals(onTheServersList(cp), r, "U+${cp.toString(16)}")
            // What the shared code refuses in a name, and in text, is that test and nothing else.
            val inside = "a" + text(cp) + "b"
            assertEquals(!r, TrustGrammar.encodeName(inside) != null, "name U+${cp.toString(16)}")
            assertEquals(!r, TrustGrammar.isText(inside), "text U+${cp.toString(16)}")
            if (r) refused++
        }
        // 32 + 33 + 1 + 1 + 1 + 5 + 7 + 5 + 10 + 1 + 3
        assertEquals(99, refused)
    }

    @Test fun everyNameRowOfTheVectorsIsTextExactlyWhenItsCharactersAre() {
        var graded = 0
        // A plain loop, not gradeEvery: the conformance sweep counts this section once, in EncodingsVectorTest.
        for (r in v.rows("name")) {
            val bytes = r.sOrNull("textHex")?.let(Bytes::fromHexLower)
            // Rows about the base64url form, the UTF-8 or the 64-byte bound say nothing about the characters.
            if (bytes == null || bytes.isEmpty() || bytes.size > 64 || Bytes.toB64(bytes) != r.s("name")) continue
            if (TrustGrammar.decodeUtf8Strict(bytes) == null) continue
            val t = bytes.decodeToString()
            // Every name is text.
            if (r.bool("valid")) assertTrue(TrustGrammar.isText(t), r.s("why"))
            // Text allows a leading or trailing space where a name does not; otherwise the verdicts agree.
            val core = t.trim(' ')
            val expect = core.isEmpty() || TrustGrammar.encodeName(core) != null
            assertEquals(expect, TrustGrammar.isText(t), r.s("why"))
            graded++
        }
        assertTrue(graded >= 60, "graded $graded rows")
    }

    @Test fun textIsOneTo256CharactersWellFormedWithSpacesAllowed() {
        assertFalse(TrustGrammar.isText(""))
        assertTrue(TrustGrammar.isText(" "))
        assertTrue(TrustGrammar.isText(" Alice's phone "))
        assertTrue(TrustGrammar.isText("a".repeat(TrustGrammar.TEXT_MAX_CHARS)))
        assertFalse(TrustGrammar.isText("a".repeat(TrustGrammar.TEXT_MAX_CHARS + 1)))
        // Counted in UTF-16 characters, as the server counts: a four-byte character is two.
        val emoji = text(0x1F600)
        assertTrue(TrustGrammar.isText(emoji.repeat(128)))
        assertFalse(TrustGrammar.isText(emoji.repeat(128) + "a"))
        // A name longer than 64 bytes is still text.
        assertTrue(TrustGrammar.isText(text(0xE9).repeat(100)))
        // Lone surrogates, at either end and inside, and a pair in the wrong order.
        val hi = 0xD800.toChar().toString()
        val lo = 0xDC00.toChar().toString()
        for (bad in listOf(hi, "a$hi", "${hi}a", lo, "a${lo}b", lo + hi)) assertFalse(TrustGrammar.isText(bad), bad)
        // The emoji built with a zero-width joiner, as the server now refuses it in these names.
        assertFalse(TrustGrammar.isText(text(0x1F468) + text(0x200D) + text(0x1F469)))
        // No normalisation: a precomposed and a combining e-acute are both text.
        assertTrue(TrustGrammar.isText(text(0xE9)) && TrustGrammar.isText("e" + text(0x301)))
    }
}
