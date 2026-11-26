package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.SignedStatement
import io.silencelen.andvari.core.crypto.SignedStatementException
import io.silencelen.andvari.core.crypto.StatementVerdict
import io.silencelen.andvari.core.crypto.isFlatStatement
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Design 2026-11-15 §2.2 "no nesting": "a statement is one flat object, so a `[` anywhere, or a second
 * `{`, is `non_canonical`, and an implementation refuses it before handing the text to any general JSON
 * parser". These rows pin the VERDICT on every template; that the refusal comes before the platform
 * parser (so that a thousand brackets cannot overflow a stack) is `StatementNestingStackTest`'s, on the
 * JVM, where a thread's stack size can be chosen.
 */
class StatementFlatRuleTest {
    private val valid = vector("statement-v2.json").rows("valid")

    private fun verdict(purpose: TrustPurpose, text: String): String =
        StatementCodec.parse(purpose, text.encodeToByteArray()).verdictOrNull()?.code ?: "ok"

    @Test
    fun isFlatStatement_allowsOneBraceAndNoBracket() {
        fun flat(text: String) = isFlatStatement(text.encodeToByteArray())
        assertTrue(flat(""))
        assertTrue(flat("{}"))
        assertTrue(flat("""{"v":2,"purpose":"vault-log"}"""))
        assertTrue(flat("no braces at all"), "what is not an object is refused by the parser, not here")
        assertFalse(flat("["))
        assertFalse(flat("{{"))
        assertFalse(flat("""{"v":[2]}"""))
        assertFalse(flat("""{"v":{"v":2}}"""))
        assertFalse(flat("""{"name":"a[b"}"""), "inside a string too: no value type admits it")
        assertFalse(flat("""{"name":"a{b"}"""))
        assertFalse(flat("{}{"))
        assertTrue(flat("{]}}"), "closers are not counted: such a text is not JSON and the parser refuses it at once")
    }

    /** One valid statement per row of `statement-v2.json`'s `valid`, and a vault grant, which that section does not carry. */
    private fun validStatements(): List<Pair<TrustPurpose, String>> {
        val grant = StatementCodec.encode(
            TrustPurpose.VAULT_GRANT,
            mapOf(
                "from" to Ids.ALICE, "to" to Ids.BOB, "toKey" to "A".repeat(43), "vaultId" to Ids.VAULT, "grantId" to Ids.id16(1),
                "issuedAt" to Ids.T0.toString(),
            ),
            secrets = mapOf("vk" to ByteArray(32)),
        ).decodeToString()
        return valid.map { TrustPurpose.fromCode(it.l("purposeCode").toInt())!! to it.s("statementUtf8") } + (TrustPurpose.VAULT_GRANT to grant)
    }

    @Test
    fun everyTemplate_refusesABracketAnywhereAndASecondBrace() {
        val statements = validStatements()
        var graded = 0
        for ((purpose, text) in statements) {
            assertEquals("ok", verdict(purpose, text), text)
            val firstValue = text.indexOf(':') + 1 // `{"v":`, then the 2
            val variants = listOf(
                text.replace("\"purpose\":\"", "\"purpose\":\"["), // inside a string value
                text.replace("\"purpose\":\"", "\"purpose\":\"{"),
                text.substring(0, firstValue) + "[2]" + text.substring(firstValue + 1), // an array where a number belongs
                text.substring(0, firstValue) + "{\"v\":2}" + text.substring(firstValue + 1), // an object where a number belongs
                "[$text]",
                "{\"v\":$text}",
            )
            for (nested in variants) {
                assertEquals("non_canonical", verdict(purpose, nested), nested)
                graded++
            }
        }
        assertEquals(statements.size * 6, graded)
        // Every purpose this package has a template for: all but 0x02, which crypto.Escrow verifies.
        assertEquals(TrustPurpose.entries.toSet() - TrustPurpose.ESCROW_UVK, statements.map { it.first }.toSet())
    }

    @Test
    fun theDeepestStatements_areNonCanonical() {
        val brackets = "[".repeat(SignedFrame.MAX_STATEMENT_BYTES)
        val objects = "{\"a\":".repeat(204) + "1" // 1,021 bytes: as deep as objects go in a statement
        assertTrue(objects.length <= SignedFrame.MAX_STATEMENT_BYTES)
        for (purpose in TrustPurpose.entries) {
            // 0x02 has no template in this package: crypto.Escrow verifies those, and the frame is refused first.
            val expected = if (purpose == TrustPurpose.ESCROW_UVK) "bad_frame" else "non_canonical"
            assertEquals(expected, verdict(purpose, brackets), purpose.literal)
            assertEquals(expected, verdict(purpose, objects), purpose.literal)
        }
    }

    @Test
    fun theSpec01Codec_refusesNestingToo() {
        fun refusal(purposeCode: Int, text: String): StatementVerdict =
            assertFailsWith<SignedStatementException> { SignedStatement.parseStatement(purposeCode, text.encodeToByteArray()) }.verdict
        for (code in listOf(0x01, 0x02)) {
            assertEquals(StatementVerdict.NON_CANONICAL, refusal(code, "[".repeat(SignedStatement.MAX_STATEMENT_BYTES)))
            assertEquals(StatementVerdict.NON_CANONICAL, refusal(code, "{\"a\":".repeat(204) + "1"))
            assertEquals(StatementVerdict.NON_CANONICAL, refusal(code, """{"v":2,"purpose":"vault-grant","from":["x"]}"""))
            assertEquals(StatementVerdict.NON_CANONICAL, refusal(code, """{"v":2,"purpose":{"x":1}}"""))
        }
    }
}
