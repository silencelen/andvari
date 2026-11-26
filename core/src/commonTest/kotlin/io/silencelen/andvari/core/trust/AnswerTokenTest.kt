package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/** The shared reader of an answer (spec 04 §7 step 3) on the points the specification settled on 2026-11-16: wrapping, `answer_bare`'s length, a file's bytes. */
class AnswerTokenTest {
    private val requestId = Bytes.toB64(ByteArray(16) { 0x44 })
    private val key = Bytes.toB64(ByteArray(32) { 3 })
    private val email = "alice@example.org"
    private val token = AnswerToken.format(requestId, key, "ab".repeat(32), ByteArray(AnswerToken.sealedBytes(email)) { 9 })

    private fun read(text: String) = AnswerToken.read(text, requestId, key, email)
    private fun refusal(text: String) = assertIs<AnswerRead.Refused>(read(text), text.take(40)).refusal

    @Test fun aTokenWrappedAtAnyWidthIsRead_andAnythingElseAfterItRefusesIt() {
        for (width in listOf(40, 80, 120, 148, 149, 150)) {
            assertEquals(token, assertIs<AnswerRead.Ok>(read(token.chunked(width).joinToString("\n")), "$width").token)
        }
        assertEquals(AnswerRefusal.NOT_AN_ANSWER, refusal("$token\nuser@host:~$"))
        // Lines before the token are passed over, whatever they hold.
        assertIs<AnswerRead.Ok>(read("Request code matches.\n  ANSWER for request …: {ok}\n\n$token\n"))
    }

    @Test fun onlyAHundredBase64urlCharactersOrMoreAreABareAnswer() {
        assertEquals(AnswerRefusal.NOT_AN_ANSWER, refusal("yes"))
        assertEquals(AnswerRefusal.NOT_AN_ANSWER, refusal(requestId))
        assertEquals(AnswerRefusal.NOT_AN_ANSWER, refusal("ab".repeat(32)))
        assertEquals(AnswerRefusal.NOT_AN_ANSWER, refusal("A".repeat(99)))
        assertEquals(AnswerRefusal.BARE, refusal("A".repeat(100)))
        assertEquals(AnswerRefusal.BARE, refusal("A".repeat(60) + "\n" + "B".repeat(40)))
        assertEquals(AnswerRefusal.BARE, refusal(token.substringAfterLast(':')))
    }

    @Test fun aFileIsReadAsUtf8_andBytesThatAreNotUtf8AreNoAnswer() {
        assertIs<AnswerRead.Ok>(AnswerToken.readFile(("\uFEFF" + token + "\r\n").encodeToByteArray(), requestId, key, email))
        val broken = "caf".encodeToByteArray() + byteArrayOf(0xC3.toByte()) + "\n$token\n".encodeToByteArray()
        assertEquals(AnswerRefusal.NOT_AN_ANSWER, assertIs<AnswerRead.Refused>(AnswerToken.readFile(broken, requestId, key, email)).refusal)
    }
}
