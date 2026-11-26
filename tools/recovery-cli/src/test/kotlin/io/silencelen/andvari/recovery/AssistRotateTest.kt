package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.trust.AnswerRead
import io.silencelen.andvari.core.trust.AnswerToken
import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.RecoveryVerdict
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** `assist` and `rotate` (spec 04 §5, §7): what the device and the server accept is what the CLI produces. */
class AssistRotateTest {
    private val crypto = createCryptoProvider()
    private val seed = crypto.randomBytes(32)
    private val org = crypto.boxKeypairFromSeed(seed)
    private val orgFp = Escrow.fingerprint(crypto, org.publicKey)
    private val instanceId = "12345678-1234-4234-8234-123456789abc"
    private val requestId = Bytes.toB64(crypto.randomBytes(16))
    private val request = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val code = AssistedRecovery.requestCode(crypto, request.publicKey)

    private fun args(userId: String, typedCode: String = code, key: ByteArray = request.publicKey, vararg extra: String, email: String? = "m@example.com") = listOf(
        "--instance", instanceId, "--request", requestId, "--request-key", Bytes.toB64(key), "--request-code", typedCode,
        "--user", userId, "--no-identity-anchor", "--identity-file", "f.json", *extra,
    ) + (email?.let { listOf("--email", it) } ?: emptyList())

    @Test
    fun assist_answerIsVersion3_opensOnTheRequestingDevice_andTheTokenCarriesTheCommitHash() {
        val m = Member(crypto, org.publicKey, "m@example.com")
        // The typed code tolerates spaces, dashes and upper case; the typed address is normalised.
        val opts = AssistCommand.parse(crypto, args(m.userId, AssistedRecovery.groupedRequestCode(code).uppercase().replace(' ', '-'), email = " M@Example.com"))
        assertEquals("m@example.com", opts.email)
        val lines = listOf(Escrow.UNANCHORED_ACK, "RECOVER ${m.userId.take(8)}").iterator()
        val out = StringBuilder()
        val opened = RecoverCommand.openAndConfirm(crypto, org, opts.recover, opts.email, m.check, m.sealed, "the signed answer", { if (lines.hasNext()) lines.next() else null }) { out.appendLine(it) }
        assertTrue(out.contains("Type 'RECOVER ${m.userId.take(8)}' to generate the signed answer"))
        val answer = AssistCommand.answer(crypto, seed, opts, opened.email!!, opened.uvk, 1_800_000_000_000)
        assertEquals(AnswerToken.sealedBytes("m@example.com"), answer.sealed.size, "the one size: 525 + E")
        assertEquals(525 + 18, answer.sealed.size)
        // The device's spec 04 §7 step 4 checks, version 3, with the pinned card's recoveryFp and the address it asked with.
        val got = AssistedRecovery.openV3(crypto, request.publicKey, request.privateKey, answer.sealed, orgFp, instanceId, requestId, "m@example.com", m.check, null).valueOrNull()
        assertContentEquals(m.uvk, got!!.uvk)
        assertEquals(m.userId, got.userId)
        // The commit value inside the answer is what the printed hash is of.
        assertEquals(answer.commitHash, AssistedRecovery.commitHashOf(crypto, got.commitB64!!))
        // The statement inside: version 3, with the copy's address and the commit value.
        val statement = crypto.sealOpen(request.publicKey, request.privateKey, answer.sealed).drop(101).toByteArray().decodeToString()
        assertTrue(statement.startsWith("""{"v":3,"purpose":"assisted-recovery","instanceId":"$instanceId","userId":"${m.userId}","email":"${Bytes.toB64("m@example.com".encodeToByteArray())}","requestId":"$requestId","requestKey":"${Bytes.toB64(request.publicKey)}","commit":"${got.commitB64}","uvk":"""), statement)
        assertTrue(statement.endsWith(""","issuedAt":1800000000000}"""), statement)
        // The device asked with another address: the same answer is refused.
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, AssistedRecovery.openV3(crypto, request.publicKey, request.privateKey, answer.sealed, orgFp, instanceId, requestId, "n@example.com", m.check, null).verdictOrNull())
        // Sealed to another key, it does not open.
        val other = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        assertEquals(RecoveryVerdict.UNOPENABLE, AssistedRecovery.openV3(crypto, other.publicKey, other.privateKey, answer.sealed, orgFp, instanceId, requestId, "m@example.com", m.check, null).verdictOrNull())

        // The printed output: the token is the last line, nothing after it, and the shared reader takes the whole output.
        val printed = answerOutput(opts, answer)
        val last = printed.trimEnd('\n').lines().last()
        assertEquals("andvari-answer:3:$requestId:${Bytes.toB64(request.publicKey)}:${answer.commitHash}:${Bytes.toB64(answer.sealed)}", last)
        assertTrue(printed.endsWith(last + "\n"))
        val read = assertIs<AnswerRead.Ok>(AnswerToken.read(printed, requestId, Bytes.toB64(request.publicKey), "m@example.com"))
        assertEquals(answer.commitHash, read.commitHash)
        assertEquals(Bytes.toB64(answer.sealed), read.sealed)
        assertFalse(got.commitB64!! in printed, "the commit value is never printed")
    }

    @Test
    fun assist_refusesAClockWithoutThirteenDigits() {
        val m = Member(crypto, org.publicKey, "m@example.com")
        val opts = AssistCommand.parse(crypto, args(m.userId))
        for (t in listOf(999_999_999_999L, 10_000_000_000_000L)) {
            assertTrue(assertFailsWith<RecoverRefused> { AssistCommand.answer(crypto, seed, opts, "m@example.com", crypto.randomBytes(32), t) }.message!!.contains("clock"))
        }
    }

    @Test
    fun assist_needsTheTypedAddress_beforeTheCodeAndTheSeed() {
        val user = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        val wrong = (if (code[0] == '0') "1" else "0") + code.substring(1)
        assertTrue(assertFailsWith<RecoverRefused> { AssistCommand.parse(crypto, args(user, email = null)) }.message!!.contains("assist needs --email"))
        // Not an address: bad_email, decided before the request code is even compared.
        val bad = assertFailsWith<RecoverRefused> { AssistCommand.parse(crypto, args(user, wrong, email = "not an address")) }.message!!
        assertTrue(bad.contains("bad_email"), bad)
    }

    @Test
    fun assist_refusesAWrongCode_beforeAskingForTheSeed_andBadArguments() {
        val user = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        val wrong = (if (code[0] == '0') "1" else "0") + code.substring(1)
        assertTrue(assertFailsWith<RecoverRefused> { AssistCommand.parse(crypto, args(user, wrong)) }.message!!.contains("does not match"))
        // A server that swapped the key: the person's code is for their own key.
        val swapped = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
        assertFailsWith<RecoverRefused> { AssistCommand.parse(crypto, args(user, code, swapped)) }
        assertFailsWith<RecoverRefused> { AssistCommand.parse(crypto, args(user).map { if (it == instanceId) "not-a-uuid" else it }) }
        assertFailsWith<RecoverRefused> { AssistCommand.parse(crypto, args(user).map { if (it == requestId) "short" else it }) }
        assertFailsWith<RecoverRefused> { AssistCommand.parse(crypto, args(user, code, request.publicKey, "--legacy")) }
        assertFailsWith<RecoverRefused> { AssistCommand.parse(crypto, args(user).filter { it != "--no-identity-anchor" }) }
    }

    /** A low-order request key is refused at parse, before the seed is asked for, even with its matching code. */
    @Test
    fun assist_refusesALowOrderRequestKey_beforeTheEscrowIsOpened() {
        val user = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        for (hex in listOf("00".repeat(32), "01" + "00".repeat(31), "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", "ec" + "ff".repeat(30) + "7f")) {
            val key = Bytes.fromHexLower(hex)!!
            val matching = AssistedRecovery.requestCode(crypto, key)
            val e = assertFailsWith<RecoverRefused>(hex) { AssistCommand.parse(crypto, args(user, matching, key)) }
            assertTrue(e.message!!.contains("low-order"), e.message)
        }
    }

    @Test
    fun rotate_producesAStatementTheVerifiersAccept() {
        val next = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
        val opts = RotateCommand.parse(listOf("--instance", instanceId, "--to", Bytes.toB64(next)))
        val (frame, fields) = RotateCommand.statement(crypto, seed, opts, 1_800_000_000_000)
        assertEquals(orgFp, fields.fromFp)
        assertEquals(Escrow.fingerprint(crypto, next), fields.toFp)
        val v = RecoveryRotation.verify(crypto, frame, instanceId, orgFp).valueOrNull()
        assertEquals(fields.toFp, v!!.fields.toFp)
        assertEquals(null, RecoveryRotation.verifyChain(crypto, listOf(frame), instanceId, orgFp, fields.toFp))
        // Another instance's verifier refuses it.
        assertEquals(null, RecoveryRotation.verify(crypto, frame, "22345678-1234-4234-8234-123456789abc", orgFp).valueOrNull())
        assertFailsWith<RecoverRefused> { RotateCommand.statement(crypto, seed, RotateCommand.Options(instanceId, org.publicKey), 1) }
        assertFailsWith<RecoverRefused> { RotateCommand.parse(listOf("--instance", instanceId)) }
        assertFailsWith<RecoverRefused> { RotateCommand.parse(listOf("--instance", instanceId, "--to", "AAAA")) }
    }
}
