package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.SignedStatement
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.readVector
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The version-3 answer (spec 04 §7 steps 3 and 4, spec 01 §5.1 and §5.5 as corrected on 2026-11-16), graded off `recovery-v3.json`,
 * which the independent oracle wrote from the specification text alone: the answer's form ([AssistedRecovery.sign]),
 * its commit hash, its size and token ([AnswerToken]), the person's device ([AssistedRecovery.openV3]) against `open`,
 * and the commit hash of a presented value ([AssistedRecovery.commitHashOf], which the server's check calls) against
 * `commitCheck`'s string rows. The server's own route answers `commitCheck`'s other rows and `fulfil`, with a stored
 * request; this layer cannot reach them. A row the code answers otherwise is listed in [KNOWN] and graded in an
 * `@Ignore`d test.
 */
class RecoveryV3VectorTest {
    private val crypto = createCryptoProvider()
    private val v: JsonObject = Json.parseToJsonElement(readVector("recovery-v3.json")).jsonObject
    private fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content
    private fun JsonObject.sOrNull(key: String): String? = get(key)?.takeIf { it !is JsonNull }?.jsonPrimitive?.content
    private fun JsonObject.b(key: String): ByteArray = Bytes.fromB64(s(key))
    private fun JsonObject.o(key: String): JsonObject = getValue(key).jsonObject
    private fun JsonObject.rows(key: String) = getValue(key).jsonArray.map { it.jsonObject }

    private val keys = v.o("keys")
    private val recoverySeed = keys.o("recoveryA").b("seedB64")
    private val rPub = v.o("requestKey").b("rPubB64")
    private val rSec = v.o("requestKey").b("rSecB64")

    @Test
    fun answers_signGivesThePinnedFrame_theCommitHash_theSize_andTheToken() {
        for (row in v.rows("answers")) {
            val i = row.o("input")
            val e = row.o("expect")
            val name = row.s("name")
            val email = TrustGrammar.emailNorm(i.s("address"))!!
            assertEquals(i.s("emailB64"), TrustGrammar.encodeEmail(email), name)
            val frame = AssistedRecovery.sign(crypto, crypto.signKeypairFromSeed(recoverySeed),
                AssistedRecoveryFields(i.s("instanceId"), i.s("userId"), i.s("requestId"), i.s("requestKey"), i.b("uvkB64"), i.s("issuedAt").toLong(), email = email, commit = i.b("commitB64")))
            assertContentEquals(e.b("frameB64"), frame, "$name: frame")
            assertEquals(e.s("statementUtf8"), frame.copyOfRange(SignedStatement.STATEMENT_OFFSET, frame.size).decodeToString(), name)
            assertEquals(e.s("commitHash"), AssistedRecovery.commitHash(crypto, i.b("commitB64")), "$name: commit hash")
            assertEquals(e.s("commitHash"), AssistedRecovery.commitHashOf(crypto, i.s("commitB64")), "$name: commit hash of the text")
            assertEquals(e.s("sealedBytes").toInt(), AnswerToken.sealedBytes(email), "$name: the one size")
            assertEquals(e.s("token"), AnswerToken.format(i.s("requestId"), i.s("requestKey"), e.s("commitHash"), e.b("sealedB64")), "$name: token")
            assertContentEquals(frame, crypto.sealOpen(rPub, rSec, e.b("sealedB64")), "$name: the oracle's seal opens to the frame")
            assertEquals(e.s("sealedBytes").toInt(), AssistedRecovery.seal(crypto, rPub, frame).size, "$name: this seal's size")
        }
    }

    @Test
    fun sizes_525PlusE() {
        for (row in v.rows("sizes")) {
            val address = row.sOrNull("checkedWith") ?: continue
            assertEquals(row.s("sealed").toInt(), AnswerToken.sealedBytes(address), address)
        }
    }

    @Test
    fun commitHash_rows() {
        for (row in v.rows("commitHash")) assertEquals(row.s("commitHash"), AssistedRecovery.commitHashOf(crypto, row.s("commitB64")))
    }

    @Test
    fun commitCheck_theStringRows_throughTheCommitHashOfThePresentedText() {
        for (row in v.rows("commitCheck")) {
            val value = row["commit"]?.takeIf { it is kotlinx.serialization.json.JsonPrimitive && it.isString }?.jsonPrimitive?.content ?: continue
            val h = AssistedRecovery.commitHashOf(crypto, value)
            val got = when {
                h == null -> "bad_commit"
                h != row.s("storedCommitHash") -> "commit_mismatch"
                else -> "ok"
            }
            assertEquals(row.o("expect").s("verdict"), got, row.s("name"))
        }
    }

    @Test
    fun workedExample_sealUvkV3AndSignGiveTheExamplesFrames() {
        val w = v.rows("workedExample").single()
        val i = w.o("input")
        val e = w.o("expect")
        val idSeed = Bytes.fromHexLower(i.s("identitySeedHex"))!!
        val recSeed = Bytes.fromHexLower(i.s("recoverySeedHex"))!!
        val uvk = Bytes.fromHexLower(i.s("uvkHex"))!!
        val recovery = crypto.boxKeypairFromSeed(recSeed)
        val request = crypto.boxKeypairFromSeed(Bytes.fromHexLower(i.s("requestSeedHex"))!!)
        assertEquals(e.s("rPubB64"), Bytes.toB64(request.publicKey))
        val sealed = Escrow.sealUvkV3(crypto, recovery.publicKey, e.s("recoveryFp"), i.s("userId"), i.s("address"), crypto.boxKeypairFromSeed(idSeed).publicKey,
            crypto.signKeypairFromSeed(idSeed), uvk, i.s("issuedAt").toLong())
        assertEquals(e.s("escrowFrameHex"), Bytes.toHexLower(crypto.sealOpen(recovery.publicKey, recovery.privateKey, sealed)))
        assertEquals(e.s("escrowSealedBytes").toInt(), sealed.size)
        val frame = AssistedRecovery.sign(crypto, crypto.signKeypairFromSeed(recSeed), AssistedRecoveryFields(i.s("instanceId"), i.s("userId"), i.s("requestId"),
            Bytes.toB64(request.publicKey), uvk, i.s("issuedAt").toLong(), email = i.s("address"), commit = Bytes.fromHexLower(i.s("commitHex"))!!))
        assertEquals(e.s("answerFrameHex"), Bytes.toHexLower(frame))
        assertEquals(e.s("commitHash"), AssistedRecovery.commitHash(crypto, Bytes.fromHexLower(i.s("commitHex"))!!))
    }

    private fun device(row: JsonObject): JsonObject {
        val r = row.o("request")
        val got = AssistedRecovery.openV3(
            crypto, rPub, rSec, row.b("sealedB64"), row.s("cardRecoveryFp"), r.s("instanceId"), r.s("requestId"), r.s("typedEmail"),
            IdentityCheck(row.s("encryptedIdentitySeedB64"), row.s("identityPubB64")), r.sOrNull("userId"),
        )
        return when (got) {
            is Checked.Ok -> JsonObject(mapOf(
                "verdict" to kotlinx.serialization.json.JsonPrimitive("ok"),
                "uvkB64" to kotlinx.serialization.json.JsonPrimitive(Bytes.toB64(got.value.uvk)),
                "commitB64" to kotlinx.serialization.json.JsonPrimitive(got.value.commitB64),
            )).also { got.value.wipe() }
            is Checked.Refused -> JsonObject(mapOf("verdict" to kotlinx.serialization.json.JsonPrimitive(got.verdict.code)))
        }
    }

    private fun differences(only: Set<String>? = null): List<String> = v.rows("open").mapNotNull { row ->
        val name = row.s("name")
        if (only != null && name !in only) return@mapNotNull null
        if (only == null && name in KNOWN) return@mapNotNull null
        val got = device(row)
        if (got != row.o("expect")) "open/$name: the oracle expects ${row.o("expect")}, the code answers $got" else null
    }

    @Test
    fun open_theDevice_everyRow() {
        val d = differences()
        assertTrue(d.isEmpty(), d.joinToString("\n"))
    }

    private companion object {
        /** Row → finding, for a row the code answers otherwise (graded then in an `@Ignore`d test naming it). None in the specification as corrected on 2026-11-16. */
        val KNOWN: Map<String, String> = mapOf()
    }
}
