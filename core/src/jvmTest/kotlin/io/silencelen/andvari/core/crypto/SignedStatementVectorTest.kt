package io.silencelen.andvari.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * SignedStatement v2 + the joint Ed25519 signing key (security review 2026-10, root cause A §1.1–§1.3),
 * graded off the SAME `signedstatement.json` the web engine consumes (web/src/crypto/signedstatement.test.ts).
 * The vector's bytes come from an independent oracle, so these pin "correct", not "the engines agree".
 * The rejection rows are the point: every one must fail closed with its exact verdict.
 */
class SignedStatementVectorTest {
    private val crypto = createCryptoProvider()
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "signedstatement.json").readText()).jsonObject
    private val sg: JsonObject = Json.parseToJsonElement(File(dir, "sharedgrant.json").readText()).jsonObject
    private fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content
    private fun JsonObject.b(key: String): ByteArray = Bytes.fromB64(s(key))
    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private val jk get() = v.getValue("jointKey").jsonObject
    private val pinned get() = v.b("pinnedIdentityPubB64")

    @Test
    fun jointKey_signPubMapsToTheExistingIdentityPub() {
        val seed = jk.b("seedB64")
        // The signer is the EXISTING sharedgrant.json member: the mapping holds for today's accounts.
        assertEquals(sg.s("memberSeedB64"), jk.s("seedB64"))
        assertEquals(sg.s("memberIdentityPubB64"), jk.s("identityPubB64"))

        val box = crypto.boxKeypairFromSeed(seed)
        val sign = crypto.signKeypairFromSeed(seed)
        assertContentEquals(jk.b("identityPubB64"), box.publicKey)
        assertContentEquals(jk.b("signPubB64"), sign.publicKey)
        assertContentEquals(jk.b("signSecretB64"), sign.privateKey)
        assertContentEquals(jk.b("curveOfSignPubB64"), crypto.ed25519PkToCurve25519(sign.publicKey))
        assertContentEquals(box.publicKey, crypto.ed25519PkToCurve25519(sign.publicKey))
        // −A has the same Montgomery u — the mapping alone cannot tell them apart; the signature does.
        assertContentEquals(box.publicKey, crypto.ed25519PkToCurve25519(jk.b("negatedSignPubB64")))

        val other = jk.getValue("other").jsonObject
        assertContentEquals(other.b("signPubB64"), crypto.signKeypairFromSeed(other.b("seedB64")).publicKey)
        assertContentEquals(other.b("identityPubB64"), crypto.ed25519PkToCurve25519(other.b("signPubB64")))
    }

    @Test
    fun jointKey_mappingHoldsForRandomSeeds() {
        repeat(32) {
            val seed = crypto.randomBytes(32)
            assertContentEquals(
                crypto.boxKeypairFromSeed(seed).publicKey,
                crypto.ed25519PkToCurve25519(crypto.signKeypairFromSeed(seed).publicKey),
            )
        }
    }

    @Test
    fun primitives_failClosedOnBadInput() {
        assertFailsWith<CryptoException> { crypto.ed25519PkToCurve25519(ByteArray(31)) }
        assertFailsWith<CryptoException> { crypto.ed25519PkToCurve25519(ByteArray(33)) }
        assertFailsWith<CryptoException> { crypto.ed25519PkToCurve25519(ByteArray(32)) } // small order
        assertFailsWith<IllegalArgumentException> { crypto.signKeypairFromSeed(ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { crypto.signDetached(ByteArray(63), byteArrayOf(1)) }
        val kp = crypto.signKeypairFromSeed(crypto.randomBytes(32))
        val msg = "m".encodeToByteArray()
        val sig = crypto.signDetached(kp.privateKey, msg)
        assertEquals(64, sig.size)
        assertTrue(crypto.signVerifyDetached(kp.publicKey, sig, msg))
        assertFalse(crypto.signVerifyDetached(kp.publicKey, sig, msg + 0))
    }

    private fun statementOf(fields: JsonObject, purposeCode: Int): Statement = when (purposeCode) {
        1 -> Statement.VaultGrant(
            from = fields.s("from"), to = fields.s("to"), toKey = fields.b("toKey"), vaultId = fields.s("vaultId"),
            grantId = fields.b("grantId"), issuedAt = fields.s("issuedAt").toLong(), vk = fields.b("vk"),
        )
        2 -> Statement.EscrowUvk(
            userId = fields.s("userId"), identityKey = fields.b("identityKey"), recoveryFp = fields.s("recoveryFp"),
            issuedAt = fields.s("issuedAt").toLong(), key = fields.b("key"),
        )
        else -> error("purpose $purposeCode")
    }

    private fun assertSameStatement(expected: Statement, actual: Statement) {
        assertEquals(expected.purpose, actual.purpose)
        assertContentEquals(SignedStatement.encode(expected), SignedStatement.encode(actual))
        when (expected) {
            is Statement.VaultGrant -> {
                val a = assertIs<Statement.VaultGrant>(actual)
                assertEquals(expected.from, a.from); assertEquals(expected.to, a.to); assertEquals(expected.vaultId, a.vaultId)
                assertContentEquals(expected.toKey, a.toKey); assertContentEquals(expected.grantId, a.grantId)
                assertEquals(expected.issuedAt, a.issuedAt); assertContentEquals(expected.vk, a.vk)
            }
            is Statement.EscrowUvk -> {
                val a = assertIs<Statement.EscrowUvk>(actual)
                assertEquals(expected.userId, a.userId); assertEquals(expected.recoveryFp, a.recoveryFp)
                assertContentEquals(expected.identityKey, a.identityKey); assertEquals(expected.issuedAt, a.issuedAt)
                assertContentEquals(expected.key, a.key)
            }
        }
    }

    /**
     * Escrow statements verify only through the ANCHORED wrapper (A4 / A3 review); the anchor used for
     * the vector rows is the valid escrow case's own account and org key, which is what an honest
     * recovery would supply out of band.
     */
    private fun verifyAny(frame: ByteArray, code: Int, pin: ByteArray): VerifiedStatement {
        if (code == StatementPurpose.ESCROW_UVK.code) {
            val f = v.getValue("valid").jsonArray[1].jsonObject.getValue("fields").jsonObject
            return SignedStatement.verifyEscrow(crypto, frame, f.s("userId"), pin, f.s("recoveryFp"))
        }
        return SignedStatement.verify(crypto, frame, StatementPurpose.fromCode(code)!!, pin)
    }

    @Test
    fun valid_encodeSignBuildAndVerifyAreByteExact() {
        val seed = jk.b("seedB64")
        val signer = crypto.signKeypairFromSeed(seed)
        for (c in v.getValue("valid").jsonArray.map { it.jsonObject }) {
            val code = c.getValue("purposeCode").jsonPrimitive.int
            val st = statementOf(c.getValue("fields").jsonObject, code)
            val statementBytes = c.s("statementUtf8").encodeToByteArray()
            assertContentEquals(statementBytes, SignedStatement.encode(st), "${c.s("name")}: canonical bytes")
            val m = SignedStatement.signedMessage(code, signer.publicKey, statementBytes)
            assertContentEquals(hex(c.s("messageHex")), m, "${c.s("name")}: signed message M")
            assertContentEquals(c.b("signatureB64"), crypto.signDetached(signer.privateKey, m), "${c.s("name")}: deterministic Ed25519")
            assertContentEquals(c.b("frameB64"), SignedStatement.build(crypto, signer, st), "${c.s("name")}: frame bytes")

            assertSameStatement(st, SignedStatement.parseStatement(code, statementBytes).parsed)
            val verified = verifyAny(c.b("frameB64"), code, pinned)
            assertSameStatement(st, verified.statement)
            assertContentEquals(signer.publicKey, verified.signerPub)
        }
    }

    @Test
    fun formatDetection() {
        for (c in v.getValue("formatDetect").jsonArray.map { it.jsonObject }) {
            val expected = when (c.s("format")) {
                "v1" -> BlobFormat.V1_JSON
                "v2" -> BlobFormat.V2_SIGNED
                else -> BlobFormat.UNKNOWN
            }
            assertEquals(expected, SignedStatement.formatOf(hex(c.s("firstBytesHex"))), c.s("firstBytesHex"))
        }
    }

    @Test
    fun rejectStatement_everyStrictnessRuleFailsClosed() {
        val rows = v.getValue("rejectStatement").jsonArray.map { it.jsonObject }
        assertTrue(rows.size >= 40, "the rejection corpus is the point of this vector")
        for (c in rows) {
            val e = assertFailsWith<SignedStatementException>(c.s("why")) {
                SignedStatement.parseStatement(c.getValue("purposeCode").jsonPrimitive.int, c.b("statementB64"))
            }
            assertEquals(c.s("verdict"), e.verdict.code, c.s("why"))
        }
    }

    @Test
    fun reject_theBindingHelperFailsClosedWithTheExactVerdict() {
        val rows = v.getValue("reject").jsonArray.map { it.jsonObject }
        for (c in rows) {
            val pin = if (c.containsKey("pinnedIdentityPubB64")) c.b("pinnedIdentityPubB64") else pinned
            val e = assertFailsWith<SignedStatementException>(c.s("why")) {
                verifyAny(c.b("frameB64"), c.getValue("expectedPurposeCode").jsonPrimitive.int, pin)
            }
            assertEquals(c.s("verdict"), e.verdict.code, c.s("why"))
        }
    }

    @Test
    fun encode_refusesValuesOutsideTheClosedGrammar() {
        val good = statementOf(v.getValue("valid").jsonArray[0].jsonObject.getValue("fields").jsonObject, 1) as Statement.VaultGrant
        fun g(
            from: String = good.from, to: String = good.to, toKey: ByteArray = good.toKey, vaultId: String = good.vaultId,
            grantId: ByteArray = good.grantId, issuedAt: Long = good.issuedAt, vk: ByteArray = good.vk,
        ) = Statement.VaultGrant(from, to, toKey, vaultId, grantId, issuedAt, vk)
        assertFailsWith<CryptoException> { SignedStatement.encode(g(vaultId = good.vaultId.uppercase())) }
        assertFailsWith<CryptoException> { SignedStatement.encode(g(from = "x\",\"role\":\"owner")) }
        assertFailsWith<CryptoException> { SignedStatement.encode(g(vk = ByteArray(31))) }
        assertFailsWith<CryptoException> { SignedStatement.encode(g(toKey = ByteArray(33))) }
        assertFailsWith<CryptoException> { SignedStatement.encode(g(grantId = ByteArray(32))) }
        assertFailsWith<CryptoException> { SignedStatement.encode(g(issuedAt = 0)) }
        assertFailsWith<CryptoException> { SignedStatement.encode(g(issuedAt = 1L shl 53)) }
        assertFailsWith<CryptoException> { SignedStatement.encode(g(to = good.from)) }
        val esc = statementOf(v.getValue("valid").jsonArray[1].jsonObject.getValue("fields").jsonObject, 2) as Statement.EscrowUvk
        assertFailsWith<CryptoException> {
            SignedStatement.encode(Statement.EscrowUvk(esc.userId, esc.identityKey, esc.recoveryFp.uppercase(), esc.issuedAt, esc.key))
        }
    }

    @Test
    fun roundTrip_freshKeysVerifyOnlyUnderTheirOwnPin() {
        val seed = crypto.randomBytes(32)
        val signer = crypto.signKeypairFromSeed(seed)
        val pin = crypto.boxKeypairFromSeed(seed).publicKey
        val st = statementOf(v.getValue("valid").jsonArray[0].jsonObject.getValue("fields").jsonObject, 1)
        val frame = SignedStatement.build(crypto, signer, st)
        assertSameStatement(st, SignedStatement.verify(crypto, frame, StatementPurpose.VAULT_GRANT, pin).statement)
        val e = assertFailsWith<SignedStatementException> {
            SignedStatement.verify(crypto, frame, StatementPurpose.VAULT_GRANT, pinned)
        }
        assertEquals(StatementVerdict.SIGNER_NOT_PINNED_KEY, e.verdict)
    }
}
