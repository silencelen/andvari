package io.silencelen.andvari.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Escrow v2 (security review 2026-10, root cause A §2; spec 04 §3–§4), graded off the SAME
 * `escrow-v2.json` the web engine consumes (web/src/crypto/escrow-v2.test.ts). Its blobs come from an
 * independent oracle, so a valid row pins "correct" and every REJECTION row must fail closed with its
 * exact verdict — the first failing step decides it.
 */
class EscrowV2VectorTest {
    private val crypto = createCryptoProvider()
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "escrow-v2.json").readText()).jsonObject
    private fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content
    private fun JsonObject.b(key: String): ByteArray = Bytes.fromB64(s(key))
    private fun JsonObject.sOrNull(key: String): String? = get(key)?.takeIf { it !is JsonNull }?.jsonPrimitive?.content

    private val org get() = crypto.boxKeypairFromSeed(v.getValue("org").jsonObject.b("seedB64"))
    private val member get() = v.getValue("member").jsonObject

    private fun open(c: JsonObject): EscrowOpened {
        val ic = c["identityCheck"]?.takeIf { it !is JsonNull }?.jsonObject
        return Escrow.open(
            crypto, org, c.b("sealedB64"), c.s("expectedUserId"), c.sOrNull("expectedIdentityFpPrefix"),
            ic?.let { IdentityCheck(it.s("encryptedIdentitySeedB64"), it.s("identityPubB64")) },
            c.sOrNull("unanchoredAck"),
        )
    }

    @Test
    fun fixedMaterial_matchesTheExistingVectors() {
        assertEquals(Escrow.UNANCHORED_ACK, v.s("unanchoredAck"))
        assertEquals(v.getValue("org").jsonObject.s("fingerprint"), Escrow.fingerprint(crypto, org.publicKey))
        val seed = member.b("identitySeedB64")
        assertContentEquals(member.b("identityPubB64"), crypto.boxKeypairFromSeed(seed).publicKey)
        assertContentEquals(member.b("signPubB64"), crypto.signKeypairFromSeed(seed).publicKey)
        assertEquals(member.s("identityFingerprint"), Escrow.fingerprint(crypto, member.b("identityPubB64")))
    }

    @Test
    fun v2Layout_sealUvkV2ProducesThePinnedFrame() {
        val v2 = v.getValue("v2").jsonObject
        val seed = member.b("identitySeedB64")
        val sealed = Escrow.sealUvkV2(
            crypto, org.publicKey, v.getValue("org").jsonObject.s("fingerprint"), member.s("userId"),
            member.b("identityPubB64"), crypto.signKeypairFromSeed(seed), member.b("uvkB64"), v2.s("issuedAt").toLong(),
        )
        // The seal is randomised (fresh ephemeral key) but its plaintext is the deterministic frame.
        assertEquals(v2.getValue("sealedLength").jsonPrimitive.content.toInt(), sealed.size, "v2 sealed length")
        assertContentEquals(v2.b("frameB64"), crypto.sealOpen(org.publicKey, org.privateKey, sealed), "frame bytes")
        assertContentEquals(v2.b("frameB64"), crypto.sealOpen(org.publicKey, org.privateKey, v2.b("sealedB64")), "oracle blob")
        val frame = v2.b("frameB64")
        assertContentEquals(v2.s("statementUtf8").encodeToByteArray(), frame.copyOfRange(SignedStatement.STATEMENT_OFFSET, frame.size))
    }

    @Test
    fun sealRefusesAFingerprintThatIsNotAFullMatch() {
        val seed = member.b("identitySeedB64")
        for (c in v.getValue("sealRefuse").jsonArray.map { it.jsonObject }) {
            assertFailsWith<CryptoException>(c.s("name")) {
                Escrow.sealUvkV2(
                    crypto, org.publicKey, c.s("verifiedRecoveryFp"), member.s("userId"), member.b("identityPubB64"),
                    crypto.signKeypairFromSeed(seed), member.b("uvkB64"), 1_791_590_400_000L,
                )
            }
        }
    }

    @Test
    fun sealRefusesASignerThatDoesNotMapToTheNamedIdentity() {
        val other = crypto.signKeypairFromSeed(crypto.randomBytes(32))
        assertFailsWith<CryptoException> {
            Escrow.sealUvkV2(
                crypto, org.publicKey, Escrow.fingerprint(crypto, org.publicKey), member.s("userId"), member.b("identityPubB64"),
                other, member.b("uvkB64"), 1_791_590_400_000L,
            )
        }
    }

    @Test
    fun open_everyRowYieldsItsExactResultOrVerdict() {
        val rows = v.getValue("open").jsonArray.map { it.jsonObject }
        assertTrue(rows.count { it.containsKey("verdict") } >= 30, "the rejection corpus is the point of this vector")
        for (c in rows) {
            val name = c.s("name")
            if (c.containsKey("verdict")) {
                val e = assertFailsWith<EscrowOpenException>(name) { open(c) }
                assertEquals(c.s("verdict"), e.verdict.code, name)
            } else {
                val want = c.getValue("expect").jsonObject
                val got = open(c)
                assertEquals(want.s("format"), got.format.code, name)
                assertEquals(want.s("userId"), got.userId, name)
                assertContentEquals(want.b("uvkB64"), got.uvk, name)
                assertContentEquals(want.b("identityKeyB64"), got.identityKey, name)
                assertEquals(want.getValue("anchored").jsonPrimitive.boolean, got.anchored, name)
            }
        }
    }

    @Test
    fun opened_isReadOnly() {
        val ok = v.getValue("open").jsonArray.map { it.jsonObject }.first { !it.containsKey("verdict") }
        val got = open(ok)
        got.uvk.fill(0)
        got.identityKey.fill(0)
        assertContentEquals(ok.getValue("expect").jsonObject.b("uvkB64"), got.uvk, "uvk hands out a copy")
        assertContentEquals(ok.getValue("expect").jsonObject.b("identityKeyB64"), got.identityKey, "identityKey hands out a copy")
        got.wipe()
        assertContentEquals(ByteArray(32), got.uvk, "wipe zeroes the held uvk")
    }
}
