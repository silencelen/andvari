package io.silencelen.andvari.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Consumes spec/test-vectors (path via -Dandvari.vectors.dir, wired in
 * core/build.gradle.kts). The TypeScript implementation runs the SAME checks off
 * the SAME files (web/src/crypto/vectors.test.ts) — keep the two in lockstep.
 */
class VectorsTest {
    private val crypto = createCryptoProvider()
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))

    private fun load(name: String): JsonObject =
        Json.parseToJsonElement(File(dir, name).readText()).jsonObject

    private fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content
    private fun JsonObject.b(key: String): ByteArray = Bytes.fromB64(s(key))
    private fun JsonObject.i(key: String): Int = getValue(key).jsonPrimitive.int
    private fun JsonObject.l(key: String): Long = getValue(key).jsonPrimitive.long
    private fun JsonObject.arr(key: String) = getValue(key).jsonArray.map { it.jsonObject }
    private fun JsonObject.params(key: String): KdfParams {
        val p = getValue(key).jsonObject
        return KdfParams(v = p.i("v"), alg = p.s("alg"), ops = p.l("ops"), memBytes = p.l("memBytes"))
    }

    @Test
    fun kdf() {
        val v = load("kdf.json")
        for (case in v.arr("argon2id")) {
            assertContentEquals(
                case.b("outB64"),
                crypto.argon2id(case.s("passwordUtf8").encodeToByteArray(), case.b("saltB64"), case.i("outLen"), case.l("ops"), case.l("memBytes")),
                "argon2id ${case.s("passwordUtf8")}",
            )
        }
        for (case in v.arr("hkdf")) {
            assertContentEquals(
                case.b("okmB64"),
                Hkdf.sha256(crypto, case.b("ikmB64"), ByteArray(0), case.s("infoUtf8").encodeToByteArray(), case.i("len")),
                "hkdf ${case.s("infoUtf8")}",
            )
        }
        for (case in v.arr("chain")) {
            val mk = Keys.masterKey(crypto, case.s("passwordUtf8"), case.b("saltB64"), case.params("kdfParams"))
            assertContentEquals(case.b("mkB64"), mk)
            assertContentEquals(case.b("authKeyB64"), Keys.authKey(crypto, mk))
            assertContentEquals(case.b("wrapKeyB64"), Keys.wrapKey(crypto, mk))
        }
    }

    @Test
    fun envelope() {
        val v = load("envelope.json")
        for (case in v.arr("seal")) {
            val ad = case.s("adUtf8").encodeToByteArray()
            val sealed = Envelope.sealWithNonce(crypto, case.b("keyB64"), case.b("nonceB64"), case.b("plaintextB64"), ad)
            assertContentEquals(case.b("envelopeB64"), sealed, "seal ${case.s("name")}")
            assertContentEquals(case.b("plaintextB64"), Envelope.open(crypto, case.b("keyB64"), case.b("envelopeB64"), ad))
        }
        for (case in v.arr("reject")) {
            assertFailsWith<CryptoException>("reject ${case.s("reason")}") {
                Envelope.open(crypto, case.b("keyB64"), case.b("envelopeB64"), case.s("adUtf8").encodeToByteArray())
            }
        }
    }

    @Test
    fun wrap() {
        val v = load("wrap.json")
        val userId = v.s("userId")
        val vaultId = v.s("personalVaultId")
        val itemId = v.s("itemId")

        val mk = Keys.masterKey(crypto, v.s("passwordUtf8"), v.b("kdfSaltB64"), v.params("kdfParams"))
        assertContentEquals(v.b("authKeyB64"), Keys.authKey(crypto, mk))
        val wrapKey = Keys.wrapKey(crypto, mk)

        assertContentEquals(
            v.b("wrappedUvkB64"),
            Envelope.sealWithNonce(crypto, wrapKey, v.b("uvkNonceB64"), v.b("uvkB64"), Ad.uvk(userId)),
        )
        val uvk = Envelope.open(crypto, wrapKey, v.b("wrappedUvkB64"), Ad.uvk(userId))
        assertContentEquals(v.b("uvkB64"), uvk)

        val identity = crypto.boxKeypairFromSeed(v.b("identitySeedB64"))
        assertContentEquals(v.b("identityPubB64"), identity.publicKey)
        assertContentEquals(v.b("identityPrivB64"), identity.privateKey)
        assertContentEquals(
            v.b("identitySeedB64"),
            Envelope.open(crypto, uvk, v.b("encryptedIdentitySeedB64"), Ad.idkey(userId)),
        )

        val vk = Envelope.open(crypto, uvk, v.b("wrappedVkB64"), Ad.vk(vaultId, userId))
        assertContentEquals(v.b("vkB64"), vk)
        assertEquals(
            v.s("vaultMetaPlaintextUtf8"),
            Envelope.open(crypto, vk, v.b("vaultMetaBlobB64"), Ad.vaultMeta(vaultId)).decodeToString(),
        )
        assertEquals(
            v.s("itemPlaintextUtf8"),
            Envelope.open(crypto, vk, v.b("itemEnvelopeB64"), Ad.item(vaultId, itemId, v.i("itemFormatVersion"))).decodeToString(),
        )
    }

    @Test
    fun seal() {
        val v = load("seal.json")
        val kp = crypto.boxKeypairFromSeed(v.b("recoverySeedB64"))
        assertContentEquals(v.b("recoveryPubB64"), kp.publicKey)
        assertContentEquals(v.b("recoveryPrivB64"), kp.privateKey)
        assertEquals(v.s("fingerprint"), Escrow.fingerprint(crypto, kp.publicKey))
        assertEquals(v.s("shortFingerprint"), Escrow.shortFingerprint(crypto, kp.publicKey))

        for (case in v.arr("open")) {
            assertContentEquals(case.b("plaintextB64"), crypto.sealOpen(kp.publicKey, kp.privateKey, case.b("sealedB64")))
        }
        val escrow = v.getValue("escrowUvk").jsonObject
        val payload = Escrow.open(crypto, kp.publicKey, kp.privateKey, escrow.b("sealedB64"))
        assertEquals(escrow.s("userId"), payload.userId)
        assertEquals(Escrow.KEY_TYPE_UVK, payload.keyType)
        assertContentEquals(escrow.b("uvkB64"), Bytes.fromB64(payload.key))

        val canary = v.getValue("canary").jsonObject
        val canaryPayload = Escrow.open(crypto, kp.publicKey, kp.privateKey, canary.b("sealedB64"))
        assertEquals(canary.s("expectedUserId"), canaryPayload.userId)
        assertContentEquals(canary.b("expectedKeyB64"), Bytes.fromB64(canaryPayload.key))

        val reject = v.getValue("rejectWrongKey").jsonObject
        val wrong = crypto.boxKeypairFromSeed(reject.b("wrongSeedB64"))
        assertFailsWith<CryptoException> { crypto.sealOpen(wrong.publicKey, wrong.privateKey, reject.b("sealedB64")) }
    }

    @Test
    fun secretstream() {
        val v = load("secretstream.json")
        val key = v.b("keyB64")
        for (stream in v.arr("streams")) {
            val plain = stream.getValue("chunksPlainB64").jsonArray.map { Bytes.fromB64(it.jsonPrimitive.content) }
            val cipher = stream.getValue("chunksCipherB64").jsonArray.map { Bytes.fromB64(it.jsonPrimitive.content) }
            val dec = crypto.secretstreamDecrypt(key, stream.b("headerB64"), cipher)
            assertEquals(plain.size, dec.size)
            for (i in plain.indices) assertContentEquals(plain[i], dec[i])
        }
        for (reject in v.arr("reject")) {
            val cipher = reject.getValue("chunksCipherB64").jsonArray.map { Bytes.fromB64(it.jsonPrimitive.content) }
            assertFailsWith<CryptoException>("reject ${reject.s("reason")}") {
                crypto.secretstreamDecrypt(key, reject.b("headerB64"), cipher)
            }
        }
    }

    @Test
    fun totp() {
        val v = load("totp.json")
        for (case in v.arr("cases")) {
            val config = TotpConfig(
                secret = Base32.decode(case.s("secretBase32")),
                algorithm = TotpAlgorithm.valueOf(case.s("algorithm")),
                digits = case.i("digits"),
                periodSeconds = case.i("period"),
            )
            assertEquals(case.s("expected"), Totp.code(crypto, config, case.l("timeSec")), "totp @${case.l("timeSec")}")
        }
        for (case in v.arr("uris")) {
            val parsed = Totp.parseUri(case.s("uri"))
            val expect = case.getValue("expect").jsonObject
            assertEquals(expect.s("secretBase32"), Base32.encode(parsed.secret))
            assertEquals(expect.s("algorithm"), parsed.algorithm.name)
            assertEquals(expect.i("digits"), parsed.digits)
            assertEquals(expect.i("period"), parsed.periodSeconds)
            assertEquals(expect.s("label"), parsed.label)
            assertEquals(expect.s("issuer"), parsed.issuer)
        }
    }

    @Test
    fun hibp() {
        val v = load("hibp.json")
        for (case in v.arr("cases")) {
            val hash = Hibp.sha1UpperHex(crypto, case.s("passwordUtf8"))
            assertEquals(case.s("sha1UpperHex"), hash)
            assertEquals(case.s("prefix"), Hibp.prefix(hash))
            assertEquals(case.s("suffix"), Hibp.suffix(hash))
            assertEquals(case.l("expectedCount"), Hibp.countInRange(case.s("rangeResponse"), hash))
        }
    }
}
