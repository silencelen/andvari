package io.silencelen.andvari.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Consumes spec/test-vectors/member-recovery.json (design 2026-07-12 §F.6) — the SAME file the
 * TypeScript suite checks. Deterministic inputs (fixed recoverySecret 00..1f + fixed userId) pin the
 * two HKDF outputs and — with a FIXED nonce, exactly as wrap.json/envelope.json do — the exact
 * `recoveryWrappedUvk` ciphertext. Keep the two implementations in lockstep off this file.
 */
class MemberRecoveryVectorTest {
    private val crypto = createCryptoProvider()
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "member-recovery.json").readText()).jsonObject

    private fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content
    private fun JsonObject.b(key: String): ByteArray = Bytes.fromB64(s(key))

    @Test
    fun derivations() {
        val secret = v.b("recoverySecretB64")
        // The two severed HKDF outputs pin byte-for-byte.
        assertContentEquals(v.b("recoveryWrapKeyB64"), MemberRecovery.wrapKey(crypto, secret), "recoveryWrapKey")
        assertContentEquals(v.b("recoveryAuthKeyB64"), MemberRecovery.authKey(crypto, secret), "recoveryAuthKey")
        // deriveAuthKey emits the same value as base64url (the wire form the server verifies).
        assertEquals(v.s("recoveryAuthKeyB64"), MemberRecovery.deriveAuthKey(crypto, secret), "deriveAuthKey b64")
        // The AD string is pinned so a twin can't drift the domain separation.
        assertEquals(v.s("adUtf8"), Ad.recovery(v.s("userId")).decodeToString(), "Ad.recovery")
    }

    @Test
    fun wrappedUvkExactCiphertextAndRoundTrip() {
        val secret = v.b("recoverySecretB64")
        val userId = v.s("userId")
        val wrapKey = MemberRecovery.wrapKey(crypto, secret)
        // Exact ciphertext under the pinned nonce (fixed-nonce vector, same posture as wrap.json).
        assertContentEquals(
            v.b("recoveryWrappedUvkB64"),
            Envelope.sealWithNonce(crypto, wrapKey, v.b("nonceB64"), v.b("uvkB64"), Ad.recovery(userId)),
            "recoveryWrappedUvk",
        )
        // openUvk recovers the SAME UVK (covers the random-nonce production path too).
        assertContentEquals(
            v.b("uvkB64"),
            MemberRecovery.openUvk(crypto, secret, v.s("recoveryWrappedUvkB64"), userId),
            "openUvk round-trip",
        )
    }

    @Test
    fun wrongSecretFailsClosed() {
        val userId = v.s("userId")
        val wrong = ByteArray(32) { (it + 1).toByte() } // 01 02 … 20, not the pinned secret
        assertFailsWith<CryptoException>("wrong recovery secret must fail the AEAD tag") {
            MemberRecovery.openUvk(crypto, wrong, v.s("recoveryWrappedUvkB64"), userId)
        }
    }
}
