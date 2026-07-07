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
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Consumes spec/test-vectors/lifecycleproof.json — the SAME file web/src/crypto checks.
 * The lifecycleKey derivation and every op's HMAC domain string must be byte-identical
 * across impls, or a member's client would reject a genuine owner action (spec 03 §11).
 */
class LifecycleProofVectorTest {
    private val crypto = createCryptoProvider()
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "lifecycleproof.json").readText()).jsonObject

    @Test
    fun lifecycleKeyDerivation() {
        val vk = Bytes.fromB64(v.getValue("vk").jsonPrimitive.content)
        assertEquals(v.getValue("lifecycleKey").jsonPrimitive.content, Bytes.toB64(LifecycleProof.lifecycleKey(crypto, vk)))
    }

    @Test
    fun everyProofMatches() {
        val key = LifecycleProof.lifecycleKey(crypto, Bytes.fromB64(v.getValue("vk").jsonPrimitive.content))
        for (case in v.getValue("cases").jsonArray.map { it.jsonObject }) {
            fun s(k: String) = case.getValue(k).jsonPrimitive.content
            val expected = s("proof")
            val actual = when (val op = s("op")) {
                "delete" -> LifecycleProof.delete(crypto, key, s("vaultId"), s("deleteId"))
                "restore" -> LifecycleProof.restore(crypto, key, s("vaultId"), s("deleteId"))
                "offer" -> LifecycleProof.offer(crypto, key, s("vaultId"), s("offerId"), s("toUserId"), case.getValue("expiresAt").jsonPrimitive.long, case.getValue("seq").jsonPrimitive.long)
                "accept" -> LifecycleProof.accept(crypto, key, s("vaultId"), s("offerId"), s("newOwnerUserId"), case.getValue("seq").jsonPrimitive.long, s("wrappedVk"))
                "remove" -> LifecycleProof.remove(crypto, key, s("vaultId"), s("targetUserId"), s("nonce"))
                else -> error("unknown op $op")
            }
            assertEquals(expected, actual, "proof for op=${s("op")}")
            assertTrue(LifecycleProof.verify(expected, actual), "verify accepts a matching proof (${s("op")})")
        }
    }

    @Test
    fun verifyRejectsTamperAndGarbage() {
        val a = v.getValue("cases").jsonArray.first().jsonObject.getValue("proof").jsonPrimitive.content
        assertFalse(LifecycleProof.verify(a, a.dropLast(1) + if (a.last() == 'A') 'B' else 'A'), "flipped last char rejected")
        assertFalse(LifecycleProof.verify(a, ""), "empty presented rejected")
        assertFalse(LifecycleProof.verify(a, "!!not base64!!"), "garbage rejected, no throw")
    }
}
