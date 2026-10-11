package io.silencelen.andvari.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
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

    /** Branch A7 (root cause A §6.1): both v2 domains, byte-exact, and a valid MAC for each. */
    @Test
    fun v2DomainsMatch() {
        val key = LifecycleProof.lifecycleKey(crypto, Bytes.fromB64(v.getValue("vk").jsonPrimitive.content))
        val cases = v.getValue("v2Cases").jsonArray.map { it.jsonObject }
        assertEquals(setOf("remove-v2", "leave"), cases.map { it.getValue("op").jsonPrimitive.content }.toSet())
        for (case in cases) {
            fun s(k: String) = case.getValue(k).jsonPrimitive.content
            val at = case.getValue("issuedAt").jsonPrimitive.long
            val actual = when (val op = s("op")) {
                "remove-v2" -> LifecycleProof.removeV2(crypto, key, s("vaultId"), s("targetUserId"), s("nonce"), at)
                "leave" -> LifecycleProof.leave(crypto, key, s("vaultId"), s("userId"), s("nonce"), at)
                else -> error("unknown op $op")
            }
            assertEquals(s("proof"), actual, "v2 proof for op=${s("op")}")
            assertEquals(s("proof"), Bytes.toB64(crypto.hmacSha256(key, s("domain").encodeToByteArray())), "the domain string is pinned (${s("op")})")
            assertTrue(LifecycleProof.isV2Nonce(s("nonce")))
        }
    }

    /**
     * Branch A7 (root cause A §6.3, §8.6): the verdict table, graded against [RemovalProof.decide], the SAME function
     * SyncEngine calls on every removed/left row (A6's lesson: never grade a helper production does not call).
     */
    @Test
    fun verdictTable() {
        val key = LifecycleProof.lifecycleKey(crypto, Bytes.fromB64(v.getValue("vk").jsonPrimitive.content))
        val t = v.getValue("verdicts").jsonObject
        val vaultId = t.getValue("vaultId").jsonPrimitive.content
        val me = t.getValue("myUserId").jsonPrimitive.content
        assertEquals(RemovalProof.SKEW_MS, t.getValue("skewMs").jsonPrimitive.long)
        val cases = t.getValue("cases").jsonArray.map { it.jsonObject }
        assertTrue(cases.size >= 20)
        for (c in cases) {
            fun str(k: String) = c[k]?.takeIf { it != JsonNull }?.jsonPrimitive?.content
            fun lng(k: String) = c[k]?.takeIf { it != JsonNull }?.jsonPrimitive?.longOrNull
            val name = str("name")
            val d = RemovalProof.decide(
                crypto, key, vaultId, me,
                reason = str("reason")!!,
                proofV = c["proofV"]?.takeIf { it != JsonNull }?.jsonPrimitive?.intOrNull,
                proof = str("proof"), nonce = str("nonce"), issuedAt = lng("issuedAt"),
                consumed = c.getValue("consumed").jsonArray.map { it.jsonPrimitive.content }.toSet(),
                consumedAccount = c.getValue("consumedAccount").jsonArray.map { it.jsonPrimitive.content }.toSet(),
                liveSince = lng("liveSince"), now = lng("now")!!,
            )
            assertEquals(str("expect"), d.verdict.code, "verdict: $name")
            assertEquals(str("step"), d.step, "deciding step: $name")
            val consume = c["consume"]?.jsonArray
            if (consume == null) {
                assertEquals(null, d.consumeNonce, "nothing consumed: $name")
            } else {
                assertEquals(consume[0].jsonPrimitive.content, d.consumeNonce, "consumed nonce: $name")
                assertEquals(consume[1].jsonPrimitive.long, d.consumeIssuedAt, "consumed issuedAt: $name")
            }
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
