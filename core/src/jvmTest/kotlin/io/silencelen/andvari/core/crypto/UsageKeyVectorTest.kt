package io.silencelen.andvari.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Consumes spec/test-vectors/usagekey.json — the SAME file web/src/vault/usage.test.ts checks.
 *
 * The usage-ledger key derivation and its AD must be byte-identical across impls, and a
 * divergence would fail in a specific, misleading way: each client would seal and open its OWN
 * ledger perfectly while being unable to open the other's, so the symptom would read as "the
 * phone just never records anything" rather than as a crypto fault (spec 02 §8.2).
 *
 * The vector's expected value was computed by an INDEPENDENT third implementation, so this pins
 * "core is correct" rather than merely "core agrees with web" — which two mirrored-but-equally-
 * wrong impls would also satisfy.
 */
class UsageKeyVectorTest {
    private val crypto = createCryptoProvider()
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "usagekey.json").readText()).jsonObject

    @Test
    fun usageKeyDerivation() {
        val vk = Bytes.fromB64(v.getValue("vkB64").jsonPrimitive.content)
        assertEquals(
            v.getValue("usageKeyB64").jsonPrimitive.content,
            Bytes.toB64(UsageKey.usageKey(crypto, vk)),
        )
    }

    @Test
    fun usageAdMatchesTheVector() {
        assertEquals(
            v.getValue("adUtf8").jsonPrimitive.content,
            Ad.usage(v.getValue("adUserId").jsonPrimitive.content).decodeToString(),
        )
    }

    @Test
    fun usageAdRefusesASeparatorInTheUserId() {
        assertFailsWith<IllegalArgumentException> { Ad.usage("a|b") }
    }
}
