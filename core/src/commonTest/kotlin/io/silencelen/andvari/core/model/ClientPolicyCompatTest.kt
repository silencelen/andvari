package io.silencelen.andvari.core.model

import io.silencelen.andvari.core.client.ClientPolicyClamps
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Wire-contract compatibility for the multi-tenant / endpoint-agnostic pivot (design
 * 2026-07-15-multi-tenant-endpoints §2.1/§2.2/§2.6). Every pivot field is additive + defaulted
 * (the AdminStatus.emailConfigured precedent), so an OLD server's JSON — which omits them — must
 * decode to exactly today's behavior: `signupMode="invite-only"` (§2.1 "Old server (field absent)"
 * row), `totpRequired=false`, decorative fields null, `mustEnrollTotp=false`. The old-CLIENT
 * direction (new server → old client) rides `ignoreUnknownKeys`, fleet-proven by the same precedent.
 */
class ClientPolicyCompatTest {
    // The client-side decode config (core AndvariApi.kt / server Repo.kt use the same shape).
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private val pivotPolicyKeys = setOf("signupMode", "totpRequired", "instanceName", "canonicalOrigin", "selfHostDocsUrl")

    /** Encode with today's serializer, then strip [keys] — an exact simulation of the OLD wire
     *  (encodeDefaults=true means an old server emitted every field it knew, and only those). */
    private fun withoutKeys(element: JsonObject, keys: Set<String>): JsonObject =
        JsonObject(element.filterKeys { it !in keys })

    @Test
    fun oldServerPolicyJson_decodesToPivotDefaults() {
        val newWire = json.encodeToJsonElement(ClientPolicy.serializer(), ClientPolicy()).jsonObject
        // Sanity: a NEW server (encodeDefaults=true) does emit the pivot fields...
        assertTrue(pivotPolicyKeys.all { it in newWire }, "new wire must carry the pivot fields")
        // ...and the OLD wire is that object minus them.
        val decoded = json.decodeFromJsonElement(ClientPolicy.serializer(), withoutKeys(newWire, pivotPolicyKeys))
        assertEquals("invite-only", decoded.signupMode, "§2.1: absent signupMode ⇒ invite-only (today's universal truth)")
        assertFalse(decoded.totpRequired, "§2.6: absent totpRequired ⇒ false (server re-prompts authoritatively)")
        assertNull(decoded.instanceName)
        assertNull(decoded.canonicalOrigin)
        assertNull(decoded.selfHostDocsUrl)
        // The pre-pivot fields still decode to their pre-pivot values.
        assertEquals(300, decoded.autoLockSeconds)
        assertTrue(decoded.offlineCacheAllowed, "§2.1: offlineCacheAllowed IS the durable-cache field, unchanged")
    }

    @Test
    fun emptyPolicyJson_decodesFullyDefaulted() {
        // Subsumes every absent-field combination any older server could send.
        val decoded = json.decodeFromString(ClientPolicy.serializer(), "{}")
        assertEquals("invite-only", decoded.signupMode)
        assertFalse(decoded.totpRequired)
        assertNull(decoded.instanceName)
        assertNull(decoded.canonicalOrigin)
        assertNull(decoded.selfHostDocsUrl)
    }

    @Test
    fun pivotPolicyFields_roundTrip() {
        val p = ClientPolicy(
            signupMode = "landing",
            totpRequired = true,
            instanceName = "andvari (reference instance)",
            canonicalOrigin = "https://andvari.monahanhosting.com",
            selfHostDocsUrl = "https://andvari.monahanhosting.com/selfhost",
        )
        val decoded = json.decodeFromString(ClientPolicy.serializer(), json.encodeToString(ClientPolicy.serializer(), p))
        assertEquals(p, decoded, "pivot fields must survive an encode/decode round trip losslessly")
    }

    @Test
    fun oldServerSessionJson_mustEnrollTotpDefaultsFalse() {
        val session = SessionResponse(
            userId = "u1", deviceId = "d1", accessToken = "at", refreshToken = "rt",
            accountKeys = AccountKeys(
                kdfSalt = "s", kdfParams = KdfParams(), wrappedUvk = "w",
                encryptedIdentitySeed = "e", identityPub = "i", escrowFingerprint = "f",
            ),
            isAdmin = false,
        )
        val newWire = json.encodeToJsonElement(SessionResponse.serializer(), session).jsonObject
        assertTrue("mustEnrollTotp" in newWire, "new wire must carry mustEnrollTotp")
        val decoded = json.decodeFromJsonElement(SessionResponse.serializer(), withoutKeys(newWire, setOf("mustEnrollTotp")))
        assertFalse(decoded.mustEnrollTotp, "§2.6: an old server omitting the field means an unrestricted session — default false")
    }

    @Test
    fun clampCeilings_pinnedPerDesign() {
        // §2.3 (B1-1) ceilings — byte-pinned against the web/ext mirrors by web/src/policy-clamps.test.ts;
        // asserted here too so the gradle gate alone catches a drift (design §11.5: 900/300).
        assertEquals(900, ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS)
        assertEquals(300, ClientPolicyClamps.CLIPBOARD_CLEAR_MAX_SECONDS)
        // The ceilings must admit the shipped wire defaults, or a default policy would be "clamped".
        assertTrue(ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS >= ClientPolicy().autoLockSeconds)
        assertTrue(ClientPolicyClamps.CLIPBOARD_CLEAR_MAX_SECONDS >= ClientPolicy().clipboardClearSeconds)
    }
}
