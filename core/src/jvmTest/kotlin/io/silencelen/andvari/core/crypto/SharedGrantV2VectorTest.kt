package io.silencelen.andvari.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Signed vault grants, format v2 (security review 2026-10, root cause A §1.4–§1.5, branch A6), graded off the
 * SAME `sharedgrant-v2.json` the web engine consumes. Every blob comes from an independent oracle; every row is
 * a §1.4 decision with the verdict the FIRST failing step must produce. The rows that matter most:
 *  - `signer-other-pinned-member`: the pin is chosen by `contacts[from]`, so a grant that NAMES the owner but is
 *    signed by another member this account also pinned is refused (`signer_not_pinned_key`);
 *  - `pending-*`: an unpinned sender, or a pin that is not current on this device (A5 review L-3), is a pending
 *    invitation, never an adoption, whatever else is wrong with the blob.
 * Also pins `sharedgrant.json`'s `legacyMode` rows (§8.2 / §8.6), the v1 legacy decision.
 */
class SharedGrantV2VectorTest {
    private val crypto = createCryptoProvider()
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "sharedgrant-v2.json").readText()).jsonObject
    private val v1: JsonObject = Json.parseToJsonElement(File(dir, "sharedgrant.json").readText()).jsonObject
    private fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content
    private fun JsonObject.b(key: String): ByteArray = Bytes.fromB64(s(key))

    @Test
    fun partiesMatchTheirSeeds() {
        for (who in listOf("owner", "member", "third")) {
            val p = v.getValue(who).jsonObject
            assertContentEquals(p.b("identityPubB64"), crypto.boxKeypairFromSeed(p.b("seedB64")).publicKey, who)
            assertContentEquals(p.b("signPubB64"), crypto.signKeypairFromSeed(p.b("seedB64")).publicKey, who)
        }
    }

    @Test
    fun everyDecisionRowHasItsVerdict() {
        val member = v.getValue("member").jsonObject
        val me = crypto.boxKeypairFromSeed(member.b("seedB64"))
        val anomalies = v.getValue("anomalyVerdicts").jsonArray.map { it.jsonPrimitive.content }.toSet()
        val cases = v.getValue("cases").jsonArray
        assertTrue(cases.size >= 20)
        for (c in cases.map { it.jsonObject }) {
            val name = c.s("name")
            val pins = c.getValue("pins").jsonObject.mapValues { Bytes.fromB64(it.value.jsonPrimitive.content) }
            val current = c.getValue("pinsCurrent").jsonPrimitive.boolean
            val held = c["heldVkB64"].takeIf { it != null && it != JsonNull }?.let { Bytes.fromB64(it.jsonPrimitive.content) }
            val outcome = SignedGrant.open(
                crypto,
                myUserId = member.s("userId"),
                myIdentityPub = me.publicKey,
                myIdentityPriv = me.privateKey,
                rowVaultId = c.s("rowVaultId"),
                sealed = c.b("sealedB64"),
                pinFor = { uid -> pins[uid]?.let { GrantPin(it, current) } },
                heldVk = held,
            )
            val expect = c.getValue("expect").jsonObject
            val verdict = expect.s("verdict")
            assertEquals(verdict, outcome.verdict.code, "$name: ${c.s("why")}")
            assertEquals(verdict in anomalies, outcome.verdict.anomaly, "$name anomaly flag")
            when (verdict) {
                "adopt" -> {
                    val a = assertIs<GrantOutcome.Adopted>(outcome, name)
                    assertContentEquals(expect.b("vkB64"), a.vk, name)
                    assertEquals(expect.s("from"), a.from, name)
                    assertEquals(expect.s("grantIdB64"), a.grantIdB64, name)
                    assertEquals(expect.getValue("issuedAt").jsonPrimitive.long, a.issuedAt, name)
                }
                "pending_invitation" -> assertEquals(expect.s("from"), assertIs<GrantOutcome.Pending>(outcome, name).from, name)
                else -> assertIs<GrantOutcome.Refused>(outcome, name)
            }
        }
    }

    /** Sender side: the owner's frame for the vector statement is byte-identical (deterministic Ed25519),
     *  and it opens as an adoption for the member with the owner pinned. */
    @Test
    fun theSenderBuildsTheVectorFrame() {
        val owner = v.getValue("owner").jsonObject
        val member = v.getValue("member").jsonObject
        val signer = crypto.signKeypairFromSeed(owner.b("seedB64"))
        val frame = SignedGrant.buildFrame(
            crypto, signer,
            Statement.VaultGrant(
                from = owner.s("userId"), to = member.s("userId"), toKey = member.b("identityPubB64"), vaultId = v.s("vaultId"),
                grantId = Bytes.fromB64("AAECAwQFBgcICQoLDA0ODw"), issuedAt = 1791590400000, vk = v.b("vkB64"),
            ),
        )
        assertEquals(v.s("frameB64"), Bytes.toB64(frame))
    }

    @Test
    fun legacyModeRows() {
        for (r in v1.getValue("legacyMode").jsonObject.getValue("rows").jsonArray.map { it.jsonObject }) {
            val mode = LegacyGrant.decide(
                inWindow = r.s("window") == "in_window",
                preUpgradeEvidence = r.getValue("evidence").jsonPrimitive.boolean,
                confirmed = r.getValue("confirmed").jsonPrimitive.boolean,
            )
            assertEquals(r.s("expect"), mode.code, r.toString())
        }
    }
}
