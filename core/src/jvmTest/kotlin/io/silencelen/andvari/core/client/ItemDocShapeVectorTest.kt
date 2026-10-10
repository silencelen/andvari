package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Security review 2026-10 (root cause D): a document that opens under a vault key was still
 * WRITTEN by whoever holds that key — any writer of a shared vault — so its JSON is untrusted.
 * Consumes spec/test-vectors/itemdoc-validate.json, the SAME file web (vitest) and the extension
 * (node --test) grade against, so the three engines quarantine exactly the same documents.
 *
 * Why core needs an explicit check at all when its decode is typed: kotlinx's tree decoder is
 * lenient where web and the extension are not — a quoted `"1"` decodes into a Long and `"true"`
 * into a Boolean — and the typed decode cannot express the value rules (a path-safe attachment
 * id, a non-negative size). Without [ItemDocShape] the fleet would disagree on the same item.
 */
class ItemDocShapeVectorTest {
    private val crypto = createCryptoProvider()
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "itemdoc-validate.json").readText()).jsonObject

    @Test
    fun items() {
        for (case in v.getValue("items").jsonArray.map { it.jsonObject }) {
            val name = case.getValue("name").jsonPrimitive.content
            val doc = Json.parseToJsonElement(case.getValue("docJson").jsonPrimitive.content)
            val problem = ItemDocShape.problem(doc)
            assertEquals(case.getValue("valid").jsonPrimitive.boolean, problem == null, "$name: $problem")
        }
    }

    @Test
    fun vaultNames() {
        for (case in v.getValue("vaultNames").jsonArray.map { it.jsonObject }) {
            val expected = case.getValue("expected").let { if (it is JsonNull) null else it.jsonPrimitive.content }
            val meta = Json.parseToJsonElement(case.getValue("metaJson").jsonPrimitive.content)
            assertEquals(expected, ItemDocShape.vaultName(meta), case.getValue("name").jsonPrimitive.content)
        }
    }

    /** The decrypt boundary itself: every failing vector document, sealed under a real vault key,
     *  is refused by [Account.decryptItem] — which every SyncEngine path already treats as
     *  "undecryptable, envelope retained" — and every passing one opens. */
    @Test
    fun decryptItem_refusesEveryInvalidVector_andOpensEveryValidOne() {
        val member = enrolledAccount()
        val vaultId = "55555555-5555-4555-8555-555555555555"
        val vk = crypto.randomBytes(32)
        member.addGrant(WireGrant(vaultId, member.userId, "writer", wrappedVk = "", rev = 1, sealedVk = Bytes.toB64(SharedGrant.seal(crypto, member.identityPub, vaultId, vk))))
        for (case in v.getValue("items").jsonArray.map { it.jsonObject }) {
            val name = case.getValue("name").jsonPrimitive.content
            val itemId = member.newItemId()
            val blob = Envelope.sealB64(crypto, vk, case.getValue("docJson").jsonPrimitive.content.encodeToByteArray(), Ad.item(vaultId, itemId, 1))
            val w = WireItem(itemId, vaultId, 1, 0, 0, false, false, 1, emptyList(), blob)
            if (case.getValue("valid").jsonPrimitive.boolean) {
                member.decryptItem(w)
            } else {
                assertFailsWith<MalformedItemException>(name) { member.decryptItem(w) }
            }
        }
    }

    @Test
    fun decryptVaultName_displaysOnlyAJsonString() {
        val member = enrolledAccount()
        val vaultId = "66666666-6666-4666-8666-666666666666"
        val vk = crypto.randomBytes(32)
        member.addGrant(WireGrant(vaultId, member.userId, "writer", wrappedVk = "", rev = 1, sealedVk = Bytes.toB64(SharedGrant.seal(crypto, member.identityPub, vaultId, vk))))
        fun meta(json: String) = Envelope.sealB64(crypto, vk, json.encodeToByteArray(), Ad.vaultMeta(vaultId))
        assertEquals("Family", member.decryptVaultName(vaultId, meta("""{"name":"Family"}""")))
        // A number used to render as "1" here while web rendered "(vault)" — one rule now.
        assertEquals(null, member.decryptVaultName(vaultId, meta("""{"name":1}""")))
        assertEquals(null, member.decryptVaultName(vaultId, meta("""{"name":true}""")))
    }

    private fun enrolledAccount(): Account {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val (_, account) = Account.enroll(
            inviteToken = "shape-test",
            email = "shape@x.com",
            displayName = "Shape",
            password = "shape test password",
            params = KdfParams(ops = 1, memBytes = 8 * 1024 * 1024),
            recoveryPublicKey = recovery.publicKey,
            recoveryFingerprint = Escrow.fingerprint(crypto, recovery.publicKey),
            deviceName = "shape-device",
            crypto = crypto,
        )
        return account
    }
}
