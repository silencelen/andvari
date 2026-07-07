package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.WireItem
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Consumes spec/test-vectors/itemdoc.json — the SAME file the web twin
 * (web/src/vault/itemdoc.test.ts) checks — so both impls preserve unknown item-doc
 * fields identically (spec 02 §3). Assertions are PER-PATH, never whole-object: this
 * impl re-encodes with encodeDefaults=true + explicit nulls, web omits absent keys,
 * and both shapes are spec-legal.
 */
class ItemDocVectorsTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "itemdoc.json").readText()).jsonObject

    /** Mirrors Account's private json config (the real encode/decode path for item docs). */
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private fun JsonObject.s(k: String) = getValue(k).jsonPrimitive.content

    /** The scripted edit through the REAL Kotlin edit shape: data-class copy(). */
    private fun applyEdit(doc: ItemDoc, edit: JsonObject): ItemDoc {
        val op = edit.keys.single()
        val value = edit.getValue(op)
        return when (op) {
            "none" -> doc
            "setName" -> doc.copy(name = value.jsonPrimitive.content)
            "setFavorite" -> doc.copy(favorite = value.jsonPrimitive.boolean)
            "setPassword" -> doc.copy(login = (doc.login ?: LoginData()).copy(password = value.jsonPrimitive.content))
            else -> error("unknown edit op: $op")
        }
    }

    /** JSON-pointer-ish walk; null = path absent (distinct from a present JsonNull). */
    private fun resolve(root: JsonElement, pointer: String): JsonElement? {
        var cur: JsonElement = root
        for (seg in pointer.removePrefix("/").split('/')) {
            cur = when (cur) {
                is JsonObject -> cur[seg] ?: return null
                is JsonArray -> cur.getOrNull(seg.toInt()) ?: return null
                else -> return null
            }
        }
        return cur
    }

    private fun assertPaths(label: String, kind: String, reencoded: JsonElement, expectations: JsonArray) {
        for (e in expectations.map { it.jsonObject }) {
            val path = e.s("path")
            val expected = Json.parseToJsonElement(e.s("valueJson"))
            val actual = resolve(reencoded, path)
            assertNotNull(actual, "$label: $kind path $path missing after round-trip")
            assertEquals(expected, actual, "$label: $kind path $path")
        }
    }

    @Test
    fun cases() {
        for (case in v.getValue("cases").jsonArray.map { it.jsonObject }) {
            val label = case.s("name")
            val doc = json.decodeFromString(ItemDoc.serializer(), case.s("docJson"))
            val edited = applyEdit(doc, case.getValue("edit").jsonObject)
            val reencoded = Json.parseToJsonElement(json.encodeToString(ItemDoc.serializer(), edited))
            assertPaths(label, "unknown", reencoded, case.getValue("expectUnknownPaths").jsonArray)
            assertPaths(label, "typed", reencoded, case.getValue("expectTyped").jsonArray)
        }
    }

    /** One case through the REAL AEAD path: encryptItem → decryptItem → edit → repeat. */
    @Test
    fun encryptDecryptRoundTrip_preservesUnknowns() {
        val account = enrolledAccount()
        val case = v.getValue("cases").jsonArray.map { it.jsonObject }.single { it.s("name") == "all-levels-set-password" }
        val doc = json.decodeFromString(ItemDoc.serializer(), case.s("docJson"))
        val itemId = account.newItemId()

        val first = account.encryptItem(account.personalVaultId, itemId, doc)
        val decrypted = account.decryptItem(wireItem(account, itemId, first.blob, formatVersion = 1))
        val edited = applyEdit(decrypted, case.getValue("edit").jsonObject)
        val second = account.encryptItem(account.personalVaultId, itemId, edited)
        val redecrypted = account.decryptItem(wireItem(account, itemId, second.blob, formatVersion = 1))

        val reencoded = Json.parseToJsonElement(json.encodeToString(ItemDoc.serializer(), redecrypted))
        assertPaths("aead-round-trip", "unknown", reencoded, case.getValue("expectUnknownPaths").jsonArray)
        assertPaths("aead-round-trip", "typed", reencoded, case.getValue("expectTyped").jsonArray)
    }

    /** spec 02 §3: fail CLOSED on a newer formatVersion — the gate fires BEFORE the
     *  envelope is opened (a rewrite would silently downgrade the version). */
    @Test
    fun decryptItem_failsClosedOnNewerFormatVersion() {
        val account = enrolledAccount()
        val doc = ItemDoc(type = "note", name = "future")
        val itemId = account.newItemId()
        val upload = account.encryptItem(account.personalVaultId, itemId, doc)

        // Same blob, declared formatVersion 2 → rejected up front, never edited/resealed.
        val e = assertFailsWith<CryptoException> {
            account.decryptItem(wireItem(account, itemId, upload.blob, formatVersion = 2))
        }
        assertTrue("formatVersion" in (e.message ?: ""), "gate must name the version, got: ${e.message}")
        // Sanity: the same envelope at its true version still decrypts.
        assertEquals("future", account.decryptItem(wireItem(account, itemId, upload.blob, formatVersion = 1)).name)
    }

    private fun wireItem(account: Account, itemId: String, blob: String?, formatVersion: Int) = WireItem(
        itemId = itemId, vaultId = account.personalVaultId, rev = 1, createdAt = 0, updatedAt = 0,
        deleted = false, conflict = false, formatVersion = formatVersion, attachmentIds = emptyList(), blob = blob,
    )

    /** Offline enrollment (no server) with minimum-cost KDF — these tests exercise the
     *  doc pipeline, not argon2id. Same shape as the server-module engine tests. */
    private fun enrolledAccount(): Account {
        val crypto = createCryptoProvider()
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val (_, account) = Account.enroll(
            inviteToken = "itemdoc-test",
            email = "itemdoc@x.com",
            displayName = "ItemDoc",
            password = "itemdoc vectors password",
            params = KdfParams(ops = 1, memBytes = 8 * 1024 * 1024),
            recoveryPublicKey = recovery.publicKey,
            recoveryFingerprint = Escrow.fingerprint(crypto, recovery.publicKey),
            deviceName = "itemdoc-device",
            crypto = crypto,
        )
        return account
    }
}
