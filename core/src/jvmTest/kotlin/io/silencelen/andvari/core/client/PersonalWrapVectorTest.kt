package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.createCryptoProvider
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
import kotlin.test.assertTrue

/** Consumes spec/test-vectors/personalwrap.json (security review 2026-10, root cause A §4.1 / §8.5) — the same
 *  file web `vault/personalwrap.test.ts` checks. */
class PersonalWrapVectorTest {
    private val crypto = createCryptoProvider()
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "personalwrap.json").readText()).jsonObject

    private fun adOf(text: String): ByteArray {
        val parts = text.split("|")
        return when (parts[1]) {
            "vk-personal" -> Ad.vkPersonal(parts[2], parts[3])
            "vk" -> Ad.vk(parts[2], parts[3])
            else -> error("unexpected AD $text")
        }
    }

    @Test
    fun wrapsOpenOnlyUnderTheirOwnPurpose() {
        val w = v.getValue("wrap").jsonObject
        val s = { k: String -> w.getValue(k).jsonPrimitive.content }
        assertEquals(s("adPersonalUtf8"), Ad.vkPersonal(s("vaultId"), s("userId")).decodeToString())
        assertEquals(s("adOwnerUtf8"), Ad.vk(s("vaultId"), s("userId")).decodeToString())
        val uvk = Bytes.fromB64(s("uvkB64"))
        val blob = { which: String -> if (which == "personal") s("personalWrapB64") else s("ownerWrapB64") }
        for (r in v.getValue("open").jsonArray.map { it.jsonObject }) {
            val vk = Envelope.openB64(crypto, uvk, blob(r.getValue("wrap").jsonPrimitive.content), adOf(r.getValue("adUtf8").jsonPrimitive.content))
            assertEquals(r.getValue("vkB64").jsonPrimitive.content, Bytes.toB64(vk), r.getValue("name").jsonPrimitive.content)
        }
        for (r in v.getValue("reject").jsonArray.map { it.jsonObject }) {
            val res = runCatching { Envelope.openB64(crypto, uvk, blob(r.getValue("wrap").jsonPrimitive.content), adOf(r.getValue("adUtf8").jsonPrimitive.content)) }
            assertTrue(res.isFailure, r.getValue("name").jsonPrimitive.content)
        }
    }

    @Test
    fun migrationDecisions() {
        for (r in v.getValue("migration").jsonArray.map { it.jsonObject }) {
            val name = r.getValue("name").jsonPrimitive.content
            val cands = r.getValue("candidates").jsonArray.map { it.jsonObject }.map { c ->
                PersonalVaultMigration.Candidate(
                    vaultId = c.getValue("vaultId").jsonPrimitive.content,
                    labelledPersonal = c.getValue("labelledPersonal").jsonPrimitive.boolean,
                    ownUvkWrap = c.getValue("ownUvkWrap").jsonPrimitive.boolean,
                    name = c.getValue("name").let { if (it is JsonNull) null else it.jsonPrimitive.content },
                )
            }
            val last = r.getValue("lastUsed").let { if (it is JsonNull) null else it.jsonPrimitive.content }
            val exp = r.getValue("expected").jsonObject
            val d = PersonalVaultMigration.decide(cands, last)
            if ("auto" in exp) {
                assertEquals(PersonalVaultMigration.Decision.Auto(exp.getValue("auto").jsonPrimitive.content), d, name)
            } else {
                assertTrue(d is PersonalVaultMigration.Decision.Ask, name)
                assertEquals(exp.getValue("ask").jsonArray.map { it.jsonPrimitive.content }, d.choices.map { it.vaultId }, name)
            }
        }
    }
}
