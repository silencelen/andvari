package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.createCryptoProvider
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

/**
 * Consumes spec/test-vectors/{strength,conflictcopy}.json — the SAME files the web suite
 * checks. Both derivations gate cross-fleet convergence: the strength score enforces the
 * spec 07 §2.3 backup-passphrase floor identically on every client, and the conflict-copy
 * id must be byte-identical or concurrent materializers double every conflict copy.
 */
class ClientDerivationVectorsTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private fun load(name: String): JsonObject = Json.parseToJsonElement(File(dir, name).readText()).jsonObject

    @Test
    fun strengthScores() {
        for (case in load("strength.json").getValue("cases").jsonArray.map { it.jsonObject }) {
            val pw = case.getValue("password").jsonPrimitive.content
            assertEquals(case.getValue("utf16Length").jsonPrimitive.int, pw.length, "UTF-16 length of '$pw'")
            assertEquals(case.getValue("score").jsonPrimitive.int, Strength.estimateStrength(pw), "score of '$pw'")
        }
    }

    @Test
    fun conflictCopyIds() {
        val crypto = createCryptoProvider()
        for (case in load("conflictcopy.json").getValue("cases").jsonArray.map { it.jsonObject }) {
            val itemId = case.getValue("itemId").jsonPrimitive.content
            val rev = case.getValue("rev").jsonPrimitive.long
            assertEquals(
                case.getValue("copyId").jsonPrimitive.content,
                ConflictCopy.id(crypto, itemId, rev),
                "copyId of ($itemId, $rev)",
            )
        }
    }
}
