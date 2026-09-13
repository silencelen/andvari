package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.ByteArrayOutputStream
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Consumes spec/test-vectors/export.json — the SAME file the web twin checks — so both
 * impls write byte-identical CSVs and produce/open byte-identical backup containers
 * (spec 07 §4). Payload serialization is deliberately NOT byte-compared across impls
 * (key order differs); the pinned payloadUtf8 is sealed as-is.
 */
class ExportVectorsTest {
    private val crypto = createCryptoProvider()
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "export.json").readText()).jsonObject

    /** Mirrors Account's item Json config — the real payload/doc (de)serialization path. */
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private fun JsonObject.s(k: String) = getValue(k).jsonPrimitive.content
    private fun JsonObject.b(k: String) = Bytes.fromB64(s(k))
    private fun JsonObject.arr(k: String) = getValue(k).jsonArray.map { it.jsonObject }

    private fun JsonObject.kdfParams(k: String): KdfParams {
        val p = getValue(k).jsonObject
        return KdfParams(
            v = p.getValue("v").jsonPrimitive.int,
            alg = p.s("alg"),
            ops = p.getValue("opsLimit").jsonPrimitive.long,
            memBytes = p.getValue("memBytes").jsonPrimitive.long,
        )
    }

    @Test
    fun csvWriter_byteExact() {
        for (case in v.arr("csv")) {
            val docs = case.getValue("docs").jsonArray.map { json.decodeFromJsonElement(ItemDoc.serializer(), it) }
            assertEquals(case.s("csvUtf8"), ExportCsv.write(docs), "csv ${case.s("name")}")
        }
    }

    @Test
    fun container_produce_byteExact() {
        for (case in v.arr("container")) {
            val out = ByteArrayOutputStream()
            Backup.buildWithPayloadBytes(
                crypto,
                case.s("passphraseUtf8"),
                case.s("fileId"),
                case.b("kdfSaltB64"),
                case.kdfParams("kdfParams"),
                case.s("payloadUtf8").encodeToByteArray(),
                emptyList(),
                case.b("envelopeNonceB64"),
            ) { out.write(it) }
            assertContentEquals(case.b("containerB64"), out.toByteArray(), "container ${case.s("name")}")
        }
    }

    @Test
    fun container_open_pinnedBytes() {
        for (case in v.arr("container")) {
            val label = case.s("name")
            val opened = Backup.open(crypto, case.s("passphraseUtf8"), case.b("containerB64"))
            assertEquals(Backup.FORMAT, opened.header.format, label)
            assertEquals(1, opened.header.v, label)
            assertEquals(case.s("fileId"), opened.header.fileId, label)
            assertEquals(case.s("kdfSaltB64"), opened.header.kdfSalt, label)
            assertEquals(0, opened.attachmentSectionCount, label)
            // The payload must decode exactly as the pinned plaintext does (unknown
            // payload-level keys tolerated; doc-level unknowns preserved via extras).
            val expected = json.decodeFromString(BackupPayload.serializer(), case.s("payloadUtf8"))
            assertEquals(expected, opened.payload, label)
        }
    }

    /**
     * Schema v9 (audit H95, 2026-09-13): the corpus had been regenerated for neither `check` nor
     * `dupeAck`, and because both consumers decode payloadUtf8 SEMANTICALLY the stale corpus stayed
     * green while never grading the round-trip with those fields present. This pins that the named
     * case exists, that its pinned plaintext carries both fields populated (a regenerate that lost
     * them would fail here, not silently pass), and that they survive the container round-trip
     * typed — the same assertion `container_open_pinnedBytes` makes structurally, made by name.
     */
    @Test
    fun container_v9_checkAndDupeAck_surviveTheRoundTrip() {
        val case = v.arr("container").first { it.s("name") == "schema-v9-check-and-dupeack" }
        val pinned = Json.parseToJsonElement(case.s("payloadUtf8")).jsonObject.getValue("items").jsonArray.map { it.jsonObject.getValue("doc").jsonObject }
        for (d in pinned) {
            assertEquals(true, d["dupeAck"]?.jsonPrimitive?.content?.isNotEmpty(), "pinned doc carries dupeAck")
            assertEquals(true, d["check"] is JsonObject, "pinned doc carries check")
        }
        val opened = Backup.open(crypto, case.s("passphraseUtf8"), case.b("containerB64"))
        val docs = opened.payload.items.map { it.doc }
        assertEquals(2, docs.size)
        assertEquals("77777777-7777-4777-8777-777777777777|88888888-8888-4888-8888-888888888888", docs[0].dupeAck)
        assertEquals(docs[0].dupeAck, docs[1].dupeAck)
        // The carry-forward shape: a failing verdict that still remembers when it last worked.
        assertEquals(ItemCheck(at = 1751843000000, result = "bad", okAt = 1751800000000), docs[0].check)
        // The snoozed shape: a verdict with a horizon.
        assertEquals(ItemCheck(at = 1751844000000, result = "blocked", until = 1754436000000), docs[1].check)
    }

    @Test
    fun rejects() {
        for (r in v.arr("reject")) {
            val e = assertFailsWith<BackupException>(r.s("name")) {
                Backup.open(crypto, r.s("passphraseUtf8"), r.b("containerB64"))
            }
            assertEquals(r.s("reason"), e.code, r.s("name"))
        }
    }
}
