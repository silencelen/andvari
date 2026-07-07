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
