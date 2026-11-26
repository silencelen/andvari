package io.silencelen.andvari.core.client.state

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.readVector
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Grades the codec and the pure merge of design §5.4 / spec 02 §9 on every row of
 * `spec/test-vectors/next/accountstate.json` (the independent oracle). Documents are compared as JSON
 * values: key order carries no meaning there (the writer's byte order is pinned in [AccountMergeTest]).
 */
class AccountStateVectorTest {
    private val crypto = createCryptoProvider()
    private val v = Json.parseToJsonElement(readVector("next/accountstate.json")).jsonObject
    private val userId = v.getValue("userId").jsonPrimitive.content

    private fun JsonObject.s(k: String) = getValue(k).jsonPrimitive.content
    private fun JsonObject.rows(k: String) = getValue(k).jsonArray.map { it.jsonObject }
    private fun JsonObject.orNull(k: String): JsonObject? = (get(k) as? JsonObject)

    private fun docOf(e: JsonObject?): AccountDocument? =
        e?.let { assertNotNull(AccountDocumentCodec.decode(userId, it.toString()), "decodes").document }

    private fun json(doc: AccountDocument): JsonElement = Json.parseToJsonElement(AccountDocumentCodec.encode(userId, doc))

    @Test fun sampleOpensAndRejectRowsDoNot() {
        val uvk = Bytes.fromB64(v.s("uvkB64"))
        val plain = Envelope.openB64(crypto, uvk, v.s("sampleBlobB64"), v.s("adUtf8").encodeToByteArray())
        assertEquals(v.s("samplePlaintext"), plain.decodeToString())
        assertEquals(v.s("sampleBlobB64").length, AccountMerge.sealedChars(AccountDocumentCodec.decode(userId, v.s("samplePlaintext"))!!.document),
            "the size rule counts the sealed blob exactly as sent")
        for (r in v.rows("rejectOpen")) {
            val opened = runCatching { Envelope.openB64(crypto, Bytes.fromB64(r.s("uvkB64")), r.s("blobB64"), r.s("adUtf8").encodeToByteArray()) }.getOrNull()
            assertNull(opened, r.s("name"))
        }
    }

    @Test fun decodeRows() {
        val rows = v.rows("decode")
        assertTrue(rows.size >= 20)
        for (r in rows) {
            val name = r.s("name")
            val expect = r.getValue("expect").jsonObject
            val got = AccountDocumentCodec.decode(userId, r.s("plaintext"))
            if (expect["refused"]?.jsonPrimitive?.content == "true") {
                assertNull(got, "$name: ${r.s("why")}")
                continue
            }
            assertNotNull(got, name)
            assertEquals(expect.getValue("dropped").jsonPrimitive.long.toInt(), got.droppedRecords, "$name dropped")
            assertEquals(expect.getValue("doc"), json(got.document), "$name: ${r.s("why")}")
        }
    }

    @Test fun mergeRows() {
        val rows = v.rows("merge")
        assertTrue(rows.size >= 60, "the revised merge corpus")
        for (r in rows) {
            val name = r.s("name")
            val why = "$name: ${r.s("why")}"
            val limitsJson = r.orNull("limits")
            val limits = AccountLimits(
                contacts = limitsJson?.get("contacts")?.jsonPrimitive?.long?.toInt() ?: AccountDocument.MAX_CONTACTS,
                tombstones = limitsJson?.get("tombstones")?.jsonPrimitive?.long?.toInt() ?: AccountDocument.MAX_TOMBSTONES,
                sealedChars = limitsJson?.get("sealedChars")?.jsonPrimitive?.long?.toInt() ?: AccountLimits.SEALED_MAX,
            )
            val local = docOf(r.orNull("local")) ?: AccountDocument.EMPTY
            val served = docOf(r.orNull("served"))
            val highWater = r.getValue("highWater").jsonPrimitive.long
            val expect = r.getValue("expect").jsonObject
            // The store's rule: a served document below the high-water mark, or none after one was seen.
            val rollback = if (served == null) highWater > 0 else served.seq < highWater
            assertEquals(expect.getValue("rollback").jsonPrimitive.content.toBooleanStrict(), rollback, why)
            val result = if (served == null) MergeResult(local, emptyList()) else AccountMerge.merge(local, served, limits)
            // expect.notWritten: the merged document is for reading only; a row without it must fit and be
            // advanceable, so it may be written.
            assertEquals(expect["notWritten"]?.jsonPrimitive?.content, result.notWritten, "$why (notWritten)")
            if (result.notWritten == null) assertTrue(result.fits, why)
            assertEquals(expect.getValue("doc"), json(result.document), why)
            val keyChanges = result.anomalies.filterIsInstance<MergeAnomaly.ContactKeyChange>()
                .map { mapOf("userId" to it.served.userId, "identityPub" to it.served.identityPub) }
            val expectedKeyChanges = expect.getValue("keyChange").jsonArray.map { e ->
                e.jsonObject.mapValues { it.value.jsonPrimitive.content }
            }
            assertEquals(expectedKeyChanges, keyChanges, why)
            assertEquals(expect.getValue("genesisAnomalies").jsonArray.map { it.jsonPrimitive.content },
                result.anomalies.filterIsInstance<MergeAnomaly.VaultGenesisMismatch>().map { it.local.vaultId }, why)
            assertEquals(expect.getValue("forks").jsonArray.map { it.jsonPrimitive.content },
                result.anomalies.filterIsInstance<MergeAnomaly.VaultRecordFork>().map { it.local.vaultId }, why)
        }
    }

    @Test fun acceptanceRows() {
        for (r in v.rows("acceptance")) {
            val name = r.s("name")
            val rec = r["record"]?.takeIf { it != JsonNull }?.jsonObject
            val vaultId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            val doc = AccountDocument.EMPTY.copy(accepted = rec?.let {
                mapOf(vaultId to AcceptedRecord(vaultId, it.s("owner"), it.getValue("addSeq").jsonPrimitive.long, it.getValue("at").jsonPrimitive.long, it.s("decision")))
            } ?: emptyMap())
            val expect = r.getValue("expect").jsonObject
            assertEquals(expect.s("answer"), AccountMerge.acceptance(doc, vaultId, r.getValue("latestAddSeq").jsonPrimitive.long).code, name)
        }
    }
}
