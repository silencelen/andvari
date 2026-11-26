package io.silencelen.andvari.core.client.log

import io.silencelen.andvari.core.client.state.AcceptedRecord
import io.silencelen.andvari.core.client.state.VaultRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.readVector
import io.silencelen.andvari.core.trust.KnownHashes
import io.silencelen.andvari.core.trust.VaultLog
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/** Grades [AdoptionRules.checkWrap] on every `adopt` row of `spec/test-vectors/wrapad.json`. */
class AdoptionVectorTest {
    private val crypto = createCryptoProvider()

    private fun JsonObject.s(k: String) = getValue(k).jsonPrimitive.content

    @Test fun everyAdoptRow() {
        val doc = Json.parseToJsonElement(readVector("wrapad.json")).jsonObject
        val vaultId = doc.s("vaultId")
        val accounts = doc.getValue("accounts").jsonObject
        val logs = doc.getValue("logs").jsonObject
        for (row in doc.getValue("adopt").jsonArray.map { it.jsonObject }) {
            val name = row.s("name")
            val me = accounts.getValue(row.s("me")).jsonObject.s("userId")
            val frames = (row["frames"] ?: logs.getValue(row.s("log")).jsonObject.getValue("frames")).jsonArray.map { Bytes.fromB64(it.jsonPrimitive.content) }
            val replay = VaultLog.replay(crypto, vaultId, frames, from = null, known = KnownHashes.NONE_HELD)
            val state = if (replay.verdict == null) replay.state else null
            val st = row.getValue("accountState").jsonObject
            val rec = st["vaults"]?.jsonObject?.get(vaultId)?.jsonObject?.let { VaultRecord(vaultId, it.s("genesisHash"), it.s("seq").toLong(), it.s("hash")) }
            val acc = st["accepted"]?.jsonObject?.get(vaultId)?.jsonObject?.let { AcceptedRecord(vaultId, it.s("owner"), it.s("addSeq").toLong(), it.s("at").toLong(), it.s("decision")) }
            val result = AdoptionRules.checkWrap(crypto, me, Bytes.fromB64(row.s("uvkB64")), state, AdoptionRules.hashes(crypto, frames), row.s("wrappedVkB64"), rec, acc)
            val expect = row.getValue("expect").jsonObject
            if (expect.s("adopt").toBooleanStrict()) {
                val ok = assertIs<AdoptCheck.Adopt>(result, name)
                assertEquals(expect.s("vkB64"), Bytes.toB64(ok.vk), name)
            } else {
                val refused = assertIs<AdoptCheck.Refuse>(result, name)
                val want = expect.getValue("failed").jsonArray.map { it.jsonPrimitive.content }
                assertEquals(want, refused.failed.map { it.letter }.sorted(), name)
            }
        }
    }
}
