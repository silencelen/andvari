package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.LogAppendRequest
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * `POST /vaults/{vaultId}/log` graded against spec/test-vectors/logappend.json (spec 03 §10.3, §10.4): for
 * every row, a fresh server holds the row's stored chain (built by appending the chain's frames in order, each
 * as its actor, then purging when the chain says so), the row's caller posts its frame, and the wire answer,
 * the stored log and the grant table must be the row's.
 */
class LogAppendVectorsTest {
    private val file: File = generateSequence(File("").absoluteFile) { it.parentFile }
        .map { File(it, "spec/test-vectors/logappend.json") }.first { it.isFile }
    private val doc: JsonObject = WireJson.json.parseToJsonElement(file.readText()).jsonObject

    private fun JsonElement?.str(): String? = if (this == null || this is JsonNull) null else jsonPrimitive.content

    /** `side` for [kind]: every side field the kind takes, well formed (the vectors leave them to the harness). */
    private fun side(kind: String?): String =
        (kind?.let { LogAppendRequest.sideFieldsFor(it) } ?: emptySet()).joinToString("") { ",\"$it\":\"AAAA\"" }

    private fun kindOf(frameB64: String): String? = runCatching { VaultLogs.parse(io.silencelen.andvari.core.crypto.Bytes.fromB64(frameB64)).entry.kind.literal }.getOrNull()

    private fun grants(s: Services, vaultId: String): Set<Triple<String, String, String?>> = s.db.read { c ->
        c.queryAll("SELECT userId,role,revokedReason FROM grants WHERE vaultId=?", vaultId) {
            Triple(
                it.getString(1), it.getString(2),
                when (it.getString(3)) { null -> null; "vault_delete" -> "delete"; "member_leave" -> "leave"; "member_remove" -> "remove"; else -> "?" },
            )
        }.toSet()
    }

    private fun expectedGrants(arr: JsonArray): Set<Triple<String, String, String?>> =
        arr.map { g -> g.jsonObject.let { Triple(it["userId"].str()!!, it["role"].str()!!, it["revokedBy"].str()) } }.toSet()

    @Test
    fun everyRow() {
        val rows = doc["rows"]!!.jsonArray
        val failures = ArrayList<String>()
        for (row in rows) {
            val r = row.jsonObject
            val name = r["name"].str()!!
            runCatching { gradeRow(r) }.onFailure { failures += "$name: ${it.message}" }
        }
        if (failures.isNotEmpty()) fail("${failures.size} of ${rows.size} rows disagree:\n" + failures.joinToString("\n"))
        assertTrue(rows.size >= 70)
    }

    private fun gradeRow(r: JsonObject) = testApplication {
        val now = doc["now"]!!.jsonPrimitive.long
        val vaultId = doc["vaultId"].str()!!
        val clock = MutableClock(now)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        // The cast: every account active and connected to every other.
        val accounts = doc["accounts"]!!.jsonObject.mapValues { it.value.jsonObject }
        val ids = accounts.mapValues { it.value["userId"].str()!! }
        s.db.tx { c ->
            for ((n, a) in accounts) {
                c.exec(
                    """INSERT INTO users(userId,email,displayName,kdfSalt,kdfParams,verifier,wrappedUvk,identityPub,encryptedIdentitySeed,genesis,personalVaultId,role,createdAt,registeredVia)
                       VALUES(?,?,?,'AAAA',?,'x','AAAA',?,'AAAA','AAAA',?,'member',?,'enrol')""",
                    a["userId"].str(), "$n@example.com", n, encodeParams(TestKit.FAST_KDF), a["identityPubB64"].str(), uuid(), now - Clock.DAY_MS,
                )
            }
            for (x in ids.values) for (y in ids.values) if (x < y) writeConnection(c, x, y, now - Clock.DAY_MS)
        }
        // The stored chain, each frame appended as its actor.
        val chain = doc["chains"]!!.jsonObject[r["stored"].str()!!]!!.jsonObject
        val actorOf = ids.entries.associate { it.value to it.key }
        for ((i, f) in chain["frames"]!!.jsonArray.withIndex()) {
            val frame = f.str()!!
            val actor = chain["entries"]!!.jsonArray[i].jsonObject["actor"].str()!!
            check(actor in actorOf) { "chain actor $actor is not in the cast" }
            val kind = kindOf(frame)
            val sides = kind?.let { LogAppendRequest.sideFieldsFor(it) } ?: emptySet()
            s.db.tx { c ->
                VaultLogs.append(
                    s, c, null, actor, null, null, vaultId, frame,
                    if ("grant" in sides) "AAAA" else null, if ("wrappedVk" in sides) "AAAA" else null, if ("metaBlob" in sides) "AAAA" else null, true,
                )
            }
        }
        if (chain["purged"].str() == "true" || chain["purged"].str() == "True") {
            s.db.tx { c -> Purge.vault(s, c, vaultId, now, keepLog = true) }
        }
        assertEquals(expectedGrants(chain["grants"]!!.jsonArray), grants(s, vaultId), "the stored chain's grants")
        val logBefore = s.db.read { it.count("SELECT COUNT(*) FROM vault_log WHERE vaultId=?", vaultId) }

        // The row's post.
        val caller = r["caller"].str()!!
        val token = s.db.tx { c ->
            val dev = s.sessions.createDevice(c, ids.getValue(caller), "linux", "vectors", "registered", null, "1.0.0")
            s.sessions.issue(c, ids.getValue(caller), dev, "linux", passwordLogin = true).accessToken
        }
        val frame = r["frameB64"].str()!!
        val resp = client.call(HttpMethod.Post, "/api/v1/vaults/$vaultId/log", """{"entry":"$frame"${side(kindOf(frame))}}""", token)
        val body = resp.bodyAsText()
        val expect = r["expect"]!!.jsonObject
        val status = expect["status"]!!.jsonPrimitive.long.toInt()
        assertEquals(status, resp.status.value, body)
        val logAfter = s.db.read { it.count("SELECT COUNT(*) FROM vault_log WHERE vaultId=?", vaultId) }
        if (status == 200) {
            val appended = expect["appended"]!!.jsonPrimitive.content.toBoolean()
            assertEquals(if (appended) logBefore + 1 else logBefore, logAfter, "the stored log")
            r["grantsAfter"]?.let { assertEquals(expectedGrants(it.jsonArray), grants(s, vaultId), "grantsAfter") }
        } else {
            assertEquals(expect["error"].str(), resp.errorCode(), body)
            assertEquals(logBefore, logAfter, "a refusal stores nothing")
            val o = WireJson.json.parseToJsonElement(body).jsonObject
            if (expect["error"].str() == "log_head_moved") {
                assertEquals(expect["seq"]!!.jsonPrimitive.long, o["seq"]!!.jsonPrimitive.long)
                assertEquals(expect["hash"].str(), o["hash"].str())
                assertEquals(expect["at"]!!.jsonPrimitive.long, o["at"]!!.jsonPrimitive.long)
            } else {
                assertTrue("seq" !in o && "hash" !in o, "only log_head_moved carries a head: $body")
            }
        }
    }
}
