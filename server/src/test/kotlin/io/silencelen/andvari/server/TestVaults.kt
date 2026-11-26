package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.contentType
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.MemberRole
import io.silencelen.andvari.core.trust.VaultLog
import kotlin.test.assertEquals

fun b16(): String = Bytes.toB64(TestKit.crypto.randomBytes(16))
fun b32(): String = Bytes.toB64(TestKit.crypto.randomBytes(32))

/** A shared vault driven through the log route, tracking its head (spec 03 §10.3). */
class SharedVault(val c: HttpClient, val s: Services, val owner: Me, val vaultId: String = uuid()) {
    var seq = -1L
    var head = TestKit.ZERO64
    var lastAt = 0L
    val next: Long get() = seq + 1
    val at: Long get() = maxOf(lastAt, s.clock.now())

    fun sign(me: Me, e: LogEntry): String = Bytes.toB64(VaultLog.sign(TestKit.crypto, me.identity.sign, e))

    suspend fun append(me: Me, e: LogEntry, side: String = ""): HttpResponse =
        c.call(HttpMethod.Post, "/api/v1/vaults/$vaultId/log", """{"entry":"${sign(me, e)}"$side}""", me.token)

    suspend fun ok(me: Me, e: LogEntry, side: String = ""): LogAppendResponse {
        val r = append(me, e, side)
        assertEquals(200, r.status.value, r.bodyAsText())
        return WireJson.json.decodeFromString(LogAppendResponse.serializer(), r.bodyAsText()).also {
            seq = it.head.seq; head = it.head.hash; lastAt = it.head.at
        }
    }

    suspend fun create(): SharedVault {
        ok(owner, LogEntry.Genesis(vaultId, owner.userId, at, owner.identity.identityPubB64, "a".repeat(64)), ""","metaBlob":"AAAA","wrappedVk":"AAAA"""")
        return this
    }

    suspend fun add(m: Me, role: MemberRole = MemberRole.WRITER) {
        s.db.tx { writeConnection(it, owner.userId, m.userId, s.clock.now()) }
        ok(owner, LogEntry.Add(vaultId, next, head, owner.userId, at, m.userId, m.identity.identityPubB64, role, b16()), ""","grant":"AAAA"""")
    }

    suspend fun remove(m: Me) = ok(owner, LogEntry.Remove(vaultId, next, head, owner.userId, at, m.userId))
}

/** One `put` through `POST /sync/push`; the single result. */
suspend fun HttpClient.putItem(me: Me, vaultId: String, itemId: String = uuid(), attachmentIds: List<String> = emptyList(), blob: String = "QUJD", base: Long = 0, fv: Int = 2): MutationResult {
    val ids = attachmentIds.joinToString(",", "[", "]") { "\"$it\"" }
    val body = """{"mutations":[{"mutationId":"${uuid()}","op":"put","itemId":"$itemId","vaultId":"$vaultId","baseItemRev":$base,"item":{"formatVersion":$fv,"attachmentIds":$ids,"blob":"$blob"}}]}"""
    val r = call(HttpMethod.Post, "/api/v1/sync/push", body, me.token)
    assertEquals(200, r.status.value, r.bodyAsText())
    return WireJson.json.decodeFromString(PushResponse.serializer(), r.bodyAsText()).results.single()
}

/** One `delete` through `POST /sync/push`. */
suspend fun HttpClient.deleteItem(me: Me, vaultId: String, itemId: String, base: Long): MutationResult {
    val body = """{"mutations":[{"mutationId":"${uuid()}","op":"delete","itemId":"$itemId","vaultId":"$vaultId","baseItemRev":$base}]}"""
    val r = call(HttpMethod.Post, "/api/v1/sync/push", body, me.token)
    assertEquals(200, r.status.value, r.bodyAsText())
    return WireJson.json.decodeFromString(PushResponse.serializer(), r.bodyAsText()).results.single()
}

/** An attachment body: a 24-byte header and [cipher] bytes of ciphertext (spec 03 §9). */
fun attachmentBytes(cipher: Int = 64, fill: Byte = 7): ByteArray = ByteArray(24 + cipher) { fill }

suspend fun HttpClient.upload(token: String, aid: String, vaultId: String, itemId: String, bytes: ByteArray = attachmentBytes()): HttpResponse =
    call(HttpMethod.Post, "/api/v1/attachments/$aid?vaultId=$vaultId&itemId=$itemId", token = token) {
        contentType(ContentType.Application.OctetStream)
        setBody(bytes)
    }

/** A fresh password login of [me] on a new device: the session. */
suspend fun HttpClient.login(me: Me, authKey: String = me.authKey): SessionResponse {
    val r = call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(secret = b32(), authKey = authKey))
    assertEquals(200, r.status.value, r.bodyAsText())
    return WireJson.json.decodeFromString(SessionResponse.serializer(), r.bodyAsText())
}

/** One row of a table-driven refusal check. */
class Expect(val name: String, val method: HttpMethod, val path: String, val token: String?, val status: Int, val code: String?, val body: String? = null)

/** Run every row and fail once, listing every row whose answer differed. */
suspend fun HttpClient.expectAll(rows: List<Expect>) {
    val wrong = ArrayList<String>()
    for (e in rows) {
        val r = call(e.method, e.path, e.body ?: if (e.method == HttpMethod.Get || e.method == HttpMethod.Delete) null else "{}", e.token)
        val code = r.errorCode()
        if (r.status.value != e.status || (e.code != null && code != e.code)) {
            wrong += "${e.name}: ${e.method.value} ${e.path} answered ${r.status.value} ${code ?: r.bodyAsText().take(120)}, expected ${e.status} ${e.code ?: ""}"
        }
    }
    assertEquals(emptyList(), wrong, wrong.joinToString("\n"))
}
