package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.LogDeleted
import io.silencelen.andvari.core.model.wire.LogHead
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.LogPurged
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.VaultLog
import kotlinx.serialization.Serializable
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The append answer and the log page (spec 03 §10.3, §10.6) are now core's `LogAppendResponse` and `LogPage`;
 * the server's own `LogAppendAnswer`/`LogPageAnswer` (and its `LogDeleted`) are gone. The bytes on the wire
 * must not change: the frozen copies below are those deleted types, byte for byte what the server sent.
 */
class LogAnswerBytesTest {
    @Serializable private data class OldLogDeleted(val deletedAt: Long, val purgeAt: Long)
    @Serializable private data class OldLogAppendAnswer(val rev: Long, val head: LogHead, val deleted: OldLogDeleted? = null)
    @Serializable private data class OldLogPageAnswer(val entries: List<String>, val head: LogHead, val purged: LogPurged? = null, val deleted: OldLogDeleted? = null)

    private val head = LogHead(7, "ab".repeat(32), 1_800_000_000_123L)

    @Test
    fun coresTypes_encodeExactlyAsTheDeletedServerTypesDid() {
        val j = WireJson.json
        for (d in listOf(null, 1_800_000_000_000L to 1_800_604_800_000L, 0L to 0L)) {
            val old = OldLogAppendAnswer(42, head, d?.let { OldLogDeleted(it.first, it.second) })
            val new = LogAppendResponse(42, head, d?.let { LogDeleted(it.first, it.second) })
            assertEquals(j.encodeToString(OldLogAppendAnswer.serializer(), old), j.encodeToString(LogAppendResponse.serializer(), new))
            for (purged in listOf(null, LogPurged(1_800_000_000_999L))) for (entries in listOf(emptyList(), listOf("QUFB", "QkJC"))) {
                val oldPage = OldLogPageAnswer(entries, head, purged, d?.let { OldLogDeleted(it.first, it.second) })
                val newPage = LogPage(entries, head, purged, d?.let { LogDeleted(it.first, it.second) })
                assertEquals(j.encodeToString(OldLogPageAnswer.serializer(), oldPage), j.encodeToString(LogPage.serializer(), newPage))
            }
        }
        // The literal shapes, so a change to either side's encoding is caught here too.
        assertEquals(
            """{"rev":42,"head":{"seq":7,"hash":"${head.hash}","at":1800000000123}}""",
            j.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(42, head)),
        )
        assertEquals(
            """{"rev":42,"head":{"seq":7,"hash":"${head.hash}","at":1800000000123},"deleted":{"deletedAt":1,"purgeAt":2}}""",
            j.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(42, head, LogDeleted(1, 2))),
        )
        assertEquals(
            """{"entries":["QUFB"],"head":{"seq":7,"hash":"${head.hash}","at":1800000000123},"purged":{"purgedAt":3},"deleted":{"deletedAt":1,"purgeAt":2}}""",
            j.encodeToString(LogPage.serializer(), LogPage(listOf("QUFB"), head, LogPurged(3), LogDeleted(1, 2))),
        )
    }

    @Test
    fun theRoutesBytes_areTheOldTypesBytes() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val crypto = TestKit.crypto
        fun sign(e: LogEntry) = Bytes.toB64(VaultLog.sign(crypto, a.identity.sign, e))
        val vaultId = uuid()
        suspend fun append(frame: String, side: String = "") =
            c.call(HttpMethod.Post, "/api/v1/vaults/$vaultId/log", """{"entry":"$frame"$side}""", a.token).also { assertEquals(200, it.status.value, it.bodyAsText()) }.bodyAsText()
        suspend fun fetch() = c.call(HttpMethod.Get, "/api/v1/vaults/$vaultId/log", token = a.token).also { assertEquals(200, it.status.value) }.bodyAsText()
        fun reencodeAppend(text: String) = WireJson.json.encodeToString(OldLogAppendAnswer.serializer(), WireJson.json.decodeFromString(OldLogAppendAnswer.serializer(), text))
        fun reencodePage(text: String) = WireJson.json.encodeToString(OldLogPageAnswer.serializer(), WireJson.json.decodeFromString(OldLogPageAnswer.serializer(), text))

        val g = append(sign(LogEntry.Genesis(vaultId, a.userId, clock.now(), a.identity.identityPubB64, "a".repeat(64))), ""","metaBlob":"AAAA","wrappedVk":"AAAA"""")
        assertEquals(reencodeAppend(g), g)
        val gh = WireJson.json.decodeFromString(LogAppendResponse.serializer(), g).head
        assertEquals("""{"rev":${WireJson.json.decodeFromString(LogAppendResponse.serializer(), g).rev},"head":{"seq":${gh.seq},"hash":"${gh.hash}","at":${gh.at}}}""", g)
        val live = fetch()
        assertEquals(reencodePage(live), live)

        clock.advance(60_000L)
        val del = append(sign(LogEntry.Delete(vaultId, gh.seq + 1, gh.hash, a.userId, clock.now(), Bytes.toB64(crypto.randomBytes(16)))))
        assertEquals(reencodeAppend(del), del)
        val dr = WireJson.json.decodeFromString(LogAppendResponse.serializer(), del)
        val dd = dr.deleted!!
        assertEquals(
            """{"rev":${dr.rev},"head":{"seq":${dr.head.seq},"hash":"${dr.head.hash}","at":${dr.head.at}},"deleted":{"deletedAt":${dd.deletedAt},"purgeAt":${dd.purgeAt}}}""",
            del,
        )
        val page = fetch()
        assertEquals(reencodePage(page), page)
        val p = WireJson.json.decodeFromString(LogPage.serializer(), page)
        assertEquals(
            """{"entries":[${p.entries.joinToString(",") { "\"$it\"" }}],"head":{"seq":${p.head.seq},"hash":"${p.head.hash}","at":${p.head.at}},"deleted":{"deletedAt":${dd.deletedAt},"purgeAt":${dd.purgeAt}}}""",
            page,
        )
    }
}
