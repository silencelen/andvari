package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The sync answer says when the account's state changed (spec 03 §4; additive; for the app interface):
 * `accountStateSeq` is the account state's `seq`, which every write advances by one and nothing lowers, on every sync,
 * full or delta, so a device learns that another device of the account wrote the state without reading it each time.
 */
class SyncStateSeqTest {
    private suspend fun sync(c: HttpClient, token: String, since: Long): Pair<Long, Long> {
        val text = c.call(HttpMethod.Get, "/api/v1/sync?since=$since", token = token).bodyAsText()
        val o = WireJson.json.parseToJsonElement(text).jsonObject
        // The core type still reads the answer as it is.
        WireJson.json.decodeFromString(SyncResponse.serializer(), text)
        return o["rev"]!!.jsonPrimitive.long to o["accountStateSeq"]!!.jsonPrimitive.long
    }

    private suspend fun put(c: HttpClient, token: String, base: Long) =
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/account/state", """{"sealedState":"QUFBQQ","baseSeq":$base}""", token).status.value)

    @Test
    fun everySync_carriesTheStateSeq_andItGrowsWithEachWriteOfAnyDevice() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val other = c.login(me)
        val stranger = Flow.member(c, s, "other@example.com")
        val (rev, seq0) = sync(c, me.token, 0)
        assertEquals(0L, seq0, "before the first write")
        // The other device writes the state twice; this device's delta sync, with no item changed, says so each time.
        put(c, other.accessToken, 0)
        assertEquals(1L, sync(c, me.token, rev).second)
        put(c, other.accessToken, 1)
        assertEquals(2L, sync(c, me.token, rev).second)
        assertEquals(2L, sync(c, me.token, 0).second, "a full sync too")
        // A refused write (a stale base) changes nothing.
        assertEquals(409, c.call(HttpMethod.Put, "/api/v1/account/state", """{"sealedState":"QkJCQg","baseSeq":0}""", me.token).status.value)
        assertEquals(2L, sync(c, me.token, rev).second)
        // Each account has its own: another account's writes never show here, nor this account's there.
        assertEquals(0L, sync(c, stranger.token, 0).second)
        put(c, stranger.token, 0)
        assertEquals(2L, sync(c, me.token, rev).second)
    }
}
