package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.builtins.ListSerializer
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Spec 03 §16.7 and §7.1: the devices list comes in pages of at most 500 rows in `(createdAt, deviceId)` order, the next
 * page after `?after=<the last deviceId>`, so an honest answer always fits the 1 MiB a client reads (§0.4) however many
 * rows an account holds. Device rows are never pruned while known (§16.8), so the list itself has to be bounded.
 */
class DevicesPageTest {
    private val get = HttpMethod.Get

    @Test
    fun theDevicesListComesInPagesThatAlwaysFitTheClientsCap() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val other = Flow.member(c, s, "other@example.com")
        // 700 rows of the largest size the grammar admits (§0.1 `text`: 256 characters, here 3 UTF-8 bytes each), all
        // created at the same instant so the deviceId decides their order, plus the account's own device.
        val longest = "ࠀ".repeat(256)
        val at = s.clock.now() + 1
        s.db.tx { db ->
            repeat(700) {
                db.exec(
                    """INSERT INTO devices(deviceId,userId,platform,name,clientVersion,how,linkedFrom,deviceSecretHash,createdAt,lastSeenAt,revokedAt,signedOutAt)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    UUID.randomUUID().toString(), me.userId, "extension", longest, "9".repeat(32), "recovered", UUID.randomUUID().toString(),
                    "0".repeat(64), at, at, null, at,
                )
            }
        }
        val all = s.db.read { db -> db.count("SELECT COUNT(*) FROM devices WHERE userId=?", me.userId) }
        assertEquals(701L, all)

        suspend fun page(path: String, token: String): List<Device> {
            val r = c.call(get, path, token = token)
            assertEquals(200, r.status.value, r.bodyAsText())
            val body = r.bodyAsText()
            assertTrue(body.encodeToByteArray().size <= 1_048_576, "a page is ${body.encodeToByteArray().size} bytes")
            return WireJson.json.decodeFromString(ListSerializer(Device.serializer()), body)
        }
        for ((base, token) in listOf("/api/v1/account/devices" to me.token, "/api/v1/admin/accounts/${me.userId}/devices" to op.token)) {
            val first = page(base, token)
            assertEquals(500, first.size, base)
            assertEquals(me.deviceId, first.first().deviceId, "the oldest row first: $base")
            val second = page("$base?after=${first.last().deviceId}", token)
            assertEquals(201, second.size, base)
            val ids = (first + second).map { it.deviceId }
            assertEquals(701, ids.toSet().size, "every row exactly once: $base")
            val keyed = (first + second).map { it.createdAt to it.deviceId }
            assertEquals(keyed.sortedWith(compareBy({ it.first }, { it.second })), keyed, "(createdAt, deviceId) order: $base")
            assertEquals(emptyList(), page("$base?after=${second.last().deviceId}", token), base)
            // A cursor that is not a uuid, or names no device of this account, is refused.
            assertEquals("bad_request", c.call(get, "$base?after=nope", token = token).errorCode())
            assertEquals("bad_request", c.call(get, "$base?after=${other.deviceId}", token = token).errorCode())
        }
        // The account's own view marks the caller; the operator's marks nothing.
        assertTrue(page("/api/v1/account/devices", me.token).single { it.current }.deviceId == me.deviceId)
    }
}
