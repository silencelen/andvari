package io.silencelen.andvari.server

import io.ktor.client.plugins.websocket.DefaultClientWebSocketSession
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readText
import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The card bell (spec 03 §6, §17.2, §17.3): when the server starts serving another chain, every open events socket of
 * every account gets the ordinary `{"type":"rev","rev":N}` at once, N a fresh global rev above everything before it.
 * Before this, a client learned of a new card (a handover, a move, a kind change) only at its next own refresh.
 */
class CardBellTest {
    private suspend fun ApplicationTestBuilder.socket(token: String): DefaultClientWebSocketSession =
        createClient { install(WebSockets) }.webSocketSession("/api/v1/events") { header("Authorization", "Bearer $token") }.also {
            it.send(Frame.Text("ping"))
            assertEquals("pong", (withTimeout(5_000) { it.incoming.receive() } as Frame.Text).readText())
        }

    /** The socket's next frame is exactly the rev bell for [rev]: nothing else, and nothing rung before it. */
    private suspend fun DefaultClientWebSocketSession.expectBell(rev: Long, what: String) {
        val f = withTimeout(5_000) { incoming.receive() }
        assertEquals("""{"type":"rev","rev":$rev}""", (f as Frame.Text).readText(), what)
    }

    @Test
    fun everyKindOfChainChange_ringsEverySocketOfEveryAccount_withAFreshRev() = testApplication {
        val recovery = TestKit.Identity()
        val fp = sha256Hex(recovery.curvePub)
        val s = TestKit.services(TestKit.config(recoveryKey = recovery.curvePub))
        application { andvariModule(s) }
        val op = Flow.finishSetup(client, s)
        val next = Flow.member(client, s, "next@example.com")
        val bystander = Flow.member(client, s, "bystander@example.com")
        val setup = s.db.read { s.instance.setupOn(it)!! }
        val cardFrames = mutableListOf(s.db.read { c -> c.queryOne("SELECT frame FROM instance_cards WHERE seq=0") { Bytes.fromB64(it.getString(1)) }!! })
        val sockets = listOf(socket(op.token), socket(next.token), socket(next.token), socket(bystander.token))

        suspend fun putCard(
            signer: Me, origin: String = s.config.canonicalOrigin, name: String = setup.name, kind: String = s.config.instanceKind,
            operator: Me = op, recoveryFp: String = fp, seq: Long = cardFrames.size.toLong(),
        ): Int {
            val frame = signer.identity.frame(
                4, TestKit.cardStatement(setup.instanceId, seq, sha256Hex(cardFrames.last()), origin, name, kind, operator.userId, operator.identity.edPub, recoveryFp, 1_800_000_000_000 + seq),
            )
            s.limiter.clear()
            val r = client.call(HttpMethod.Put, "/api/v1/instance/card", """{"card":"${Bytes.toB64(frame)}","currentAuthKey":"${signer.authKey}"}""", signer.token)
            if (r.status.value == 200) cardFrames += frame
            return r.status.value
        }

        suspend fun changeRings(what: String, change: suspend () -> Unit) {
            val before = s.db.read { currentRev(it) }
            change()
            val after = s.db.read { currentRev(it) }
            assertTrue(after > before, "$what: the store takes a fresh global rev")
            for (sock in sockets) sock.expectBell(after, what)
        }

        // A refused card changes nothing and rings nothing: the next frame every socket sees is the rename's own.
        assertEquals(409, putCard(op, seq = 5))
        changeRings("a rename") { assertEquals(200, putCard(op, name = Grammar.nameOf("Our family")!!)) }
        changeRings("a move") { assertEquals(200, putCard(op, origin = "https://vault.example.org")) }
        changeRings("a kind change") { assertEquals(200, putCard(op, origin = "https://vault.example.org", kind = "public", recoveryFp = fp)) }
        // A signed rotation first (it changes what GET /instance serves), then the card that names the new key.
        val nextKey = TestKit.Identity()
        val nextFp = sha256Hex(nextKey.curvePub)
        val rotation = Bytes.toB64(recovery.frame(8, """{"v":2,"purpose":"recovery-rotation","instanceId":"${setup.instanceId}","fromFp":"$fp","toFp":"$nextFp","issuedAt":1800000000000}"""))
        suspend fun putRotation() = s.limiter.clear().let { client.call(HttpMethod.Put, "/api/v1/instance/rotation", """{"statement":"$rotation","currentAuthKey":"${op.authKey}"}""", op.token) }
        changeRings("a rotation statement") { assertEquals(200, putRotation().status.value) }
        // A byte-identical repeat stores nothing, so it rings nothing either: the next frame is the recovery card's.
        assertEquals(200, putRotation().status.value)
        changeRings("a recovery-key change") {
            assertEquals(200, putCard(op, origin = "https://vault.example.org", kind = "public", recoveryFp = nextFp))
        }
        changeRings("a handover") {
            assertEquals(200, putCard(op, origin = "https://vault.example.org", kind = "public", operator = next, recoveryFp = nextFp))
        }
        assertEquals("operator", s.db.read { c -> c.queryOne("SELECT role FROM users WHERE userId=?", next.userId) { it.getString(1) } })
        // The bell named nothing: what changed is read from the chain itself, which now ends at the handover.
        val served = client.call(HttpMethod.Get, "/api/v1/instance").bodyAsText()
        assertTrue(served.contains(Bytes.toB64(cardFrames.last())), served)
        sockets.forEach { it.close() }
    }

    /** A new card 0 (the first one, or after `reset-instance-identity`) rings too: to a device that pinned the old chain it is the fork. */
    @Test
    fun card0_ringsTheSocketsAlreadyOpen() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val op = Me("operator@example.com")
        Flow.register(client, s, op, Flow.setupAuth(s))
        val sock = socket(op.token)
        val before = s.db.read { currentRev(it) }
        Flow.finishSetupCardOnly(client, s, op)
        val after = s.db.read { currentRev(it) }
        assertTrue(after > before)
        sock.expectBell(after, "card 0")
        sock.close()
    }
}
