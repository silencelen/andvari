package io.silencelen.andvari.server

import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.InstanceResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** spec 03 §17: serving the chain and the setup block, signing cards, handover, variant R. */
class InstanceCardTest {
    private fun card0(s: Services, op: TestKit.Account, recoveryFp: String = "none", kind: String = s.config.instanceKind): ByteArray {
        val setup = s.db.read { s.instance.setupOn(it)!! }
        return op.identity.frame(
            4,
            TestKit.cardStatement(setup.instanceId, 0, TestKit.ZERO64, s.config.canonicalOrigin, setup.name, kind, op.userId, op.identity.edPub, recoveryFp, 1_800_000_000_000),
        )
    }

    private fun put(card: ByteArray, key: String) = """{"card":"${Bytes.toB64(card)}","currentAuthKey":"$key"}"""

    @Test
    fun setupBlockUntilCard0_thenChain_etag304() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val r0 = client.call(HttpMethod.Get, "/api/v1/instance")
        assertEquals(200, r0.status.value)
        val body0 = WireJson.json.decodeFromString(InstanceResponse.serializer(), r0.bodyAsText())
        assertTrue(body0.cards.isEmpty())
        val setup = assertNotNull(body0.setup)
        assertEquals(s.config.canonicalOrigin, setup.origin)
        assertEquals("none", setup.recoveryFp)
        assertNull(body0.rotations)
        assertTrue(r0.bodyAsText().contains("\"cards\":[]"))

        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val token = TestKit.session(s, op)
        val c0 = card0(s, op)
        val put = client.call(HttpMethod.Put, "/api/v1/instance/card", put(c0, op.authKey), token)
        assertEquals(200, put.status.value, put.bodyAsText())
        assertTrue(put.bodyAsText().contains(sha256Hex(c0)))

        val r1 = client.call(HttpMethod.Get, "/api/v1/instance")
        val body1 = WireJson.json.decodeFromString(InstanceResponse.serializer(), r1.bodyAsText())
        assertEquals(listOf(Bytes.toB64(c0)), body1.cards)
        assertEquals(emptyList(), body1.rotations)
        assertNull(body1.setup)
        val etag = r1.headers["ETag"]!!
        val r2 = client.call(HttpMethod.Get, "/api/v1/instance") { header("If-None-Match", etag) }
        assertEquals(304, r2.status.value)

        // The next card must sit at head+1 with prev = H(card 0): anything else carries the stored head.
        val stale = op.identity.frame(4, TestKit.cardStatement(s.db.read { s.instance.instanceId(it) }, 0, TestKit.ZERO64, s.config.canonicalOrigin, Grammar.nameOf("again")!!, "private", op.userId, op.identity.edPub, "none", 1))
        val moved = client.call(HttpMethod.Put, "/api/v1/instance/card", put(stale, op.authKey), token)
        assertEquals(409, moved.status.value)
        assertEquals("card_head_moved", moved.errorCode())
        assertTrue(moved.bodyAsText().contains("\"seq\":0"))
    }

    @Test
    fun callerChecks_notOperator_web_reauth() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val member = TestKit.seedAccount(s, "m@example.com")
        val c0 = card0(s, op)
        assertEquals("not_operator", client.call(HttpMethod.Put, "/api/v1/instance/card", put(c0, member.authKey), TestKit.session(s, member)).errorCode())
        assertEquals("operator_web_refused", client.call(HttpMethod.Put, "/api/v1/instance/card", put(c0, op.authKey), TestKit.session(s, op, platform = "web")).errorCode())
        val wrong = client.call(HttpMethod.Put, "/api/v1/instance/card", put(c0, Bytes.toB64(ByteArray(32))), TestKit.session(s, op))
        assertEquals(403, wrong.status.value)
        assertEquals("reauth_failed", wrong.errorCode())
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='reauth_fail'") })
        assertEquals("missing_token", client.call(HttpMethod.Put, "/api/v1/instance/card", put(c0, op.authKey)).errorCode())
        assertEquals("invalid_credentials", client.call(HttpMethod.Put, "/api/v1/instance/card", put(c0, op.authKey), "nope").errorCode())
    }

    @Test
    fun card0MustMatchSetup_andNameTheCaller() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val token = TestKit.session(s, op)
        // A recoveryFp the instance was not set up with.
        val bad = card0(s, op, recoveryFp = "a".repeat(64))
        assertEquals("bad_card", client.call(HttpMethod.Put, "/api/v1/instance/card", put(bad, op.authKey), token).errorCode())
        // A card 0 whose operator key is not the caller's identity.
        val other = TestKit.Identity()
        val setup = s.db.read { s.instance.setupOn(it)!! }
        val forged = other.frame(4, TestKit.cardStatement(setup.instanceId, 0, TestKit.ZERO64, s.config.canonicalOrigin, setup.name, "private", op.userId, other.edPub, "none", 1))
        assertEquals("bad_card", client.call(HttpMethod.Put, "/api/v1/instance/card", put(forged, op.authKey), token).errorCode())
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM instance_cards") })
    }

    @Test
    fun publicInstance_refusesRecoveryFpCard_andHidesRRoutes() = testApplication {
        val s = TestKit.services(TestKit.config(kind = "public"))
        application { andvariModule(s) }
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val token = TestKit.session(s, op)
        val withFp = card0(s, op, recoveryFp = "b".repeat(64))
        assertEquals("bad_card", client.call(HttpMethod.Put, "/api/v1/instance/card", put(withFp, op.authKey), token).errorCode())
        // R routes answer 404 before anything else, even to the operator with a valid body.
        val rot = client.call(HttpMethod.Put, "/api/v1/instance/rotation", """{"statement":"x","currentAuthKey":"${op.authKey}"}""", token)
        assertEquals(404, rot.status.value)
        assertEquals("not_found", rot.errorCode())
        assertEquals(404, client.call(HttpMethod.Get, "/api/v1/recovery-pubkey").status.value)
    }

    @Test
    fun handover_switchesTheOperatorRoleAtomically() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val next = TestKit.seedAccount(s, "next@example.com")
        val token = TestKit.session(s, op)
        val c0 = card0(s, op)
        assertEquals(200, client.call(HttpMethod.Put, "/api/v1/instance/card", put(c0, op.authKey), token).status.value)
        val setup = s.db.read { s.instance.setupOn(it)!! }
        // Card 1 is signed by card 0's operator key and names the next account.
        val c1 = op.identity.frame(4, TestKit.cardStatement(setup.instanceId, 1, sha256Hex(c0), s.config.canonicalOrigin, setup.name, "private", next.userId, next.identity.edPub, "none", 2))
        val r = client.call(HttpMethod.Put, "/api/v1/instance/card", put(c1, op.authKey), token)
        assertEquals(200, r.status.value, r.bodyAsText())
        assertEquals("member", s.db.read { c -> c.queryOne("SELECT role FROM users WHERE userId=?", op.userId) { it.getString(1) } })
        assertEquals("operator", s.db.read { c -> c.queryOne("SELECT role FROM users WHERE userId=?", next.userId) { it.getString(1) } })
        // The old operator's session is now a member session.
        assertEquals("not_operator", client.call(HttpMethod.Put, "/api/v1/instance/card", put(c1, op.authKey), token).errorCode())
    }

    @Test
    fun recoveryPubkey_servedOnlyWhileTheCardNamesIt() = testApplication {
        val key = TestKit.crypto.randomBytes(32)
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val r = client.call(HttpMethod.Get, "/api/v1/recovery-pubkey")
        assertEquals(200, r.status.value)
        assertEquals(Bytes.toB64(key), r.bodyAsText())
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val c0 = card0(s, op, recoveryFp = sha256Hex(key))
        assertEquals(200, client.call(HttpMethod.Put, "/api/v1/instance/card", put(c0, op.authKey), TestKit.session(s, op)).status.value)
        assertEquals(200, client.call(HttpMethod.Get, "/api/v1/recovery-pubkey").status.value)
    }
}
