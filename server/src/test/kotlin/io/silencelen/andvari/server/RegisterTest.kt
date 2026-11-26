package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.RegisterAuth
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** `POST /auth/register` (spec 03 §14.3): every auth kind and the check order. */
class RegisterTest {
    private suspend fun io.ktor.client.HttpClient.reg(s: Services, me: Me, auth: RegisterAuth, posture: String = "private", escrow: EscrowUpload? = null) =
        call(HttpMethod.Post, "/api/v1/auth/register", me.register(s, auth, posture, escrow))

    @Test
    fun setupThenCard0ThenEnrol_andTheStep2Gates() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        // Before any operator: an enrol link cannot even be minted (no card), and a ticket waits for card 0.
        assertEquals("setup_incomplete", c.reg(s, Me("a@example.com"), RegisterAuth.Ticket(Bytes.toB64(ByteArray(32)))).errorCode())
        val op = Me("operator@example.com")
        val opSession = Flow.register(c, s, op, Flow.setupAuth(s))
        assertEquals("operator", opSession.role)
        assertTrue(opSession.recoveryPieceId != null)
        // A second setup is refused once an operator exists.
        assertEquals("setup_done", c.reg(s, Me("b@example.com"), Flow.setupAuth(s)).errorCode())
        Flow.finishSetupCardOnly(c, s, op)
        val m = Me("member@example.com")
        Flow.register(c, s, m, Flow.enrolAuth(s))
        assertEquals("member", m.session!!.role)
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM vaults WHERE type='personal' AND vaultId=?", m.personalVaultId) })
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM devices WHERE userId=? AND how='registered' AND deviceSecretHash IS NOT NULL", m.userId) })
        // The account keys carry both the personal wrap and the genesis.
        val keys = c.call(HttpMethod.Get, "/api/v1/account/keys", token = m.token).bodyAsText()
        assertTrue(keys.contains("\"personalWrap\"") && keys.contains("\"genesis\""), keys)
    }

    @Test
    fun linkRowChecks_unknown_kind_used_expired_boundEmail() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val enrol = Flow.enrolAuth(s)
        assertEquals("link_unknown", c.reg(s, Me("x@example.com"), RegisterAuth.Enrol(enrol.linkId, Bytes.toB64(ByteArray(32)))).errorCode())
        val setupLink = Flow.setupAuth(s)
        assertEquals("kind_mismatch", c.reg(s, Me("x@example.com"), RegisterAuth.Enrol(setupLink.linkId, setupLink.registerToken)).errorCode())
        Flow.register(c, s, Me("first@example.com"), enrol)
        assertEquals("link_used", c.reg(s, Me("second@example.com"), enrol).errorCode())
        val late = Flow.enrolAuth(s)
        clock.advance(Clock.DAY_MS + 1)
        val expired = c.reg(s, Me("late@example.com"), late)
        assertEquals(410, expired.status.value)
        assertEquals("link_expired", expired.errorCode())
        val bound = Flow.enrolAuth(s, bound = "bound@example.com")
        assertEquals("email_mismatch", c.reg(s, Me("other@example.com"), bound).errorCode())
        Flow.register(c, s, Me("Bound@Example.com"), bound)
    }

    @Test
    fun laterSteps_cap_taken_retired_genesis_posture_vaultIds_memberRecovery() = testApplication {
        val s = TestKit.services(TestKit.config(signupCap = 2))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        Flow.member(c, s, "one@example.com")
        // Step 1: the kit is mandatory.
        val noKit = Me("nokit@example.com")
        assertEquals("recovery_required", c.call(HttpMethod.Post, "/api/v1/auth/register", noKit.register(s, Flow.enrolAuth(s), memberRecovery = null)).errorCode())
        // Step 6: the address is taken (case-folded).
        assertEquals("email_taken", c.reg(s, Me("ONE@example.com"), Flow.enrolAuth(s)).errorCode())
        // A retired id is taken for good.
        val retired = uuid()
        s.db.tx { it.exec("INSERT INTO retired_ids(idHash) VALUES(?)", sha256Hex(retired)) }
        assertEquals("user_id_taken", c.reg(s, Me("r@example.com", userId = retired), Flow.enrolAuth(s)).errorCode())
        // Step 7: a genesis for another instance.
        val g = Me("g@example.com")
        val body = g.register(s, Flow.enrolAuth(s)).replace(g.genesis(s.db.read { s.instance.instanceId(it) }), g.genesis(uuid()))
        assertEquals("bad_genesis", c.call(HttpMethod.Post, "/api/v1/auth/register", body).errorCode())
        // Step 8: no recovery key on this instance.
        val esc = EscrowUpload(Bytes.toB64(ByteArray(200)), "a".repeat(64))
        assertEquals("operator_recovery_unavailable", c.reg(s, Me("o@example.com"), Flow.enrolAuth(s), "operator", esc).errorCode())
        assertEquals("escrow_not_allowed", c.reg(s, Me("p@example.com"), Flow.enrolAuth(s), "private", esc).errorCode())
        // Step 9.
        val mm = Me("mm@example.com")
        assertEquals("personal_vault_mismatch", c.call(HttpMethod.Post, "/api/v1/auth/register", mm.register(s, Flow.enrolAuth(s), wrapVaultId = uuid())).errorCode())
        // Step 5: the cap counts active members only (2 here); the operator is not counted.
        Flow.member(c, s, "two@example.com")
        assertEquals("signup_full", c.reg(s, Me("three@example.com"), Flow.enrolAuth(s)).errorCode())
        s.db.tx { it.exec("UPDATE users SET status='disabled' WHERE email='two@example.com'") }
        Flow.member(c, s, "three@example.com")
    }

    @Test
    fun operatorPosture_withARecoveryCard() = testApplication {
        val key = TestKit.crypto.randomBytes(32)
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        // The operator account itself can never take operator recovery (S3-C8), at setup too.
        val esc = Flow.escrowFor("z@example.com", sha256Hex(key))
        assertEquals("operator_recovery_unavailable", c.reg(s, Me("op@example.com"), Flow.setupAuth(s), "operator", esc).errorCode())
        Flow.finishSetup(c, s)
        assertEquals("bad_escrow", c.reg(s, Me("x@example.com"), Flow.enrolAuth(s), "operator", EscrowUpload(Bytes.toB64(ByteArray(200)), "b".repeat(64))).errorCode())
        assertEquals("bad_escrow", c.reg(s, Me("y@example.com"), Flow.enrolAuth(s), "operator", EscrowUpload("AAAA", sha256Hex(key))).errorCode())
        val m = Me("z@example.com")
        Flow.register(c, s, m, Flow.enrolAuth(s), "operator", esc)
        assertEquals("operator", s.db.read { db -> db.queryOne("SELECT recovery FROM users WHERE userId=?", m.userId) { it.getString(1) } })
        assertNotNull(s.db.read { db -> db.queryOne("SELECT sealed FROM escrow WHERE userId=?", m.userId) { it.getString(1) } })
    }

    /** A sign-up ticket for [email], stored as `POST /signup/verify` stores one (spec 03 §14.2). */
    private fun ticket(s: Services, email: String): RegisterAuth.Ticket {
        val t = Bytes.toB64(TestKit.crypto.randomBytes(32))
        s.db.tx { it.exec("INSERT INTO signup_tickets(ticketHash,emailHash,expiresAt) VALUES(?,?,?)", ServerCrypto.hashToken(t), s.config.addressHash(email), s.clock.now() + Signup.TICKET_TTL_MS) }
        return RegisterAuth.Ticket(t)
    }

    @Test
    fun dailyMaximum_countsTodaysTicketAndLinkAccounts_fromRegisteredVia_notFromAudit() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(TestKit.config(mode = "open", signupDailyMax = 2), clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        for (e in listOf("t1@example.com", "t2@example.com")) Flow.register(c, s, Me(e), ticket(s, e))
        assertEquals(listOf("setup", "ticket", "ticket"), s.db.read { db -> db.queryAll("SELECT registeredVia FROM users ORDER BY registeredVia") { it.getString(1) } })
        // The third ticket account of the UTC day is refused, even when the audit rows are gone.
        s.db.tx { it.exec("DELETE FROM audit") }
        val t3 = c.call(HttpMethod.Post, "/api/v1/auth/register", Me("t3@example.com").register(s, ticket(s, "t3@example.com")))
        assertEquals(429, t3.status.value)
        assertEquals("signup_daily_max", t3.errorCode())
        // The refusal carries its wait, the time to the next midnight UTC (since 2026-11-17; before, no Retry-After), in
        // whole seconds rounded up, and it counts down with the clock.
        val midnight = Clock.utcDayStart(clock.now()) + Clock.DAY_MS
        assertEquals("${(midnight - clock.now() + 999) / 1000}", t3.headers["Retry-After"])
        clock.ms = midnight - 3 * Clock.HOUR_MS
        val later = c.call(HttpMethod.Post, "/api/v1/auth/register", Me("t3@example.com").register(s, ticket(s, "t3@example.com")))
        assertEquals("signup_daily_max", later.errorCode()); assertEquals("10800", later.headers["Retry-After"])
        clock.ms = midnight - 1
        val last = c.call(HttpMethod.Post, "/api/v1/auth/register", Me("t3@example.com").register(s, ticket(s, "t3@example.com")))
        assertEquals("signup_daily_max", last.errorCode()); assertEquals("1", last.headers["Retry-After"])
        // An enrol link counts against the cap only.
        Flow.member(c, s, "enrolled@example.com")
        // The next UTC day the budget is back.
        clock.ms = Clock.utcDayStart(clock.now()) + Clock.DAY_MS
        Flow.register(c, s, Me("t3@example.com"), ticket(s, "t3@example.com"))
    }
}
