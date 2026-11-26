package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminPolicyPut
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireJson
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The hashing cost the server serves is never below its own floor (spec 03 §1.1, §2, §7.2), whatever is stored and
 * whenever the floor was raised: the accounts are made on a server without a floor, which is then started again with the
 * operator's raised floor on the same database, as a real operator raises it.
 */
class KdfFloorServedTest {
    private val post = HttpMethod.Post
    private val json = WireJson.json

    private fun kdfJson(k: KdfParams) = json.encodeToString(KdfParams.serializer(), k)

    private suspend fun policy(c: HttpClient): KdfParams =
        json.decodeFromString(ClientPolicy.serializer(), c.call(HttpMethod.Get, "/api/v1/client-policy").bodyAsText()).kdfParams

    private suspend fun prelogin(c: HttpClient, email: String): KdfParams =
        json.decodeFromString(PreloginResponse.serializer(), c.call(post, "/api/v1/auth/prelogin", """{"email":"$email"}""").bodyAsText()).kdfParams

    /** What a client sends at a recovery with the kit: a ticket, then the commit at the cost [k]. */
    private suspend fun recover(c: HttpClient, me: Me, k: KdfParams, newRecoveryAuthKey: String) = run {
        val ticket = json.decodeFromString(
            RecoveryVerifyResponse.serializer(),
            c.call(post, "/api/v1/recovery/self/verify", """{"email":"${me.email}","recoveryAuthKey":"${me.recoveryAuthKey}"}""").bodyAsText(),
        ).recoveryTicket
        c.call(
            post, "/api/v1/recovery/self/commit",
            """{"recoveryTicket":"$ticket","newAuthKey":"${b32()}","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 4 })}","newKdfParams":${kdfJson(k)},""" +
                """"newWrappedUvk":"AAAA","newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"$newRecoveryAuthKey"},""" +
                """"device":{"platform":"android","name":"phone","deviceSecret":"${b32()}"}}""",
        )
    }

    private fun b32() = Bytes.toB64(TestKit.crypto.randomBytes(32))

    @Test
    fun noPolicyStored_theServedCostMeetsTheRaisedFloor_andARecoveryThatFollowsItIsTaken() {
        val dir = TestKit.tempDir()
        lateinit var me: Me
        // Before: no floor; the member's account is made at the tests' fast cost, under the tests' policy, which is then
        // removed: the server starts again with nothing stored.
        val before = TestKit.services(TestKit.config(dir))
        testApplication {
            application { andvariModule(before) }
            Flow.finishSetup(client, before)
            me = Flow.member(client, before, "me@example.com")
            before.db.tx { it.exec("DELETE FROM policies") }
            before.policy.invalidate()
            assertEquals(KdfParams.DEFAULT, policy(client))
        }
        before.db.close()
        // The operator raises the floor above the default on both figures; the memory floor is not a whole KiB.
        val s = TestKit.services(TestKit.config(dir, minKdfOps = 4, minKdfMemBytes = 100_000_000), policyKdf = null)
        testApplication {
            application { andvariModule(s) }
            val c = client
            val served = policy(c)
            assertEquals(KdfParams(ops = 4, memBytes = 97_657L * 1024), served, "each figure at least the floor's, the memory a whole KiB")
            // An address without an account is answered with the same cost; an account's own stays its own.
            assertEquals(served, prelogin(c, "nobody@example.com"))
            assertEquals(TestKit.FAST_KDF, prelogin(c, me.email))
            // A commit below the floor is still refused, and changes nothing.
            val weak = recover(c, me, served.copy(ops = 3), b32())
            assertEquals(400, weak.status.value, weak.bodyAsText()); assertEquals("kdf_too_weak", weak.errorCode())
            assertEquals(TestKit.FAST_KDF, prelogin(c, me.email))
            // A recovery that follows the served policy is taken, and the account's cost is then the served one.
            val r = recover(c, me, served, b32())
            assertEquals(200, r.status.value, r.bodyAsText())
            assertEquals(served, json.decodeFromString(SessionResponse.serializer(), r.bodyAsText()).accountKeys.kdfParams)
            assertEquals(served, prelogin(c, me.email))
        }
    }

    /**
     * The floor for a new wrap applies to each figure by itself, on every route that stores one (decided on 2026-11-17):
     * the cost the server serves (the policy's, raised to the environment's floor) on passes and on memory alike. The web
     * client's journey found the sequence: an account at 4 passes over 64 MiB; the operator raises the policy to 3 passes
     * over 128 MiB; a password change at 4 passes over 64 MiB was stored, below the policy's memory figure, because a new
     * wrap was held only to the environment's floor. Now it is refused as `kdf_too_weak`, and so is one below on passes;
     * the higher of each figure (4 passes, 128 MiB) is taken. A recovery's commit and a registration are held the same.
     */
    @Test
    fun aNewWrap_meetsTheServedCost_onEachFigure_onEveryRouteThatStoresOne() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "rae@example.com")
        val mib = 1024L * 1024
        var current = me.authKey
        suspend fun change(k: KdfParams) = run {
            s.limiter.clear()
            val next = b32()
            val r = c.call(
                HttpMethod.Put, "/api/v1/account/password",
                """{"currentAuthKey":"$current","newAuthKey":"$next","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 6 })}","newKdfParams":${kdfJson(k)},"newWrappedUvk":"AAAA"}""",
                me.token,
            )
            if (r.status.value == 200) current = next
            r
        }
        suspend fun policyCost(k: KdfParams) {
            clock.advance(Clock.MINUTE_MS)
            s.limiter.clear()
            val p = json.decodeFromString(AdminPolicy.serializer(), c.call(HttpMethod.Get, "/api/v1/admin/policy", token = op.token).bodyAsText())
            val r = c.call(HttpMethod.Put, "/api/v1/admin/policy", json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(p.copy(kdfParams = k), op.authKey)), op.token)
            assertEquals(200, r.status.value, r.bodyAsText())
        }
        suspend fun stored() = prelogin(c, me.email)

        // The account at 4 passes over 64 MiB, then the policy raised to 3 passes over 128 MiB.
        assertEquals(200, change(KdfParams(ops = 4, memBytes = 64 * mib)).status.value)
        policyCost(KdfParams(ops = 3, memBytes = 128 * mib))
        assertEquals(KdfParams(ops = 3, memBytes = 128 * mib), policy(c))

        // The account's own cost: above on passes, below on memory. Refused, with the figure named; nothing stored.
        val below = change(KdfParams(ops = 4, memBytes = 64 * mib))
        val text = below.bodyAsText()
        assertEquals(400, below.status.value, text)
        assertEquals("kdf_too_weak", below.errorCode())
        assertEquals(true, "kdfParams.memBytes=${64 * mib}" in text, text)
        // Above on memory, below on passes: refused too.
        val fewer = change(KdfParams(ops = 2, memBytes = 256 * mib))
        assertEquals("kdf_too_weak", fewer.errorCode(), fewer.bodyAsText())
        assertEquals(KdfParams(ops = 4, memBytes = 64 * mib), stored(), "nothing was stored")
        // The higher of each figure is taken.
        assertEquals(200, change(KdfParams(ops = 4, memBytes = 128 * mib)).status.value)
        assertEquals(KdfParams(ops = 4, memBytes = 128 * mib), stored())

        // A recovery's commit below the served memory is refused; one at the served cost is taken.
        s.limiter.clear()
        val weak = recover(c, me, KdfParams(ops = 4, memBytes = 64 * mib), b32())
        assertEquals("kdf_too_weak", weak.errorCode(), weak.bodyAsText())
        s.limiter.clear()
        assertEquals(200, recover(c, me, KdfParams(ops = 3, memBytes = 128 * mib), b32()).status.value)

        // A registration at the tests' fast cost, below both figures now, is refused.
        val late = Me("late@example.com")
        val r = c.call(HttpMethod.Post, "/api/v1/auth/register", late.register(s, Flow.enrolAuth(s)))
        assertEquals("kdf_too_weak", r.errorCode(), r.bodyAsText())
    }

    /**
     * A policy the operator writes later is held to the floor's limits, with the floor's lines (decided on 2026-11-17): a
     * cost above what the clients accept (10 passes, 1 GiB) or above the server's own limit (64 passes, 4 GiB) is refused
     * at the write, `400 kdf_too_weak` with the line as its message, and the served cost stays as it was. Before, 11
     * passes and 2 GiB were taken and served, and every client then refused the served cost. The clients' own limits are
     * taken.
     */
    @Test
    fun aPolicyWrittenLater_isHeldToTheFloorsLimits_withTheSameLines() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val p = json.decodeFromString(AdminPolicy.serializer(), c.call(HttpMethod.Get, "/api/v1/admin/policy", token = op.token).bodyAsText())
        val served = policy(c)
        val gib = 1L shl 30
        val refused = listOf(
            KdfParams(ops = 11, memBytes = 64L * 1024 * 1024) to "kdfParams.ops=11 is above what the clients accept (at most 10 passes, spec 01 §7)",
            KdfParams(ops = 3, memBytes = 2 * gib) to "kdfParams.memBytes=${2 * gib} is above what the clients accept (at most $gib bytes, spec 01 §7)",
            KdfParams(ops = 65, memBytes = 64L * 1024 * 1024) to "kdfParams.ops=65 is above the server's own upper limit for a stored hashing cost (64 passes)",
            KdfParams(ops = 3, memBytes = 5 * gib) to "kdfParams.memBytes=${5 * gib} is above the server's own upper limit for a stored hashing cost (${4 * gib} bytes)",
        )
        for ((k, line) in refused) {
            s.limiter.clear()
            val r = c.call(HttpMethod.Put, "/api/v1/admin/policy", json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(p.copy(kdfParams = k), op.authKey)), op.token)
            val text = r.bodyAsText()
            assertEquals(400, r.status.value, "$k $text")
            assertEquals("kdf_too_weak", r.errorCode())
            assertEquals(true, line in text, "$k: $text")
            assertEquals(served, policy(c), "nothing stored for $k")
        }
        // The clients' own limits are taken.
        s.limiter.clear()
        val top = KdfParams(ops = 10, memBytes = gib)
        val ok = c.call(HttpMethod.Put, "/api/v1/admin/policy", json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(p.copy(kdfParams = top), op.authKey)), op.token)
        assertEquals(200, ok.status.value, ok.bodyAsText())
        assertEquals(top, policy(c))
    }

    @Test
    fun aPolicyStoredBeforeTheFloorWasRaised_isServedRaisedFigureByFigure_andTheOperatorsRoundTripIsTaken() {
        val dir: File = TestKit.tempDir()
        val clock = MutableClock()
        lateinit var op: Me
        val stored = KdfParams(ops = 3, memBytes = 256L * 1024 * 1024)
        val before = TestKit.services(TestKit.config(dir), clock)
        testApplication {
            application { andvariModule(before) }
            op = Flow.finishSetup(client, before)
            val p = json.decodeFromString(AdminPolicy.serializer(), client.call(HttpMethod.Get, "/api/v1/admin/policy", token = op.token).bodyAsText())
            val r = client.call(HttpMethod.Put, "/api/v1/admin/policy", json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(p.copy(kdfParams = stored, autoLockSeconds = 120), op.authKey)), op.token)
            assertEquals(200, r.status.value, r.bodyAsText())
        }
        before.db.close()
        // The floor is raised above the stored passes and below its stored memory.
        val s = TestKit.services(TestKit.config(dir, minKdfOps = 5, minKdfMemBytes = 128L * 1024 * 1024), clock)
        testApplication {
            application { andvariModule(s) }
            val c = client
            val raised = KdfParams(ops = 5, memBytes = 256L * 1024 * 1024)
            assertEquals(raised, policy(c))
            assertEquals(raised, prelogin(c, "nobody@example.com"))
            // The operator sees the cost in force, and sending the policy back with another field changed is taken.
            val seen = json.decodeFromString(AdminPolicy.serializer(), c.call(HttpMethod.Get, "/api/v1/admin/policy", token = op.token).bodyAsText())
            assertEquals(raised, seen.kdfParams)
            assertEquals(120L, seen.autoLockSeconds)
            clock.advance(Clock.MINUTE_MS)
            val r = c.call(HttpMethod.Put, "/api/v1/admin/policy", json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(seen.copy(autoLockSeconds = 60), op.authKey)), op.token)
            assertEquals(200, r.status.value, r.bodyAsText())
            // A policy below the floor is still refused at the operator's write.
            clock.advance(Clock.MINUTE_MS)
            val low = c.call(HttpMethod.Put, "/api/v1/admin/policy", json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(seen.copy(kdfParams = stored), op.authKey)), op.token)
            assertEquals("kdf_too_weak", low.errorCode())
            assertEquals(raised, policy(c))
        }
    }
}
