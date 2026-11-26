package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Account deletion checks the password proof before the two-step code (spec 03 §13), as turning two-step sign-in off
 * and replacing its secret do. Before, the route looked at the code first, so a session in the wrong hands learnt from
 * `bad_totp_code` against `reauth_failed` whether a code was right. Now a wrong or missing proof is answered the same
 * for a right code, a wrong one and none, and nothing is consumed: no step, no count on the codes' back-off, no
 * `totp_verify_fail` row. The proof draws on the proofs' back-off; the code, once the proof passed, on the codes'.
 */
class AccountDeleteProofFirstTest {
    private val post = HttpMethod.Post

    private companion object {
        const val DELETE = "/api/v1/account/delete"
    }

    private fun code(secret: String, clock: Clock) = Flow.totp(secret, clock.now())

    private fun wrong(secret: String, clock: Clock): String {
        val near = (-1..1).map { Flow.totp(secret, clock.now() + it * 30_000L) }.toSet()
        return (0..9).map { "$it".repeat(6) }.first { it !in near }
    }

    private fun body(me: Me, code: String?, key: String?) = listOfNotNull(
        "\"confirmEmail\":\"${me.email}\"",
        key?.let { "\"currentAuthKey\":\"$it\"" },
        code?.let { "\"totp\":\"$it\"" },
        "\"leaves\":[]",
    ).joinToString(",", "{", "}")

    private suspend fun enrol(c: HttpClient, clock: MutableClock, me: Me): String {
        val setup = c.call(post, "/api/v1/account/totp/setup", """{"currentAuthKey":"${me.authKey}"}""", me.token)
        assertEquals(200, setup.status.value, setup.bodyAsText())
        val secret = WireJson.json.decodeFromString(TotpSetupResponse.serializer(), setup.bodyAsText()).secretBase32
        assertEquals(200, c.call(post, "/api/v1/account/totp/confirm", """{"code":"${code(secret, clock)}"}""", me.token).status.value)
        clock.advance(30_000)
        return secret
    }

    private fun lastStep(s: Services, userId: String) =
        s.db.read { it.queryOne("SELECT totpLastStep FROM users WHERE userId=?", userId) { r -> r.getLong(1) } }

    private fun rows(s: Services, type: String, userId: String) =
        s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type=? AND userId=?", type, userId) }

    private fun exists(s: Services, userId: String) =
        s.db.read { it.queryOne("SELECT userId FROM users WHERE userId=?", userId) { r -> r.getString(1) } }

    @Test
    fun aWrongOrMissingProof_tellsNothingOfTheCode_andTheCodeIsCheckedOnlyAfterIt() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val a = enrol(c, clock, me)
        val step = lastStep(s, me.userId)
        // A wrong proof, then none at all: a right code, a wrong one and no code get the same bytes.
        var wrongProofs = 0L
        for (k in listOf(b32(), null)) {
            val answers = listOf(code(a, clock), wrong(a, clock), null).map { t ->
                s.limiter.clear()
                c.call(post, DELETE, body(me, t, k), me.token).let { it.status.value to it.bodyAsText() }
            }
            if (k != null) wrongProofs += answers.size
            val expect = if (k == null) "bad_request" else "reauth_failed"
            assertEquals(if (k == null) 400 else 403, answers[0].first, "proof $k: ${answers[0].second}")
            assertEquals(expect, WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.WireError.serializer(), answers[0].second).error)
            assertEquals(1, answers.toSet().size, "proof $k: the answer tells nothing of the code: $answers")
        }
        // Nothing happened to the code: no step consumed, nothing counted or recorded; the wrong proofs were recorded.
        assertEquals(step, lastStep(s, me.userId))
        assertEquals(0L, rows(s, "totp_verify_fail", me.userId))
        assertEquals(0L, s.codeLock(me))
        assertEquals(wrongProofs, rows(s, "account_delete_reauth_fail", me.userId))
        assertNotNull(exists(s, me.userId))
        // With the right proof the code is looked at: none is asked for, a wrong one is a wrong code (recorded) ...
        s.limiter.clear()
        assertEquals("totp_code_required", c.call(post, DELETE, body(me, null, me.authKey), me.token).errorCode())
        s.limiter.clear()
        assertEquals("bad_totp_code", c.call(post, DELETE, body(me, wrong(a, clock), me.authKey), me.token).errorCode())
        assertEquals(1L, rows(s, "totp_verify_fail", me.userId))
        assertEquals(step, lastStep(s, me.userId))
        // ... and the very code the refused requests carried, still unspent, deletes the account.
        s.limiter.clear()
        val ok = c.call(post, DELETE, body(me, code(a, clock), me.authKey), me.token)
        assertEquals(200, ok.status.value, ok.bodyAsText())
        assertNull(exists(s, me.userId))
    }

    @Test
    fun wrongProofsRunIntoTheProofsBackoff_andTheCodesAreNeverCounted() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val a = enrol(c, clock, me)
        val step = lastStep(s, me.userId)
        // Five wrong proofs, with right and wrong codes in turn: five reauth_failed, and the proofs' lock.
        val answers = (1..5).map { n ->
            s.limiter.clear()
            val r = c.call(post, DELETE, body(me, if (n % 2 == 0) code(a, clock) else wrong(a, clock), b32()), me.token)
            "${r.status.value}:${r.errorCode()}"
        }
        assertEquals(List(5) { "403:reauth_failed" }, answers)
        assertEquals(0L, rows(s, "totp_verify_fail", me.userId))
        assertEquals(0L, s.codeLock(me))
        // Now the right proof with the right code is refused by the proofs' back-off before either is looked at,
        // and so is the right proof with a wrong code, with the same bytes.
        s.limiter.clear()
        val locked = c.call(post, DELETE, body(me, code(a, clock), me.authKey), me.token)
        // The wait named is the lock's real one: one second after the fifth wrong proof (spec 03 §8, since 2026-11-17).
        assertEquals(429, locked.status.value, locked.bodyAsText()); assertEquals("1", locked.headers["Retry-After"])
        s.limiter.clear()
        val lockedWrong = c.call(post, DELETE, body(me, wrong(a, clock), me.authKey), me.token)
        assertEquals(locked.status.value, lockedWrong.status.value); assertEquals(locked.bodyAsText(), lockedWrong.bodyAsText())
        assertEquals(step, lastStep(s, me.userId))
        assertEquals(0L, rows(s, "totp_verify_fail", me.userId))
        assertEquals(5L, rows(s, "account_delete_reauth_fail", me.userId))
        assertNotNull(exists(s, me.userId))
        // When it lapses, the right proof and the right code delete the account.
        clock.advance(1_000)
        s.limiter.clear()
        val ok = c.call(post, DELETE, body(me, code(a, clock), me.authKey), me.token)
        assertEquals(200, ok.status.value, ok.bodyAsText())
        assertNull(exists(s, me.userId))
    }
}
