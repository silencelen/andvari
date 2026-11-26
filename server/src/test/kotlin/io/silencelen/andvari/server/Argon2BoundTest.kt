package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.RegisterAuth
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Register refuses on its mode, ticket or link before any Argon2 work, and all Argon2 work is bounded. */
class Argon2BoundTest {
    @Test
    fun aRefusedRegister_doesNoArgon2Work() = testApplication {
        val s = TestKit.services(TestKit.config(mode = "links"))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val before = ServerCrypto.argon2Calls.get()
        // A ticket on a links-mode instance (signup closed to tickets), and an unknown enrol link.
        val closed = c.call(HttpMethod.Post, "/api/v1/auth/register", Me("a@example.com").register(s, RegisterAuth.Ticket(Bytes.toB64(ByteArray(32) { 1 }))))
        assertEquals(403, closed.status.value, closed.bodyAsText()); assertEquals("signup_closed", closed.errorCode())
        val unknown = c.call(HttpMethod.Post, "/api/v1/auth/register", Me("b@example.com").register(s, RegisterAuth.Enrol(Bytes.toB64(ByteArray(16) { 2 }), Bytes.toB64(ByteArray(32) { 3 }))))
        assertEquals(404, unknown.status.value, unknown.bodyAsText()); assertEquals("link_unknown", unknown.errorCode())
        assertEquals(before, ServerCrypto.argon2Calls.get(), "no hash for a refused register")
    }

    /**
     * Whoever holds a link not bound to an address learns from `409 email_taken` that an address is taken (accepted,
     * spec 05); since 2026-11-17 such a try costs no hash, because the address is looked up before the hashing. The
     * answer is as before, and the link is not used up.
     */
    @Test
    fun aRegisterWithATakenAddress_doesNoArgon2Work_andIsAnsweredAsBefore() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        Flow.member(c, s, "taken@example.com")
        val link = Flow.enrolAuth(s)
        val before = ServerCrypto.argon2Calls.get()
        val taken = c.call(HttpMethod.Post, "/api/v1/auth/register", Me("Taken@example.com").register(s, link))
        assertEquals(409, taken.status.value, taken.bodyAsText()); assertEquals("email_taken", taken.errorCode())
        assertEquals(before, ServerCrypto.argon2Calls.get(), "no hash for a taken address")
        val free = c.call(HttpMethod.Post, "/api/v1/auth/register", Me("free@example.com").register(s, link))
        assertEquals(200, free.status.value, free.bodyAsText())
    }

    @Test
    fun argon2Work_neverRunsMoreThanThePermitsAtOnce() {
        ServerCrypto.argon2MaxInFlight.set(0)
        val pool = Executors.newFixedThreadPool(16)
        val go = CountDownLatch(1)
        val done = CountDownLatch(16)
        repeat(16) {
            pool.execute {
                go.await()
                ServerCrypto.hashVerifier(Bytes.toB64(ByteArray(32) { it.toByte() }))
                done.countDown()
            }
        }
        go.countDown()
        done.await()
        pool.shutdown()
        val max = ServerCrypto.argon2MaxInFlight.get()
        assertTrue(max in 1..ServerCrypto.ARGON2_PERMITS, "at most ${ServerCrypto.ARGON2_PERMITS} at once, saw $max")
    }
}
