package io.silencelen.andvari.server

import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Spec 05 T11, spec 03 §8: the email backoff reserves an attempt before the verify. */
class BackoffReserveTest {
    @Test
    fun reserve_isAtomic_acrossThreads() {
        val b = EmailBackoff()
        val pool = Executors.newFixedThreadPool(16)
        val go = CountDownLatch(1)
        val admitted = AtomicInteger()
        val done = CountDownLatch(64)
        repeat(64) {
            pool.execute {
                go.await()
                if (b.reserve("victim@example.com")) admitted.incrementAndGet()
                done.countDown()
            }
        }
        go.countDown()
        done.await()
        pool.shutdown()
        assertEquals(5, admitted.get(), "five attempts before the lock, however many arrive at once")
        b.success("victim@example.com")
        assertTrue(b.reserve("victim@example.com"), "a verified attempt clears the state")
    }

    @Test
    fun simultaneousWrongPasswords_getFiveVerifiesNotNine() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val statuses = coroutineScope {
            List(9) { i -> async { c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(secret = b32(), authKey = b32()), ip = "10.9.9.${i + 1}").status.value } }.awaitAll()
        }
        assertEquals(5, statuses.count { it == 401 }, "statuses $statuses")
        assertEquals(4, statuses.count { it == 429 }, "statuses $statuses")
        assertEquals(5L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='login_fail'") })
        // A correct password is then refused until the lock lapses, as before.
        assertEquals(429, c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody()).status.value)
    }
}
