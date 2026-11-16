package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.LoginRequest
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The email backoff reserves an attempt before the verify. It used to check the lock before the
 * Argon2id verify and count the failure after it, so requests for one address sent at the same moment
 * (each from its own client address, past every per-IP bucket) all passed the check and were all
 * verified: once the lock was at its cap, a caller with B addresses had 5·B guesses per lock period
 * instead of one.
 */
class LoginBackoffConcurrencyTest : P4TestSupport() {

    private fun attempt(services: Services, email: String, i: Int): String = try {
        services.service.login(LoginRequest(email, "d3JvbmcgcGFzc3dvcmQ", DeviceInfo("test", "t")), "198.51.100.$i")
        "ok"
    } catch (e: Unauthorized) {
        "401"
    } catch (e: RateLimited) {
        "429"
    }

    @Test
    fun attemptsSentAtOnce_getNoMoreVerifiesThanTheThreshold() {
        val services = buildServices(config(), Notifier())
        val n = 8
        val pool = Executors.newFixedThreadPool(n)
        val barrier = CyclicBarrier(n)
        try {
            val futures = (1..n).map { i -> pool.submit<String> { barrier.await(); attempt(services, "parallel@example.com", i) } }
            val outcomes = futures.map { it.get(120, TimeUnit.SECONDS) }.sorted()
            assertEquals(List(5) { "401" } + List(n - 5) { "429" }, outcomes, "five verifies, then the lock, however the requests interleave")
        } finally {
            pool.shutdownNow()
        }
        // Rows: one login_fail per verify that ran, none for a refused attempt.
        assertEquals(5, services.repo.auditQuery(0, "login_fail", null, 50).size)
    }

    @Test
    fun attemptsInSequence_lockAfterFive_asBefore() {
        val services = buildServices(config(), Notifier())
        val outcomes = (1..7).map { attempt(services, "sequential@example.com", it) }
        assertEquals(List(5) { "401" } + listOf("429", "429"), outcomes)
    }
}
