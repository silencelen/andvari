package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import io.ktor.client.statement.HttpResponse
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout

/**
 * HIBP k-anonymity range relay for ITEM passwords (spec 03 §8). The client sends only a
 * 5-hex-char prefix; HIBP never sees a full hash or the client IP.
 *
 * Stateless on purpose (security review 2026-10, root cause C): the relay used to keep each
 * prefix in `hibp_cache(prefix, body, fetchedAt)` for up to 45 days, and a cache row written
 * seconds after a `register` or `password_change` audit row was 20 bits of that account's
 * master-password SHA-1, sitting in the same database as its Argon2id verifier. No client sends
 * a master-password prefix any more, but the server cannot tell an item prefix from any other,
 * so it keeps none: nothing here is written to the database, the log or the audit trail.
 */
class HibpRelay(private val http: HttpClient, private val timeoutMs: Long = 10_000) {
    suspend fun range(prefix: String): String {
        val p = prefix.uppercase()
        require(p.length == 5 && p.all { it in "0123456789ABCDEF" }) { "bad prefix" }
        // Bound the upstream call like GraphEmailSender's withTimeout (bug-server--2): a
        // black-holed HIBP must not park the request coroutine forever — the web Health scan
        // awaits these sequentially and would hang with it. Timeout and non-2xx both surface
        // as 502-class [BadGateway] ("HIBP is down"), never a 400 ("your prefix was bad").
        val resp: HttpResponse = try {
            withTimeout(timeoutMs) {
                http.get("https://api.pwnedpasswords.com/range/$p") {
                    header("Add-Padding", "true")
                    header("User-Agent", "andvari-hibp-relay")
                }
            }
        } catch (e: TimeoutCancellationException) {
            throw BadGateway("hibp_timeout")
        }
        if (!resp.status.isSuccess()) throw BadGateway("hibp_upstream_${resp.status.value}")
        return resp.bodyAsText()
    }
}
