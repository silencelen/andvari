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
 * HIBP k-anonymity range relay + 7-day cache (spec 03 §8). The client sends only a
 * 5-hex-char prefix; HIBP never sees a full hash or the client IP.
 */
class HibpRelay(private val repo: Repo, private val http: HttpClient, private val timeoutMs: Long = 10_000) {
    private val cacheMaxAgeMs = 7L * 24 * 3600 * 1000

    suspend fun range(prefix: String): String {
        val p = prefix.uppercase()
        require(p.length == 5 && p.all { it in "0123456789ABCDEF" }) { "bad prefix" }
        repo.hibpCached(p, cacheMaxAgeMs)?.let { return it }
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
        val body = resp.bodyAsText()
        repo.hibpStore(p, body)
        return body
    }
}
