package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import io.ktor.client.statement.HttpResponse

/**
 * HIBP k-anonymity range relay + 7-day cache (spec 03 §8). The client sends only a
 * 5-hex-char prefix; HIBP never sees a full hash or the client IP.
 */
class HibpRelay(private val repo: Repo, private val http: HttpClient) {
    private val cacheMaxAgeMs = 7L * 24 * 3600 * 1000

    suspend fun range(prefix: String): String {
        val p = prefix.uppercase()
        require(p.length == 5 && p.all { it in "0123456789ABCDEF" }) { "bad prefix" }
        repo.hibpCached(p, cacheMaxAgeMs)?.let { return it }
        val resp: HttpResponse = http.get("https://api.pwnedpasswords.com/range/$p") {
            header("Add-Padding", "true")
            header("User-Agent", "andvari-hibp-relay")
        }
        if (!resp.status.isSuccess()) throw BadRequest("hibp_upstream_${resp.status.value}")
        val body = resp.bodyAsText()
        repo.hibpStore(p, body)
        return body
    }
}
