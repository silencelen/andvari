package io.silencelen.andvari.cli

import com.sun.net.httpserver.HttpServer
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

/**
 * A hostile server in front of [s]: every request goes on to the real server, and [lie] rewrites the JSON answer (a 200,
 * or any status when the route is in [anyStatus]) of the routes it names. A run reaches it with `dial = address`, so the
 * tool still names the real origin ([io.silencelen.andvari.cli.e2e.Redirect]).
 */
class LyingProxy(private val s: TestServer) : AutoCloseable {
    @Volatile var lie: Map<WireRoute, (JsonElement) -> JsonElement> = emptyMap()
    @Volatile var anyStatus: Set<WireRoute> = emptySet()

    /**
     * Routes the proxy answers itself: the function gets the request's body and a call that forwards it to the real server
     * (its status and body), and answers with a status and a JSON body. A route that is never forwarded is a change the
     * server never stores; one forwarded and answered otherwise is a change stored behind another answer.
     */
    @Volatile var answer: Map<WireRoute, (ByteArray, () -> Pair<Int, ByteArray>) -> Pair<Int, String>> = emptyMap()

    /**
     * Routes whose requests the real server never gets, and whose connection is closed with nothing answered. To the tool
     * that is no answer at all (a transport failure), a server that was not reached at that step.
     */
    @Volatile var cut: Set<WireRoute> = emptySet()

    /** Every request that passed, in order, as `METHOD /path?query`: what a test counts, and what a [lie] may read. */
    val seen: MutableList<String> = java.util.Collections.synchronizedList(ArrayList())

    private val born = System.nanoTime()

    /**
     * Every request as [seen] has it, with when it arrived and when its answer was done (milliseconds since this proxy
     * started), and the answer's status: what a test prints when something took longer than it should.
     */
    val timed: MutableList<String> = java.util.Collections.synchronizedList(ArrayList())

    private fun ms(): Long = (System.nanoTime() - born) / 1_000_000

    /**
     * How many of the next requests that carry a password proof (`currentAuthKey`) go on with that proof changed (one
     * character, so it stays well formed and is wrong). The tool proves a password on the device first and sends nothing
     * for a wrong one, so a test that needs wrong proofs to reach the server on the account's own session (the server's
     * proof back-off, spec 03 §8, counts only those) makes them here, from the right one on its way.
     */
    @Volatile var wrongProofs: Int = 0

    /** How many proofs were changed on their way ([wrongProofs]). */
    val proofsChanged = java.util.concurrent.atomic.AtomicInteger()

    /** Every `Retry-After` the real server sent, as (request as in [seen], the server's value), in order. */
    val retryAfters: MutableList<Pair<String, String>> = java.util.Collections.synchronizedList(ArrayList())

    /** When set, the `Retry-After` the tool receives is this function of the server's own (which [retryAfters] keeps). */
    @Volatile var retryAfterAs: ((String) -> String)? = null

    private fun withWrongProof(body: ByteArray): ByteArray {
        synchronized(this) {
            if (wrongProofs <= 0 || body.isEmpty()) return body
            val o = runCatching { Json.parseToJsonElement(String(body)) as? kotlinx.serialization.json.JsonObject }.getOrNull() ?: return body
            val proof = (o["currentAuthKey"] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content ?: return body
            if (proof.isEmpty()) return body
            wrongProofs--
            proofsChanged.incrementAndGet()
            val changed = (if (proof[0] == 'A') "B" else "A") + proof.substring(1)
            return kotlinx.serialization.json.JsonObject(o + ("currentAuthKey" to kotlinx.serialization.json.JsonPrimitive(changed))).toString().toByteArray()
        }
    }

    private val http = HttpClient.newHttpClient()
    private val server = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 50).apply {
        createContext("/") { ex ->
            val at = ms()
            try {
                seen += "${ex.requestMethod} ${ex.requestURI}"
                val body = withWrongProof(ex.requestBody.readBytes())
                val path = ex.requestURI.rawPath
                val req = HttpRequest.newBuilder(URI.create(s.origin + ex.requestURI.toString())).method(ex.requestMethod, HttpRequest.BodyPublishers.ofByteArray(body))
                for ((k, vs) in ex.requestHeaders) if (k.lowercase() !in RESTRICTED) vs.forEach { req.header(k, it) }
                val route = WireRoute.entries.firstOrNull { it.method == ex.requestMethod && pathOf(it).matches(path) }
                if (route != null && route in cut) {
                    // The connection is closed with nothing sent: a handler that throws before it answers has its
                    // connection closed by the server. (This used to send a status line, promise a body and write one byte
                    // of it. Closing the body then only marked the exchange closed and left the socket open, so the device
                    // waited its whole request time, a minute, for bytes that never came; and with the socket really closed
                    // after the byte, whether the device read that as no answer or as an answer it could not use depended
                    // on timing.)
                    throw java.io.IOException("cut by the proxy before any answer")
                }
                val own = route?.let { answer[it] }
                if (own != null) {
                    val (status, text) = own(body) { http.send(req.build(), HttpResponse.BodyHandlers.ofByteArray()).let { it.statusCode() to it.body() } }
                    val bytes = text.toByteArray()
                    ex.responseHeaders.add("Content-Type", "application/json")
                    ex.sendResponseHeaders(status, if (bytes.isEmpty()) -1 else bytes.size.toLong())
                    if (bytes.isNotEmpty()) ex.responseBody.write(bytes)
                    return@createContext
                }
                val r = http.send(req.build(), HttpResponse.BodyHandlers.ofByteArray())
                val rewrite = route?.let { lie[it] }
                val answer = if (rewrite != null && (r.statusCode() == 200 || route in anyStatus)) {
                    rewrite(Json.parseToJsonElement(String(r.body()))).toString().toByteArray()
                } else r.body()
                for ((k, vs) in r.headers().map()) if (k.lowercase() !in RESTRICTED && k != ":status") vs.forEach { v ->
                    if (k.equals("retry-after", ignoreCase = true)) {
                        retryAfters += "${ex.requestMethod} ${ex.requestURI}" to v
                        ex.responseHeaders.add(k, retryAfterAs?.invoke(v) ?: v)
                    } else ex.responseHeaders.add(k, v)
                }
                ex.sendResponseHeaders(r.statusCode(), if (answer.isEmpty()) -1 else answer.size.toLong())
                if (answer.isNotEmpty()) ex.responseBody.write(answer)
            } finally {
                ex.close()
                timed += "$at..${ms()} ms  ${ex.requestMethod} ${ex.requestURI} -> ${ex.responseCode}"
            }
        }
        start()
    }
    val address = "http://127.0.0.1:${server.address.port}"
    override fun close() = server.stop(0)

    companion object {
        private val RESTRICTED = setOf("host", "content-length", "connection", "transfer-encoding", "upgrade", "expect", "keep-alive")

        /** [route]'s path with each `{param}` matching one path segment. */
        fun pathOf(route: WireRoute): Regex = Regex(route.path.split(Regex("\\{[^}]+}")).joinToString("[^/]+") { Regex.escape(it) })
    }
}
