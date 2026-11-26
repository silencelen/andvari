package io.silencelen.andvari.core.client.net

import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpRequestTimeoutException
import io.ktor.client.request.header
import io.ktor.client.request.prepareRequest
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.contentLength
import io.ktor.utils.io.readAvailable
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.contentType
import io.ktor.http.encodeURLPathPart
import io.silencelen.andvari.core.client.ANDVARI_CLIENT_VERSION
import io.silencelen.andvari.core.model.wire.Caller
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CancellationException

/**
 * The session's tokens as the engine's HTTP port sees them. Owned by the session layer, which
 * stores and rotates the pair; [refresh] is called at most once per call, after a `401` on an
 * authenticated route, and answers whether a fresh access token is now available.
 */
interface TokenSource {
    fun accessToken(): String?
    suspend fun refresh(staleAccessToken: String): Boolean
}

/**
 * [WireClient] over a ktor [HttpClient] (the engine per platform is the host's). One origin per
 * instance; every request carries `X-Andvari-Client: <platform>/<version>` (spec 03 §1).
 *
 * Path parameters are refused unless they are id-shaped (`[A-Za-z0-9_-]`, 1..128): a served id becomes a
 * path segment of THIS device's authenticated request, so nothing else may ever be interpolated (spec 02
 * §3.2, spec 05 R18). The refusal is a [WireResult.Refused] with status 0 and code `bad_path_segment`,
 * and nothing is sent.
 *
 * Its constructor is internal: a host gets one only through [Dialer.open], behind the [OriginGuard] (design §4.4
 * "The stop is enforced where the client dials").
 *
 * Every answer is read up to its route's cap in [ResponseCaps], by length and without one, before a Trust Gate as
 * after it; over the cap it is `Refused(0, `[BODY_OVER_LIMIT]`)` and the bytes read are zeroed.
 */
class KtorWireClient internal constructor(
    override val origin: String,
    private val http: HttpClient,
    platform: String,
    private val tokens: TokenSource? = null,
) : WireClient {
    private val clientHeader = "$platform/$ANDVARI_CLIENT_VERSION"

    override suspend fun <T> call(
        route: WireRoute,
        pathParams: Map<String, String>,
        query: String?,
        bodyJson: String?,
        authenticated: Boolean,
        decode: (String) -> T,
    ): WireResult<T> = exchange(route, pathParams, query, bodyJson, authenticated, ResponseCaps.of(route)) { interpret(it, decode) }

    override suspend fun <T> callBytes(
        route: WireRoute,
        pathParams: Map<String, String>,
        query: String?,
        body: ByteArray,
        authenticated: Boolean,
        decode: (String) -> T,
    ): WireResult<T> = exchange(route, pathParams, query, body, authenticated, ResponseCaps.of(route)) { interpret(it, decode) }

    /** A raw-bytes answer read to its route's cap ([ResponseCaps]). */
    override suspend fun fetchBytes(
        route: WireRoute,
        pathParams: Map<String, String>,
        query: String?,
        authenticated: Boolean,
    ): WireResult<ByteArray> = fetchBytes(route, pathParams, query, authenticated, null)

    /**
     * The download with a cap ([WireClient.fetchBytes]): streamed, so a success body over [maxBytes] is never buffered
     * past [maxBytes] + 1 bytes, and a `Content-Length` over it is refused before any body byte is read. Null: the
     * route's cap ([ResponseCaps]). Same path checks, bearer and single refresh as every other call.
     */
    override suspend fun fetchBytes(
        route: WireRoute,
        pathParams: Map<String, String>,
        query: String?,
        authenticated: Boolean,
        maxBytes: Long?,
    ): WireResult<ByteArray> {
        val cap = (maxBytes ?: ResponseCaps.of(route)).coerceIn(0L, MAX_CAP)
        return exchange(route, pathParams, query, null, authenticated, cap) { got ->
            when {
                got.status !in 200..299 -> interpret(got) { error("a refusal has no success body") }
                got.body == null -> bodyOverLimit(got.cap)
                else -> WireResult.Ok(got.body, got.status)
            }
        }
    }

    /**
     * One answer as read: its [status], its body read to [cap] ([body] null when the body was over it: nothing of it
     * is kept), and the `Retry-After` header.
     */
    private class Got(val status: Int, val body: ByteArray?, val cap: Long, val retryAfter: String?) {
        fun wipe() { body?.fill(0) }
    }

    /** A body read to at most [cap] + 1 bytes: null over [cap] (what was read is zeroed). A read failure throws, zeroed. */
    private suspend fun readCapped(resp: HttpResponse, cap: Long): ByteArray? {
        val declared = resp.contentLength()
        if (declared != null && declared > cap) return null
        val channel = resp.bodyAsChannel()
        val limit = cap + 1
        var buf = ByteArray(minOf(limit, declared?.plus(1) ?: CHUNK, CHUNK).toInt())
        var n = 0
        try {
            while (n < limit) {
                if (n == buf.size) {
                    val grown = buf.copyOf(minOf(limit, buf.size.toLong() * 2).toInt())
                    buf.fill(0)
                    buf = grown
                }
                val read = channel.readAvailable(buf, n, buf.size - n)
                if (read < 0) break
                n += read
            }
        } catch (e: Throwable) {
            buf.fill(0)
            throw e
        }
        if (n > cap) {
            buf.fill(0)
            return null
        }
        val out = buf.copyOf(n)
        buf.fill(0)
        return out
    }

    /** The request URL with its path parameters checked, or the `bad_path_segment` refusal (nothing is sent). */
    private fun url(route: WireRoute, pathParams: Map<String, String>, query: String?): WireResult<String> {
        var path = route.path
        for ((k, v) in pathParams) {
            if (!SEGMENT.matches(v)) return WireResult.Refused(0, WireError(BAD_PATH_SEGMENT, "not an id path segment"))
            path = path.replace("{$k}", v.encodeURLPathPart())
        }
        if ('{' in path) return WireResult.Refused(0, WireError(BAD_PATH_SEGMENT, "missing path parameter"))
        return WireResult.Ok(origin + path + (query?.let { "?$it" } ?: ""), 0)
    }

    /**
     * The path checks, the bearer and the single refresh every call shape shares; [body] is a JSON string, raw bytes or
     * null. A success body is read to [cap], a refusal's to [ResponseCaps.ofRefusal] at most.
     */
    private suspend fun <T> exchange(
        route: WireRoute,
        pathParams: Map<String, String>,
        query: String?,
        body: Any?,
        authenticated: Boolean,
        cap: Long,
        answer: suspend (Got) -> WireResult<T>,
    ): WireResult<T> {
        val url = when (val u = url(route, pathParams, query)) {
            is WireResult.Refused -> return u
            else -> (u as WireResult.Ok<String>).value
        }
        // The token actually sent is the one a 401 names stale, so concurrent 401s refresh once.
        val sent = if (authenticated) tokens?.accessToken() else null
        val failed = Failure()
        var got = send(route, url, body, sent, cap, failed) ?: return failed.answer()
        if (got.status == 401 && authenticated && route.caller != Caller.NONE && sent != null && tokens!!.refresh(sent)) {
            got.wipe()
            got = send(route, url, body, tokens.accessToken(), cap, failed) ?: return failed.answer()
        }
        return answer(got)
    }

    /** How this call's request failed, kept per call (concurrent calls never read each other's). */
    private class Failure {
        var kind: NoAnswerKind = NoAnswerKind.TRANSPORT
        var neverLeft = false
        fun answer() = WireResult.NoAnswer(kind, neverLeft)
    }

    /** One request, its answer's body read inside the exchange to its cap (so nothing past the cap is ever buffered). */
    private suspend fun send(route: WireRoute, url: String, body: Any?, bearer: String?, cap: Long, failed: Failure): Got? = try {
        http.prepareRequest(url) {
            method = HttpMethod.parse(route.method)
            header("X-Andvari-Client", clientHeader)
            if (bearer != null) header("Authorization", "Bearer $bearer")
            when (body) {
                is String -> { contentType(ContentType.Application.Json); setBody(body) }
                is ByteArray -> { contentType(ContentType.Application.OctetStream); setBody(body) }
                else -> {}
            }
        }.execute { resp ->
            val status = resp.status.value
            val bodyCap = if (status in 200..299) cap else ResponseCaps.ofRefusal(route)
            Got(status, readCapped(resp, bodyCap), bodyCap, resp.headers["Retry-After"])
        }
    } catch (e: CancellationException) {
        throw e
    } catch (_: HttpRequestTimeoutException) {
        failed.kind = NoAnswerKind.TIMEOUT; failed.neverLeft = false; null
    } catch (t: Throwable) {
        // A connection never made sent nothing: a write it carried was not made (said apart from "no answer").
        failed.kind = NoAnswerKind.TRANSPORT; failed.neverLeft = neverLeft(t); null
    }

    /** [got] as a result: a body over its cap is [BODY_OVER_LIMIT]; the bytes read are zeroed once decoded. */
    private fun <T> interpret(got: Got, decode: (String) -> T): WireResult<T> {
        val bytes = got.body ?: return bodyOverLimit(got.cap)
        val text = try { bytes.decodeToString() } finally { bytes.fill(0) }
        val status = got.status
        if (status in 200..299) {
            return try { WireResult.Ok(decode(text), status) } catch (e: CancellationException) { throw e } catch (_: Throwable) { WireResult.NoAnswer(NoAnswerKind.UNDECODABLE) }
        }
        val err = runCatching { WireJson.json.decodeFromString(WireError.serializer(), text) }.getOrNull()
        if (err == null) return WireResult.NoAnswer(if (status >= 500) NoAnswerKind.SERVER_ERROR else NoAnswerKind.UNDECODABLE)
        val retryAfter = if (err.error == WireErrors.RATE_LIMITED) RetryAfter.seconds(got.retryAfter) else null
        return WireResult.Refused(status, err, retryAfter)
    }

    companion object {
        const val BAD_PATH_SEGMENT = "bad_path_segment"
        private val SEGMENT = Regex("^[A-Za-z0-9_-]{1,128}$")

        /** The largest cap a capped download takes (a byte array holds it with its one extra byte). */
        private const val MAX_CAP: Long = Int.MAX_VALUE - 16L

        /** The first buffer of a capped download; it doubles up to the cap. */
        private const val CHUNK: Long = 64L * 1024

        /**
         * The failures, by class name along the cause chain, that happen before any byte of a request is written: the
         * connection was refused, had no route, timed out while connecting, or the name did not resolve (the JVM's and
         * Android's engines). Shared code cannot name the platforms' classes; an engine that reports otherwise (the
         * iPhone's) is never "never left", so its outcome stays unknown, which is the conservative reading.
         */
        private val NOT_CONNECTED = setOf(
            "ConnectException", "NoRouteToHostException", "UnknownHostException", "UnresolvedAddressException", "ConnectTimeoutException",
        )

        // A failure with another attached as suppressed is a second try of a request whose first attempt may have left
        // (Android's engine sends a written request again on a new connection and attaches the sent attempt that way).
        internal fun neverLeft(t: Throwable): Boolean {
            val chain = generateSequence(t) { it.cause }.take(8).toList()
            return chain.none { it.suppressedExceptions.isNotEmpty() } && chain.any { it::class.simpleName in NOT_CONNECTED }
        }
    }
}
