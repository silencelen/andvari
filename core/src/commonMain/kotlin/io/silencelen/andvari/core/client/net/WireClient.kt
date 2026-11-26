package io.silencelen.andvari.core.client.net

import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireRoute

/**
 * The engine's HTTP port for the overhaul's routes (spec 03, [WireRoute]). One instance talks to ONE
 * origin: the origin of the pin it was opened for (design §4.4). Nothing in this interface chooses an
 * origin from a served value; a move is followed only through [io.silencelen.andvari.core.client.pin.InstanceTrust].
 *
 * Results are values, never exceptions with free text ([WireResult]). The engine maps a refusal's
 * `error` code (spec 03 §0.1: clients key on the code, never the status or message) to its own sealed
 * results.
 */
interface WireClient {
    /** The origin this client dials (the `origin` grammar, design §2.2). */
    val origin: String

    /**
     * True when the [OriginGuard] stops every request of this client that carries a credential (the origin's pin is
     * forked, damaged, moving or unreadable, or the origin holds no pin in force, design §4.4). A flow asks it before it
     * SIGNS or stores anything it would then send, so nothing is made for a server it may not talk to. Only a guarded
     * client ([Dialer], [OriginGuard.guard]) can say true.
     */
    val stopped: Boolean get() = false

    /**
     * Calls [route] with its JSON body [bodyJson] (already encoded with `WireJson.json`, or null), the
     * `{param}` values in [pathParams] (each checked against the id grammar before it is sent, spec 02
     * §3.2), and the raw [query] string (already encoded, without `?`). [authenticated] attaches the
     * session's bearer. [decode] turns a success body into [T]; a throw from it is
     * [NoAnswerKind.UNDECODABLE]. The answer is read to its route's cap in [ResponseCaps] and no further; over it the
     * call is `Refused(0, `[BODY_OVER_LIMIT]`)` and nothing of the answer is decoded.
     */
    suspend fun <T> call(
        route: WireRoute,
        pathParams: Map<String, String> = emptyMap(),
        query: String? = null,
        bodyJson: String? = null,
        authenticated: Boolean = route.caller != io.silencelen.andvari.core.model.wire.Caller.NONE,
        decode: (String) -> T,
    ): WireResult<T>

    /**
     * A route whose request body is raw bytes (spec 03 §9, `POST /attachments/{attachmentId}?vaultId=&itemId=`):
     * [body] is sent as `application/octet-stream`, with the same path checks, bearer and single refresh as [call],
     * and the JSON answer decoded by [decode]. A client that carries no raw bodies answers
     * [NoAnswerKind.TRANSPORT] (nothing was sent).
     */
    suspend fun <T> callBytes(
        route: WireRoute,
        pathParams: Map<String, String> = emptyMap(),
        query: String? = null,
        body: ByteArray,
        authenticated: Boolean = route.caller != io.silencelen.andvari.core.model.wire.Caller.NONE,
        decode: (String) -> T,
    ): WireResult<T> = WireResult.NoAnswer(NoAnswerKind.TRANSPORT)

    /**
     * A route whose answer is raw bytes (spec 03 §9, `GET /attachments/{attachmentId}`): the body as it came, on a
     * success status; a refusal in the error envelope as in [call]. Same path checks, bearer and refresh as [call], and
     * the same cap: the body is read to its route's cap in [ResponseCaps] and refused over it ([BODY_OVER_LIMIT]).
     */
    suspend fun fetchBytes(
        route: WireRoute,
        pathParams: Map<String, String> = emptyMap(),
        query: String? = null,
        authenticated: Boolean = route.caller != io.silencelen.andvari.core.model.wire.Caller.NONE,
    ): WireResult<ByteArray> = WireResult.NoAnswer(NoAnswerKind.TRANSPORT)

    /**
     * [fetchBytes] that never buffers more than [maxBytes] of a success body (an attachment download passes the size
     * its item's record claims): a `Content-Length` above [maxBytes] is refused before any body byte is read; without
     * one, the body is read to [maxBytes] + 1 bytes at most and refused there. The refusal is
     * `Refused(0, `[BODY_OVER_LIMIT]`)`, and the bytes read are zeroed. Null: the route's own cap, as the other
     * [fetchBytes] ([ResponseCaps]; every answer [KtorWireClient] reads has one).
     *
     * A client that cannot stream (the default here) fetches with the other [fetchBytes] and refuses an answer over
     * [maxBytes] after it, zeroed; [KtorWireClient] streams.
     */
    suspend fun fetchBytes(
        route: WireRoute,
        pathParams: Map<String, String>,
        query: String?,
        authenticated: Boolean,
        maxBytes: Long?,
    ): WireResult<ByteArray> {
        val r = fetchBytes(route, pathParams, query, authenticated)
        if (maxBytes == null || r !is WireResult.Ok || r.value.size.toLong() <= maxBytes) return r
        r.value.fill(0)
        return bodyOverLimit(maxBytes)
    }
}

/** [WireResult.Refused]'s code (status 0) when a success body is larger than the caller's cap ([WireClient.fetchBytes]). */
const val BODY_OVER_LIMIT = "body_over_limit"

internal fun bodyOverLimit(maxBytes: Long): WireResult.Refused =
    WireResult.Refused(0, WireError(BODY_OVER_LIMIT, "the answer is larger than the $maxBytes bytes expected"))

/**
 * The one reading of a server's "wait this long" (`Retry-After`): a whole number of seconds from 0 to [MAX_SECONDS], or
 * null ("later", no number). A wait beyond a day, a negative one, a date, a fraction, text, or a number past any integer
 * is null, so that no line shows an absurd, a wrapped or a negative wait, and a caller may multiply it into milliseconds
 * or take it as an `Int` safely.
 */
object RetryAfter {
    /** A day: the longest wait a server's answer is taken at its word for. */
    const val MAX_SECONDS: Long = 86_400L

    fun seconds(header: String?): Long? {
        val t = header?.trim() ?: return null
        // Digits only, and short enough that the number cannot pass a day by many orders (no overflow to read).
        if (t.isEmpty() || t.length > 6 || !t.all { it in '0'..'9' }) return null
        return t.toLong().takeIf { it <= MAX_SECONDS }
    }
}

/** What one call came back with. */
sealed class WireResult<out T> {
    /** A success status with a decodable body. */
    data class Ok<T>(val value: T, val status: Int) : WireResult<T>()

    /**
     * A refusal in the spec 03 §0.1 envelope. [retryAfterSeconds] from `Retry-After` on a `429 rate_limited`, read only
     * by [RetryAfter.seconds]: 0 to a day; null where the server named none, or a wait beyond a day, a negative one or
     * one that does not read (the line then says "later", with no number).
     */
    data class Refused(val status: Int, val error: WireError, val retryAfterSeconds: Long? = null) : WireResult<Nothing>() {
        val code: String get() = error.error
    }

    /**
     * No usable answer: a transport failure, a timeout, a 5xx without the envelope, or a body that is not
     * the route's JSON (a proxy's page). The outcome of a write is UNKNOWN (spec 03 §13 client duties).
     */
    data class NoAnswer(val kind: NoAnswerKind) : WireResult<Nothing>() {
        /**
         * True only when nothing of the request left this device: no connection was made (refused, no route, a name that
         * does not resolve, the connection's own time limit), so a write it carried was certainly not made. False when
         * the request may have left (its outcome is unknown) and wherever the transport cannot tell. Not part of equality.
         */
        var neverLeft: Boolean = false
            private set

        internal constructor(kind: NoAnswerKind, neverLeft: Boolean) : this(kind) {
            this.neverLeft = neverLeft
        }
    }
}

enum class NoAnswerKind { TRANSPORT, TIMEOUT, SERVER_ERROR, UNDECODABLE }
