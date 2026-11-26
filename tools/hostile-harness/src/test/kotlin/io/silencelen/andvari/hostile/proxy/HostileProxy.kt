package io.silencelen.andvari.hostile.proxy

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import java.io.IOException
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Spec 03's route index as matchers: which [WireRoute] a method and path are, and the `{param}` values in the path.
 * A literal path wins over a parameterised one (`/links/answers` before `/links/{linkId}`).
 */
object Routes {
    private class Pattern(val route: WireRoute, val regex: Regex, val names: List<String>)

    private val param = Regex("\\{([A-Za-z]+)}")

    private val patterns: List<Pattern> = WireRoute.entries.map { r ->
        val names = param.findAll(r.path).map { it.groupValues[1] }.toList()
        Pattern(r, Regex("^" + r.path.split(param).joinToString("([^/]+)") { Regex.escape(it) } + "$"), names)
    }.sortedBy { it.names.size }

    fun of(method: String, path: String): WireRoute? = patterns.firstOrNull { it.route.method == method && it.regex.matches(path) }?.route

    fun params(route: WireRoute, path: String): Map<String, String> {
        val p = patterns.first { it.route == route }
        val m = p.regex.matchEntire(path) ?: return emptyMap()
        return p.names.mapIndexed { i, n -> n to m.groupValues[i + 1] }.toMap()
    }
}

/** One request as a device sent it: recorded whole, body included, before any rule ran. */
class Req(
    val seq: Int,
    /** The device that sent it: the tag of the listener it dialed. */
    val tag: String,
    val method: String,
    val path: String,
    val query: String?,
    val headers: Map<String, List<String>>,
    val body: ByteArray,
) {
    val route: WireRoute? = Routes.of(method, path)
    val text: String get() = body.decodeToString()
    val json: JsonObject? get() = runCatching { Json.parseToJsonElement(text).jsonObject }.getOrNull()

    fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value?.firstOrNull()

    /** The session's access token, when the request carried one. */
    val bearer: String? get() = header("Authorization")?.removePrefix("Bearer ")

    /** A `{param}` of the route's path (`vaultId`, `linkId`, `requestId`, …). */
    fun param(name: String): String? = route?.let { Routes.params(it, path)[name] }

    fun queryParam(name: String): String? = query?.split('&')?.firstOrNull { it.startsWith("$name=") }?.substringAfter('=')

    /** The same request, changed: what a rule forwards in its place (the recording keeps the original). */
    fun with(method: String = this.method, path: String = this.path, query: String? = this.query, body: ByteArray = this.body): Req =
        Req(seq, tag, method, path, query, headers, body)

    fun withJson(edit: (JsonObject) -> JsonObject): Req = with(body = edit(json ?: error("$this has no JSON body")).toString().encodeToByteArray())

    override fun toString(): String = "#$seq [$tag] $method $path${query?.let { "?$it" } ?: ""}"
}

/**
 * An answer body the proxy streams instead of a held one: [upTo] bytes of [fill], written in pieces while the device
 * reads, under a `Content-Length` of [declaredLength] (null: chunked, no length at all). The proxy counts what the
 * device let it write ([Exchange.written]); a device that hangs up stops the stream.
 */
class Endless(val declaredLength: Long?, val upTo: Long, val fill: Byte = 0x41, val prefix: ByteArray = ByteArray(0)) {
    companion object {
        /**
         * [real] cut at [keep] bytes: under its own full `Content-Length` (the connection closes short of it), or with
         * no length at all (chunked, which ends cleanly after the cut). A truncated answer.
         */
        fun truncated(real: ByteArray, keep: Int, declared: Boolean): Endless =
            Endless(if (declared) real.size.toLong() else null, keep.toLong(), prefix = real.copyOf(keep))
    }
}

/** One answer: the real server's, or the one a rule made of it. [endless] replaces [body] with a streamed one. */
class Resp(val status: Int, val headers: Map<String, String>, val body: ByteArray, val endless: Endless? = null) {
    val text: String get() = body.decodeToString()
    val json: JsonObject? get() = runCatching { Json.parseToJsonElement(text).jsonObject }.getOrNull()
    val ok: Boolean get() = status in 200..299

    fun withBody(text: String): Resp = Resp(status, headers, text.encodeToByteArray())

    /** The same answer with its JSON object changed. A rule that expects an object and meets none fails loudly. */
    fun withJson(edit: (JsonObject) -> JsonObject): Resp = withBody(edit(json ?: error("the answer is not a JSON object: $status ${text.take(200)}")).toString())

    override fun toString(): String = "$status ${text.take(160)}"

    companion object {
        private val JSON = mapOf("Content-Type" to "application/json")

        fun json(status: Int, body: JsonElement): Resp = Resp(status, JSON, body.toString().encodeToByteArray())

        /** A refusal in spec 03 §0.1's envelope, with [code] as its `error`. */
        fun error(status: Int, code: String, extra: JsonObject = JsonObject(emptyMap())): Resp = json(
            status,
            JsonObject(buildJsonObject { put("error", JsonPrimitive(code)); put("message", JsonPrimitive("the hostile proxy says $code")) } + extra),
        )

        /** The plain-text `ok` of the routes that answer nothing else. */
        fun ok(): Resp = Resp(200, mapOf("Content-Type" to "text/plain"), "ok".encodeToByteArray())
    }
}

/** One recorded exchange: the request, what the real server answered (if it was asked), and what the device was served. */
class Exchange(val req: Req) {
    /** The real server's answer to the last forward of this request; null when it was never forwarded. */
    @Volatile var upstream: Resp? = null

    /** How many times the request reached the real server. */
    @Volatile var forwards: Int = 0

    /** What the device was sent; null while held, and for good when the connection was dropped. */
    @Volatile var served: Resp? = null

    /** True when the device got no answer at all: the connection was closed. */
    @Volatile var dropped: Boolean = false

    /** The rule that handled it; null for a plain pass. */
    @Volatile var rule: String? = null

    /** The body bytes the device let the proxy write so far (an [Endless] answer counts as it goes). */
    @Volatile var written: Long = 0

    override fun toString(): String = "$req -> " + when {
        dropped -> "dropped"
        served == null -> "held"
        else -> served.toString()
    } + (rule?.let { "  (rule: $it)" } ?: "")
}

/** What a rule sees of one request. */
class Ctx internal constructor(val req: Req, val exchange: Exchange, private val proxy: HostileProxy) {
    /** Send [r] (default: the request as it came) to the real server and answer what it said. */
    fun forward(r: Req = req): Resp = proxy.forward(exchange, r)

    /**
     * Ask the real server something else with this request's own credentials (its bearer and headers): a hostile
     * server knows everything it stores, so a rule may look it up. The side request is not part of the recording.
     */
    fun ask(route: WireRoute, params: Map<String, String> = emptyMap(), query: String? = null): Resp {
        var path = route.path
        for ((k, v) in params) path = path.replace("{$k}", v)
        return proxy.forward(null, req.with(method = route.method, path = path, query = query, body = ByteArray(0)))
    }
}

/** What a rule does with a request: the answer the device gets, or null to close the connection without one. */
fun interface Handler {
    fun handle(x: Ctx): Resp?
}

/**
 * One programmed behaviour. A request is handled by the NEWEST rule that matches it: its [route] (null: any), the
 * device [tags] (null: any) and [where]; a rule made with `times = n` steps aside after n requests.
 */
class Rule internal constructor(
    val name: String,
    val route: WireRoute?,
    val tags: Set<String>?,
    private val where: (Req) -> Boolean,
    times: Int?,
    internal val handler: Handler,
    private val owner: HostileProxy,
) {
    private val left = AtomicInteger(times ?: -1)

    /** How many requests this rule handled. */
    val hits = AtomicInteger()

    internal fun take(req: Req): Boolean {
        if (route != null && req.route != route) return false
        if (tags != null && req.tag !in tags) return false
        if (!where(req)) return false
        while (true) {
            val n = left.get()
            if (n == 0) return false
            if (n < 0 || left.compareAndSet(n, n - 1)) break
        }
        hits.incrementAndGet()
        return true
    }

    /** The server stops doing this. */
    fun remove() = owner.remove(this)
}

/** A door a held request waits at until the test opens it: "delay until released", and the tool for every race. */
class Gate(private val maxWaitMs: Long = 30_000) {
    private val arrived = CountDownLatch(1)
    private val open = CountDownLatch(1)

    internal fun enter() {
        arrived.countDown()
        check(open.await(maxWaitMs, TimeUnit.MILLISECONDS)) { "a held request was never released" }
    }

    /** Block until a request is waiting at the gate. */
    fun awaitArrival(timeoutMs: Long = 20_000) = check(arrived.await(timeoutMs, TimeUnit.MILLISECONDS)) { "no request reached the gate" }

    fun release() = open.countDown()
}

/**
 * The hostile server: an HTTP proxy between the client engine and the real server (spec 05 T1, design §1).
 *
 * Every device dials a listener of its own ([dial]), so the proxy knows which device is asking and can show different
 * devices different things. Each request is recorded whole, body included, BEFORE any rule runs ([log]); recording
 * matters as much as tampering, because several assertions are "this value never left the device". A request no rule
 * claims passes through untouched.
 *
 * What a rule can do, all through [Handler]: pass; drop (the connection closes with no answer); answer a chosen status;
 * hold until a [Gate] opens; replay an earlier answer; substitute a body or one JSON field; change the request on its
 * way in; forward twice; ask the real server anything else with the caller's credentials. Reordering is two gates.
 *
 * **WebSocket.** The engine as the headless host drives it never opens `/api/v1/events` (it has no socket code at all;
 * it learns of changes by asking). An upgrade request is therefore REFUSED with `501` and recorded, never passed
 * through, so a test would see one if the engine ever started to rely on the bell.
 *
 * [upstream] answers where the real server listens now (read at every request, so a restart of the server, which binds
 * a new port, is followed); [originAuthority] is the `host:port` of the instance's origin, sent on as `Host`. With
 * [stampClientIp] each device gets its own `X-Forwarded-For`, as a fleet behind a real front-end has, so the server's
 * per-IP limits do not couple the devices of one test.
 *
 * Every listener binds port 0, so no port of the proxy is picked first and bound later (another process on a busy
 * machine could take it in between). The origin's own port is held by the test server from its construction; a test
 * that wants the proxy there routes it to a listener of the proxy (`World.originListener`, `TestServer.interpose`).
 */
class HostileProxy(
    private val upstream: () -> String,
    private val originAuthority: String,
    private val stampClientIp: Boolean = true,
) : AutoCloseable {
    private val listeners = ConcurrentHashMap<String, HttpServer>()
    private val tags = CopyOnWriteArrayList<String>()
    private val pool = Executors.newCachedThreadPool { r -> Thread(r, "hostile-proxy").apply { isDaemon = true } }
    private val client: HttpClient
    private val rules = CopyOnWriteArrayList<Rule>()
    private val exchanges: MutableList<Exchange> = Collections.synchronizedList(ArrayList())
    private val counter = AtomicInteger()

    /** A rule that threw: a mistake in the test, never an answer. [io.silencelen.andvari.hostile.World] fails the test on any. */
    val failures: MutableList<Throwable> = CopyOnWriteArrayList()

    init {
        // A device's request names the address it dialed (H7, declined), so the proxy names the origin to the server
        // itself (`forward`). The JDK client allows a `Host` header only with this property, read once per JVM, so it is
        // set before the first client exists.
        System.setProperty("jdk.httpclient.allowRestrictedHeaders", "host")
        client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(10)).build()
    }

    // ---------------------------------------------------------------------------------------------
    // Listeners
    // ---------------------------------------------------------------------------------------------

    /** The address the device tagged [tag] dials: a listener of its own, bound to port 0 (the system picks it as it binds). */
    fun dial(tag: String): String = "http://127.0.0.1:${listener(tag).address.port}"

    private fun listener(tag: String): HttpServer = listeners.computeIfAbsent(tag) {
        tags += tag
        HttpServer.create(InetSocketAddress("127.0.0.1", 0), 64).also { s ->
            s.executor = pool
            s.createContext("/") { ex -> handle(tag, ex) }
            s.start()
        }
    }

    private fun clientIp(tag: String): String {
        val i = tags.indexOf(tag).coerceAtLeast(0)
        return "10.77.${i / 250}.${i % 250 + 1}"
    }

    // ---------------------------------------------------------------------------------------------
    // Rules
    // ---------------------------------------------------------------------------------------------

    /**
     * Add a rule. [tag] names one device (null: every device); [times] limits it to that many requests. The newest
     * matching rule handles a request, so a later rule overrides an earlier one for the requests it matches.
     */
    fun on(
        route: WireRoute?,
        tag: String? = null,
        name: String = (route?.name ?: "any") + (tag?.let { "@$it" } ?: ""),
        times: Int? = null,
        where: (Req) -> Boolean = { true },
        handler: Handler,
    ): Rule = Rule(name, route, tag?.let(::setOf), where, times, handler, this).also { rules += it }

    internal fun remove(rule: Rule) {
        rules -= rule
    }

    /** The server turns honest: every rule goes. */
    fun honest() = rules.clear()

    // ---------------------------------------------------------------------------------------------
    // The recording
    // ---------------------------------------------------------------------------------------------

    /** Every exchange so far, in arrival order. */
    fun log(): List<Exchange> = synchronized(exchanges) { exchanges.toList() }

    /** A position in the recording, for [since]. */
    fun mark(): Int = exchanges.size

    fun since(mark: Int): List<Exchange> = log().drop(mark)

    /** The requests of [route] (null: any) from [tag] (null: any device), from [since] on. */
    fun requests(route: WireRoute? = null, tag: String? = null, since: Int = 0): List<Req> =
        log().drop(since).map { it.req }.filter { (route == null || it.route == route) && (tag == null || it.tag == tag) }

    /** The latest exchange of [route] from [tag]. */
    fun last(route: WireRoute, tag: String? = null): Exchange? = log().lastOrNull { it.req.route == route && (tag == null || it.req.tag == tag) }

    /** The end of the recording, for failure messages. */
    fun tail(n: Int = 40): String = log().takeLast(n).joinToString("\n")

    // ---------------------------------------------------------------------------------------------
    // The exchange
    // ---------------------------------------------------------------------------------------------

    private fun handle(tag: String, ex: HttpExchange) {
        try {
            val body = ex.requestBody.readAllBytes()
            val req = Req(counter.incrementAndGet(), tag, ex.requestMethod, ex.requestURI.rawPath, ex.requestURI.rawQuery, HashMap(ex.requestHeaders), body)
            val exchange = Exchange(req)
            exchanges += exchange
            val resp: Resp? = if (req.header("Upgrade")?.equals("websocket", ignoreCase = true) == true) {
                exchange.rule = "websocket refused"
                Resp.error(501, "websocket_refused")
            } else {
                val rule = rules.toList().asReversed().firstOrNull { it.take(req) }
                exchange.rule = rule?.name
                try {
                    (rule?.handler ?: pass).handle(Ctx(req, exchange, this))
                } catch (t: Throwable) {
                    failures += IllegalStateException("rule '${rule?.name ?: "pass"}' failed on $req: $t", t)
                    null
                }
            }
            if (resp == null) {
                exchange.dropped = true
                return
            }
            exchange.served = resp
            for ((k, v) in resp.headers) if (k.lowercase() !in HOP_BY_HOP) ex.responseHeaders[k] = listOf(v)
            resp.endless?.let { e ->
                // A declared length of 0 would mean "chunked" to the JDK server; an endless answer declares one or none.
                ex.sendResponseHeaders(resp.status, e.declaredLength?.coerceAtLeast(1) ?: 0)
                val piece = ByteArray(64 * 1024) { e.fill }
                ex.responseBody.use { out ->
                    while (exchange.written < e.upTo) {
                        val w = exchange.written
                        if (w < e.prefix.size) {
                            val n = minOf(piece.size.toLong(), e.prefix.size - w, e.upTo - w).toInt()
                            out.write(e.prefix, w.toInt(), n)
                            out.flush()
                            exchange.written += n
                            continue
                        }
                        val n = minOf(piece.size.toLong(), e.upTo - exchange.written).toInt()
                        out.write(piece, 0, n)
                        out.flush()
                        exchange.written += n
                    }
                }
                return
            }
            val bodyless = resp.body.isEmpty() || resp.status == 204 || resp.status == 304 || resp.status in 100..199
            ex.sendResponseHeaders(resp.status, if (bodyless) -1 else resp.body.size.toLong())
            if (!bodyless) ex.responseBody.use { it.write(resp.body) }
        } catch (_: IOException) {
            // The device went away; nothing to answer.
        } finally {
            ex.close()
        }
    }

    /** One request to the real server. [exchange] is the recorded exchange it belongs to (null for a side question). */
    internal fun forward(exchange: Exchange?, req: Req): Resp {
        val b = HttpRequest.newBuilder(URI.create(upstream() + req.path + (req.query?.let { "?$it" } ?: ""))).timeout(Duration.ofSeconds(30))
        for ((k, vs) in req.headers) {
            if (k.lowercase() in HOP_BY_HOP || k.lowercase() in FORWARDING) continue
            for (v in vs) b.header(k, v)
        }
        runCatching { b.header("Host", originAuthority) }
        if (stampClientIp) b.header("X-Forwarded-For", clientIp(req.tag))
        val bodyless = req.body.isEmpty() && (req.method == "GET" || req.method == "DELETE" || req.method == "HEAD")
        b.method(req.method, if (bodyless) HttpRequest.BodyPublishers.noBody() else HttpRequest.BodyPublishers.ofByteArray(req.body))
        val r = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray())
        val headers = r.headers().map().filterKeys { it.lowercase() !in HOP_BY_HOP }.mapValues { it.value.joinToString(", ") }
        val resp = Resp(r.statusCode(), headers, r.body())
        if (exchange != null) {
            exchange.upstream = resp
            exchange.forwards++
        }
        return resp
    }

    override fun close() {
        listeners.values.forEach { it.stop(0) }
        pool.shutdownNow()
    }

    private companion object {
        val HOP_BY_HOP = setOf("connection", "content-length", "expect", "host", "upgrade", "http2-settings", "transfer-encoding", "keep-alive", "date")
        val FORWARDING = setOf("x-forwarded-for", "x-real-ip", "forwarded", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port")
    }
}

// -------------------------------------------------------------------------------------------------
// The handlers a rule is made of
// -------------------------------------------------------------------------------------------------

/** Untouched. */
val pass = Handler { it.forward() }

/** The connection closes with no answer, and the server never saw the request. */
val drop = Handler { null }

/** The server acts on the request and the device never learns: the outcome of a write is unknown to it. */
val dropAnswer = Handler { it.forward(); null }

/** A chosen refusal, without asking the real server. */
fun refuse(status: Int, code: String, extra: JsonObject = JsonObject(emptyMap())) = Handler { Resp.error(status, code, extra) }

/** A chosen answer, without asking the real server: a replay of an earlier one, or a fabrication. */
fun answer(resp: () -> Resp) = Handler { resp() }

/** Hold the request at [gate], then [then] (default: pass it on). The server has not seen it while it waits. */
fun hold(gate: Gate, then: Handler = pass) = Handler { x -> gate.enter(); then.handle(x) }

/** Pass the request on at once and hold the ANSWER at [gate]: the server acted, the device does not know yet. */
fun holdAnswer(gate: Gate) = Handler { x -> val r = x.forward(); gate.enter(); r }

/** Pass it on and change the JSON object of a successful answer. */
fun editAnswer(edit: (JsonObject) -> JsonObject) = Handler { x -> x.forward().let { if (it.ok) it.withJson(edit) else it } }

/** Change the request's JSON body on its way to the real server. */
fun editRequest(edit: (JsonObject) -> JsonObject) = Handler { x -> x.forward(x.req.withJson(edit)) }

/** The request reaches the real server twice; the device gets the second answer. */
val twice = Handler { x -> x.forward(); x.forward() }
