package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.http.Headers
import io.ktor.http.content.OutgoingContent
import io.ktor.http.content.TextContent
import io.ktor.http.withCharset
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.http.content.LocalFileContent
import io.ktor.server.routing.head
import io.ktor.util.AttributeKey
import io.ktor.server.application.install
import io.ktor.server.metrics.micrometer.MicrometerMetrics
import io.ktor.server.plugins.conditionalheaders.ConditionalHeaders
import io.ktor.server.plugins.partialcontent.PartialContent
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.ApplicationReceivePipeline
import io.ktor.server.request.contentLength
import io.ktor.server.request.path
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondFile
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readRemaining
import io.micrometer.core.instrument.config.MeterFilter
import io.micrometer.prometheusmetrics.PrometheusConfig
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.io.readByteArray
import kotlin.time.Duration.Companion.seconds
import java.io.File

/** The release version, from :core's single source. */
const val SERVER_VERSION = io.silencelen.andvari.core.client.ANDVARI_CLIENT_VERSION

/**
 * Request-body caps (spec 03 preamble): 256 KiB by default; the per-route ceilings the spec lists; the
 * streamed attachment upload is exempt (it bounds itself). Enforced from a declared Content-Length before
 * routing, and again while reading an undeclared body.
 */
internal const val BODY_CAP_DEFAULT = 256L * 1024
internal const val BODY_CAP_PUSH = 8L * 1024 * 1024
internal const val BODY_CAP_USAGE = 512L * 1024 + 4 * 1024
internal const val BODY_CAP_ACCOUNT_STATE = 1024L * 1024 + 64 * 1024
internal const val BODY_CAP_ACCOUNT_DELETE = 1024L * 1024

/** Inbound WebSocket frame ceiling (spec 03 §6): 4 KiB, refused from the header (close 1009). */
internal const val WS_MAX_FRAME_BYTES = 4L * 1024

internal const val EVENTS_PATH = "/api/v1/events"

/** Bearer upgrades of `GET /events` per device and minute (spec 03 §8, `ws_bearer`). */
internal const val WS_BEARER_PER_MINUTE = 60

/** Their bucket, kept per device with its ceiling per account as every session route's ([Bucket]). */
internal val WS_BEARER_BUCKET = Bucket.devicePerMinute("ws_bearer", WS_BEARER_PER_MINUTE)

/** The method tag values the request metrics keep; any other method token is tagged `OTHER`. */
internal val METRIC_METHODS = setOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")

internal fun bodyCapBytes(path: String): Long? = when {
    path.startsWith("/api/v1/attachments/") -> null
    path == "/api/v1/sync/push" -> BODY_CAP_PUSH
    path.startsWith("/api/v1/items/") && path.endsWith("/restore") -> BODY_CAP_PUSH
    path == "/api/v1/usage" -> BODY_CAP_USAGE
    path == "/api/v1/account/state" || path == "/api/v1/account/recovery" -> BODY_CAP_ACCOUNT_STATE
    path == "/api/v1/account/delete" -> BODY_CAP_ACCOUNT_DELETE
    else -> BODY_CAP_DEFAULT
}

internal const val STATIC_CACHE_IMMUTABLE = "public, max-age=31536000, immutable"
internal const val STATIC_CACHE_REVALIDATE = "no-cache"
internal const val STATIC_CACHE_NOSTORE = "no-store"

/** Everything a request handler can reach. One instance per server process (or per test). */
class Services(
    val config: Config,
    val clock: Clock,
    val db: Db,
    val trust: TrustVerifiers,
    val notifier: Notifier = Notifier(),
) {
    val audit = Audit(clock)
    val policy = PolicyStore(config, db)
    val sessions = Sessions(config, policy, clock)
    val instance = InstanceStore(config, db, clock)
    val limiter = RateLimiter { clock.now() }
    /** The request metrics; a method token outside [METRIC_METHODS] is tagged `OTHER`. */
    val metrics = PrometheusMeterRegistry(PrometheusConfig.DEFAULT).also { r ->
        r.config().meterFilter(MeterFilter.replaceTagValues("method", { v -> if (v in METRIC_METHODS) v else "OTHER" }))
    }
    val http: HttpClient by lazy { HttpClient(Java) }
    private var hibpRelay: HibpRelay? = null

    /** The HIBP relay, built on first use; tests put one over a scripted upstream here (no test reaches the real HIBP). */
    var hibp: HibpRelay
        get() = hibpRelay ?: HibpRelay(http).also { hibpRelay = it }
        set(value) { hibpRelay = value }
    val attachments = AttachmentStore(this)
    val tickets = EventsTicketStore { clock.now() }
    val recoveryTickets = RecoveryTickets(clock)
    val janitor = Janitor(this)
    val loginBackoff = EmailBackoff().also { b -> b.clock = { clock.now() } }

    /**
     * The password proofs' own back-off: per device ([deviceCounterKey]), the sign-in's curve, counted only by proofs
     * made on that device's own sessions ([Req.reauth]) and refusing only proofs. A caller without a session cannot
     * reach it, so wrong sign-ins for an address never refuse that account's proofs; a stolen session still gets no
     * more guesses than a sign-in does, on its own counter, and its wrong proofs never refuse the proofs of the
     * account's other devices. (It was per account until 2026-11-17: a session without the password could then hold
     * the account's counter at its cap with about a hundred requests a day, and the owner was refused every proof on
     * every device.)
     */
    val proofBackoff = EmailBackoff().also { b -> b.clock = { clock.now() } }

    /**
     * The two-step codes' own back-off: per device ([deviceCounterKey]), the sign-in's curve, counted only by codes
     * checked on that device's own sessions ([Req.checkSessionCode]: TOTP setup, confirm and disable, and the account
     * deletion's code) and refusing only the checking of a code, never a sign-in or a password proof. Without it the
     * per-minute buckets alone let a session in the wrong hands try thousands of codes a day. A code at sign-in counts
     * on [loginBackoff] instead, as part of the sign-in. Per device, not per account, for the same reason as
     * [proofBackoff].
     */
    val codeBackoff = EmailBackoff().also { b -> b.clock = { clock.now() } }

    /**
     * The key of a device's counters in [proofBackoff] and [codeBackoff]: the device row's `devices.deviceId`, the
     * server-minted id every session of that device carries (a refresh issues the next session on the same row, and
     * a sign-in from a known device lands on its row). A row is made only by a registration, a sign-in or a
     * device-link pickup (the password, and the code where two-step sign-in is on) or a recovery commit (the kit, or
     * the operator's answer), so a session cannot make itself a fresh counter.
     */
    fun deviceCounterKey(deviceId: String): String = "device:$deviceId"

    /**
     * True for the first refusal of [kind] under [key] in each period of [periodMs] (a window that starts at that
     * refusal), false for every other one: a refusal by a limit leaves one audit record an operator can see per period,
     * never one per request (decided on 2026-11-17), so a flood of refused requests cannot fill the log. Kept in the
     * limiter's memory like the limits themselves; a restart lets one more record through.
     */
    fun refusalTraceDue(kind: String, key: String, periodMs: Long): Boolean = limiter.allow("trace_$kind:$key", 1, periodMs)

    /**
     * A removed device takes its counters with it, its back-offs and its rate budgets alike (called after the commit
     * that revoked or deleted the rows).
     */
    fun forgetDeviceCounters(deviceIds: Collection<String>) {
        for (d in deviceIds) {
            proofBackoff.success(deviceCounterKey(d))
            codeBackoff.success(deviceCounterKey(d))
            limiter.forgetDevice(d)
        }
    }
    var mailTransport: MailTransport? = Mail.transportFor(config) { http }
    val mail: Mail by lazy { Mail(config, db, clock, audit, mailTransport) { c -> instance.displayName(c) } }

    /** Off in tests that drive [Mail.drain] themselves. */
    var backgroundWorkers: Boolean = true

    /**
     * Tests only: called with a named point between a route's unlocked checks and its transaction
     * (`"pickup.afterGate"`, `"login.afterGate"`, `"password.afterGate"`, `"delete.afterGate"`), so a race test can commit a concurrent change exactly
     * there. Null in production.
     */
    @Volatile internal var raceHook: ((String) -> Unit)? = null

    init { instance.ensureSetup() }

    fun close() = db.close()
}

/** The clock [config] asks for: the test clock file in test mode, else the wall clock. */
fun clockFor(config: Config): Clock = config.testClockFile?.let { FileClock(File(it)) } ?: Clock.SYSTEM

fun buildServices(config: Config, clock: Clock = clockFor(config), trust: TrustVerifiers = CoreTrust()): Services =
    Services(config, clock, Db(config.dbPath), trust)

fun Application.andvariModule(s: Services) {
    val config = s.config

    install(WebSockets) {
        pingPeriodMillis = 30_000
        timeoutMillis = 60_000
        maxFrameSize = WS_MAX_FRAME_BYTES
    }
    // A request that matches no route is tagged `n/a`, not with its raw path (and [Services.metrics]
    // folds unknown methods), so no caller can mint a new meter per request.
    install(MicrometerMetrics) {
        registry = s.metrics
        distinctNotRegisteredRoutes = false
    }
    install(ConditionalHeaders)
    install(PartialContent)
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            val (status, body, retry) = when (cause) {
                is ApiException -> Triple(cause.status, cause.body, cause.retryAfterSeconds)
                is io.ktor.server.plugins.ContentTransformationException,
                is io.ktor.server.plugins.BadRequestException -> Triple(400, WireError(WireErrors.BAD_REQUEST, "bad request"), null)
                is PayloadTooLarge -> Triple(413, WireError(WireErrors.BODY_TOO_LARGE, "body too large"), null)
                else -> {
                    call.application.environment.log.error("unhandled", cause)
                    Triple(500, WireError(WireErrors.INTERNAL, "internal error"), null)
                }
            }
            if (retry != null) call.response.headers.append(HttpHeaders.RetryAfter, retry.toString(), false)
            call.respondText(WireJson.json.encodeToString(WireError.serializer(), body), ContentType.Application.Json, HttpStatusCode.fromValue(status))
        }
    }

    // Baseline security headers on every response; HSTS when the operator turned it on (§1.1: mandatory
    // for an https origin, which Config enforces at boot).
    intercept(ApplicationCallPipeline.Plugins) {
        context.response.headers.append("X-Content-Type-Options", "nosniff", false)
        context.response.headers.append("Referrer-Policy", "no-referrer", false)
        context.response.headers.append("Permissions-Policy", "camera=(), microphone=(), geolocation=()", false)
        context.response.headers.append("X-Robots-Tag", "noindex, nofollow", false)
        if (config.forceHsts) context.response.headers.append("Strict-Transport-Security", "max-age=31536000; includeSubDomains", false)
    }

    // Body cap, layer 1: a declared Content-Length over the route's cap, before any routing or parsing.
    intercept(ApplicationCallPipeline.Plugins) {
        val cap = bodyCapBytes(context.request.path())
        val declared = context.request.contentLength()
        if (cap != null && declared != null && declared > cap) throw PayloadTooLarge()
    }
    // Layer 2: an undeclared (chunked) body is read up to cap+1 bytes and refused past the cap.
    receivePipeline.intercept(ApplicationReceivePipeline.Before) {
        val path = context.request.path()
        if (path == EVENTS_PATH) return@intercept
        val cap = bodyCapBytes(path) ?: return@intercept
        val body = subject as? ByteReadChannel ?: return@intercept
        val head = body.readRemaining(cap + 1).readByteArray()
        body.closedCause?.let { throw it }
        if (head.size > cap) throw PayloadTooLarge()
        proceedWith(ByteReadChannel(head))
    }

    // The mail sender worker (spec 03 §14.5): drains the outbox every 15 seconds.
    if (s.backgroundWorkers) launch(Dispatchers.IO) {
        while (true) {
            runCatching { s.mail.drain() }.onFailure { environment.log.warn("mail worker pass failed", it) }
            delay(15.seconds)
        }
    }

    // The refresh grace's pairs are dropped once their minute has passed ([RefreshGrace.sweepExpired]), every second.
    if (s.backgroundWorkers) launch(Dispatchers.Default) {
        while (true) {
            s.sessions.refreshGrace.sweepExpired()
            delay(1.seconds)
        }
    }

    // The janitor (spec 03 §11.1): once a few minutes after boot, then daily at 04:30 local time.
    if (s.backgroundWorkers) launch(Dispatchers.IO) {
        delay(300.seconds)
        while (true) {
            runCatching { s.janitor.sweep() }.onFailure { environment.log.warn("janitor sweep failed", it) }
            delay(msUntilNextDaily(4, 30))
        }
    }

    // Metrics the operator's alerts key on (spec 03 §8, §11.1, §14.5).
    s.metrics.gauge("andvari.mail.outbox.oldest.seconds", s) { sv -> sv.db.read { c -> sv.mail.oldestQueuedAt(c)?.let { (sv.clock.now() - it) / 1000.0 } ?: 0.0 } }
    s.metrics.gauge("andvari.mail.failed.total", s) { sv -> sv.mail.failedTotal.toDouble() }
    s.metrics.gauge("andvari.vaults.purge.overdue", s) { sv ->
        sv.db.read { c -> c.count("SELECT COUNT(*) FROM vaults WHERE deletedAt IS NOT NULL AND purgedAt IS NULL AND purgeAt<?", sv.clock.now() - 2 * Clock.DAY_MS).toDouble() }
    }

    // Attachment orphan GC (spec 02 §6): hourly.
    if (s.backgroundWorkers) launch(Dispatchers.IO) {
        delay(10.seconds * 60)
        while (true) {
            runCatching { s.attachments.sweepOrphans() }.onFailure { environment.log.warn("attachment GC failed", it) }
            delay(3600.seconds)
        }
    }

    routing {
        miscRoutes(s)
        instanceRoutes(s)
        signupRoutes(s)
        registerRoutes(s)
        authRoutes(s)
        linkRoutes(s)
        deviceRoutes(s)
        vaultLogRoutes(s)
        vaultDataRoutes(s)
        recoveryRoutes(s)
        accountDeleteRoutes(s)
        assistedRecoveryRoutes(s)
        operatorRoutes(s)
        staticRoutes(s)
    }
}

/** A body over its route's cap (`413 body_too_large`). */
class PayloadTooLarge : Exception("body_too_large")

/** Rows 1 and 88–92: policy, health, metrics, robots, downloads, self-host. */
fun Route.miscRoutes(s: Services) {
    val config = s.config

    /** `GET /client-policy` (spec 03 §1.1), bucket `client_policy` 60/min per IP. */
    api(WireRoute.CLIENT_POLICY, s, Bucket.ipPerMinute("client_policy", 60)) {
        respond(ClientPolicy.serializer(), s.policy.clientPolicy(now))
    }

    /** Row 88: 200 when the database is readable (a read-only SELECT). */
    get("/healthz") {
        val ok = runCatching { s.db.read { c -> c.count("SELECT COUNT(*) FROM meta") } }.isSuccess
        if (ok) call.respondText("ok") else call.respond(HttpStatusCode.ServiceUnavailable, "db")
    }

    /** Row 89: loopback only, and never through a forwarding front (spec 03 §8). */
    get("/metrics") {
        if (!call.peerIsLoopback() || call.hasForwardedHeader(config.trustedIpHeaders)) {
            call.respond(HttpStatusCode.Forbidden, "metrics are loopback-only")
        } else {
            call.respondText(s.metrics.scrape())
        }
    }

    /** Row 90: the instance is never indexed. */
    get("/robots.txt") { call.respondText("User-agent: *\nDisallow: /\n") }

    /** Row 91: the signed update channel and installers, from `ANDVARI_DOWNLOADS_DIR`. */
    config.downloadsDir?.let { dir ->
        val root = File(dir)
        get("/downloads/{file}") {
            val name = call.parameters["file"] ?: return@get call.respond(HttpStatusCode.NotFound, "not found")
            if (name.contains("..") || name.contains("/") || name.contains("\\")) return@get call.respond(HttpStatusCode.NotFound, "not found")
            val f = File(root, name)
            if (!f.isFile || f.parentFile != root) return@get call.respond(HttpStatusCode.NotFound, "not found")
            if (name == "manifest.json") call.response.headers.append(HttpHeaders.ContentType, "application/json", false)
            call.respondFile(f)
        }
    }

    /** Row 92: the self-host guide and deploy artifacts, registered before the SPA fallback. */
    get("/selfhost") {
        call.response.headers.append("Content-Security-Policy", SelfHost.CSP, false)
        call.respondText(SelfHost.pageHtml(), ContentType.Text.Html)
    }
    get("/selfhost/{file}") {
        val name = call.parameters["file"] ?: return@get call.respond(HttpStatusCode.NotFound, "not found")
        val body = SelfHost.artifact(name) ?: return@get call.respond(HttpStatusCode.NotFound, "not found")
        call.response.headers.append("Content-Disposition", "attachment; filename=\"$name\"", false)
        call.respondBytes(body, ContentType.Text.Plain)
    }
}

/**
 * The web client (any other path), with a self-only CSP; an unknown `/api/v1` path is a JSON 404. `HEAD` on
 * these paths answers as `GET` does (status and headers, `Content-Length` included) with no body (spec 03
 * §0.2, below the index); no other route gains a `HEAD`.
 */
fun Route.staticRoutes(s: Services) {
    get("/api/{path...}") { notFound() }
    val dir = s.config.webDir ?: return
    val root = File(dir)
    get("/{path...}") {
        if (downloadsUnserved(call.request.path(), call.parameters.getAll("path").orEmpty(), s.config)) return@get call.respond(HttpStatusCode.NotFound, "not found")
        serveWebFile(call, root, head = false)
    }
    head("/{path...}") {
        if (downloadsUnserved(call.request.path(), call.parameters.getAll("path").orEmpty(), s.config)) return@head call.respond(HttpStatusCode.NotFound)
        // A path a more specific GET route owns is not the web app's: leave it unanswered, as before.
        val segments = call.parameters.getAll("path").orEmpty()
        if (!ownedByAnotherGetRoute(segments, s.config)) serveWebFile(call, root, head = true)
    }
}

/**
 * True for every path under `/downloads/` when no downloads directory is set (spec 03 §0.2): those answer
 * `404`, never the web app's page, so a client asking for the signed update list (`manifest.json` and its
 * `.sig`) learns the server serves none, rather than reading an HTML page as a list that failed its check.
 * With a directory set nothing changes.
 */
internal fun downloadsUnserved(path: String, segments: List<String>, config: Config): Boolean =
    config.downloadsDir == null && (path.startsWith("/downloads/") || (segments.size >= 2 && segments[0] == "downloads"))

/**
 * True when a `GET` of [segments] is routed to something other than the web app: `/api/…`, rows 88–90,
 * row 91 when downloads are configured, row 92 (spec 03 §0.2). These keep answering `HEAD` as they did.
 */
internal fun ownedByAnotherGetRoute(segments: List<String>, config: Config): Boolean {
    val first = segments.firstOrNull() ?: return false
    return when {
        first == "api" -> true
        segments.size == 1 -> first in setOf("healthz", "metrics", "robots.txt", "selfhost")
        segments.size == 2 -> first == "selfhost" || (first == "downloads" && config.downloadsDir != null)
        else -> false
    }
}

private suspend fun serveWebFile(call: ApplicationCall, root: File, head: Boolean) {
    suspend fun send(content: OutgoingContent) = call.respond(if (head) BodilessHead(content) else content)
    val rel = call.parameters.getAll("path")?.joinToString("/") ?: ""
    val safe = rel.replace("..", "")
    val file = File(root, safe.ifEmpty { "index.html" })
    val hashedAsset = safe.startsWith("assets/")
    val target = if (file.isFile) file else File(root, "index.html")
    if ((hashedAsset && !file.isFile) || !target.isFile) {
        call.response.headers.append(HttpHeaders.CacheControl, STATIC_CACHE_NOSTORE, false)
        return send(TextContent("not found", ContentType.Text.Plain.withCharset(Charsets.UTF_8), HttpStatusCode.NotFound))
    }
    call.response.headers.append(HttpHeaders.CacheControl, if (hashedAsset) STATIC_CACHE_IMMUTABLE else STATIC_CACHE_REVALIDATE, false)
    call.response.headers.append(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'none'",
        false,
    )
    send(LocalFileContent(target))
}

/**
 * [original]'s status, type, length, headers and properties (so ConditionalHeaders still sees the file's
 * version) with no body: what a `HEAD` answers.
 */
private class BodilessHead(private val original: OutgoingContent) : OutgoingContent.NoContent() {
    override val status: HttpStatusCode? get() = original.status
    override val contentType: ContentType? get() = original.contentType
    override val contentLength: Long? get() = original.contentLength
    override val headers: Headers get() = original.headers
    override fun <T : Any> getProperty(key: AttributeKey<T>): T? = original.getProperty(key)
    override fun <T : Any> setProperty(key: AttributeKey<T>, value: T?) = original.setProperty(key, value)
}

/** Milliseconds until the next local HH:MM. */
internal fun msUntilNextDaily(hour: Int, minute: Int, nowMs: Long = System.currentTimeMillis()): Long {
    val zone = java.time.ZoneId.systemDefault()
    val nowZ = java.time.Instant.ofEpochMilli(nowMs).atZone(zone)
    var next = nowZ.withHour(hour).withMinute(minute).withSecond(0).withNano(0)
    if (!next.isAfter(nowZ)) next = next.plusDays(1)
    return java.time.Duration.between(nowZ, next).toMillis()
}
