package io.silencelen.andvari.server

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.origin
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.contentLength
import io.ktor.server.request.header
import io.ktor.server.request.path
import io.ktor.server.request.receive
import io.ktor.server.request.receiveText
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.delete
import io.ktor.server.routing.routing
import io.ktor.server.routing.RoutingContext
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readText
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.ApiError
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.DeletedItemsResponse
import io.silencelen.andvari.core.client.EnrollLink
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.ItemRestoreResponse
import io.silencelen.andvari.core.model.ItemUpload
import io.silencelen.andvari.core.model.ItemVersionsResponse
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.PreloginRequest
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.RecoveryCommitRequest
import io.silencelen.andvari.core.model.RecoverySelfConfirmRequest
import io.silencelen.andvari.core.model.RecoverySelfSetupRequest
import io.silencelen.andvari.core.model.RecoverySelfSetupResponse
import io.silencelen.andvari.core.model.RecoveryUpload
import io.silencelen.andvari.core.model.RecoveryVerifyRequest
import io.silencelen.andvari.core.model.RefreshRequest
import io.silencelen.andvari.core.model.RegisterRequest
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.http.ContentType
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.metrics.micrometer.MicrometerMetrics
import io.ktor.server.plugins.conditionalheaders.ConditionalHeaders
import io.ktor.server.plugins.partialcontent.PartialContent
import io.ktor.server.request.ApplicationReceivePipeline
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondFile
import io.ktor.server.response.respondOutputStream
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readRemaining
import io.micrometer.prometheusmetrics.PrometheusConfig
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import io.silencelen.andvari.core.model.PasswordChangeRequest
import io.silencelen.andvari.core.model.TotpCodeRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.io.readByteArray
import io.silencelen.andvari.core.model.WsTicketResponse
import kotlinx.serialization.Serializable
import java.io.File
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

/** Bootstrap invite email sentinel: matches whatever email the first admin registers with. */
const val BOOTSTRAP_ANY_EMAIL = "*"

// Aliases the single release-version source in :core — Admin Status and the update
// check lied for a whole release when this was a separate hand-bumped literal.
const val SERVER_VERSION = io.silencelen.andvari.core.client.ANDVARI_CLIENT_VERSION

/**
 * The POST /api/v1/admin/users wire shape (#21): InviteResponse + the email-dispatch outcome, so
 * "she never got it" is debuggable from the Admin UI. Server-local (NOT core Wire.kt) — the shape
 * is additive and every client decodes with ignoreUnknownKeys, so older ones simply don't see it.
 * emailStatus reports the dispatch ATTEMPT honestly: the send runs off-thread AFTER the tx commits
 * (A3), so "queued" is the ceiling — never a delivery claim. Values:
 *   queued | skipped_rate_limited | not_requested | not_configured | failed
 * Status only — the recipient/link never ride it (A4).
 */
@Serializable
data class InviteCreateResponse(val inviteToken: String, val email: String, val expiresAt: Long, val emailStatus: String)

/** Path/query ids that name files or rows MUST be canonical UUIDs (also kills traversal). */
fun requireUuid(value: String?, field: String): String {
    val v = value ?: throw BadRequest("missing_$field")
    if (!UUID_RE.matches(v)) throw BadRequest("bad_$field")
    return v
}

/**
 * Structural escrow-blob gate (spec 04 §3). The blob is crypto_box_seal'd to the OFFLINE
 * recovery key, so the server CANNOT verify it cryptographically — by design (ZK: the
 * recovery secret never exists server-side). What it can do is refuse obvious garbage
 * before it becomes an account's only recovery path: base64url validity + sealed-length
 * bounds. crypto_box_SEALBYTES = 48 (32B ephemeral pk + 16B MAC); the v1 canonical
 * payload (Escrow.canonicalPayload: uuid userId, keyType "uvk", 32B key + its sha256,
 * both base64url) is exactly 178 bytes → 226 sealed. Bounds leave headroom for future
 * additive payload versions while still rejecting truncated/random junk. Real
 * verification happens offline: `recovery-cli verify` (docs/drills/escrow-canary-drill.md).
 */
const val ESCROW_SEAL_OVERHEAD = 48
const val ESCROW_SEALED_MIN = ESCROW_SEAL_OVERHEAD + 150
const val ESCROW_SEALED_MAX = ESCROW_SEAL_OVERHEAD + 1024

/** Ceiling on the §8.2 usage-ledger blob, in base64 characters. An entry is roughly 70 bytes of
 *  plaintext (itemId + two numbers), so this clears a vault of tens of thousands of items with
 *  room to spare — generous on purpose, since refusing a legitimate write would silently freeze a
 *  user's staleness column, while still stopping an authenticated client from treating its own
 *  row as free storage. */
const val USAGE_SEALED_MAX = 512 * 1024

fun requireEscrowBlob(sealedB64: String) {
    val bytes = try {
        Bytes.fromB64(sealedB64)
    } catch (e: Exception) {
        throw BadRequest("bad_escrow_blob")
    }
    if (bytes.size < ESCROW_SEALED_MIN || bytes.size > ESCROW_SEALED_MAX) throw BadRequest("bad_escrow_blob")
}

/**
 * Global request-body caps (spec 03; pentest M4 [S4-01]: an 8 MiB body POSTed to the
 * unauthenticated /auth/prelogin was fully heap-buffered — a concurrent flood away from
 * OOMing the single CT122 process). Three route classes:
 *   EXEMPT   — the attachment upload streams via receiveChannel and AttachmentStore
 *              enforces its own per-attachment/per-user quotas mid-stream; the /events
 *              WebSocket upgrade (draining its live bidirectional channel in the layer-2
 *              receive interceptor would block the handshake forever).
 *   GENEROUS — /sync/push: a CSV import lands here as ONE JSON body (up to 200
 *              mutations, item blobs uncapped upstream), so the ceiling is sized to
 *              bound the buffer without breaking a fat import batch.
 *   TIGHT    — every other route, notably ALL unauthenticated ones; the largest
 *              legitimate body (register, a single-item restore) sits well under it.
 * Enforced in two layers in [andvariModule]: a declared Content-Length over the cap is
 * refused before the handler runs; chunked/undeclared bodies are cut off at receive time.
 * Breach ⇒ 413 [PayloadTooLarge] "body_too_large" via StatusPages' house error shape.
 */
internal const val BODY_CAP_TIGHT_BYTES = 256L * 1024
internal const val BODY_CAP_PUSH_BYTES = 8L * 1024 * 1024

/** The request-body cap for [path], or null when exempt (the streamed attachment upload; the
 *  /events WebSocket upgrade, whose live channel must not be drained by the receive interceptor). */
internal fun bodyCapBytes(path: String): Long? = when {
    path.startsWith("/api/v1/attachments/") -> null
    path == "/api/v1/events" -> null
    path == "/api/v1/sync/push" -> BODY_CAP_PUSH_BYTES
    // A single-item restore re-uploads that item's re-encrypted blob, which is uncapped upstream
    // exactly like a push mutation — so it gets the GENEROUS ceiling, not TIGHT. Otherwise a big
    // item the server accepted at creation (via push) would 413 on restore = un-restorable Trash.
    path.startsWith("/api/v1/items/") && path.endsWith("/restore") -> BODY_CAP_PUSH_BYTES
    else -> BODY_CAP_TIGHT_BYTES
}

class Services(
    val repo: Repo,
    val service: Service,
    val admin: AdminService,
    val hibp: HibpRelay,
    val notifier: Notifier,
    val config: Config,
    val metrics: PrometheusMeterRegistry,
    val janitor: Janitor,
    val email: EmailSender? = null, // cut 4: the SMTP sender when config.emailConfigured, else null (feature off)
    val wsTickets: EventsTicketStore = EventsTicketStore(),
) {
    fun metricsScrape(): String = metrics.scrape()
}

fun buildServices(config: Config, notifier: Notifier): Services {
    val db = Db(config.dbPath)
    val repo = Repo(db)
    seedBootstrap(repo, config)
    val http = HttpClient(Java)
    val service = Service(repo, config) { userIds, rev -> notifier.notifyRev(userIds, rev) }
    val metrics = PrometheusMeterRegistry(PrometheusConfig.DEFAULT)
    registerPurgeGauges(metrics, db)
    val janitor = Janitor(repo, service.attachments, config) { userIds, rev -> notifier.notifyRev(userIds, rev) }
    // cut 4: pick the transport — Graph (preferred, durable) when configured, else SMTP; null = OFF.
    // Constructed only when emailConfigured (a full transport + a valid canonical base URL), so a
    // partial/typo'd config stays OFF rather than half-armed. GraphEmailSender reuses `http` (no new dep).
    val email: EmailSender? = when {
        !config.emailConfigured -> null
        config.graphConfigured -> GraphEmailSender(http, config.graphTenantId!!, config.graphClientId!!, config.graphClientSecret!!, config.graphSender!!)
        else -> SmtpEmailSender(config.smtpHost!!, config.smtpPort, config.smtpUser!!, config.smtpPass!!, config.smtpFrom!!)
    }
    val anyEmailEnv = !config.smtpHost.isNullOrBlank() || !config.graphClientId.isNullOrBlank() || !config.graphTenantId.isNullOrBlank()
    if (email == null && anyEmailEnv) {
        System.err.println("[andvari] email-invite is OFF — ${config.canonicalOriginIssue() ?: "email transport config incomplete (a full SMTP or Graph set)"}")
    }
    return Services(repo, service, AdminService(repo, config), HibpRelay(repo, http), notifier, config, metrics, janitor, email)
}

/** A purge stalled this long past its due time means the janitor is dead — alert-worthy. */
internal const val PURGE_OVERDUE_MS = 2 * Service.DAY_MS

/**
 * Purge-visibility gauges (design 2026-07-07 skipti §4 step 6 ops mandate): the ops
 * alert on stalled purges keys off these two /metrics series (the Grafana rule itself
 * lives ops-side).
 *   andvari_vaults_deleted_pending — tombstones awaiting purge (normal during grace)
 *   andvari_vaults_purge_overdue  — due >2 days ago and still unpurged (janitor stalled)
 * Scrape-time COUNTs under the Db lock: cheap (vaults is small + idx_vaults_purge) and
 * safe (the single ReentrantLock serializes with route txs). Micrometer holds gauge
 * state WEAKLY — `db` is strongly held for the app's lifetime via Services.repo.db, so
 * these can never silently GC to NaN.
 */
private fun registerPurgeGauges(metrics: PrometheusMeterRegistry, db: Db) {
    metrics.gauge("andvari.vaults.deleted.pending", db) { d ->
        d.read { c ->
            c.queryOne("SELECT COUNT(*) FROM vaults WHERE deletedAt IS NOT NULL AND purgedAt IS NULL") { it.getLong(1) } ?: 0L
        }.toDouble()
    }
    metrics.gauge("andvari.vaults.purge.overdue", db) { d ->
        d.read { c ->
            c.queryOne(
                "SELECT COUNT(*) FROM vaults WHERE deletedAt IS NOT NULL AND purgedAt IS NULL AND purgeAt IS NOT NULL AND purgeAt < ?",
                now() - PURGE_OVERDUE_MS,
            ) { it.getLong(1) } ?: 0L
        }.toDouble()
    }
}

private suspend fun ApplicationCall.respondFileContent(file: File) {
    // STREAMED (LocalFileContent: bounded buffers, Content-Length, a Last-Modified version) —
    // never file.readBytes(): this serves both the SPA assets and the /downloads installers
    // (80–150 MB each), and heap-buffering a handful of concurrent desktop updates used to
    // allocate them all as byte[] at once (polish audit 2026-07-27 quality-perf--1). The
    // ConditionalHeaders + PartialContent plugins turn the version into 304 revalidation and
    // Range support (resumable installer downloads).
    respondFile(file)
}

/** First-run: if no users exist and a bootstrap token is set, mint the admin invite. */
private fun seedBootstrap(repo: Repo, config: Config) {
    val userCount = repo.db.read { it.queryOne("SELECT COUNT(*) FROM users") { rs -> rs.getInt(1) } ?: 0 }
    if (userCount > 0) return
    val token = config.bootstrapToken ?: return
    // #22 self-heal: with ZERO users no invite was ever redeemed (redeem creates the user in the
    // same tx), so an EXPIRED leftover row here is pure debris — yet it used to count as "existing"
    // and block re-minting until the janitor's 30-day prune, bricking a first-run admin whose 72 h
    // fuse lapsed before enrollment. Clear it (which also frees the tokenHash PK for the same
    // ANDVARI_BOOTSTRAP_TOKEN), then only a LIVE invite blocks the re-mint.
    repo.db.tx { c -> c.exec("DELETE FROM invites WHERE usedAt IS NULL AND expiresAt < ?", now()) }
    val existing = repo.db.read { it.queryOne("SELECT COUNT(*) FROM invites") { rs -> rs.getInt(1) } ?: 0 }
    if (existing > 0) return
    repo.db.tx { c ->
        c.exec(
            "INSERT INTO invites(tokenHash,email,isAdmin,createdAt,expiresAt) VALUES(?,?,1,?,?)",
            ServerCrypto.hashToken(token), BOOTSTRAP_ANY_EMAIL, now(), now() + 72L * 3600 * 1000,
        )
    }
    System.err.println("[andvari] bootstrap admin invite created (redeem with ANDVARI_BOOTSTRAP_TOKEN and any email)")
}

fun Application.andvariModule(services: Services) {
    val config = services.config
    val service = services.service

    install(ContentNegotiation) { json(json) }
    // Ping keepalive (spec 03 §6 "server pings every 30 s" — now true): browsers auto-pong,
    // so a healthy idle dirty-bell has recurring inbound traffic and survives any Netty
    // request-read timeout (LOW-6) comfortably above the 60 s frame timeout.
    install(WebSockets) {
        pingPeriodMillis = 30_000
        timeoutMillis = 60_000
    }
    install(MicrometerMetrics) { registry = services.metrics }
    // quality-perf--1: for the streamed file responses (respondFileContent) these turn the file's
    // Last-Modified version into 304 revalidation and add Range support (resumable installer
    // downloads). No-ops for the API routes — JSON responses carry no versions and the attachment
    // GET streams via WriteChannelContent, which PartialContent does not touch.
    install(ConditionalHeaders)
    install(PartialContent)
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            when (cause) {
                is UpgradeRequired -> call.respond(HttpStatusCode(426, "Upgrade Required"), ApiError("upgrade_required", "min ${cause.platform} ${cause.minVersion}"))
                is Unauthorized -> call.respond(HttpStatusCode.Unauthorized, ApiError(cause.reason, "authentication failed"))
                is Forbidden -> call.respond(HttpStatusCode.Forbidden, ApiError(cause.reason, "forbidden"))
                is BadRequest -> call.respond(HttpStatusCode.BadRequest, ApiError(cause.reason, "bad request"))
                is NotFound -> call.respond(HttpStatusCode.NotFound, ApiError(cause.reason, "not found"))
                is Conflict -> call.respond(HttpStatusCode.Conflict, ApiError(cause.reason, "conflict"))
                is Gone -> call.respond(HttpStatusCode.Gone, ApiError(cause.reason, "gone"))
                is ResyncRequired -> call.respond(HttpStatusCode.Gone, ApiError("resync_required", "cursor predates retained history"))
                is RateLimited -> call.respond(HttpStatusCode.TooManyRequests, ApiError("rate_limited", "slow down"))
                is PayloadTooLarge -> call.respond(HttpStatusCode.PayloadTooLarge, ApiError(cause.reason, "quota exceeded"))
                is BadGateway -> call.respond(HttpStatusCode.BadGateway, ApiError(cause.reason, "upstream failed"))
                is ServiceUnavailable -> call.respond(HttpStatusCode.ServiceUnavailable, ApiError(cause.reason, "not configured on this instance"))
                // PT-L11 (CR-04): Ktor's own malformed-input throwables (a bad/empty JSON body on any
                // receive route — incl. unauthenticated /auth/*) are CLIENT errors → 400, not a 500 with
                // "unhandled" log spam. In Ktor 3.0.3 these are disjoint hierarchies
                // (ContentTransformationException : IOException, BadRequestException : Exception — the
                // latter is what convertBody wraps a bad JSON body as).
                // Deliberately NO blanket `is IllegalArgumentException -> 400`: kotlinx
                // SerializationException and NumberFormatException BOTH extend IllegalArgumentException, so a
                // corrupt/rolled-back SERVER-persisted row (policy, kdfParams, attachmentIds, idempotency
                // resultJson) must stay a LOGGED 500, never a silent 400 (server review 2026-07-15 F1).
                // Genuine client-input arg errors already throw the house BadRequest (matched above) or are
                // validated in-route (e.g. the Hibp prefix check).
                is io.ktor.server.plugins.ContentTransformationException -> call.respond(HttpStatusCode.BadRequest, ApiError("bad_request", "malformed request body"))
                is io.ktor.server.plugins.BadRequestException -> call.respond(HttpStatusCode.BadRequest, ApiError("bad_request", "bad request"))
                else -> {
                    call.application.environment.log.error("unhandled", cause)
                    call.respond(HttpStatusCode.InternalServerError, ApiError("internal", "internal error"))
                }
            }
        }
    }

    val limiter = RateLimiter()

    // Break-glass observability: count public-origin traffic + stamp the last-seen
    // time (admin status + the andvari_public_origin_requests metric).
    val publicCounter = services.metrics.counter("andvari.public.origin.requests")
    var lastPublicMetaWrite = 0L
    intercept(ApplicationCallPipeline.Monitoring) {
        if (context.isPublicOrigin(config)) {
            publicCounter.increment()
            val t = now()
            if (t - lastPublicMetaWrite > 60_000) {
                lastPublicMetaWrite = t
                runCatching { services.repo.setMeta("lastPublicRequestAt", t.toString()) }
            }
        }
    }

    // Pentest hygiene (#22): baseline security headers on EVERY response — API and SPA alike.
    // nosniff stops MIME-sniffing of API JSON/served files; no-referrer keeps the private origin
    // out of outbound Referer headers; the minimal Permissions-Policy denies powerful features the
    // app never uses (QR codes are DISPLAYED here, scanned by a phone camera — the web app itself
    // never opens one); X-Robots-Tag backstops /robots.txt so the public break-glass origin's
    // 200-HTML SPA fallthrough is never indexed. ADD-only — the SPA route's self-only CSP stands.
    intercept(ApplicationCallPipeline.Plugins) {
        context.response.headers.append("X-Content-Type-Options", "nosniff", false)
        context.response.headers.append("Referrer-Policy", "no-referrer", false)
        context.response.headers.append("Permissions-Policy", "camera=(), microphone=(), geolocation=()", false)
        context.response.headers.append("X-Robots-Tag", "noindex, nofollow", false)
        // CR-17 (ASVS V9.1/V14.4): HSTS on the public break-glass origin — the one origin designed
        // for hostile networks, TLS-terminated at Cloudflare. GATED to isPublicOrigin so the plain-http
        // RFC1918/loopback LAN dev path is never pinned to HTTPS (an HSTS pin there would brick dev).
        // This header alone is insufficient without the CF "Always Use HTTPS" redirect (ops), but it
        // closes the header half in-code so a first-visit-over-TLS client won't downgrade thereafter.
        // §7.2 re-home: ANDVARI_FORCE_HSTS=1 opts a single-origin TLS instance in (the reference
        // instance sets it once ANDVARI_PUBLIC_HOSTNAME is retired) — default off, dev unchanged.
        if (context.isPublicOrigin(config) || config.forceHsts) {
            context.response.headers.append("Strict-Transport-Security", "max-age=31536000; includeSubDomains", false)
        }
    }

    // Request-body cap, layer 1 (spec 03; pentest M4): a declared Content-Length over the
    // route's cap is refused up front — before routing, auth, or rate-limit work — so an
    // oversize body never costs more than header parsing (nothing of it is read).
    intercept(ApplicationCallPipeline.Plugins) {
        val cap = bodyCapBytes(context.request.path())
        val declared = context.request.contentLength()
        if (cap != null && declared != null && declared > cap) throw PayloadTooLarge("body_too_large")
    }

    // Layer 2: chunked/undeclared-length bodies. Read at most cap+1 bytes at receive time
    // and hand the handler a bounded replay channel — every capped route buffers its whole
    // body in call.receive anyway (the streaming attachment upload is exempt), so this adds
    // no buffering, just a bound. Deliberately NOT a wrapper channel whose writer coroutine
    // throws mid-stream: ktor-io's CloseToken rewraps a writer failure in IOException, which
    // would surface the house PayloadTooLarge as a 500 instead of a 413 at StatusPages.
    receivePipeline.intercept(ApplicationReceivePipeline.Before) {
        val cap = bodyCapBytes(context.request.path()) ?: return@intercept
        val body = subject as? ByteReadChannel ?: return@intercept
        val head = body.readRemaining(cap + 1).readByteArray()
        body.closedCause?.let { throw it } // a mid-body client abort stays an IO failure, as before
        if (head.size > cap) throw PayloadTooLarge("body_too_large")
        proceedWith(ByteReadChannel(head))
    }

    // Attachment orphan GC (spec 02 §6): hourly sweep, first pass shortly after boot.
    launch(Dispatchers.IO) {
        delay(10.minutes)
        while (true) {
            runCatching { service.attachments.sweepOrphans() }
                .onFailure { environment.log.warn("attachment GC failed", it) }
            delay(1.hours)
        }
    }

    // Lifecycle + retention janitor (spec 03 §11, spec 02 §7): vault purge, transfer-offer
    // expiry, item-tombstone GC, `changes` pruning + the oldestRetainedRev fence, and the
    // bounded-retention prunes (sessions/mutations/audit/invites/hibp) — Janitor.kt's
    // header has the full sweep set. Daily at 04:30 local, plus one delayed on-boot pass
    // (a server down over 04:30 must not defer a due purge a whole day).
    // ANDVARI_JANITOR_DRYRUN → log-only.
    launch(Dispatchers.IO) {
        delay(5.minutes)
        while (true) {
            runCatching { services.janitor.sweep() }
                .onFailure { environment.log.warn("lifecycle janitor sweep failed", it) }
            delay(msUntilNextDaily(4, 30))
        }
    }

    routing {
        get("/healthz") {
            val ok = runCatching { services.repo.currentRevSafe() }.isSuccess
            if (ok) call.respondText("ok") else call.respond(HttpStatusCode.ServiceUnavailable, "db")
        }

        get("/metrics") {
            // Loopback-only for a GENUINE local Alloy scrape (CR-18). peerIsLoopback() alone is
            // insufficient: both front-ends (tailscale-serve, cloudflared) terminate TLS on
            // 127.0.0.1, so every PROXIED request — the whole tailnet, and the public break-glass
            // tunnel — also presents a loopback peer. Additionally require the ABSENCE of any
            // reverse-proxy forwarding header: a real local scrape carries none, a proxied request
            // always carries at least one. Header-presence only — clientIp() trust is untouched.
            if (!call.peerIsLoopback() || call.hasForwardedHeader(config.trustedIpHeaders)) {
                call.respond(HttpStatusCode.Forbidden, "metrics are loopback-only")
            } else {
                call.respondText(services.metricsScrape())
            }
        }

        // #22: a household hoard has no business in a search index — the public break-glass origin
        // otherwise serves the SPA fallthrough as 200 HTML to any crawler. Exact path beats the
        // {path...} SPA catch-all in Ktor routing, so this wins regardless of declaration order.
        get("/robots.txt") {
            call.respondText("User-agent: *\nDisallow: /\n")
        }

        get("/api/v1/client-policy") {
            // §2.2: fetched pre-login by all four clients on boot/unlock/switch/landing — the
            // most-hammered anonymous route on a public instance, so it gets a per-IP bucket
            // (generous: a legitimate client re-fetches a handful of times a minute at worst).
            if (!limiter.allow("client_policy:${call.clientIp(config)}", 60, 60_000)) throw RateLimited()
            // Per-origin overlay (§2.2): the break-glass twin origin always answers
            // signupMode="closed" — same isPublicOrigin authority the login route uses.
            call.respond(service.policy(call.isPublicOrigin(config)))
        }

        // Org recovery PUBLIC key (base64url) — public; the client confirms its
        // fingerprint against the printed sheet before sealing escrow to it.
        get("/api/v1/recovery-pubkey") {
            // The SUCCESS body stays bare base64 (every client does fromB64 on the raw text);
            // the failure rides the house ApiError so "this instance has no escrow key" reaches
            // the enroll flow as a named cause instead of an opaque 503 (bug-server--9).
            if (!config.escrowConfigured) throw ServiceUnavailable("escrow_not_configured")
            call.respondText(Bytes.toB64(config.recoveryPublicKey))
        }

        // Desktop distribution + in-app update check (spec P3). The manifest and the
        // installer files live in ANDVARI_DOWNLOADS_DIR; the desktop client fetches
        // manifest.json on launch and compares versions.
        config.downloadsDir?.let { dir ->
            val root = File(dir)
            get("/downloads/manifest.json") {
                val manifest = File(root, "manifest.json")
                if (manifest.isFile) {
                    call.response.headers.append("Content-Type", "application/json", false)
                    call.respondBytes(manifest.readBytes())
                } else {
                    call.respond(HttpStatusCode.NotFound, "no manifest")
                }
            }
            get("/downloads/{file}") {
                val name = call.parameters["file"] ?: return@get call.respond(HttpStatusCode.BadRequest, "no file")
                if (name.contains("..") || name.contains("/") || name.contains("\\")) {
                    return@get call.respond(HttpStatusCode.BadRequest, "bad name")
                }
                val f = File(root, name)
                if (f.isFile && f.parentFile == root) call.respondFileContent(f)
                else call.respond(HttpStatusCode.NotFound, "not found")
            }
        }

        // ---- auth ----
        post("/api/v1/auth/prelogin") {
            if (!limiter.allow("prelogin:${call.clientIp(config)}", 10, 60_000)) throw RateLimited()
            val req = call.receive<PreloginRequest>()
            call.respond(service.prelogin(req.email))
        }
        post("/api/v1/auth/register") {
            // F22: the last anonymous POST without a bucket. It yields no credential (the invite is
            // 256-bit and checked before any argon2 work), but it deserializes a TIGHT-capped body and
            // opens a write tx on the ONE SQLite connection the whole process serializes on — cheap
            // requests converted into contention on every authenticated sync. Same 5/min per-IP shape
            // as its login/recovery siblings; a household enrolls devices, not floods.
            if (!limiter.allow("register:${call.clientIp(config)}", 5, 60_000)) throw RateLimited()
            enforceVersion(call, service)
            if (call.isPublicOrigin(config)) throw Forbidden("register_public_disabled")
            val req = call.receive<RegisterRequest>()
            call.respond(service.register(req, call.clientIp(config), call.declaredClientVersion()))
        }
        post("/api/v1/auth/login") {
            val publicOrigin = call.isPublicOrigin(config)
            // §2.5 (B1-3): ONE flat per-IP bucket, decoupled from origin — the old private-origin
            // relaxation to 10/min is revoked (unsetting ANDVARI_PUBLIC_HOSTNAME must not loosen
            // online-guessing resistance). ANDVARI_LOGIN_RATE_PER_MIN tunes it (default 5); the
            // email-keyed exponential backoff inside Service.login is the per-account half.
            if (!limiter.allow("login:${call.clientIp(config)}", config.loginRatePerMin, 60_000)) throw RateLimited()
            enforceVersion(call, service)
            val req = call.receive<LoginRequest>()
            call.respond(service.login(req, call.clientIp(config), publicOrigin, call.declaredClientVersion()))
        }
        post("/api/v1/auth/refresh") {
            // spec 03 §8: no refresh via the public origin — break-glass sessions re-login (with TOTP).
            if (call.isPublicOrigin(config)) throw Forbidden("public_refresh_disabled")
            // F22: per-IP like its siblings, but with headroom — a multi-device household waking at
            // once (or a fleet whose access tokens expire together) legitimately bursts here, and a
            // refresh token is a 256-bit secret, so this bounds resource use, not guessing.
            if (!limiter.allow("refresh:${call.clientIp(config)}", 30, 60_000)) throw RateLimited()
            val req = call.receive<RefreshRequest>()
            call.respond(service.refresh(req.refreshToken, call.clientIp(config), call.declaredClientVersion()))
        }
        post("/api/v1/auth/logout") {
            val p = requirePrincipal(call, service)
            service.logout(p)
            call.respondText("ok")
        }

        // ---- account ----
        get("/api/v1/account/keys") {
            val p = requirePrincipal(call, service)
            call.respond(service.accountKeys(p.userId))
        }
        put("/api/v1/account/password") {
            val p = requirePrincipal(call, service)
            // bug-server--5: same bucket shape as the recovery routes — the verify below is a
            // memory-hard 64 MiB argon2 per attempt (plus an audit row per miss), so it must not
            // be free to loop. Per-user, not per-IP: the caller is authenticated, matching the
            // vault_create/lookup/invite buckets.
            if (!limiter.allow("password_change:${p.userId}", 5, 60_000)) throw RateLimited()
            service.changePassword(p, call.receive<PasswordChangeRequest>(), call.clientIp(config))
            services.notifier.notifyRevokedUserExcept(p.userId, p.deviceId) // M8: lock the user's OTHER devices (this one is kept)
            call.respondText("ok")
        }

        // ---- server TOTP (spec 03 §2; required for public-origin logins) ----
        get("/api/v1/account/totp") {
            val p = requirePrincipal(call, service)
            call.respond(service.totpStatus(p.userId))
        }
        // F02: the routes below verify 6-digit codes, so each carries an anti-automation bucket —
        // per-user, not per-IP, like password_change: the caller is already authenticated. Without
        // them a HIJACKED session could loop /setup with guessed current codes until it rotated the
        // second factor onto a secret it holds — durable break-glass access on a public instance.
        // Service audits every miss (totp_verify_fail) so the attempt is visible in GET /admin/audit,
        // not just refused.
        //
        // The keys are cut by WHICH SECRET a call checks, not by which route it is (server review
        // 2026-08-13) — one key per route gave the LIVE factor 10 guesses/min across two independent
        // 5/min buckets, twice the budget the finding asked for:
        //   totp_verify:<userId>  — the live ENROLLED secret. /disable always checks it; /setup
        //                           checks it too when the account is enrolled (the rotation gate).
        //                           ONE budget across both, so the live factor really faces 5/min.
        //   totp_setup:<userId>   — a FIRST enrollment, which verifies nothing (it only stages a
        //                           server-generated pending secret). Separate so an exhausted
        //                           live-secret budget can't block initial enrollment and vice versa.
        //   totp_confirm:<userId> — the PENDING secret, which the server just handed this caller, so
        //                           guessing it buys nothing. Its own key keeps a rotation that is
        //                           already staged finishable even in a minute when the live-secret
        //                           budget is spent.
        // Login's TOTP check is deliberately outside these: it is pre-auth (no userId yet) and is
        // covered by the per-IP login bucket plus the email-keyed backoff (design 2026-07-15 §2.5).
        post("/api/v1/account/totp/setup") {
            val p = requirePrincipal(call, service)
            // Enrolled ⇒ this call is a rotation and will verify the LIVE secret below, so it draws
            // on the shared verify budget; not enrolled ⇒ there is no secret to guess yet.
            val setupKey = if (service.totpStatus(p.userId).enrolled) "totp_verify:${p.userId}" else "totp_setup:${p.userId}"
            if (!limiter.allow(setupKey, 5, 60_000)) throw RateLimited()
            // Additive OPTIONAL body (bug-server--0): an ENROLLED account must present its current
            // code to stage a rotation (Service gates it — 400 totp_code_required when enrolled and
            // absent); a fresh enrollment sends no body, exactly the fielded wire shape. Body parse
            // rule mirrors /recovery/self/confirm: blank/absent ⇒ null; non-blank ⇒ TotpCodeRequest,
            // decode failure ⇒ 400 bad_request.
            val text = call.receiveText()
            val code = if (text.isBlank()) null else runCatching {
                json.decodeFromString(TotpCodeRequest.serializer(), text).code
            }.getOrElse { throw BadRequest("bad_request") }
            call.respond(service.totpSetup(p.userId, code, call.clientIp(config)))
        }
        post("/api/v1/account/totp/confirm") {
            val p = requirePrincipal(call, service)
            if (!limiter.allow("totp_confirm:${p.userId}", 5, 60_000)) throw RateLimited()
            service.totpConfirm(p.userId, call.receive<TotpCodeRequest>().code, call.clientIp(config))
            call.respond(service.totpStatus(p.userId))
        }
        post("/api/v1/account/totp/disable") {
            val p = requirePrincipal(call, service)
            // Always a live-secret check ⇒ always the shared verify budget (see the note above).
            if (!limiter.allow("totp_verify:${p.userId}", 5, 60_000)) throw RateLimited()
            service.totpDisable(p.userId, call.receive<TotpCodeRequest>().code, call.clientIp(config))
            call.respond(service.totpStatus(p.userId))
        }

        // ---- attachments (spec 02 §6: blob first, then the item update referencing it) ----
        post("/api/v1/attachments/{id}") {
            val p = requirePrincipal(call, service)
            enforceVersion(call, service)
            val id = requireUuid(call.parameters["id"], "attachment_id")
            val vaultId = requireUuid(call.request.queryParameters["vaultId"], "vault_id")
            val itemId = requireUuid(call.request.queryParameters["itemId"], "item_id")
            val role = services.repo.db.read { c -> services.repo.grantRole(c, p.userId, vaultId) }
            if (role == null || role == "reader") throw Forbidden("no_write_grant")
            val meta = withContext(Dispatchers.IO) {
                service.attachments.store(p.userId, id, itemId, vaultId, call.receiveChannel(), service.policy())
            }
            call.respond(meta)
        }
        get("/api/v1/attachments/{id}") {
            val p = requirePrincipal(call, service)
            val id = requireUuid(call.parameters["id"], "attachment_id")
            val row = services.repo.db.read { c -> service.attachments.rowById(c, id) }
                ?: throw Forbidden("no_grant") // hidden-as-403 for cross-tenant probes (spec 03 §8)
            services.repo.db.read { c -> services.repo.grantRole(c, p.userId, row.vaultId) }
                ?: throw Forbidden("no_grant")
            val blob = service.attachments.file(id)
            if (!blob.isFile) throw Forbidden("no_grant")
            val header = Bytes.fromB64(row.header)
            call.respondOutputStream(ContentType.Application.OctetStream, contentLength = header.size + blob.length()) {
                write(header)
                blob.inputStream().use { it.copyTo(this) }
            }
        }

        // Item history (feature: item history & restore): the archived ciphertext versions of an
        // item (server keeps the last 10; spec 02 §7). Grant-checked against the item's OWN vault.
        // The item row persists even when tombstoned, so this also serves a deleted item's versions
        // (a future undelete slice builds on it). Client decrypts each blob under the VK it holds.
        get("/api/v1/items/{id}/versions") {
            val p = requirePrincipal(call, service)
            val id = requireUuid(call.parameters["id"], "item_id")
            // Hidden as 403 for cross-tenant probes (spec 03 §8): unknown item AND no grant both 403.
            val item = services.repo.db.read { c -> services.repo.itemById(c, id) } ?: throw Forbidden("no_grant")
            services.repo.db.read { c -> services.repo.grantRole(c, p.userId, item.vaultId) } ?: throw Forbidden("no_grant")
            val versions = services.repo.db.read { c -> services.repo.itemVersions(c, id) }
            call.respond(ItemVersionsResponse(id, versions))
        }

        // Item undelete (feature): the caller's tombstoned items, grant-scoped (a tombstone's blob
        // is null, so the client fetches each item's last version for the name/preview).
        get("/api/v1/items/deleted") {
            val p = requirePrincipal(call, service)
            call.respond(DeletedItemsResponse(service.deletedItems(p.userId)))
        }
        // Restore a tombstoned item: the client re-encrypts a chosen version and POSTs it here; the
        // server un-tombstones cleanly (dedicated path, not a put — avoids the edit-over-tombstone
        // conflict that would spawn a spurious copy). Writer/owner only; only a deleted item.
        // Item lifecycle buckets, the per-ITEM sibling of the vault_destructive/vault_recovery
        // pair below (bug-server--10 — these two routes carried no bucket at all). Windows are an
        // hour and the counts are generous by design: a household emptying or rebuilding its whole
        // Trash in one sitting must never hit them, while an automated walk of every tombstone is
        // throttled and leaves a bucket in the audit/metrics story. Recovery is the looser of the
        // two for the same reason as vaults — a restore is never blocked by the purge spree it undoes.
        post("/api/v1/items/{id}/restore") {
            val p = requirePrincipal(call, service)
            // Version-pinned like /sync/push: a restore re-uploads a re-encrypted item blob, so a
            // build the min-version pin bans must not write item ciphertext through this door.
            enforceVersion(call, service)
            if (!limiter.allow("item_recovery:${p.userId}", 400, 3_600_000)) throw RateLimited()
            val id = requireUuid(call.parameters["id"], "item_id")
            val rev = service.restoreItem(p, id, call.receive<ItemUpload>(), call.clientIp(config))
            call.respond(ItemRestoreResponse(rev))
        }
        // "Delete forever" (F49): hard-delete a tombstoned item + its versions. Writer/owner only.
        // The module's only irreversible per-item destruction (Repo.purgeItem leaves no tombstone),
        // so it takes the tighter bucket. Deliberately NOT enforceVersion'd: the pin exists to keep
        // a banned build from WRITING ciphertext, and a purge writes none.
        post("/api/v1/items/{id}/purge") {
            val p = requirePrincipal(call, service)
            if (!limiter.allow("item_destructive:${p.userId}", 200, 3_600_000)) throw RateLimited()
            val id = requireUuid(call.parameters["id"], "item_id")
            call.respond(ItemRestoreResponse(service.purgeItem(p, id, call.clientIp(config))))
        }

        // ---- sync ----
        get("/api/v1/sync") {
            val p = requirePrincipal(call, service)
            enforceVersion(call, service)
            val since = call.request.queryParameters["since"]?.toLongOrNull() ?: 0L
            call.respond(service.pull(p.userId, since))
        }
        post("/api/v1/sync/push") {
            val p = requirePrincipal(call, service)
            enforceVersion(call, service)
            val req = call.receive<PushRequest>()
            call.respond(service.push(p, req.mutations, call.clientIp(config)))
        }

        // ---- shared vaults (spec 03 §10) — authed, version-checked, owner-managed,
        // refused on the public break-glass origin (sharing admin is a sit-at-home op).
        // Every route below shares ONE preamble (sharingPrincipal) so the public-origin
        // guard can never be silently dropped again (F23). ----
        post("/api/v1/vaults") {
            val p = sharingPrincipal(config, service)
            if (!limiter.allow("vault_create:${p.userId}", 5, 3_600_000)) throw RateLimited()
            call.respond(HttpStatusCode.Created, service.createSharedVault(p, call.receive(), call.clientIp(config)))
        }
        post("/api/v1/users/lookup") {
            val p = sharingPrincipal(config, service)
            if (!limiter.allow("lookup:${p.userId}", 20, 60_000)) throw RateLimited()
            call.respond(service.lookupUser(p, call.receive<io.silencelen.andvari.core.model.UserLookupRequest>().email, call.clientIp(config)))
        }
        get("/api/v1/vaults/{vaultId}/members") {
            // F23: this GET had drifted past the public-origin refusal — now it rides the
            // shared preamble like every other sharing route.
            val p = sharingPrincipal(config, service)
            call.respond(service.listVaultMembers(p, requireUuid(call.parameters["vaultId"], "vault_id")))
        }
        post("/api/v1/vaults/{vaultId}/members") {
            val p = sharingPrincipal(config, service)
            val vaultId = requireUuid(call.parameters["vaultId"], "vault_id")
            call.respond(HttpStatusCode.Created, service.addVaultMember(p, vaultId, call.receive(), call.clientIp(config)))
        }
        put("/api/v1/vaults/{vaultId}/members/{userId}") {
            val p = sharingPrincipal(config, service)
            val vaultId = requireUuid(call.parameters["vaultId"], "vault_id")
            val userId = requireUuid(call.parameters["userId"], "user_id")
            call.respond(service.setVaultMemberRole(p, vaultId, userId, call.receive<io.silencelen.andvari.core.model.VaultMemberRole>().role, call.clientIp(config)))
        }
        delete("/api/v1/vaults/{vaultId}/members/{userId}") {
            val p = sharingPrincipal(config, service)
            val vaultId = requireUuid(call.parameters["vaultId"], "vault_id")
            val userId = requireUuid(call.parameters["userId"], "user_id")
            // Additive optional removal-proof body (spec 03 §10/§11). Distinguish ABSENT
            // (no body → proofless removal, the 0.4.0 shape) from PRESENT-but-unparseable
            // (→ 400 bad_request so the client knows the proof did NOT land and can retry) —
            // never silently swallow a sent-but-malformed proof (#5).
            val body = if ((call.request.contentLength() ?: 0L) > 0L) {
                runCatching { call.receive<io.silencelen.andvari.core.model.VaultMemberRemoveRequest>() }
                    .getOrElse { throw BadRequest("bad_request") }
            } else null
            call.respond(service.removeVaultMember(p, vaultId, userId, call.clientIp(config), body?.proof, body?.nonce))
        }

        // ---- vault lifecycle (spec 03 §11) — authed, version-checked, refused on the
        // public break-glass origin, rate-bucketed: vault_destructive (delete, transfer
        // offer, rename) 10/h vs vault_recovery (restore, cancel, accept, leave) 30/h —
        // a restore is never blocked by the delete spree it undoes. Idempotency is by
        // operation identity (deleteId/offerId), enforced in Service. ----
        post("/api/v1/vaults/{vaultId}/delete") {
            val p = sharingPrincipal(config, service)
            if (!limiter.allow("vault_destructive:${p.userId}", 10, 3_600_000)) throw RateLimited()
            val vaultId = requireUuid(call.parameters["vaultId"], "vault_id")
            call.respond(service.deleteVault(p, vaultId, call.receive(), call.clientIp(config)))
        }
        post("/api/v1/vaults/{vaultId}/restore") {
            val p = sharingPrincipal(config, service)
            if (!limiter.allow("vault_recovery:${p.userId}", 30, 3_600_000)) throw RateLimited()
            val vaultId = requireUuid(call.parameters["vaultId"], "vault_id")
            call.respond(service.restoreVault(p, vaultId, call.receive(), call.clientIp(config)))
        }
        get("/api/v1/vaults/deleted") {
            val p = sharingPrincipal(config, service)
            call.respond(service.listDeletedVaults(p))
        }
        post("/api/v1/vaults/{vaultId}/leave") {
            val p = sharingPrincipal(config, service)
            if (!limiter.allow("vault_recovery:${p.userId}", 30, 3_600_000)) throw RateLimited()
            val vaultId = requireUuid(call.parameters["vaultId"], "vault_id")
            call.respond(service.leaveVault(p, vaultId, call.clientIp(config)))
        }
        post("/api/v1/vaults/{vaultId}/transfer") {
            val p = sharingPrincipal(config, service)
            if (!limiter.allow("vault_destructive:${p.userId}", 10, 3_600_000)) throw RateLimited()
            val vaultId = requireUuid(call.parameters["vaultId"], "vault_id")
            call.respond(HttpStatusCode.Created, service.offerTransfer(p, vaultId, call.receive(), call.clientIp(config)))
        }
        delete("/api/v1/vaults/{vaultId}/transfer") {
            val p = sharingPrincipal(config, service)
            if (!limiter.allow("vault_recovery:${p.userId}", 30, 3_600_000)) throw RateLimited()
            val vaultId = requireUuid(call.parameters["vaultId"], "vault_id")
            call.respond(service.cancelTransfer(p, vaultId, call.clientIp(config)))
        }
        post("/api/v1/vaults/{vaultId}/transfer/accept") {
            val p = sharingPrincipal(config, service)
            if (!limiter.allow("vault_recovery:${p.userId}", 30, 3_600_000)) throw RateLimited()
            val vaultId = requireUuid(call.parameters["vaultId"], "vault_id")
            call.respond(service.acceptTransfer(p, vaultId, call.receive(), call.clientIp(config)))
        }
        put("/api/v1/vaults/{vaultId}/meta") {
            val p = sharingPrincipal(config, service)
            if (!limiter.allow("vault_destructive:${p.userId}", 10, 3_600_000)) throw RateLimited()
            val vaultId = requireUuid(call.parameters["vaultId"], "vault_id")
            call.respond(service.updateVaultMeta(p, vaultId, call.receive(), call.clientIp(config)))
        }

        // ---- escrow ----
        put("/api/v1/escrow/self") {
            val p = requirePrincipal(call, service)
            val body = call.receive<io.silencelen.andvari.core.model.EscrowUpload>()
            // F19: the §F.4 escrow-polarity gate is TOTAL over BOTH ingestion points, not just
            // register. Without this the second one leaked: a member enrolled under a `waived`
            // invite — an account the design guarantees has NO admin backstop — could PUT one blob
            // carrying the publicly-served org fingerprint and give itself an escrow row, so the
            // Admin console read "admin backstop" over a users.escrowPolicy still saying `waived`
            // and an operator auditing recovery coverage saw a backstop nobody can open.
            if (!config.escrowConfigured) throw ServiceUnavailable("escrow_not_configured")
            if (services.repo.escrowWaived(p.userId)) throw BadRequest("escrow_not_allowed_when_waived")
            if (body.fingerprint != config.recoveryFingerprint) throw BadRequest("escrow_fingerprint_mismatch")
            requireEscrowBlob(body.sealed)
            services.repo.db.tx { c ->
                c.exec(
                    "INSERT INTO escrow(userId,sealed,fingerprint,updatedAt) VALUES(?,?,?,?) ON CONFLICT(userId) DO UPDATE SET sealed=excluded.sealed, fingerprint=excluded.fingerprint, updatedAt=excluded.updatedAt",
                    p.userId, body.sealed, body.fingerprint, now(),
                )
                // Escrow is the sole recovery path (spec 04); replacing it is security-relevant.
                services.repo.auditOn(c, "escrow_self_upload", p.userId, p.deviceId, call.clientIp(config), body.fingerprint)
            }
            call.respondText("ok")
        }

        // ---- usage ledger (spec 02 §8.2, design 2026-08-22-login-health) ----
        // One opaque AEAD blob per user, sealed under the UVK. The server stores and returns bytes
        // and can decrypt none of it — the shape `escrow` and `member_recovery` already use.
        //
        // Deliberately NOT per-item rows: that would hand the server the per-item behavioral timing
        // (which login, how often, when) that this whole design exists to withhold. What leaks here
        // is that a user's ledger changed and roughly how big it is — nothing about which login.
        get("/api/v1/usage") {
            val p = requirePrincipal(call, service)
            call.respond(services.repo.usageLedger(p.userId))
        }
        put("/api/v1/usage") {
            val p = requirePrincipal(call, service)
            val body = call.receive<io.silencelen.andvari.core.model.UsageUpload>()
            // Bounded like every other client-supplied blob: the ledger is ~50 bytes of ciphertext
            // per item, so this ceiling clears a very large vault by a wide margin while keeping an
            // authenticated client from using its own row as free storage.
            if (body.sealedUsage.isEmpty() || body.sealedUsage.length > USAGE_SEALED_MAX) throw BadRequest("bad_usage_blob")
            services.repo.db.tx { c ->
                c.exec(
                    "INSERT INTO usage_ledger(userId,sealedUsage,updatedAt) VALUES(?,?,?) ON CONFLICT(userId) DO UPDATE SET sealedUsage=excluded.sealedUsage, updatedAt=excluded.updatedAt",
                    p.userId, body.sealedUsage, now(),
                )
            }
            // Deliberately NOT audited: this endpoint is written on a routine cadence by every
            // client, and an audit row per flush would rebuild — in the audit log — exactly the
            // per-user activity trace the batching rule exists to avoid. It is not
            // security-relevant: it grants nothing, and losing it costs a health column.
            call.respondText("ok")
        }

        // ---- per-member self-service recovery (design 2026-07-12 §F.3) ----
        // Two-phase (verify → commit) + a setup/rotation path. All FOUR (the confirm below included)
        // refuse the public break-glass origin (like register, App.kt:332) and are per-IP fixed-window
        // rate-limited at the public-login tightness (5/min) — a per-IP counter, never per-account, so a
        // targeted account can't be locked out of its own recovery (§F.8). No enforceVersion: recovery
        // must work even for a client the min-version pin would gate, and pre-recovery clients never
        // call these paths.
        post("/api/v1/recovery/self/verify") {
            if (call.isPublicOrigin(config)) throw Forbidden("recovery_public_disabled")
            if (!limiter.allow("recovery_verify:${call.clientIp(config)}", 5, 60_000)) throw RateLimited()
            call.respond(service.recoverySelfVerify(call.receive<RecoveryVerifyRequest>(), call.clientIp(config)))
        }
        post("/api/v1/recovery/self/commit") {
            if (call.isPublicOrigin(config)) throw Forbidden("recovery_public_disabled")
            if (!limiter.allow("recovery_commit:${call.clientIp(config)}", 5, 60_000)) throw RateLimited()
            val recovered = service.recoverySelfCommit(call.receive<RecoveryCommitRequest>(), call.clientIp(config))
            services.notifier.notifyRevokedUser(recovered) // M8: self-recovery revoked all this user's sessions
            call.respondText("ok")
        }
        put("/api/v1/recovery/self-setup") {
            if (call.isPublicOrigin(config)) throw Forbidden("recovery_public_disabled")
            if (!limiter.allow("recovery_setup:${call.clientIp(config)}", 5, 60_000)) throw RateLimited()
            val p = requirePrincipal(call, service)
            val pieceId = service.recoverySelfSetup(p, call.receive<RecoverySelfSetupRequest>(), call.clientIp(config))
            // Piece-binding (design 2026-07-13 §1.4): the response carries the fresh pieceId (was the
            // text "ok" — no fielded client parses that body) so the capture gate's type-back confirm
            // can bind to the piece THIS setup committed.
            call.respond(RecoverySelfSetupResponse(pieceId))
        }
        // §F.9 capture confirmation (enroll happy-path + the gate's type-back): authenticated, public-
        // origin-refused, per-IP rate-limited like the other recovery routes. A session suffices (no key
        // material moves — the committed piece is what was shown); it flips the durable recoveryConfirmed
        // flag ONLY when the confirm still names the CURRENT piece (design 2026-07-13 §2.2; stale ⇒
        // 409 recovery_piece_stale via StatusPages' Conflict mapping). Body parse rule (§1.4, BINDING):
        // blank/absent ⇒ pieceId=null (the fielded 0.15/0.16 body-less wire shape — R2 device-scoped
        // acceptance); non-blank ⇒ RecoverySelfConfirmRequest, decode failure ⇒ 400 bad_request.
        post("/api/v1/recovery/self/confirm") {
            if (call.isPublicOrigin(config)) throw Forbidden("recovery_public_disabled")
            if (!limiter.allow("recovery_confirm:${call.clientIp(config)}", 5, 60_000)) throw RateLimited()
            val p = requirePrincipal(call, service)
            val text = call.receiveText()
            val pieceId = if (text.isBlank()) null else runCatching {
                json.decodeFromString(RecoverySelfConfirmRequest.serializer(), text).pieceId
            }.getOrElse { throw BadRequest("bad_request") }
            service.recoverySelfConfirm(p, pieceId, call.clientIp(config))
            call.respondText("ok")
        }

        // ---- hibp relay ----
        get("/api/v1/hibp/range/{prefix}") {
            val p = requirePrincipal(call, service)
            // bug-server--2: a per-user bucket in the shape of its siblings (lookup 20/min,
            // client-policy 60/min), sized for the Health breach scan — one request per UNIQUE
            // password prefix, awaited sequentially and mostly served from the 7-day cache on a
            // rescan — so a big-vault scan never trips it while a runaway loop stays bounded.
            if (!limiter.allow("hibp:${p.userId}", 600, 60_000)) throw RateLimited()
            val prefix = call.parameters["prefix"] ?: throw BadRequest("no_prefix")
            // PT-L11 (CR-04): validate the k-anonymity prefix in-route → a clean 400 (bad_prefix)
            // instead of Hibp.range()'s require() throwing IllegalArgumentException down to StatusPages.
            if (prefix.length != 5 || !prefix.all { it in "0123456789abcdefABCDEF" }) throw BadRequest("bad_prefix")
            call.respondText(withContext(Dispatchers.IO) { services.hibp.range(prefix) })
        }

        // ---- admin ----
        get("/api/v1/admin/users") {
            requireAdmin(call, service)
            call.respond(services.admin.listUsers())
        }
        post("/api/v1/admin/users") {
            val p = requireAdmin(call, service)
            if (!limiter.allow("invite:${p.userId}", 20, 3_600_000)) throw RateLimited() // A6: cap invite mints (mail-abuse)
            val req = call.receive<InviteRequest>()
            // escrowPolicy is persisted on the invite row and read SERVER-SIDE at register (design §F.4).
            // Passed through as the admin's explicit posture — the Admin UI defaults it to "waived" for
            // emailed invites (§F.1: a server-composed emailed link carries no authoritative rfp, so
            // required+emailed forces the discouraged typed-sheet ceremony; frictionless waived is the
            // common remote case). The server never forces it, so an explicit in-person-QR required
            // invite is preserved and a silent posture strip stays visible on admin reconciliation.
            val (resp, token) = services.admin.createInvite(req.email, req.isAdmin, p.userId, req.ttlMinutes, req.sendEmail, req.escrowPolicy)
            // A3: send the enroll link AFTER the tx committed (createInvite returned), off the request
            // path, best-effort, in the APPLICATION scope so it survives the response — a slow/failed
            // relay never stalls the SQLite writer or the HTTP reply. The link is composed from the
            // server-owned canonical origin (§3: ANDVARI_CANONICAL_ORIGIN, with the deprecated
            // ANDVARI_INVITE_BASE_URL as fallback alias — never a client-supplied URL); a null
            // (ill-formed) skips the email.
            val emailSender = services.email
            val base = config.canonicalOrigin
            // #21: each branch reports its own emailStatus (see InviteCreateResponse) so a mint-but-
            // no-email outcome is visible to the admin, not indistinguishable from a send.
            val emailStatus = when {
                !req.sendEmail -> "not_requested"
                emailSender == null || base == null -> "not_configured"
                // A6: a PER-RECIPIENT email cap on top of the per-admin invite cap above — so a
                // compromised admin can't email-bomb one address under the household mail domain. The
                // invite still MINTS (and responds); only the email is skipped past the cap.
                !limiter.allow("invite_email:${resp.email}", 5, 3_600_000) -> "skipped_rate_limited"
                else -> {
                    val link = EnrollLink.compose(base, token, resp.email)
                    if (link == null) "failed" else {
                        val to = resp.email
                        // #2: the branded body names the inviter and matches the invite's real posture —
                        // read here (request path, cheap single-row) so the launch captures plain values.
                        // escrowWaived mirrors createInvite's normalization (anything but the literal
                        // "waived" ⇒ required — fail-safe in the same direction).
                        val inviterName = services.repo.userById(p.userId)?.displayName
                        val escrowWaived = req.escrowPolicy == "waived"
                        val expiresAt = resp.expiresAt
                        call.application.launch(Dispatchers.IO) {
                            try {
                                emailSender.sendInvite(to, link, inviterName, escrowWaived, expiresAt)
                            } catch (e: Exception) {
                                call.application.environment.log.warn("invite email failed (${e.javaClass.simpleName})") // A4: no PII
                            }
                        }
                        "queued"
                    }
                }
            }
            call.respond(InviteCreateResponse(resp.inviteToken, resp.email, resp.expiresAt, emailStatus))
        }
        post("/api/v1/admin/users/{id}/disable") {
            val p = requireAdmin(call, service)
            val targetId = requireUuid(call.parameters["id"], "user_id")
            services.admin.disableUser(targetId, p.userId)
            services.notifier.notifyRevokedUser(targetId) // M8 (spec 03 §6): drop the disabled user's live sockets
            call.respondText("ok")
        }
        post("/api/v1/admin/devices/{id}/revoke") {
            val p = requireAdmin(call, service)
            val deviceId = requireUuid(call.parameters["id"], "device_id")
            val owner = services.admin.revokeDevice(deviceId, p.userId) // throws NotFound on an unknown id
            services.notifier.notifyRevokedDevice(owner, deviceId) // M8: lock + close that device's socket
            call.respondText("ok")
        }
        get("/api/v1/admin/users/{id}/escrow") {
            requireAdmin(call, service)
            // 404, not 400: the id was well-formed, the row simply isn't there — the same stance
            // every other state-of-the-world miss takes (no_such_user, not_a_member). A 400 told
            // the Admin UI "you sent a bad id" for a member who is merely waived (bug-server--9).
            val sealed = services.admin.userSealed(requireUuid(call.parameters["id"], "user_id")) ?: throw NotFound("no_escrow")
            call.respondText(sealed)
        }
        post("/api/v1/admin/recovery") {
            val p = requireAdmin(call, service)
            val req = call.receive<RecoveryUpload>()
            services.admin.applyRecovery(req, p.userId)
            services.notifier.notifyRevokedUser(req.userId) // M8: admin recovery revokes all the user's sessions
            call.respondText("ok")
        }
        get("/api/v1/admin/audit") {
            requireAdmin(call, service)
            val since = call.request.queryParameters["since"]?.toLongOrNull() ?: 0L
            val type = call.request.queryParameters["type"]
            val user = call.request.queryParameters["userId"]
            val limit = call.request.queryParameters["limit"]?.toIntOrNull() ?: 200
            call.respond(services.repo.auditQuery(since, type, user, limit))
        }
        get("/api/v1/admin/users/{id}/devices") {
            requireAdmin(call, service)
            call.respond(services.admin.listDevices(requireUuid(call.parameters["id"], "user_id")))
        }
        get("/api/v1/admin/status") {
            requireAdmin(call, service)
            call.respond(services.admin.status(config, service.attachments))
        }
        get("/api/v1/admin/policy") {
            requireAdmin(call, service)
            call.respond(service.policy())
        }
        put("/api/v1/admin/policy") {
            val p = requireAdmin(call, service)
            // Audited inside the policy tx (INFO-5) — no standalone audit call here.
            service.setPolicy(call.receive<ClientPolicy>(), p.userId, call.clientIp(config))
            call.respond(service.policy())
        }

        // ---- events (WS dirty-bell) ----
        // Browsers can't set headers on a WS upgrade, so web clients mint a single-use 30 s
        // ticket over the authenticated REST channel and connect with THAT (LOW-9): the
        // long-lived access token never rides a query string into edge logs. Raw access
        // tokens in the query are NOT accepted; the Bearer header path stays for non-browser
        // callers.
        post("/api/v1/events/ticket") {
            val p = requirePrincipal(call, service)
            call.respond(WsTicketResponse(services.wsTickets.mint(p.userId, p.deviceId), 30))
        }
        webSocket("/api/v1/events") {
            // M8: bind the socket to (userId, deviceId) — ticket carries the minting device; the Bearer
            // fallback takes the token's own session device — so a single-device revoke can target it.
            val auth = call.request.queryParameters["ticket"]?.let { services.wsTickets.redeem(it) }
                ?: call.request.header(HttpHeaders.Authorization)?.removePrefix("Bearer ")?.trim()
                    ?.let { service.authenticate(it) }
                    // §2.6: the Bearer upgrade path bypasses requirePrincipal, so it mirrors the
                    // restricted-session refusal here (the ticket path is covered upstream — a
                    // restricted session can't mint a ticket in the first place).
                    ?.takeIf { !it.mustEnrollTotp }
                    ?.let { EventsTicketStore.Redeemed(it.userId, it.deviceId) }
            if (auth == null) {
                close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "unauthorized"))
                return@webSocket
            }
            // M8 / CR-05: re-check revocation at (re)connect — the ticket path only checks TTL, so a
            // device revoked inside its 30 s ticket window must be refused here. REGISTER FIRST, then
            // re-check, to close the check-then-register TOCTOU: a concurrent revoke commits its DB row
            // BEFORE its notifier fan-out (App.kt device-revoke route), so either (a) that commit lands
            // before this recheck's read → we see the dead session and self-close, or (b) it lands after
            // register() → the fan-out's snapshot includes this conn and closes it. Either interleaving
            // tears the socket down; the old order (check, then register after the fan-out) left it live.
            services.notifier.register(auth.userId, auth.deviceId, this)
            try {
                // Recheck revocation INSIDE the try (F2, server review 2026-07-15): deviceHasLiveSession is a
                // db.read that can throw (wedged/closing DB); if it threw before this try we'd exit with the
                // conn registered but the finally un-run → a leaked Notifier entry until restart. The
                // register-first ordering above still closes the TOCTOU; return@webSocket here still runs the
                // finally, and a double-unregister is an idempotent removeIf.
                if (!service.deviceHasLiveSession(auth.deviceId)) {
                    close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "unauthorized"))
                    return@webSocket
                }
                for (frame in incoming) {
                    if (frame is Frame.Text && frame.readText() == "ping") outgoing.send(Frame.Text("pong"))
                }
            } finally {
                services.notifier.unregister(auth.userId, this)
            }
        }

        // ---- self-host docs (design 2026-07-15 §8.1, B2-4) ----
        // A REAL route registered BEFORE the SPA fallback below (whose {path...} catch-all would
        // otherwise swallow /selfhost into index.html; exact paths also beat the catch-all in ktor
        // routing — both the order and the specificity protect it). Serves a bundled HTML render of
        // docs/self-hosting.md plus the deploy artifacts as downloads, baked into the jar by
        // server/build.gradle.kts processResources from files the DOCS/DEPLOY lane owns
        // (docs/self-hosting.md + deploy/{docker-compose.yml,andvari.env.template,bringup.sh}).
        // Registered unconditionally (webDir or not) so `selfHostDocsUrl` resolves on EVERY instance.
        get("/selfhost") {
            call.response.headers.append("Content-Security-Policy", SelfHost.CSP, false)
            call.respondText(SelfHost.pageHtml(), ContentType.Text.Html)
        }
        get("/selfhost/{file}") {
            // Fixed-name allowlist inside SelfHost.artifact — no path input reaches the classpath
            // lookup (and ktor single-segment params never match a slash anyway).
            val name = call.parameters["file"] ?: return@get call.respond(HttpStatusCode.NotFound, "not found")
            val body = SelfHost.artifact(name) ?: return@get call.respond(HttpStatusCode.NotFound, "not found")
            call.response.headers.append("Content-Disposition", "attachment; filename=\"$name\"", false)
            call.respondBytes(body, ContentType.Text.Plain)
        }

        // ---- static web (served with a self-only CSP) ----
        config.webDir?.let { dir ->
            val root = File(dir)
            get("/{path...}") {
                val rel = call.parameters.getAll("path")?.joinToString("/") ?: ""
                val safe = rel.replace("..", "")
                val file = File(root, safe.ifEmpty { "index.html" })
                val target = if (file.isFile) file else File(root, "index.html")
                if (target.isFile) {
                    // style-src 'unsafe-inline' is deliberate (audit INFO-8, document-and-keep):
                    // React inline style={{…}} is used across web/src/ui, there is no
                    // HTML-injection sink, and script-src already blocks inline JS — dropping
                    // it is a styling refactor with no exploitability win today.
                    call.response.headers.append(
                        "Content-Security-Policy",
                        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'none'",
                        false,
                    )
                    call.respondFileContent(target)
                } else {
                    call.respond(HttpStatusCode.NotFound, "not found")
                }
            }
        }
    }
}

/** Milliseconds until the next local-time HH:MM (janitor schedule: daily 04:30). */
internal fun msUntilNextDaily(hour: Int, minute: Int, nowMs: Long = now()): Long {
    val zone = java.time.ZoneId.systemDefault()
    val nowZ = java.time.Instant.ofEpochMilli(nowMs).atZone(zone)
    var next = nowZ.withHour(hour).withMinute(minute).withSecond(0).withNano(0)
    if (!next.isAfter(nowZ)) next = next.plusDays(1)
    return java.time.Duration.between(nowZ, next).toMillis()
}

private suspend fun enforceVersion(call: io.ktor.server.application.ApplicationCall, service: Service) {
    enforceMinVersion(service.policy(), call.clientId())
}

/**
 * The single shared preamble for EVERY §10 sharing + §11 lifecycle route (#7): authenticate,
 * enforce the min-version pin, and refuse the public break-glass origin. Consolidating it into
 * one call means a future sharing/lifecycle route cannot silently omit the public-origin guard
 * (the exact copy-paste omission that caused the F23 members-GET drift) — it either calls this
 * and is guarded, or has no principal at all.
 */
private suspend fun RoutingContext.sharingPrincipal(config: Config, service: Service): Principal {
    val p = requirePrincipal(call, service)
    enforceVersion(call, service)
    if (call.isPublicOrigin(config)) throw Forbidden("sharing_public_disabled")
    return p
}

/**
 * §2.6: the ONLY authenticated routes a TOTP-enrollment-RESTRICTED session may reach — the setup +
 * confirm pair that lifts the restriction, and logout. Everything else (status GET and disable
 * included) answers 403 totp_enrollment_required until enrollment completes.
 */
private val TOTP_ENROLL_ALLOWED_PATHS = setOf(
    "/api/v1/account/totp/setup",
    "/api/v1/account/totp/confirm",
    "/api/v1/auth/logout",
)

private fun requirePrincipal(call: io.ktor.server.application.ApplicationCall, service: Service): Principal {
    val token = call.request.header(HttpHeaders.Authorization)?.removePrefix("Bearer ")?.trim()
        ?: throw Unauthorized("missing_token")
    val p = service.authenticate(token) ?: throw Unauthorized()
    // §2.6 restricted session (instance totpRequired + user not enrolled): the SINGLE enforcement
    // point — every requirePrincipal route inherits it. The /events WS upgrade is the one authed
    // path not built on requirePrincipal: its ticket path can't be reached (minting a ticket goes
    // through here) and its Bearer fallback mirrors this check in-route.
    if (p.mustEnrollTotp && call.request.path() !in TOTP_ENROLL_ALLOWED_PATHS) {
        throw Forbidden("totp_enrollment_required")
    }
    return p
}

private fun requireAdmin(call: io.ktor.server.application.ApplicationCall, service: Service): Principal {
    val p = requirePrincipal(call, service)
    if (!p.isAdmin) throw Forbidden("admin_only")
    return p
}
