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
import io.ktor.http.defaultForFile
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.metrics.micrometer.MicrometerMetrics
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondOutputStream
import io.micrometer.prometheusmetrics.PrometheusConfig
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import io.silencelen.andvari.core.model.PasswordChangeRequest
import io.silencelen.andvari.core.model.TotpCodeRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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

private val UUID_PATH_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

/** Path/query ids that name files or rows MUST be canonical UUIDs (also kills traversal). */
fun requireUuid(value: String?, field: String): String {
    val v = value ?: throw BadRequest("missing_$field")
    if (!UUID_PATH_RE.matches(v)) throw BadRequest("bad_$field")
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

fun requireEscrowBlob(sealedB64: String) {
    val bytes = try {
        Bytes.fromB64(sealedB64)
    } catch (e: Exception) {
        throw BadRequest("bad_escrow_blob")
    }
    if (bytes.size < ESCROW_SEALED_MIN || bytes.size > ESCROW_SEALED_MAX) throw BadRequest("bad_escrow_blob")
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
        System.err.println("[andvari] email-invite is OFF — ${config.inviteBaseUrlIssue() ?: "email transport config incomplete (a full SMTP or Graph set)"}")
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
    respondBytes(file.readBytes(), ContentType.defaultForFile(file))
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
            // Loopback-only; Alloy scrapes locally. Shares peerIsLoopback() with clientIp()
            // so the two peer gates can't drift. Never trusts forwarded headers.
            if (!call.peerIsLoopback()) {
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
            val p = service.policy()
            call.respond(p)
        }

        // Org recovery PUBLIC key (base64url) — public; the client confirms its
        // fingerprint against the printed sheet before sealing escrow to it.
        get("/api/v1/recovery-pubkey") {
            if (!config.escrowConfigured) call.respond(HttpStatusCode.ServiceUnavailable, "escrow_not_configured")
            else call.respondText(Bytes.toB64(config.recoveryPublicKey))
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
            enforceVersion(call, service)
            if (call.isPublicOrigin(config)) throw Forbidden("register_public_disabled")
            val req = call.receive<RegisterRequest>()
            call.respond(service.register(req, call.clientIp(config)))
        }
        post("/api/v1/auth/login") {
            val publicOrigin = call.isPublicOrigin(config)
            // Public origin is rate-limited harder (spec 03 §8: 5/min vs 10/min).
            if (!limiter.allow("login:${call.clientIp(config)}", if (publicOrigin) 5 else 10, 60_000)) throw RateLimited()
            enforceVersion(call, service)
            val req = call.receive<LoginRequest>()
            call.respond(service.login(req, call.clientIp(config), publicOrigin))
        }
        post("/api/v1/auth/refresh") {
            // spec 03 §8: no refresh via the public origin — break-glass sessions re-login (with TOTP).
            if (call.isPublicOrigin(config)) throw Forbidden("public_refresh_disabled")
            val req = call.receive<RefreshRequest>()
            call.respond(service.refresh(req.refreshToken, call.clientIp(config)))
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
            service.changePassword(p, call.receive<PasswordChangeRequest>(), call.clientIp(config))
            services.notifier.notifyRevokedUserExcept(p.userId, p.deviceId) // M8: lock the user's OTHER devices (this one is kept)
            call.respondText("ok")
        }

        // ---- server TOTP (spec 03 §2; required for public-origin logins) ----
        get("/api/v1/account/totp") {
            val p = requirePrincipal(call, service)
            call.respond(service.totpStatus(p.userId))
        }
        post("/api/v1/account/totp/setup") {
            val p = requirePrincipal(call, service)
            call.respond(service.totpSetup(p.userId))
        }
        post("/api/v1/account/totp/confirm") {
            val p = requirePrincipal(call, service)
            service.totpConfirm(p.userId, call.receive<TotpCodeRequest>().code, call.clientIp(config))
            call.respond(service.totpStatus(p.userId))
        }
        post("/api/v1/account/totp/disable") {
            val p = requirePrincipal(call, service)
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
        post("/api/v1/items/{id}/restore") {
            val p = requirePrincipal(call, service)
            val id = requireUuid(call.parameters["id"], "item_id")
            val rev = service.restoreItem(p, id, call.receive<ItemUpload>(), call.clientIp(config))
            call.respond(ItemRestoreResponse(rev))
        }
        // "Delete forever" (F49): hard-delete a tombstoned item + its versions. Writer/owner only.
        post("/api/v1/items/{id}/purge") {
            val p = requirePrincipal(call, service)
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
            requirePrincipal(call, service)
            val prefix = call.parameters["prefix"] ?: throw BadRequest("no_prefix")
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
            // server-owned base URL (never a client-supplied URL); a null (ill-formed) skips the email.
            val emailSender = services.email
            val base = config.inviteBaseUrl
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
            val owner = services.admin.revokeDevice(deviceId, p.userId)
            if (owner != null) services.notifier.notifyRevokedDevice(owner, deviceId) // M8: lock + close that device's socket
            call.respondText("ok")
        }
        get("/api/v1/admin/users/{id}/escrow") {
            requireAdmin(call, service)
            val sealed = services.admin.userSealed(requireUuid(call.parameters["id"], "user_id")) ?: throw BadRequest("no_escrow")
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
                    ?.let { service.authenticate(it) }?.let { EventsTicketStore.Redeemed(it.userId, it.deviceId) }
            // M8: re-check revocation at (re)connect — the ticket path (EventsTicketStore.redeem) only
            // checks TTL, so a device revoked inside its 30 s ticket window must be refused here, not
            // left registered and receiving dirty-bells. (The Bearer path already re-checked in authenticate.)
            if (auth == null || !service.deviceHasLiveSession(auth.deviceId)) {
                close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "unauthorized"))
                return@webSocket
            }
            services.notifier.register(auth.userId, auth.deviceId, this)
            try {
                for (frame in incoming) {
                    if (frame is Frame.Text && frame.readText() == "ping") outgoing.send(Frame.Text("pong"))
                }
            } finally {
                services.notifier.unregister(auth.userId, this)
            }
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

private fun requirePrincipal(call: io.ktor.server.application.ApplicationCall, service: Service): Principal {
    val token = call.request.header(HttpHeaders.Authorization)?.removePrefix("Bearer ")?.trim()
        ?: throw Unauthorized("missing_token")
    return service.authenticate(token) ?: throw Unauthorized()
}

private fun requireAdmin(call: io.ktor.server.application.ApplicationCall, service: Service): Principal {
    val p = requirePrincipal(call, service)
    if (!p.isAdmin) throw Forbidden("admin_only")
    return p
}
