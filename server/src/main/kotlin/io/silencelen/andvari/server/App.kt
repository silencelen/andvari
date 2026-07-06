package io.silencelen.andvari.server

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.origin
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.header
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
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
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.PreloginRequest
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.RecoveryUpload
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
import java.io.File
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

/** Bootstrap invite email sentinel: matches whatever email the first admin registers with. */
const val BOOTSTRAP_ANY_EMAIL = "*"

const val SERVER_VERSION = "0.2.0"

private val UUID_PATH_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

/** Path/query ids that name files or rows MUST be canonical UUIDs (also kills traversal). */
fun requireUuid(value: String?, field: String): String {
    val v = value ?: throw BadRequest("missing_$field")
    if (!UUID_PATH_RE.matches(v)) throw BadRequest("bad_$field")
    return v
}

class Services(
    val repo: Repo,
    val service: Service,
    val admin: AdminService,
    val hibp: HibpRelay,
    val notifier: Notifier,
    val config: Config,
    val metrics: PrometheusMeterRegistry,
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
    return Services(repo, service, AdminService(repo), HibpRelay(repo, http), notifier, config, metrics)
}

private suspend fun ApplicationCall.respondFileContent(file: File) {
    respondBytes(file.readBytes(), ContentType.defaultForFile(file))
}

/** First-run: if no users exist and a bootstrap token is set, mint the admin invite. */
private fun seedBootstrap(repo: Repo, config: Config) {
    val userCount = repo.db.read { it.queryOne("SELECT COUNT(*) FROM users") { rs -> rs.getInt(1) } ?: 0 }
    if (userCount > 0) return
    val token = config.bootstrapToken ?: return
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
    install(WebSockets)
    install(MicrometerMetrics) { registry = services.metrics }
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            when (cause) {
                is UpgradeRequired -> call.respond(HttpStatusCode(426, "Upgrade Required"), ApiError("upgrade_required", "min ${cause.platform} ${cause.minVersion}"))
                is Unauthorized -> call.respond(HttpStatusCode.Unauthorized, ApiError(cause.reason, "authentication failed"))
                is Forbidden -> call.respond(HttpStatusCode.Forbidden, ApiError(cause.reason, "forbidden"))
                is BadRequest -> call.respond(HttpStatusCode.BadRequest, ApiError(cause.reason, "bad request"))
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

    // Attachment orphan GC (spec 02 §6): hourly sweep, first pass shortly after boot.
    launch(Dispatchers.IO) {
        delay(10.minutes)
        while (true) {
            runCatching { service.attachments.sweepOrphans() }
                .onFailure { environment.log.warn("attachment GC failed", it) }
            delay(1.hours)
        }
    }

    routing {
        get("/healthz") {
            val ok = runCatching { services.repo.currentRevSafe() }.isSuccess
            if (ok) call.respondText("ok") else call.respond(HttpStatusCode.ServiceUnavailable, "db")
        }

        get("/metrics") {
            // Loopback-only; Alloy scrapes locally. Use the raw peer address (not the
            // reverse-resolved host) and test it as a loopback address. Never trust XFF.
            val peer = call.request.origin.remoteAddress
            val isLoopback = runCatching { java.net.InetAddress.getByName(peer).isLoopbackAddress }.getOrDefault(false)
            if (!isLoopback) {
                call.respond(HttpStatusCode.Forbidden, "metrics are loopback-only")
            } else {
                call.respondText(services.metricsScrape())
            }
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
            if (!limiter.allow("prelogin:${call.clientIp()}", 10, 60_000)) throw RateLimited()
            val req = call.receive<PreloginRequest>()
            call.respond(service.prelogin(req.email))
        }
        post("/api/v1/auth/register") {
            enforceVersion(call, service)
            if (call.isPublicOrigin(config)) throw Forbidden("register_public_disabled")
            val req = call.receive<RegisterRequest>()
            call.respond(service.register(req, call.clientIp()))
        }
        post("/api/v1/auth/login") {
            val publicOrigin = call.isPublicOrigin(config)
            // Public origin is rate-limited harder (spec 03 §8: 5/min vs 10/min).
            if (!limiter.allow("login:${call.clientIp()}", if (publicOrigin) 5 else 10, 60_000)) throw RateLimited()
            enforceVersion(call, service)
            val req = call.receive<LoginRequest>()
            call.respond(service.login(req, call.clientIp(), publicOrigin))
        }
        post("/api/v1/auth/refresh") {
            // spec 03 §8: no refresh via the public origin — break-glass sessions re-login (with TOTP).
            if (call.isPublicOrigin(config)) throw Forbidden("public_refresh_disabled")
            val req = call.receive<RefreshRequest>()
            call.respond(service.refresh(req.refreshToken, call.clientIp()))
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
            service.changePassword(p, call.receive<PasswordChangeRequest>(), call.clientIp())
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
            service.totpConfirm(p.userId, call.receive<TotpCodeRequest>().code, call.clientIp())
            call.respond(service.totpStatus(p.userId))
        }
        post("/api/v1/account/totp/disable") {
            val p = requirePrincipal(call, service)
            service.totpDisable(p.userId, call.receive<TotpCodeRequest>().code, call.clientIp())
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
            call.respond(service.push(p, req.mutations, call.clientIp()))
        }

        // ---- escrow ----
        put("/api/v1/escrow/self") {
            val p = requirePrincipal(call, service)
            val body = call.receive<io.silencelen.andvari.core.model.EscrowUpload>()
            if (body.fingerprint != config.recoveryFingerprint) throw BadRequest("escrow_fingerprint_mismatch")
            services.repo.db.tx { c ->
                c.exec(
                    "INSERT INTO escrow(userId,sealed,fingerprint,updatedAt) VALUES(?,?,?,?) ON CONFLICT(userId) DO UPDATE SET sealed=excluded.sealed, fingerprint=excluded.fingerprint, updatedAt=excluded.updatedAt",
                    p.userId, body.sealed, body.fingerprint, now(),
                )
            }
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
            val req = call.receive<InviteRequest>()
            call.respond(services.admin.createInvite(req.email, req.isAdmin, p.userId).first)
        }
        post("/api/v1/admin/users/{id}/disable") {
            val p = requireAdmin(call, service)
            services.admin.disableUser(call.parameters["id"]!!, p.userId)
            call.respondText("ok")
        }
        post("/api/v1/admin/devices/{id}/revoke") {
            val p = requireAdmin(call, service)
            services.admin.revokeDevice(call.parameters["id"]!!, p.userId)
            call.respondText("ok")
        }
        get("/api/v1/admin/users/{id}/escrow") {
            requireAdmin(call, service)
            val sealed = services.admin.userSealed(call.parameters["id"]!!) ?: throw BadRequest("no_escrow")
            call.respondText(sealed)
        }
        post("/api/v1/admin/recovery") {
            val p = requireAdmin(call, service)
            services.admin.applyRecovery(call.receive<RecoveryUpload>(), p.userId)
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
            service.setPolicy(call.receive<ClientPolicy>())
            services.repo.audit("policy_update", p.userId, null, call.clientIp())
            call.respond(service.policy())
        }

        // ---- events (WS dirty-bell) ----
        webSocket("/api/v1/events") {
            val token = call.request.queryParameters["access"]
                ?: call.request.header(HttpHeaders.Authorization)?.removePrefix("Bearer ")
            val principal = token?.let { service.authenticate(it) }
            if (principal == null) {
                close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "unauthorized"))
                return@webSocket
            }
            services.notifier.register(principal.userId, this)
            try {
                for (frame in incoming) {
                    if (frame is Frame.Text && frame.readText() == "ping") outgoing.send(Frame.Text("pong"))
                }
            } finally {
                services.notifier.unregister(principal.userId, this)
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
                    call.response.headers.append(
                        "Content-Security-Policy",
                        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
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

private suspend fun enforceVersion(call: io.ktor.server.application.ApplicationCall, service: Service) {
    enforceMinVersion(service.policy(), call.clientId())
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
