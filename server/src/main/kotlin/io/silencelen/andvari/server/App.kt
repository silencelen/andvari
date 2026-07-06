package io.silencelen.andvari.server

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
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
import io.ktor.server.metrics.micrometer.MicrometerMetrics
import io.ktor.server.response.respondBytes
import io.micrometer.prometheusmetrics.PrometheusConfig
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** Bootstrap invite email sentinel: matches whatever email the first admin registers with. */
const val BOOTSTRAP_ANY_EMAIL = "*"

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
                else -> {
                    call.application.environment.log.error("unhandled", cause)
                    call.respond(HttpStatusCode.InternalServerError, ApiError("internal", "internal error"))
                }
            }
        }
    }

    val limiter = RateLimiter()

    routing {
        get("/healthz") {
            val ok = runCatching { services.repo.currentRevSafe() }.isSuccess
            if (ok) call.respondText("ok") else call.respond(HttpStatusCode.ServiceUnavailable, "db")
        }

        get("/metrics") {
            // Loopback-only; Alloy scrapes locally. Never trust XFF here.
            if (call.clientIp() !in setOf("127.0.0.1", "0:0:0:0:0:0:0:1", "::1")) {
                call.respond(HttpStatusCode.Forbidden, "metrics are loopback-only")
            } else {
                call.respondText(services.metricsScrape())
            }
        }

        get("/api/v1/client-policy") {
            val p = service.policy()
            call.respond(p)
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
            if (!limiter.allow("login:${call.clientIp()}", 10, 60_000)) throw RateLimited()
            enforceVersion(call, service)
            if (call.isPublicOrigin(config)) throw Forbidden("public_login_requires_totp") // P4 wires TOTP
            val req = call.receive<LoginRequest>()
            call.respond(service.login(req, call.clientIp()))
        }
        post("/api/v1/auth/refresh") {
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
