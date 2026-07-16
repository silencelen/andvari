package io.silencelen.andvari.server

import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty

fun main() {
    // §2.1 env lint: WARN on unknown/invalid ANDVARI_* (typo'd/renamed vars silently defaulting is
    // exactly how an operator stance fails to apply); under ANDVARI_STRICT_ENV=1, EXIT — bringup.sh
    // sets strict so a bad env kills boot and fails the healthz wait (B2-1). Notes (deprecated
    // ANDVARI_INVITE_BASE_URL alias in use, signupMode `open`→`landing` coercion §7.3) warn only.
    val lint = Config.envLint(System.getenv())
    lint.notes.forEach { System.err.println("[andvari] env: $it") }
    lint.problems.forEach { System.err.println("[andvari] env WARNING: $it") }
    if (Config.parseBool(System.getenv("ANDVARI_STRICT_ENV")) == true && lint.problems.isNotEmpty()) {
        System.err.println("[andvari] ANDVARI_STRICT_ENV=1 — refusing to start with ${lint.problems.size} env problem(s)")
        kotlin.system.exitProcess(1)
    }
    val config = Config.fromEnv()
    val notifier = Notifier()
    val services = buildServices(config, notifier)
    System.err.println("[andvari] server listening on ${config.host}:${config.port} (escrow configured: ${config.escrowConfigured})")
    embeddedServer(
        Netty,
        configure = {
            connector {
                host = config.host
                port = config.port
            }
            // 0 = off. Reaps stalled request bodies (slow-loris uploads, LOW-6); enable via
            // ANDVARI_REQUEST_READ_TIMEOUT_S only after verifying idle-WS survival on the
            // deployment (30 s ping keepalive must reset the reaper).
            requestReadTimeoutSeconds = config.requestReadTimeoutSeconds
            // 0 = off (override Netty's 10 s default, which truncates slow large-file
            // downloads mid-body). See Config.responseWriteTimeoutSeconds.
            responseWriteTimeoutSeconds = config.responseWriteTimeoutSeconds
        },
    ) {
        andvariModule(services)
    }.start(wait = true)
}
