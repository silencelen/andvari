package io.silencelen.andvari.server

import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty

fun main() {
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
        },
    ) {
        andvariModule(services)
    }.start(wait = true)
}
