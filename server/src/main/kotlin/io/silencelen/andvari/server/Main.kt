package io.silencelen.andvari.server

import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty

fun main() {
    val config = Config.fromEnv()
    val notifier = Notifier()
    val services = buildServices(config, notifier)
    System.err.println("[andvari] server listening on ${config.host}:${config.port} (escrow configured: ${config.escrowConfigured})")
    embeddedServer(Netty, port = config.port, host = config.host) {
        andvariModule(services)
    }.start(wait = true)
}
