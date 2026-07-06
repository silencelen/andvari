package io.silencelen.andvari.server

import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin
import io.ktor.server.request.header
import io.silencelen.andvari.core.model.ClientPolicy

/** The authenticated caller, resolved from a Bearer access token. */
data class Principal(val userId: String, val deviceId: String, val sessionId: String, val isAdmin: Boolean)

class UpgradeRequired(val platform: String, val minVersion: String) : Exception()
class Unauthorized(val reason: String = "invalid_credentials") : Exception()
class Forbidden(val reason: String = "forbidden") : Exception()
class BadRequest(val reason: String) : Exception()
class RateLimited : Exception()
class ResyncRequired : Exception()

/** X-Andvari-Client: <platform>/<semver>; used for version pins + audit. */
data class ClientId(val platform: String, val version: String)

fun ApplicationCall.clientId(): ClientId {
    val raw = request.header("X-Andvari-Client") ?: return ClientId("unknown", "0.0.0")
    val slash = raw.indexOf('/')
    return if (slash < 0) ClientId(raw, "0.0.0") else ClientId(raw.take(slash), raw.substring(slash + 1))
}

fun ApplicationCall.clientIp(): String = request.origin.remoteHost

/**
 * True when the request arrived via the configured public (break-glass) hostname.
 * The public path is hardened separately (spec 03 §7); in P1 the tunnel is not even
 * deployed, so this is defensive.
 */
fun ApplicationCall.isPublicOrigin(config: Config): Boolean {
    val host = request.header("Host") ?: request.origin.serverHost
    return config.publicHostname != null && host.contains(config.publicHostname, ignoreCase = true)
}

/** semver compare a<b → -1; only numeric major.minor.patch (pre-release ignored). */
fun compareVersions(a: String, b: String): Int {
    fun parts(v: String) = v.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
    val pa = parts(a); val pb = parts(b)
    for (i in 0 until maxOf(pa.size, pb.size)) {
        val x = pa.getOrElse(i) { 0 }; val y = pb.getOrElse(i) { 0 }
        if (x != y) return x.compareTo(y)
    }
    return 0
}

fun enforceMinVersion(policy: ClientPolicy, client: ClientId) {
    val min = policy.minVersion[client.platform] ?: return
    if (compareVersions(client.version, min) < 0) throw UpgradeRequired(client.platform, min)
}
