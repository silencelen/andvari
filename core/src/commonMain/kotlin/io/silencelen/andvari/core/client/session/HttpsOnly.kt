package io.silencelen.andvari.core.client.session

import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpSend
import io.ktor.client.plugins.plugin
import kotlinx.io.IOException

/**
 * The transport rule of a platform with no cleartext of its own (design 2026-11-09, iOS): https only, except plain
 * http to the [exempt] hosts, loopback alone, as on Android. Anything else fails before a byte is sent, as an
 * [IOException], so it reads as an unreachable server wherever the client branches on one. The Trust Gate says so
 * before Connect ([trustGateRender] with the same set).
 */
fun HttpClient.httpsOnly(exempt: Set<String>): HttpClient {
    plugin(HttpSend).intercept { request ->
        val url = request.url
        if (url.protocol.name != "https" && url.host !in exempt) throw IOException("plain http to ${url.host} is not allowed")
        execute(request)
    }
    return this
}

/**
 * A client that sends nothing: every request fails as an [IOException] before it leaves. The iOS AutoFill extension
 * builds its read-only engine on one, because the account has a single token holder and the extension is not it
 * (design 2026-11-09, "AutoFill").
 */
fun HttpClient.offlineOnly(): HttpClient {
    plugin(HttpSend).intercept { request -> throw IOException("this process never contacts ${request.url.host}") }
    return this
}
