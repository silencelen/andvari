package io.silencelen.andvari.cli.e2e

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.http.Url

/**
 * The tests' way to put a listener of their own (a proxy, a connection counter) between a device and the server: every
 * request for [origin] is SENT to the loopback [dial]; every check the engine makes still uses [origin]. A request for
 * any other host is refused, never sent.
 *
 * **The limit.** The request names [dial], not [origin], in its `Host` header: ktor's Java engine drops a `Host` header
 * the caller sets, and the library that could name the origin (ktor's CIO engine) was declined by the owner on
 * 2026-11-15. Nothing the tests prove rests on it: the hostile proxy names the origin to the server itself,
 * and the server does not read `Host`. The tool's own `--connect` therefore refuses any address but the origin's own.
 */
object Redirect {
    fun client(origin: String, dial: String, extra: HttpClientConfig<*>.() -> Unit = {}): HttpClient {
        val o = Url(origin)
        val c = Url(dial)
        require(c.protocol.name == "http" && (c.host == "127.0.0.1" || c.host == "localhost")) { "a test redirects only to a loopback address: $dial" }
        return HttpClient(Java) {
            install(HttpTimeout) { requestTimeoutMillis = 60_000; connectTimeoutMillis = 10_000 }
            expectSuccess = false
            install(createClientPlugin("redirect") {
                onRequest { req, _ ->
                    // A URL builder holds port 0 for "the scheme's default", so an https origin's requests carry 0.
                    val port = req.url.port.takeIf { it != 0 } ?: req.url.protocol.defaultPort
                    if (req.url.host == o.host && port == o.port && req.url.protocol == o.protocol) {
                        req.url.protocol = c.protocol
                        req.url.host = c.host
                        req.url.port = c.port
                    } else {
                        error("refusing to dial ${req.url.host}: this test redirects only ${o.host}")
                    }
                }
            })
            extra()
        }
    }
}
