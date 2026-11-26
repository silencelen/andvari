package io.silencelen.andvari.desktop.trust

import com.sun.net.httpserver.HttpServer
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.silencelen.andvari.desktop.updateHttpClient
import kotlinx.coroutines.runBlocking
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * No HTTP client the desktop builds follows a redirect, except the update check by its one closed
 * rule ([io.silencelen.andvari.desktop.fetchUpdateFile], which follows each hop by hand and checks it).
 */
class NoRedirectTest {
    @Test
    fun theEnginesClientHandsEveryRedirectBackAndAsksNothingWhereItPoints() {
        val asked = CopyOnWriteArrayList<String>()
        val server = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
        server.createContext("/") { ex ->
            asked += ex.requestMethod + " " + ex.requestURI.path
            val code = ex.requestURI.path.removePrefix("/r/").toIntOrNull()
            ex.requestBody.readBytes()
            if (code != null) {
                ex.responseHeaders.add("Location", "/elsewhere")
                ex.sendResponseHeaders(code, -1)
            } else {
                ex.sendResponseHeaders(200, 2)
                ex.responseBody.write("ok".toByteArray())
            }
            ex.close()
        }
        server.start()
        val client = TrustSeam.httpClient()
        try {
            val base = "http://127.0.0.1:${server.address.port}"
            for (code in listOf(301, 302, 303, 307, 308)) {
                val got = runBlocking { client.get("$base/r/$code") }
                assertEquals(code, got.status.value, "GET $code reaches the caller as it is")
                val posted = runBlocking { client.post("$base/r/$code") { setBody("x") } }
                assertEquals(code, posted.status.value, "POST $code reaches the caller as it is")
            }
            assertTrue(asked.none { it.endsWith("/elsewhere") }, "nothing is asked where a redirect points: $asked")
            assertEquals(10, asked.size)
        } finally {
            client.close()
            server.stop(0)
        }
    }

    @Test
    fun theUpdateChecksClientFollowsNoneByItself() {
        assertEquals(java.net.http.HttpClient.Redirect.NEVER, updateHttpClient().followRedirects())
    }

    @Test
    fun theDesktopBuildsNoOtherHttpClient() {
        val builds = File("src/main/kotlin").walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }
            .flatMap { f -> Regex("\\bHttpClient\\(|\\bHttpClient\\.newBuilder\\(|openConnection\\(|OkHttpClient").findAll(f.readText()).map { f.name + ": " + it.value } }
            .toList()
        assertEquals(listOf("Platform.kt: HttpClient.newBuilder(", "TrustSeam.kt: HttpClient("), builds.sorted(), "every client the desktop builds is checked above")
    }
}
