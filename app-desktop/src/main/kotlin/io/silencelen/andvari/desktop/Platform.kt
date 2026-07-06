package io.silencelen.andvari.desktop

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

const val DESKTOP_VERSION = "0.1.0"

private val json = Json { ignoreUnknownKeys = true }
private val clipboardCleaner = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "andvari-clip").apply { isDaemon = true } }

@Serializable
private data class DownloadsManifest(val windows: PlatformBuild? = null, val linux: PlatformBuild? = null)

@Serializable
private data class PlatformBuild(val version: String = "", val url: String = "", val sha256: String = "")

/**
 * In-app update check (spec P3): fetch {base}/downloads/manifest.json and return the
 * available version string if it's newer than this build, else null. No auto-install.
 */
fun checkForUpdate(baseUrl: String): String? {
    val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4)).build()
    val req = HttpRequest.newBuilder(URI.create("$baseUrl/downloads/manifest.json")).timeout(Duration.ofSeconds(4)).GET().build()
    val resp = client.send(req, HttpResponse.BodyHandlers.ofString())
    if (resp.statusCode() != 200) return null
    val manifest = json.decodeFromString(DownloadsManifest.serializer(), resp.body())
    val available = manifest.windows?.version?.takeIf { it.isNotBlank() } ?: return null
    return if (compareVersions(available, DESKTOP_VERSION) > 0) available else null
}

private fun compareVersions(a: String, b: String): Int {
    val pa = a.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
    val pb = b.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
    for (i in 0 until maxOf(pa.size, pb.size)) {
        val x = pa.getOrElse(i) { 0 }; val y = pb.getOrElse(i) { 0 }
        if (x != y) return x.compareTo(y)
    }
    return 0
}

/** Copy to the system clipboard and auto-clear after [clearSeconds] (best-effort). */
fun copyWithAutoClear(value: String, clearSeconds: Int = 30) {
    val clipboard = Toolkit.getDefaultToolkit().systemClipboard
    clipboard.setContents(StringSelection(value), null)
    clipboardCleaner.schedule({
        runCatching {
            val current = clipboard.getData(java.awt.datatransfer.DataFlavor.stringFlavor) as? String
            if (current == value) clipboard.setContents(StringSelection(""), null)
        }
    }, clearSeconds.toLong(), TimeUnit.SECONDS)
}
