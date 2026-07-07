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

// Aliases the single release-version source in :core (a hand-bumped literal skewed to
// 0.3.0 while the build shipped 0.4.0, giving a freshly-installed MSI a perpetual
// "update available" nag against itself).
const val DESKTOP_VERSION = io.silencelen.andvari.core.client.ANDVARI_CLIENT_VERSION

private val json = Json { ignoreUnknownKeys = true }
private val clipboardCleaner = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "andvari-clip").apply { isDaemon = true } }

// Last vault secret handed to [copyWithAutoClear] — lets lock/sign-out/exit clear the
// clipboard without ever stomping an unrelated value the user copied since.
@Volatile
private var lastSecretCopied: String? = null

// The cleaner is a daemon thread: pending clears die silently at JVM exit, leaving the
// secret on the clipboard after the app closes. This hook covers exit (still ==-guarded).
private val exitClipGuard: Thread = Thread { runCatching { clearVaultClipboard() } }.also {
    Runtime.getRuntime().addShutdownHook(it)
}

/**
 * Clear the system clipboard iff it still holds the last secret copied via
 * [copyWithAutoClear]. Called on lock/sign-out (DesktopState) and at JVM exit — a vault
 * secret must not outlive the session, but an unrelated user clipboard is never touched.
 */
fun clearVaultClipboard() {
    val secret = lastSecretCopied ?: return
    runCatching {
        val clipboard = Toolkit.getDefaultToolkit().systemClipboard
        val current = clipboard.getData(java.awt.datatransfer.DataFlavor.stringFlavor) as? String
        if (current == secret) clipboard.setContents(StringSelection(""), null)
    }
    lastSecretCopied = null
}

@Serializable
private data class DownloadsManifest(val windows: PlatformBuild? = null, val linux: PlatformBuild? = null)

@Serializable
private data class PlatformBuild(val version: String = "", val url: String = "", val sha256: String = "")

/** Where to download an update — surfaced to the user next to the banner. */
fun downloadsUrl(baseUrl: String): String = "$baseUrl/downloads"

/**
 * In-app update check (spec P3): fetch {base}/downloads/manifest.json and return the
 * available version string if it's newer than this build, else null. No auto-install.
 * Selects the manifest entry for THIS OS — a Linux build must not compare itself against
 * the Windows MSI's version (and vice-versa).
 */
fun checkForUpdate(baseUrl: String): String? {
    val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4)).build()
    val req = HttpRequest.newBuilder(URI.create("$baseUrl/downloads/manifest.json")).timeout(Duration.ofSeconds(4)).GET().build()
    val resp = client.send(req, HttpResponse.BodyHandlers.ofString())
    if (resp.statusCode() != 200) return null
    val manifest = json.decodeFromString(DownloadsManifest.serializer(), resp.body())
    val isWindows = System.getProperty("os.name").orEmpty().lowercase().contains("win")
    val available = (if (isWindows) manifest.windows else manifest.linux)?.version?.takeIf { it.isNotBlank() } ?: return null
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

/** Plain clipboard copy, NO auto-clear — for setup material the user pastes elsewhere (TOTP URI/secret). */
fun copyPlain(value: String) {
    Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(value), null)
}

/**
 * Copy to the system clipboard and auto-clear after [clearSeconds] (best-effort). Vault-secret
 * call sites pass `max(1, policy.clipboardClearSeconds)` — clamped exactly like web's useCopy,
 * so a policy of 0 still clears after 1 s (never "keep forever" for secrets).
 */
fun copyWithAutoClear(value: String, clearSeconds: Int = 30) {
    val clipboard = Toolkit.getDefaultToolkit().systemClipboard
    clipboard.setContents(StringSelection(value), null)
    lastSecretCopied = value
    clipboardCleaner.schedule({
        runCatching {
            val current = clipboard.getData(java.awt.datatransfer.DataFlavor.stringFlavor) as? String
            if (current == value) clipboard.setContents(StringSelection(""), null)
        }
        if (lastSecretCopied == value) lastSecretCopied = null // cleared (or superseded elsewhere)
    }, clearSeconds.toLong(), TimeUnit.SECONDS)
}
