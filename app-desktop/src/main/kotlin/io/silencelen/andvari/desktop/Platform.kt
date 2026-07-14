package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.UpdateVerify
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant
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
private data class DownloadsManifest(
    val windows: PlatformBuild? = null,
    val linux: PlatformBuild? = null,
    // H2 signed-update envelope (design 2026-07-13-signed-updates §C/§M) — parsed only AFTER
    // UpdateVerify accepted the raw fetched bytes. `seq` = the monotonic anti-rollback counter;
    // `signedAt` = the signing timestamp the §M-D4 staleness check consumes. Defaults keep the
    // decode total; a genuine signed manifest carries both.
    val seq: Long = 0,
    val signedAt: String = "",
)

// `sha256` is retained for parse-compat but consumed by NOBODY on this path (§M-D1): the desktop
// update flow is nag-only — the browser is opened at /downloads and the OS-level installer
// signature (Authenticode MSI / GPG deb) is the load-bearing integrity control, never this field.
@Serializable
private data class PlatformBuild(val version: String = "", val url: String = "", val sha256: String = "")

/** Where to download an update — surfaced to the user next to the banner. */
fun downloadsUrl(baseUrl: String): String = "$baseUrl/downloads"

/**
 * The outcome of one update check (H2, design 2026-07-13-signed-updates §M). Everything that is
 * not a VERIFIED manifest collapses into [Unverified] — a deliberately QUIET state (§M-D5): a
 * tampering/sig-stripping server must never be able to force a scary banner (cry-wolf DoS), so
 * the UI shows at most one muted Settings line, never a nag and never a modal.
 */
sealed interface UpdateCheck {
    /** Verified manifest, strictly newer version for THIS OS — show the update nag. */
    data class Available(val version: String, val seq: Long) : UpdateCheck

    /** Verified manifest, nothing newer. */
    data class UpToDate(val seq: Long) : UpdateCheck

    /** Verified, nothing newer, but `signedAt` is older than [UPDATE_STALE_AFTER_DAYS] (or
     *  unreadable) — the channel can't prove freshness (§M-D4: withheld updates made DETECTABLE). */
    data class Stale(val seq: Long) : UpdateCheck

    /** Fail-closed-quiet (§M-D5/D6): fetch failed, sig missing/invalid, parse failed, or the seq
     *  regressed below the persisted floor. NO update is offered; no state is persisted. */
    data object Unverified : UpdateCheck

    /** §M-D3: only the TEST pubkey is pinned — the entire update path is compile-time disabled. */
    data object Disabled : UpdateCheck
}

/** §M-D4: a verified manifest signed longer ago than this can't prove the channel is fresh. */
private const val UPDATE_STALE_AFTER_DAYS = 45L

// Verify-only Ed25519 (jvm lazysodium); lazy so sodium loads on the checker's IO thread, not at class init.
private val updateCrypto by lazy { createCryptoProvider() }

/**
 * In-app update check (spec P3 + H2 §M): fetch the EXACT bytes of {base}/downloads/manifest.json
 * (ofByteArray — §M-D6: the sig is over the raw bytes, so no string round-trip may touch them),
 * fetch the detached base64url Ed25519 signature from manifest.json.sig (the update-signer's
 * output format), verify against the pinned key set BEFORE parsing, then gate on the anti-rollback
 * `seq` against [lastAcceptedSeq] (the caller's persisted floor). ANY failure on that path returns
 * the quiet [UpdateCheck.Unverified] — never an offer, never a loud error. Still nag-only: no
 * installer is ever downloaded or run from here (§M-D1). Selects the manifest entry for THIS OS —
 * a Linux build must not compare itself against the Windows MSI's version (and vice-versa).
 *
 * Blocking I/O — call from a background dispatcher (UI-audit #24: this ran synchronously on the
 * Compose thread and froze the window for up to ~8 s).
 */
fun checkForUpdate(baseUrl: String, lastAcceptedSeq: Long): UpdateCheck {
    if (!UpdateVerify.updatesEnabled()) return UpdateCheck.Disabled // §M-D3 hard-off on the test key
    val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4)).build()
    val raw: ByteArray = try {
        val req = HttpRequest.newBuilder(URI.create("$baseUrl/downloads/manifest.json")).timeout(Duration.ofSeconds(4)).GET().build()
        val resp = client.send(req, HttpResponse.BodyHandlers.ofByteArray())
        if (resp.statusCode() != 200) return UpdateCheck.Unverified
        resp.body()
    } catch (_: Exception) {
        return UpdateCheck.Unverified
    }
    val sig: ByteArray = try {
        val req = HttpRequest.newBuilder(URI.create("$baseUrl/downloads/manifest.json.sig")).timeout(Duration.ofSeconds(4)).GET().build()
        val resp = client.send(req, HttpResponse.BodyHandlers.ofString())
        if (resp.statusCode() != 200) return UpdateCheck.Unverified
        Bytes.fromB64(resp.body().trim())
    } catch (_: Exception) {
        return UpdateCheck.Unverified
    }
    // The crux (§D#2): verify the raw bytes against the pinned key set BEFORE any parse.
    if (!UpdateVerify.verify(updateCrypto, raw, sig)) return UpdateCheck.Unverified
    val manifest = try {
        json.decodeFromString(DownloadsManifest.serializer(), raw.decodeToString())
    } catch (_: Exception) {
        return UpdateCheck.Unverified
    }
    // Anti-rollback (§B/§M-D4): refuse a manifest BELOW the floor — a validly-signed but OLD
    // manifest replayed to steer a downgrade. `==` is NOT refused: steady state re-fetches the
    // very manifest whose seq set the floor, and refusing our own current manifest would turn
    // every launch into a false "couldn't verify". The floor only advances on seq > floor.
    if (manifest.seq < lastAcceptedSeq) return UpdateCheck.Unverified
    val isWindows = System.getProperty("os.name").orEmpty().lowercase().contains("win")
    val available = (if (isWindows) manifest.windows else manifest.linux)?.version?.takeIf { it.isNotBlank() }
    return when {
        available != null && compareVersions(available, DESKTOP_VERSION) > 0 -> UpdateCheck.Available(available, manifest.seq)
        updateChannelStale(manifest.signedAt) -> UpdateCheck.Stale(manifest.seq)
        else -> UpdateCheck.UpToDate(manifest.seq)
    }
}

/** §M-D4 freshness: true when `signedAt` is missing/unreadable or older than the window — a
 *  verified-but-old manifest is safe to be QUIETLY suspicious about, never loud. */
private fun updateChannelStale(signedAt: String): Boolean = try {
    Instant.parse(signedAt).isBefore(Instant.now().minus(Duration.ofDays(UPDATE_STALE_AFTER_DAYS)))
} catch (_: Exception) {
    true
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
