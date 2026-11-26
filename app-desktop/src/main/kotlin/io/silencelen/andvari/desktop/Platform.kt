package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.UpdateVerify
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.awt.Desktop
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

/** The system clipboard as [SecretClipboard] uses it; null where there is none (a headless JVM). */
private object SystemClipboardPort : ClipboardPort {
    private fun board() = Toolkit.getDefaultToolkit().systemClipboard

    override fun put(selection: SensitiveTextSelection) = board().setContents(selection, selection)

    override fun clear() = board().setContents(StringSelection(""), null)

    override fun text(): String? {
        val b = board()
        if (!b.isDataFlavorAvailable(java.awt.datatransfer.DataFlavor.stringFlavor)) return null
        return b.getData(java.awt.datatransfer.DataFlavor.stringFlavor) as? String
    }
}

/** The app's one secret clipboard, on both clocks. */
internal val secretClipboard = SecretClipboard(
    port = { runCatching { Toolkit.getDefaultToolkit().systemClipboard }.getOrNull()?.let { SystemClipboardPort } },
    monotonicMs = { System.nanoTime() / 1_000_000 },
    wallMs = { System.currentTimeMillis() },
)

// The clear's tick: once a second, on its own daemon thread, so a clear that failed is tried again a second later.
private val clipboardTicker = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "andvari-clip").apply { isDaemon = true } }.also {
    it.scheduleWithFixedDelay({ runCatching { secretClipboard.tick() } }, 1, 1, TimeUnit.SECONDS)
}

// The ticker is a daemon thread and dies at JVM exit: this hook makes the exit's own attempt. A kill or a crash runs no
// hook at all, so a secret copied then stays on a Windows clipboard (a remaining risk; X11 drops it with the process).
private val exitClipGuard: Thread = Thread { runCatching { secretClipboard.clearNow() } }.also {
    Runtime.getRuntime().addShutdownHook(it)
}

/**
 * Clear a secret this app copied, now, if the clipboard still belongs to it. Called when the vault leaves the
 * unlocked phase (TrustApp) and at JVM exit. A clear that fails stays due and is tried again at the next tick; an
 * unrelated value the person copied since is never touched.
 */
fun clearVaultClipboard() = secretClipboard.clearNow()

@Serializable
internal data class DownloadsManifest(
    val windows: PlatformBuild? = null,
    // The Debian package. Its AndvariApi device-platform tag is "linux" and STAYS "linux" for the
    // Arch build too — that tag names the device's OS to the server, not a package format.
    val linux: PlatformBuild? = null,
    // The Arch pacman package built beside the deb (scripts/build-linux.sh): the same fleet
    // version as `linux`, its own url + sha256. ADDITIVE in the signed manifest — a manifest
    // from before the Arch package simply lacks it (null here), and [selectPlatformBuild] then
    // falls back to `linux`, whose version is the same fleet version.
    val linuxArch: PlatformBuild? = null,
    // Audit F09, wave 3: the phone platform, carried here so this model is the honest mirror of
    // the manifest web's Devices card reads (Devices.tsx names this file as its twin). [checkForUpdate]
    // never SELECTS it — a desktop build compares itself against its own OS entry only, and there is
    // no APK to nag a desktop about — but a key the signed manifest carries belongs in the shape of
    // it, so a reader of either side sees the same document.
    val android: PlatformBuild? = null,
    // H2 signed-update envelope (design 2026-07-13-signed-updates §C/§M) — parsed only AFTER
    // UpdateVerify accepted the raw fetched bytes. `seq` = the monotonic anti-rollback counter;
    // `signedAt` = the signing timestamp the §M-D4 staleness check consumes. Defaults keep the
    // decode total; a genuine signed manifest carries both.
    val seq: Long = 0,
    val signedAt: String = "",
)

// `version` is the only field of a build entry this path READS (compared against DESKTOP_VERSION in
// [checkForUpdate]). `url` and `sha256` are declared for shape-parity with the signed manifest and
// consumed by NOBODY here (§M-D1): the desktop update flow is nag-only — it opens the browser at
// [downloadsUrl], never `url`, and the OS-level installer signature (Authenticode MSI / GPG deb) is
// the load-bearing integrity control, never `sha256`.
@Serializable
internal data class PlatformBuild(val version: String = "", val url: String = "", val sha256: String = "")

/**
 * The house convention for "this is an Arch-family install": os-release(5) `ID` equal to `arch`,
 * or ANY `ID_LIKE` token equal to `arch` (Omarchy reports `ID=omarchy` / `ID_LIKE=arch`; Arch
 * itself `ID=arch`; Manjaro `ID_LIKE=arch`). Token equality, never a prefix match — `archcraft`
 * is not `arch`. Pure over the file's text so it is unit-testable; quoting is optional per the
 * spec and both quote styles are stripped.
 */
internal fun isArchLike(osRelease: String): Boolean = osRelease.lineSequence().any { raw ->
    val line = raw.trim()
    val eq = line.indexOf('=')
    if (eq <= 0 || line.startsWith("#")) return@any false
    val key = line.substring(0, eq).trim()
    val value = line.substring(eq + 1).trim().trim('"', '\'')
    when (key) {
        "ID" -> value == "arch"
        "ID_LIKE" -> value.split(' ', '\t').any { it == "arch" }
        else -> false
    }
}

/** os-release(5): `/etc/os-release` first, `/usr/lib/os-release` as the documented fallback; empty when neither reads. */
private fun readOsRelease(): String =
    listOf("/etc/os-release", "/usr/lib/os-release").firstNotNullOfOrNull { p ->
        runCatching { java.io.File(p).takeIf { it.isFile }?.readText() }.getOrNull()
    } ?: ""

/**
 * The manifest entry THIS build compares itself against — a build must never nag about another
 * package family's version. Windows → `windows`. Arch-family Linux → `linuxArch`, falling back
 * to `linux` when the manifest predates the Arch package (same fleet version either way, and the
 * nag only opens `/downloads`, where both packages are listed). Any other Linux → `linux`.
 */
internal fun selectPlatformBuild(manifest: DownloadsManifest, isWindows: Boolean, isArch: Boolean): PlatformBuild? = when {
    isWindows -> manifest.windows
    isArch -> manifest.linuxArch?.takeIf { it.version.isNotBlank() } ?: manifest.linux
    else -> manifest.linux
}

/**
 * design 2026-07-13 platform-fit §2, Help ▸ Open web vault: open [url] in the OS default browser.
 * Fails GRACEFULLY — Desktop is unsupported on headless/no-browser Linux and Desktop.browse THROWS
 * there — returning false instead of crashing the menu action (the web-vault URL is also always
 * visible in Settings → Server). Returns true only on a dispatched browse.
 */
fun openInBrowser(url: String): Boolean = runCatching {
    if (!Desktop.isDesktopSupported()) return false
    val desktop = Desktop.getDesktop()
    if (!desktop.isSupported(Desktop.Action.BROWSE)) return false
    val uri = URI(url)
    // A user name or password before the host is never opened (the callers say why).
    if (uri.rawUserInfo != null) return false
    desktop.browse(uri)
    true
}.getOrDefault(false)

/**
 * Audit H126: open [dir] in the OS file manager — the About dialog's door to the diagnostic log.
 * The log lives in a DOTFILE directory (`~/.andvari-desktop`), which is hidden by default in both
 * Explorer and every GNOME/KDE file manager, so "the path is written down" is not on its own a way
 * for a household member to reach it during a support conversation.
 *
 * Same graceful-failure contract as [openInBrowser] (a headless or file-manager-less Linux session
 * throws out of `Desktop.open`): false means nothing opened, and the caller keeps the path on
 * screen as selectable text — which is the primary affordance either way, never this button.
 */
fun openFolder(dir: java.io.File): Boolean = runCatching {
    if (!Desktop.isDesktopSupported()) return false
    val desktop = Desktop.getDesktop()
    if (!desktop.isSupported(Desktop.Action.OPEN)) return false
    if (!dir.isDirectory) return false
    desktop.open(dir)
    true
}.getOrDefault(false)

/**
 * The outcome of one update check (H2, design 2026-07-13-signed-updates §M). Everything that is
 * not a VERIFIED manifest collapses into [Unverified] — a deliberately QUIET state (§M-D5): a
 * tampering/sig-stripping server must never be able to force a scary banner (cry-wolf DoS), so
 * the UI shows at most one muted Settings line, never a nag and never a modal.
 */
sealed interface UpdateCheck {
    /**
     * Verified manifest, strictly newer version for THIS OS — show the update nag. [downloadUrl] is where the banner
     * points: the signed list's own address for this platform when it passes [UpdateChannel.bannerAddress], else the
     * project's GitHub releases page. Never the relaying server's origin.
     */
    data class Available(val version: String, val seq: Long, val downloadUrl: String = UpdateChannel.GITHUB_RELEASES_PAGE, val signedAt: String = "") : UpdateCheck

    /** Verified manifest, nothing newer. [signedAt]: the list's own signed date, as it carries it. */
    data class UpToDate(val seq: Long, val signedAt: String = "") : UpdateCheck

    /** Verified, nothing newer, but `signedAt` is older than [UPDATE_STALE_AFTER_DAYS] (or
     *  unreadable) — the channel can't prove freshness (§M-D4: withheld updates made DETECTABLE). */
    data class Stale(val seq: Long, val signedAt: String = "") : UpdateCheck

    /** Fail-closed-quiet (§M-D5/D6): an answer came, but the sig was missing/invalid, the list did not
     *  parse, or the seq regressed below the persisted floor. NO update is offered; no state is persisted.
     *  About says "could not verify". */
    data object Unverified : UpdateCheck

    /** No source could be reached, or none serves a list. About says "could not check since …". */
    data object Unreachable : UpdateCheck

    /** Nothing was asked: no server is attached yet ([UpdateChannel.ASK_GITHUB_BEFORE_A_SERVER] is off). */
    data object NotAsked : UpdateCheck

    /** §M-D3: only the TEST pubkey is pinned — the entire update path is compile-time disabled. */
    data object Disabled : UpdateCheck
}

/** One check's outcome: [from] is the source that gave it (null when nothing was asked), [atMs] when it ran. */
data class UpdateReport(val from: UpdateSource?, val check: UpdateCheck, val atMs: Long) {
    /** A verified list came: the floor may ratchet, and the check counts as done. */
    val verified: Boolean get() = check is UpdateCheck.Available || check is UpdateCheck.UpToDate || check is UpdateCheck.Stale

    val seq: Long? get() = when (val c = check) {
        is UpdateCheck.Available -> c.seq
        is UpdateCheck.UpToDate -> c.seq
        is UpdateCheck.Stale -> c.seq
        else -> null
    }

    /** The verified list's own signed date (`signedAt`, as signed; empty when it carries none or nothing verified). */
    val signedAt: String get() = when (val c = check) {
        is UpdateCheck.Available -> c.signedAt
        is UpdateCheck.UpToDate -> c.signedAt
        is UpdateCheck.Stale -> c.signedAt
        else -> ""
    }
}

/** What fetching one file came to. */
sealed interface Fetched {
    class Body(val bytes: ByteArray) : Fetched

    /** The source answered and has no such file (or answered something other than 200). */
    data object Missing : Fetched

    /** Larger than its cap, or a redirect that may not be followed. */
    data object Refused : Fetched

    /** No answer: the network, a timeout, a name that does not resolve. */
    data object Failed : Fetched
}

/** §M-D4: a verified manifest signed longer ago than this can't prove the channel is fresh. */
private const val UPDATE_STALE_AFTER_DAYS = 45L

// Verify-only Ed25519 (jvm lazysodium); lazy so sodium loads on the checker's IO thread, not at class init.
private val updateCrypto by lazy { createCryptoProvider() }

/**
 * In-app update check (spec P3 + H2 §M), from the sources [UpdateChannel.sources] gives (the attached server, then
 * GitHub's latest release): fetch the EXACT bytes of the source's manifest.json
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
fun checkForUpdates(
    attachedOrigin: String?,
    lastAcceptedSeq: Long,
    nowMs: Long = System.currentTimeMillis(),
    enabled: Boolean = UpdateVerify.updatesEnabled(),
    sources: List<UpdateSource> = UpdateChannel.sources(attachedOrigin),
    fetch: (String, Int) -> Fetched = ::fetchUpdateFile,
    verify: (ByteArray, ByteArray) -> Boolean = { raw, sig -> UpdateVerify.verify(updateCrypto, raw, sig) },
    platform: Pair<Boolean, Boolean> = currentPlatform(),
): UpdateReport {
    if (!enabled) return UpdateReport(null, UpdateCheck.Disabled, nowMs) // §M-D3 hard-off on the test key
    // Nothing is asked before a server is chosen, and the old address never.
    if (sources.isEmpty()) return UpdateReport(null, UpdateCheck.NotAsked, nowMs)
    // §M-D4(a) anti-rollback FLOOR (mirror of extension background.ts:711 `Math.max(storedSeq, MIN_SEQ)`):
    // a fresh install (or one whose persisted lastAcceptedSeq was wiped) evaluates from MIN_SEQ, not 0,
    // so a T1 server can't steer it below the compile-time floor with a validly-signed-but-older manifest.
    val floorSeq = maxOf(lastAcceptedSeq, UpdateVerify.MIN_SEQ)
    // The attached server first; when it gives no verified list (none served, unreachable, not verifiable, or below
    // the floor), GitHub. A source can withhold an update this way; it can never forge one. The quiet state reported
    // when no source verified is "could not verify" if any source answered with a list, else "could not check".
    var unverifiedFrom: UpdateSource? = null
    for (source in sources) {
        when (val c = checkSource(source, floorSeq, fetch, verify, platform)) {
            is UpdateCheck.Available, is UpdateCheck.UpToDate, is UpdateCheck.Stale -> return UpdateReport(source, c, nowMs)
            UpdateCheck.Unverified -> if (unverifiedFrom == null) unverifiedFrom = source
            else -> {}
        }
    }
    return unverifiedFrom?.let { UpdateReport(it, UpdateCheck.Unverified, nowMs) } ?: UpdateReport(sources.last(), UpdateCheck.Unreachable, nowMs)
}

/** (isWindows, isArch) of this computer: a Linux build must not compare itself against the Windows MSI's version. */
private fun currentPlatform(): Pair<Boolean, Boolean> {
    val isWindows = System.getProperty("os.name").orEmpty().lowercase().contains("win")
    return isWindows to (!isWindows && isArchLike(readOsRelease()))
}

/** One source's list: fetched size-capped, verified over its raw bytes BEFORE any parse, then floored and selected. */
internal fun checkSource(
    source: UpdateSource,
    floorSeq: Long,
    fetch: (String, Int) -> Fetched,
    verify: (ByteArray, ByteArray) -> Boolean,
    platform: Pair<Boolean, Boolean>,
): UpdateCheck {
    // q19 (security review 2026-10): both bodies are UNVERIFIED source bytes, so they are size-capped while they are
    // read — never buffered whole first.
    val raw = when (val f = fetch(source.manifestUrl, UPDATE_MANIFEST_MAX_BYTES)) {
        is Fetched.Body -> f.bytes
        Fetched.Refused -> return UpdateCheck.Unverified
        Fetched.Missing, Fetched.Failed -> return UpdateCheck.Unreachable
    }
    val sig: ByteArray = when (val f = fetch(source.signatureUrl, UPDATE_SIG_MAX_BYTES)) {
        is Fetched.Body -> runCatching { Bytes.fromB64(f.bytes.decodeToString().trim()) }.getOrNull() ?: return UpdateCheck.Unverified
        // A list with no signature beside it is a list that cannot be verified.
        Fetched.Missing, Fetched.Refused -> return UpdateCheck.Unverified
        Fetched.Failed -> return UpdateCheck.Unreachable
    }
    // The crux (§D#2): verify the raw bytes against the pinned key set BEFORE any parse.
    if (!verify(raw, sig)) return UpdateCheck.Unverified
    val manifest = try {
        json.decodeFromString(DownloadsManifest.serializer(), raw.decodeToString())
    } catch (_: Exception) {
        return UpdateCheck.Unverified
    }
    // Anti-rollback (§B/§M-D4): refuse a manifest BELOW the floor — a validly-signed but OLD
    // manifest replayed to steer a downgrade. `==` is NOT refused: steady state re-fetches the
    // very manifest whose seq set the floor, and refusing our own current manifest would turn
    // every launch into a false "couldn't verify". The floor only advances on seq > floor.
    // floorSeq (not the raw stored seq) is the effective floor — never below MIN_SEQ (§M-D4a).
    if (manifest.seq < floorSeq) return UpdateCheck.Unverified
    val (isWindows, isArch) = platform
    val build = selectPlatformBuild(manifest, isWindows, isArch)
    val available = build?.version?.takeIf { it.isNotBlank() }
    return when {
        available != null && compareVersions(available, DESKTOP_VERSION) > 0 ->
            UpdateCheck.Available(available, manifest.seq, UpdateChannel.bannerAddress(build.url), manifest.signedAt)
        updateChannelStale(manifest.signedAt) -> UpdateCheck.Stale(manifest.seq, manifest.signedAt)
        else -> UpdateCheck.UpToDate(manifest.seq, manifest.signedAt)
    }
}

/** Redirects followed at most (GitHub's latest-asset address redirects once, to the asset's storage). */
private const val UPDATE_MAX_REDIRECTS = 5

/**
 * GET [url] with [fetchBounded]'s caps, following redirects by hand so that each hop is checked: never the retired
 * host ([UpdateChannel.mayAsk]), never from https down to http, and never to another host than the request's own
 * (GitHub's asset hosts from github.com only: [UpdateChannel.mayRedirect]).
 */
internal fun fetchUpdateFile(url: String, limit: Int, client: HttpClient = updateHttpClient()): Fetched {
    var uri = runCatching { URI.create(url) }.getOrNull() ?: return Fetched.Refused
    val start = uri
    repeat(UPDATE_MAX_REDIRECTS + 1) {
        if (!UpdateChannel.mayAsk(uri)) return Fetched.Refused
        val req = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(8)).GET().build()
        val resp = try {
            client.send(req, HttpResponse.BodyHandlers.ofInputStream())
        } catch (e: Exception) {
            return Fetched.Failed
        }
        resp.body().use { body ->
            val status = resp.statusCode()
            if (status in 300..399) {
                val next = resp.headers().firstValue("Location").orElse(null) ?: return Fetched.Missing
                val target = runCatching { uri.resolve(next) }.getOrNull() ?: return Fetched.Refused
                if (uri.scheme.equals("https", true) && !target.scheme.equals("https", true)) return Fetched.Refused
                if (!UpdateChannel.mayRedirect(start, target)) return Fetched.Refused
                uri = target
                return@use
            }
            if (status != 200) return Fetched.Missing
            val declared = resp.headers().firstValueAsLong("Content-Length")
            if (declared.isPresent && declared.asLong > limit) return Fetched.Refused
            return runCatching { readBounded(body, limit) }.getOrNull()?.let { Fetched.Body(it) } ?: Fetched.Refused
        }
    }
    return Fetched.Refused
}

internal fun updateHttpClient(): HttpClient =
    HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4)).followRedirects(HttpClient.Redirect.NEVER).build()

/** q19: the signed downloads manifest is a few KiB; 256 KiB leaves room for growth and still cannot exhaust a heap. */
internal const val UPDATE_MANIFEST_MAX_BYTES = 256 * 1024

/** q19: the detached signature is 64 bytes, i.e. 86 base64url characters plus a newline. */
internal const val UPDATE_SIG_MAX_BYTES = 1024

/**
 * q19: GET [url] and return its body only when the status is 200 and the body is at most [limit] bytes; null
 * otherwise. A declared Content-Length over the limit is refused before reading; an undeclared (chunked) body is read
 * through [readBounded], which stops at the limit. The request timeout bounds the wait for headers.
 */
internal fun fetchBounded(client: HttpClient, url: String, limit: Int): ByteArray? {
    val req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(4)).GET().build()
    val resp = client.send(req, HttpResponse.BodyHandlers.ofInputStream())
    resp.body().use { body ->
        if (resp.statusCode() != 200) return null
        val declared = resp.headers().firstValueAsLong("Content-Length")
        if (declared.isPresent && declared.asLong > limit) return null
        return readBounded(body, limit)
    }
}

/**
 * Read at most [limit] bytes from [input]; null if the source is larger, so an oversized body is refused without ever
 * being buffered whole. (Moved here from the old `DesktopState.kt`, where the attachment picker and the CSV import also
 * used it; the update fetch is its only caller now.)
 */
internal fun readBounded(input: java.io.InputStream, limit: Int): ByteArray? {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(64 * 1024)
    var total = 0L
    while (true) {
        val r = input.read(buf)
        if (r < 0) break
        total += r
        if (total > limit) return null
        out.write(buf, 0, r)
    }
    return out.toByteArray()
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

/** Plain clipboard copy, NO auto-clear — for setup material the user pastes elsewhere (TOTP URI/secret).
 *  False = the write failed (ux-error--3: `setContents` throws IllegalStateException while another
 *  process holds the clipboard open — RDP, clipboard managers, Office on Windows) — guarded like
 *  every other clipboard call in this file, so a Copy click can never crash the app; callers own
 *  the honest feedback. */
fun copyPlain(value: String): Boolean =
    runCatching { Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(value), null) }.isSuccess

/**
 * Copy a secret to the system clipboard, marked sensitive where the platform has a mark (A14, F9), and clear it after
 * [clearSeconds] (at least 1: a policy of 0 never means "keep forever"). The one way anything of the app reaches the
 * clipboard: a text field's own Ctrl+C, Ctrl+X and context menu come here too ([SensitiveClipboardManager]).
 * False = the write failed (ux-error--3): nothing landed on the clipboard and no clear is due.
 */
fun copyWithAutoClear(value: String, clearSeconds: Int = 30): Boolean = secretClipboard.copy(value, clearSeconds)
