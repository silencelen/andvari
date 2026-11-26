package io.silencelen.andvari.desktop

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

/**
 * What is left of the old path's store in `~/.andvari-desktop/prefs.json`: the three preferences the first-launch
 * wipe keeps — the theme, the last-backup time and the update rollback floor — plus when and where
 * the update check last got a verified list. Sessions, keys, caches and namespaces of the old design are gone; the new path keeps its own files in
 * `v2/` (`trust/DesktopStores.kt`). An unknown or unreadable `prefs.json` reads as the defaults.
 *
 * [dir] is injectable for tests only; production always uses the default.
 */
class DesktopSessionStore(
    private val dir: File = File(System.getProperty("user.home"), ".andvari-desktop"),
) {
    private val json = Json { ignoreUnknownKeys = true; prettyPrint = true }
    private val prefsFile = File(dir, "prefs.json")

    @Serializable
    private data class Prefs(
        val lastExportAt: Long = 0,
        // UI-audit #26: the user's Auto/Light/Dark override ("auto"/"light"/"dark"), a plain string so an unrecognised
        // value degrades to Auto in the reader ([ThemeMode.fromStore]) instead of failing the whole decode.
        val themeMode: String = "auto",
        // H2 signed updates (design 2026-07-13-signed-updates §B/§M-D4): the highest `seq` of any VERIFIED downloads
        // manifest this install ever accepted, the anti-rollback floor. Ratchets up only.
        val lastAcceptedSeq: Long = 0,
        // When a verified update list last came, and from where (About's "last checked"
        // and "could not check since …"). Written only after a list verified.
        val lastUpdateCheckAt: Long = 0,
        val lastUpdateCheckFrom: String = "",
        // For the update check: the date that list itself was signed (its `signedAt`, as
        // signed), so a held-back list can be noticed in About.
        val lastUpdateListSignedAt: String = "",
        // The owner's decision of 2026-11-16: "allow screen capture" on this computer. Off (capture hidden) by default,
        // and an unreadable file reads as off.
        val allowScreenCapture: Boolean = false,
    )

    @Volatile
    private var cachedPrefs: Prefs? = null

    private fun prefs(): Prefs = cachedPrefs
        ?: runCatching { json.decodeFromString(Prefs.serializer(), prefsFile.readText()) }.getOrDefault(Prefs()).also { cachedPrefs = it }

    private fun writePrefs(p: Prefs) { dir.mkdirsOwnerOnly(); prefsFile.writeTextOwnerOnly(json.encodeToString(Prefs.serializer(), p)); cachedPrefs = p }

    /** When the last backup was made (unix ms; 0 = never), recorded locally only (spec 07 §2.6). */
    var lastExportAt: Long
        get() = prefs().lastExportAt
        set(v) { writePrefs(prefs().copy(lastExportAt = v)) }

    /** Whether andvari's windows may be captured on this computer ([CaptureGuard]): off by default. Per computer, never in the account. */
    var allowScreenCapture: Boolean
        get() = prefs().allowScreenCapture
        set(v) { writePrefs(prefs().copy(allowScreenCapture = v)) }

    /** UI-audit #26: the persisted Auto/Light/Dark theme override (raw store string). */
    var themeMode: String
        get() = prefs().themeMode
        set(v) { writePrefs(prefs().copy(themeMode = v)) }

    /** H2 anti-rollback floor (signed updates §M): written only after a manifest verified (design §D#5). */
    var lastAcceptedSeq: Long
        get() = prefs().lastAcceptedSeq
        set(v) { writePrefs(prefs().copy(lastAcceptedSeq = v)) }

    /** When a verified update list last came (unix ms; 0 = never), and the source's name ([UpdateSource.shown]). */
    val lastUpdateCheck: Pair<Long, String>
        get() = prefs().let { it.lastUpdateCheckAt to it.lastUpdateCheckFrom }

    /** The signed date of that last verified list (its `signedAt`, as signed; empty = none recorded). */
    val lastUpdateListSignedAt: String
        get() = prefs().lastUpdateListSignedAt

    fun recordUpdateCheck(atMs: Long, from: String, signedAt: String = "") {
        writePrefs(prefs().copy(lastUpdateCheckAt = atMs, lastUpdateCheckFrom = from, lastUpdateListSignedAt = signedAt))
    }
}

// ---- at-rest permissions (audit F35) ----

/**
 * The permissions are part of the CREATE: a file written at the umask and chmodded afterwards can be opened by another
 * local user in between, and keeps that fd whatever the later chmod says. Where the platform has no POSIX view
 * (Windows) these fall back to the plain create, which the ACL-based file system there wants anyway. Used by the
 * diagnostic log, the extracted libsodium and the prefs above.
 */
private val posixSupported: Boolean = runCatching {
    java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")
}.getOrDefault(false)

internal fun ownerOnly(spec: String): Array<java.nio.file.attribute.FileAttribute<*>> =
    if (posixSupported) {
        arrayOf(java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString(spec)))
    } else {
        emptyArray()
    }

/** `mkdirs()` with `rwx------` on every directory this call actually creates. Existing
 *  directories are left alone (their mode is the user's business, and re-chmodding a shared
 *  parent would be worse than the gap). Total — never throws, exactly like [File.mkdirs]. */
internal fun File.mkdirsOwnerOnly() {
    if (isDirectory) return
    parentFile?.mkdirsOwnerOnly()
    runCatching { java.nio.file.Files.createDirectory(toPath(), *ownerOnly("rwx------")) }
    if (!isDirectory) runCatching { mkdirs() } // lost a race, or an FS that refused the attribute
}

/**
 * [File.writeText] where the file is CREATED `rw-------` rather than repaired to it. The chmod
 * still runs afterwards, for one case the create-time mode cannot cover: a file that already
 * exists from a build before this fix, whose mode `CREATE` leaves untouched.
 */
internal fun File.writeTextOwnerOnly(text: String) {
    parentFile?.mkdirsOwnerOnly()
    val opts = setOf(
        java.nio.file.StandardOpenOption.CREATE,
        java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
        java.nio.file.StandardOpenOption.WRITE,
    )
    val bytes = text.encodeToByteArray()
    val wrote = runCatching {
        java.nio.file.Files.newByteChannel(toPath(), opts, *ownerOnly("rw-------")).use {
            it.write(java.nio.ByteBuffer.wrap(bytes))
        }
    }
    if (wrote.isFailure) writeText(text) // never lose the write over a permissions nicety
    runCatching { setReadable(false, false); setReadable(true, true); setWritable(false, false); setWritable(true, true) }
}
