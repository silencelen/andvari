package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.PreCutoverStore
import io.silencelen.andvari.core.app.PreCutoverStores
import io.silencelen.andvari.core.app.engine.SqliteVaultCacheFiles
import io.silencelen.andvari.core.app.engine.VaultCacheFiles
import io.silencelen.andvari.core.client.DeviceStateFile
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.VaultCache
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions

/**
 * Where the new path keeps its files on this computer.
 *
 * Everything new lives in [dir] (`~/.andvari-desktop/v2/`), a directory the first-launch wipe never enters
 * ([DesktopOldStores] deletes named old files only). Beside it, in the old root, stay what is not vault state: the
 * diagnostic log, the extracted libsodium, and `prefs.json` cut down to the theme, the last-backup time and the update
 * rollback floor.
 *
 * - `device-state.json` ([stateFile]): the engine's device state: server pins, this device's log state, known
 *   devices. Not secrets; always stored.
 * - `secure-state.json` ([secureFile]): the session's tokens and keys. On disk only while the person opted in to keep
 *   the sign-in on this computer ([DesktopTrustPrefs.keepSignIn]); otherwise held in memory for the run. On disk it is
 *   wrapped by this computer's key store ([keyStore], note N2), or plain only where the person chose that because
 *   there is none ([DesktopTrustPrefs.plainFile]).
 * - `vault-cache/` ([cacheFiles]): the vault's offline copy, under the same opt-in, and only where the server's policy
 *   allows one (core decides that part).
 * - `content/` ([content]): what a lock cut short, sealed by core, under the same opt-in and the server's policy.
 * - `desktop-prefs.json` ([prefs]): this device's choices of the new path.
 */
class DesktopHome(
    val root: File = defaultRoot(),
    val keyStore: OsKeyStore = OsKeyStores.forThisComputer(),
    log: (String) -> Unit = io.silencelen.andvari.desktop.DesktopDiagnostics::log,
    keyStorePause: () -> Unit = { Thread.sleep(SignInStoreFile.ASK_AGAIN_MS) },
) {
    val dir: File = File(root, NEW_DIR)

    init {
        ownerOnlyDir(root)
        ownerOnlyDir(dir)
    }

    val prefs = DesktopTrustPrefs(OwnerOnlyFile(File(dir, "desktop-prefs.json")))

    /**
     * What the switch said when this start began. At every start while it is off, the
     * files of a kept sign-in are removed unread (one Windows held open at the switch-off goes now); while it is
     * [Keep.UNKNOWN] (its file could not be read) nothing kept is deleted or read.
     */
    val keepAtStart: Keep = prefs.keep()

    fun stateFile(): DeviceStateFile = OwnerOnlyFile(File(dir, JsonDeviceState.FILE_NAME))

    /** Where [secureFile] keeps the session while the person keeps the sign-in here. */
    val secureStateFile: File = File(dir, "secure-state.json")

    /**
     * The account open is not the one the switch belongs to ([setForeign]): while so, everything kept reads the switch
     * as [Keep.UNKNOWN], so nothing is written, read or deleted on disk, and that account is held in memory.
     */
    @Volatile
    var foreign: Boolean = false
        private set

    /** The switch as what is kept reads it: [Keep.UNKNOWN] while [foreign]. */
    fun keepNow(): Keep = if (foreign) Keep.UNKNOWN else prefs.keep()

    val secureFile = SignInStoreFile(secureStateFile, keyStore, log, plainChosen = { prefs.plainFile }, migration = prefs, pause = keyStorePause, bindings = prefs) { keepNow() }

    /**
     * Assisted recovery's requests (the app interface's `requestStore`): a request waits days for its hold, so it is
     * kept whatever the switch says, wrapped by this computer's key store like the kept sign-in. With no key store it is
     * held in memory only (never an unwrapped file the person did not choose), so it does not outlive the run.
     */
    val requestFile = SignInStoreFile(File(dir, "assist-requests.json"), keyStore, log, pause = keyStorePause) { Keep.ON }

    val cacheDir: File = File(dir, "vault-cache")

    val cacheFiles = OptInCacheFiles(cacheDir, root) { keepNow() }

    /** What a lock cuts short, under the same opt-in ([DesktopContentStores]). */
    val content = DesktopContentStores(File(dir, "content"), wipeAtStart = keepAtStart == Keep.OFF, within = root) { keepNow() == Keep.ON }

    /**
     * An account other than the one the switch belongs to is open (the kept one could not be
     * opened, so core let another sign in). Nothing of the kept account is deleted for it, and it inherits nothing:
     * while [on], it is held in memory (core is told, so an open vault moves to memory), and a sign-in file this run
     * wrote for it goes. Off again when the kept account is back or that one has ended.
     */
    fun setForeign(on: Boolean) {
        if (foreign == on) return
        foreign = on
        if (on) {
            consentWithdrawn()
            secureFile.withdrawWrittenThisRun()
        }
    }

    init {
        if (keepAtStart == Keep.OFF) {
            cacheFiles.deleteAll()
            secureFile.deleteUnread()
        }
    }

    /**
     * The opt-in changed: what is held in memory goes to disk, or what is on disk goes. [account] is the account the
     * switch now belongs to (null when off): another account does not inherit it. [plainFile]: the person chose a file
     * only their account can read, because this computer has no key store (note N2).
     */
    fun setKeepSignIn(on: Boolean, account: String? = null, plainFile: Boolean = false) {
        // Switching off: what the content keeps on disk is copied to memory first, so whatever reads it next (core,
        // composing the vault again) finds it there; then the switch reads as off; then core is told, before any file
        // is deleted, so an open vault moves to memory with what is queued; and only then do the files go.
        if (!on) content.carryToMemory()
        // The person switched it on for the account open: it is that account's now, not another's.
        if (on) foreign = false
        prefs.write(on, if (on) account else null, plainFile)
        if (!on) consentWithdrawn()
        secureFile.keepChanged(on)
        content.keepChanged(on)
        if (!on) cacheFiles.deleteAll()
    }

    /**
     * Called once the switch reads as off and before any file is deleted: the app interface's
     * `atRestConsentChanged()` ([TrustSeam] sets it). The engine reads the switch as its at-rest consent
     * ([io.silencelen.andvari.core.app.engine.AppEngine.keepsAtRest]).
     */
    @Volatile
    var consentWithdrawn: () -> Unit = {}

    /** The platform's consent to keep a copy at rest, as the engine reads it: on only while the switch says on. */
    fun keepsAtRest(): Boolean = keepNow() == Keep.ON

    /**
     * The person answered the question an unreadable settings file raised. The file is kept under a new name first
     * (never deleted for not being readable), then the answer is written as a new one.
     */
    fun answerUnreadablePrefs(on: Boolean, account: String? = null, plainFile: Boolean = false) {
        prefs.setAside()
        setKeepSignIn(on, account, plainFile)
    }

    companion object {
        const val NEW_DIR = "v2"

        /** `~/.andvari-desktop`, the old app's root and the new path's. */
        fun defaultRoot(): File = File(System.getProperty("user.home"), ".andvari-desktop")
    }
}

/**
 * One owner-only file, replaced atomically (written beside, then renamed over), for [JsonDeviceState]: the
 * command-line client's `OwnerOnlyFile`, with one difference that matters to the engine: a file that is there but
 * cannot be read **throws** instead of reading as "no file", so a trust record that cannot be read reaches the engine
 * as unknown, never as empty (design §4.4, "a trust record that cannot be read is not an empty one").
 */
class OwnerOnlyFile(private val f: File) : DeviceStateFile {
    override fun read(): String? {
        if (!f.exists()) return null
        return try {
            f.readText()
        } catch (e: IOException) {
            throw IOException("${f.name} is there but could not be read", e)
        }
    }

    override fun replace(text: String) {
        val bytes = text.encodeToByteArray()
        try {
            replaceOwnerOnly(f, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    /** Deletes the file and any temporary one a crash left beside it. */
    fun delete(): Boolean {
        sweepTemps(f)
        return !f.exists() || f.delete()
    }

    /** Keeps the file under a new name (`<name>.unreadable-<time>`), unread; true when nothing is left at the name. */
    fun setAside(): Boolean {
        if (!f.exists()) return true
        val aside = File(f.absoluteFile.parentFile, f.name + ".unreadable-" + System.currentTimeMillis())
        return runCatching { Files.move(f.toPath(), aside.toPath()) }.isSuccess
    }
}

/**
 * Writes [bytes] to [target] by an atomic replace: an owner-only temporary file of its own in the same directory
 * (`Files.createTempFile`: a name no other writer shares), then a rename over [target]. Before,
 * one fixed `.tmp` name let two writers delete and move each other's file. A temporary file that was not moved is
 * deleted.
 */
internal fun replaceOwnerOnly(target: File, bytes: ByteArray) {
    val parent = target.absoluteFile.parentFile
    ownerOnlyDir(parent)
    val attrs = if (posix(parent)) arrayOf(PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))) else emptyArray()
    val tmp = Files.createTempFile(parent.toPath(), target.name + ".", TEMP_SUFFIX, *attrs)
    try {
        Files.write(tmp, bytes)
        Files.move(tmp, target.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
    } finally {
        Files.deleteIfExists(tmp)
    }
}

private const val TEMP_SUFFIX = ".tmp"

/** Deletes the temporary files [replaceOwnerOnly] (or the old fixed name) may have left beside [target]. */
internal fun sweepTemps(target: File) {
    val prefix = target.name + "."
    target.absoluteFile.parentFile?.listFiles()?.forEach { f ->
        if (f.isFile && f.name.startsWith(prefix) && f.name.endsWith(TEMP_SUFFIX)) f.delete()
    }
}

/**
 * The item engine's cache files under the same opt-in: SQLite files in [dir] while the person keeps the sign-in on
 * this computer, memory otherwise. Core makes a cache a file only where the server's policy allows it as well.
 */
class OptInCacheFiles(private val dir: File, private val within: File, private val keep: () -> Keep) : VaultCacheFiles {
    private val files = SqliteVaultCacheFiles(dir.absolutePath) { path -> File(path).let { f -> !f.exists() || f.delete() } }

    override fun open(fileName: String, userId: String): VaultCache {
        when (keep()) {
            Keep.ON -> {
                ownerOnlyDir(dir)
                ownerOnlyDatabase(File(dir, fileName))
                return files.open(fileName, userId)
            }
            Keep.OFF -> files.delete(fileName)
            // The settings could not be read: the file is neither opened nor deleted; this run keeps its copy in memory.
            Keep.UNKNOWN -> {}
        }
        return InMemoryVaultCache()
    }

    override fun delete(fileName: String): Boolean = files.delete(fileName)

    /**
     * Core opens the cache with the SQLite driver (`SqlBox`), which creates the database with the process's umask, so
     * `rw-r--r--` (seen in the run, inside the owner-only directory). The database is made here first, empty and
     * `rw-------`, before core opens it; SQLite then creates its `-wal`, `-shm` and `-journal` files with the database's
     * own mode. Files an earlier build left readable by others are made owner-only.
     */
    private fun ownerOnlyDatabase(db: File) {
        if (!db.exists()) runCatching { Files.createFile(db.toPath(), *ownerOnlyFileAttrs(dir)) }
        for (f in listOf(db, File(db.path + "-wal"), File(db.path + "-shm"), File(db.path + "-journal"))) ownerOnlyFile(f)
    }

    /**
     * The opt-in went off, or a start found it off: every cache file goes. One Windows still holds open goes at the
     * next start ([DesktopHome.keepAtStart]).
     */
    fun deleteAll() {
        SafeDelete.entries(dir).forEach { SafeDelete.tree(it, within) }
    }
}

/** The switch "keep me signed in on this computer", as its settings file says: on, off, or not readable. */
enum class Keep { ON, OFF, UNKNOWN }

/** The new path's own choices on this device. */
class DesktopTrustPrefs(private val file: OwnerOnlyFile) : PlainMigration, BindingRecord {
    /**
     * [plainFile]: the person chose, on a computer with no key store, to keep the sign-in in a file only their account
     * can read (note N2). It belongs with the switch: it goes when the switch goes off.
     *
     * [wraps] says these settings were written by a build that wraps the kept sign-in, so an
     * unwrapped `secure-state.json` is no longer an earlier build's file and is accepted only by [plainFile]. Settings an
     * earlier build wrote lack it: their unwrapped file is accepted once, as that build's migration, and the migration is
     * recorded: [migratedPlain] is the SHA-256 of the file accepted (it alone is accepted again, until it is wrapped or
     * the person answers the no-key-store question), [migratedAt] when it happened.
     */
    @Serializable
    private data class Prefs(
        val keepSignIn: Boolean = false,
        val keptFor: String? = null,
        val plainFile: Boolean = false,
        val wraps: Boolean = false,
        val migratedPlain: String? = null,
        val migratedAt: Long? = null,
        val sealedFor: String? = null,
        val sealedAt: String? = null,
    )

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * The settings, or null when the file is there but cannot be read or parsed. A
     * preferences file that cannot be read is unknown, never "off", so nothing kept is deleted because of it. No file
     * at all is the default (off).
     */
    private fun load(): Prefs? = try {
        file.read()?.let { json.decodeFromString(Prefs.serializer(), it) } ?: Prefs()
    } catch (e: Exception) {
        null
    }

    fun keep(): Keep = load()?.let { if (it.keepSignIn) Keep.ON else Keep.OFF } ?: Keep.UNKNOWN

    /** The person opted in to keep the sign-in (tokens, keys, the offline copy) on this computer. Off by default. */
    val keepSignIn: Boolean get() = keep() == Keep.ON

    /** The account the switch belongs to (its account ID), or null: another account does not inherit it. */
    val keptFor: String? get() = load()?.keptFor

    /** The person chose a file only their account can read where there is no key store; false while off or unreadable. */
    val plainFile: Boolean get() = load()?.let { it.keepSignIn && it.plainFile } ?: false

    /**
     * Writes the switch. Every file this build writes says it [Prefs.wraps]; a migration still in progress (its file
     * neither wrapped nor answered yet) is kept while the switch stays on, and its record always.
     */
    fun write(on: Boolean, keptFor: String?, plainFile: Boolean = false) {
        val old = load()
        val migrating = old?.migratedPlain?.takeIf { on && !plainFile }
        save(
            Prefs(
                on, keptFor, on && plainFile, wraps = true, migratedPlain = migrating, migratedAt = old?.migratedAt,
                sealedFor = old?.sealedFor?.takeIf { on }, sealedAt = old?.sealedAt?.takeIf { on },
            ),
        )
    }

    /**
     * The account and server the kept file was last sealed for. A file sealed for another does
     * not open here ([SessionWrap.open]). None recorded (settings answered anew): the file's own, which its seal binds.
     */
    override fun expected(): KeptBinding? = load()?.let { p -> if (p.sealedFor != null && p.sealedAt != null) KeptBinding(p.sealedFor, p.sealedAt) else null }

    override fun record(binding: KeptBinding) {
        val p = load() ?: return
        if (p.sealedFor != binding.account || p.sealedAt != binding.origin) save(p.copy(sealedFor = binding.account, sealedAt = binding.origin))
    }

    private fun save(p: Prefs) = file.replace(json.encodeToString(Prefs.serializer(), p))

    override fun accept(text: String, now: Long): Boolean {
        val p = load() ?: return false
        val digest = sha256(text)
        if (!p.wraps) {
            save(p.copy(wraps = true, migratedPlain = digest, migratedAt = now))
            return true
        }
        return p.migratedPlain != null && p.migratedPlain == digest
    }

    override fun done() {
        val p = load() ?: return
        if (p.migratedPlain != null) save(p.copy(migratedPlain = null))
    }

    /** When an earlier build's unwrapped file was accepted as its migration, or null (for tests and Settings). */
    val migratedAt: Long? get() = load()?.migratedAt

    private fun sha256(text: String): String {
        val bytes = text.encodeToByteArray()
        try {
            return java.util.Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(bytes))
        } finally {
            bytes.fill(0)
        }
    }

    /** Keeps an unreadable settings file under a new name. */
    fun setAside(): Boolean = file.setAside()
}

/**
 * §12.4 on desktop: the first launch of a new build removes the old design's stores from `~/.andvari-desktop/`
 * It deletes named files only and never enters [DesktopHome.NEW_DIR].
 *
 * - `prefs.json` is cut down to the theme, the last-backup time and the update rollback floor; the old server address
 *   and every per-origin record go with [PreCutoverStore.SAVED_SESSIONS].
 * - A file that cannot be deleted (Windows holds it open) makes its store answer false: core then reports the store
 *   as left ([io.silencelen.andvari.core.app.OldDataLeft]) and the app starts nothing new beside it.
 */
class DesktopOldStores(private val root: File) : PreCutoverStores {
    private val ns = File(root, "ns")

    override fun wipe(store: PreCutoverStore): Boolean = runCatching {
        when (store) {
            PreCutoverStore.OFFLINE_CACHE ->
                deleteAll(namespaced { it.name.startsWith("vault-") && it.name.contains(".db") } + rootFiles { it.name.startsWith("vault-") && it.name.contains(".db") })
            PreCutoverStore.SAVED_SESSIONS ->
                deleteAll(listOf(File(root, "session.json"), File(root, "pending-server.json"), File(root, "account-keys.json")) + namespaced { it.name == "account-keys.json" }) &&
                    cutDownPrefs()
            PreCutoverStore.TRUST_RECORDS ->
                // The old device state held the trust records too (with the personal wrap, below).
                deleteAll(namespaced { it.name == "self-identity-pub" || it.name == "device-state.json" } + selfIdentityByEmail()) && pruneEmpty()
            // The personal wrap and the pinned personal vault lived in the old device state.
            PreCutoverStore.PERSONAL_WRAP_CACHE -> deleteAll(namespaced { it.name == "device-state.json" })
            PreCutoverStore.QUICK_UNLOCK_KEYS, PreCutoverStore.APP_GROUP_SNAPSHOT_AND_SAVE_QUEUE -> true
        }
    }.getOrDefault(false)

    // Note N1: every listing below enters plain directories only and every delete goes through [SafeDelete], so a link
    // or a Windows junction planted in `ns/` is removed as itself and nothing is deleted through it.

    /** Files in `ns/<originKey>/<userId>/`, plain directories only; a link where a file was is listed (and goes as itself). */
    private fun namespaced(match: (File) -> Boolean): List<File> =
        SafeDelete.entries(ns).filter(SafeDelete::isRealDir).flatMap { o -> SafeDelete.entries(o).filter(SafeDelete::isRealDir) }
            .flatMap { u -> SafeDelete.entries(u).filter { !SafeDelete.isRealDir(it) && match(it) } }

    private fun rootFiles(match: (File) -> Boolean): List<File> = SafeDelete.entries(root).filter { !SafeDelete.isRealDir(it) && match(it) }

    /** `ns/<originKey>/self-identity-by-email`, whatever it is: a plain directory goes with what is in it, a link as itself. */
    private fun selfIdentityByEmail(): List<File> =
        SafeDelete.entries(ns).filter(SafeDelete::isRealDir).map { File(it, "self-identity-by-email") }.filter(SafeDelete::exists)
            .flatMap { d -> SafeDelete.entries(d) + d }

    private fun deleteAll(files: List<File>): Boolean = files.map { SafeDelete.entry(it, root) }.all { it }

    /**
     * Removes `ns/` directories left empty, and any link found among them (as itself). A directory still holding
     * something is left, and does not fail the wipe.
     */
    private fun pruneEmpty(): Boolean {
        // A link or junction is neither a plain directory nor a plain file: it goes as itself.
        fun planted(f: File) = !SafeDelete.isRealDir(f) && !SafeDelete.isRealFile(f)
        for (o in SafeDelete.entries(ns)) {
            if (planted(o)) SafeDelete.tree(o, root)
            if (!SafeDelete.isRealDir(o)) continue
            for (u in SafeDelete.entries(o)) {
                if (planted(u)) SafeDelete.tree(u, root) else if (SafeDelete.isRealDir(u) && SafeDelete.entries(u).isEmpty()) u.delete()
            }
            if (SafeDelete.entries(o).isEmpty()) o.delete()
        }
        if (SafeDelete.isRealDir(ns) && SafeDelete.entries(ns).isEmpty()) ns.delete()
        return true
    }

    /** `prefs.json` keeps only [KEPT_PREFS]; anything else in it (the server address, per-origin records) goes. */
    private fun cutDownPrefs(): Boolean {
        val f = File(root, "prefs.json")
        if (!f.exists()) return true
        val json = Json { ignoreUnknownKeys = true }
        val old = runCatching { json.parseToJsonElement(f.readText()).jsonObject }.getOrNull()
        val kept: Map<String, JsonElement> = old?.filterKeys { it in KEPT_PREFS } ?: emptyMap()
        if (old != null && old.keys == kept.keys) return true
        OwnerOnlyFile(f).replace(JsonObject(kept).toString())
        return true
    }

    companion object {
        /**
         * What the old `prefs.json` keeps across the cut-over, and the update check's record of its
         * last verified list (written by this app only, so a wipe that runs again keeps it).
         */
        val KEPT_PREFS = setOf("themeMode", "lastExportAt", "lastAcceptedSeq", "lastUpdateCheckAt", "lastUpdateCheckFrom", "lastUpdateListSignedAt")
    }
}

internal fun posix(dir: File): Boolean = runCatching { Files.getFileStore(dir.toPath()).supportsFileAttributeView("posix") }.getOrDefault(false)

/** Made `rwx------` on POSIX; Windows relies on the profile's ACL, as the old app did. */
internal fun ownerOnlyDir(dir: File) {
    // Every directory this call creates is made owner-only, not only the last one (`content/<store>` made `content` with
    // the umask's mode); directories that were there already, the person's home among them, are left as they are.
    val created = generateSequence(dir.absoluteFile) { it.parentFile }.takeWhile { !it.exists() }.toList()
    dir.mkdirs()
    if (posix(dir)) (created + dir).distinct().forEach { d -> runCatching { Files.setPosixFilePermissions(d.toPath(), PosixFilePermissions.fromString("rwx------")) } }
}

/** The create-time attribute for an owner-only file in [dir] (`rw-------`), or none where the file system has no POSIX modes. */
internal fun ownerOnlyFileAttrs(dir: File): Array<java.nio.file.attribute.FileAttribute<*>> =
    if (posix(dir)) arrayOf(PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))) else emptyArray()

/** An existing file made `rw-------` on POSIX (one an earlier build, or another library, created readable by others). */
internal fun ownerOnlyFile(f: File) {
    if (f.isFile && posix(f.absoluteFile.parentFile)) runCatching { Files.setPosixFilePermissions(f.toPath(), PosixFilePermissions.fromString("rw-------")) }
}
