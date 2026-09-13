package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoUnavailableException
import io.silencelen.andvari.core.crypto.NATIVE_SODIUM_PATH_PROPERTY
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.crypto.nativeSodiumFallbackCause
import java.io.File
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.time.Instant

/**
 * The startup crypto self-check's verdict (audit H15). 0.26.3 shipped the check and then threw
 * its answer away: `runStartupSelfCheck()` returned Unit, Main discarded it, and a machine whose
 * native libsodium does not load was waved through to the password field — where the first crypto
 * touch inside sign-in/unlock threw the SAME error again and the household canon flattened it to
 * "Sign-in failed. Please try again." / "Couldn't unlock — please try again." for a permanent,
 * non-retryable, local condition. A password manager must never induce "I forgot my password" or
 * "the server is broken" for a failure it has already diagnosed. The verdict now travels to
 * [DesktopState.applySelfCheck], which renders the blocking, honest state (the 426 upgrade-screen
 * idiom) naming the diagnostic log instead of the password field.
 */
sealed class SelfCheck {
    object Ok : SelfCheck()

    /** [summary] is the throwable chain in one line — for the log and tests; the UI renders the
     *  STATIC sentence ([DesktopState.CRYPTO_UNAVAILABLE_NOTICE]) plus the log path, never this. */
    data class CryptoUnavailable(val summary: String) : SelfCheck()
}

/**
 * Field diagnostics for failures that the household canon deliberately flattens to a calm,
 * jargon-free line ([HouseholdCopy]) — most of all sign-in, whose "Sign-in failed. Please try
 * again." is the same string for a late crypto throw as for anything else the `else` branch
 * catches ([HouseholdCopy.forSignInError]). The user-facing copy stays calm; this writes the
 * underlying cause where a maintainer can read it, never the user.
 *
 * Log file: `~/.andvari-desktop/diagnostic.log` (the store's own dir), rotated to `.log.1` at
 * [MAX_LOG_BYTES]; best-effort — a diagnostics failure must never affect the app.
 *
 * Contains NO vault material: exception CLASS chains, allowlisted structural messages, stack
 * frames, environment facts and the crypto self-check verdict. That is now a property of the code
 * ([redactedLink]) rather than a promise about the throwables that happen to reach it — audit H58
 * found the promise already broken, by an app-minted message carrying a decrypted attachment name
 * and by kotlinx-serialization quoting a window of the JSON it failed to decode. Anything added
 * here must go through [log]/[logThrowable]; never write a raw `message`, and never reach for
 * `Throwable.stackTraceToString`.
 *
 * At-rest permissions (audit H11, a regression of F35): this object runs FIRST in main(), before
 * [DesktopSessionStore] ever touches `~/.andvari-desktop`, so on a fresh POSIX install it is the
 * one that CREATES the store directory. 0.26.3 did that with a bare `mkdirs()` (0777 & ~umask —
 * world-traversable), and because the store's [mkdirsOwnerOnly] leaves an existing directory
 * alone by design, every new install from 0.26.3 on kept `session.json` (refresh token) and the
 * `ns/` cache tree under a 0755 parent forever — the F35 essay in DesktopSession.kt names the
 * directory mode "the load-bearing half". The log itself was created at the umask (0644): the home
 * path, every op() exception chain and full stack trace, readable by every local user. Both are
 * now created the store's way — the mode is part of the CREATE ([ownerOnly]), never a chmod after.
 */
object DesktopDiagnostics {
    /** Audit H126: rotate at 256 KiB keeping one generation — the log is bounded at 512 KiB total.
     *  Deliberately small: this is a support artifact a household member may be asked to send. */
    internal const val MAX_LOG_BYTES = 256L * 1024

    /** Audit H58/H126 bounds on ONE logged throwable: enough of a trace to place the failure,
     *  never a coroutine/ktor wall of frames, and never an unbounded message. */
    private const val MAX_FRAMES = 24
    private const val MAX_CHAIN_LINKS = 8
    private const val MAX_MESSAGE_CHARS = 300

    /** Test seam: point the log at a scratch home so the create-time modes can be asserted
     *  without touching the real `~/.andvari-desktop`. Production never sets it. */
    @Volatile
    internal var logFileOverride: File? = null

    private val defaultLogFile: File by lazy {
        File(File(System.getProperty("user.home"), ".andvari-desktop"), "diagnostic.log")
    }

    internal val logFile: File get() = logFileOverride ?: defaultLogFile

    fun log(line: String) {
        val stamped = "${Instant.now()} $line"
        System.err.println("[andvari-diag] $stamped")
        append(stamped + "\n")
    }

    fun logThrowable(context: String, t: Throwable) {
        log("$context :: ${throwableChain(t)}")
        append(redactedStackTrace(t))
    }

    /** One line naming every link of the cause chain — the log's and [SelfCheck]'s shape. Every
     *  link is REDACTED by [redactedLink]: a class name always, its message only when the type
     *  is one whose messages this app mints itself (audit H58). */
    private fun throwableChain(t: Throwable): String =
        causeChain(t).joinToString("  <-  ") { redactedLink(it) }

    /** The cause chain, bounded: a `cause` cycle (rare but legal — a handler that re-wraps its own
     *  cause) must not spin the logger, and beyond a handful of links nothing is diagnostic. */
    private fun causeChain(t: Throwable): List<Throwable> {
        val out = ArrayList<Throwable>(MAX_CHAIN_LINKS)
        var link: Throwable? = t
        while (link != null && out.size < MAX_CHAIN_LINKS && out.none { it === link }) {
            out.add(link)
            link = link.cause
        }
        return out
    }

    /**
     * Audit H58 — the redaction the file's own "contains NO vault material" contract needs.
     *
     * `logThrowable` is called from op()'s general catch, which every vault action passes through,
     * so the throwables reaching here are not a fixed set: they are whatever core, ktor, the
     * SQLite driver, kotlinx-serialization or this app happened to throw. Two of those routinely
     * put decrypted material into a `message`:
     *
     *  - **kotlinx-serialization** appends `"\nJSON input: <window of the input>"` to a
     *    `JsonDecodingException` (the whole input when it is under 200 chars). Core decodes
     *    PLAINTEXT item docs, backup payloads and escrow payloads with it (Account.kt, Export.kt,
     *    Escrow.kt), so a malformed-but-authenticated document would write a window of vault
     *    plaintext straight into a cleartext file.
     *  - **this app**, which minted `backup verification failed — attachment "<name>"` from a
     *    DECRYPTED attachment name. That sentence is also shown to the user (exportError's #23
     *    carve-out) where naming the file is the useful half, so it stays — the fix is that its
     *    TYPE, `IllegalStateException`, is not allowlisted here, which covers the next one too.
     *
     * So the rule is an ALLOWLIST, not a denylist: a message is written only for the types whose
     * messages are structural and app-minted, and every other throwable contributes its class name
     * alone. That is what the 0.26.3 diagnosis actually needed — the failing CLASS chain — and the
     * one thing a denylist could never promise, because the next dependency to be added does not
     * have to tell us what it puts in a message.
     *
     * The allowlist:
     *  - [ApiException] (and its [UpgradeRequiredException] subclass) — logged as `status`+`code`,
     *    never its `message`: that text comes off the wire from a server that may be hostile, and
     *    the code is the part anything downstream actually branches on.
     *  - [ImportException] — its message IS its code (`too_large` | `too_many_rows` | …).
     *  - [CryptoException] — constant, hand-written strings in LazySodiumCryptoProvider that name
     *    a primitive and a size, never a value.
     *  - `LinkageError` and friends (`UnsatisfiedLinkError`, `NoClassDefFoundError`,
     *    `ExceptionInInitializerError`) — the JVM's own loader text, naming libraries and search
     *    paths. This is the whole reason the log exists (H15/H81): dropping it would leave the
     *    Windows native-load failure diagnosable only by its class, which is what 0.26.3 already
     *    had. No user data can reach a loader message.
     *
     * Belt inside the allowlist: any message is cut at a `JSON input:` marker and capped at
     * [MAX_MESSAGE_CHARS], in case an allowlisted type is ever constructed around one.
     */
    private fun redactedLink(t: Throwable): String {
        val cls = t::class.qualifiedName ?: t::class.simpleName ?: "(anonymous throwable)"
        val detail: String? = when (t) {
            // Wire-supplied text is never logged — the structured pair is.
            is ApiException -> "status=${t.status} code=${t.code}"
            is CsvImport.ImportException -> "code=${t.code}"
            is CryptoException -> safeMessage(t)
            is LinkageError -> safeMessage(t)
            else -> null
        }
        return if (detail == null) cls else "$cls: $detail"
    }

    private fun safeMessage(t: Throwable): String? {
        val raw = t.message ?: return null
        val cut = raw.substringBefore("JSON input:").trim()
        if (cut.isEmpty()) return null
        return if (cut.length <= MAX_MESSAGE_CHARS) cut else cut.take(MAX_MESSAGE_CHARS) + "…"
    }

    /**
     * A stack trace with the header lines redacted (audit H58) and the frames bounded (audit H126).
     *
     * `Throwable.stackTraceToString` reprints every link's `toString()` — i.e. the very messages
     * [redactedLink] exists to withhold — so it cannot be used here at all. The FRAMES are the
     * diagnostic value and carry no user data: a [StackTraceElement] is class + method + file +
     * line. This rebuilds the familiar shape from redacted headers plus at most [MAX_FRAMES] frames
     * per link, which also bounds what one failed action can append (a ktor/coroutine trace runs to
     * dozens of KiB, appended once per failed sync on a laptop that is offline for a week).
     */
    private fun redactedStackTrace(t: Throwable): String = buildString {
        causeChain(t).forEachIndexed { i, link ->
            append(if (i == 0) "" else "Caused by: ").append(redactedLink(link)).append('\n')
            val frames = link.stackTrace
            frames.take(MAX_FRAMES).forEach { append("\tat ").append(it.toString()).append('\n') }
            if (frames.size > MAX_FRAMES) append("\t… ${frames.size - MAX_FRAMES} more\n")
        }
    }

    /**
     * The ONE write path. The directory is created `rwx------` and the file `rw-------` AT
     * CREATE (the F35 helpers three lines away in DesktopSession.kt — one implementation, no
     * second copy to drift); an existing file keeps whatever mode it has, exactly like the
     * store's own files. Best-effort: any failure is swallowed, because diagnostics must never
     * affect the app — but it is never allowed to fall back to a umask-mode create.
     *
     * Audit H126 — bounded. The log was append-only with no cap, rotation or trim: every failed
     * op() (an unreachable server on a laptop that syncs on window focus, one attempt per focus)
     * appended a multi-KiB trace forever, in the store directory, for the life of the profile. It
     * now rotates at [MAX_LOG_BYTES] keeping ONE generation, so the worst case is bounded at twice
     * that — small enough to be a support attachment, long enough to hold a launch's ~15 startup
     * lines plus the failures around it, which is the whole diagnostic window. `.log.1` is written
     * by a rename of a file that was already created `rw-------`, so it inherits the mode.
     */
    private fun append(text: String) {
        runCatching {
            val f = logFile
            f.parentFile?.mkdirsOwnerOnly()
            rotateIfOversized(f, text.length.toLong())
            val opts = setOf(StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE)
            Files.newByteChannel(f.toPath(), opts, *ownerOnly("rw-------")).use {
                it.write(ByteBuffer.wrap(text.encodeToByteArray()))
            }
        }
    }

    /**
     * H11 → recheck R16: the create-time modes only cover installs created AFTER this build.
     * `mkdirsOwnerOnly` leaves an existing directory alone by design and `CREATE` never touches an
     * existing file's mode, so every 0.26.3-created install kept `~/.andvari-desktop` at 0755 and
     * `diagnostic.log` (home path, exception chains, stack traces) at 0644 forever. Run ONCE per
     * launch, POSIX only (Windows uses ACLs; nothing to repair there): the store's own
     * `writeTextOwnerOnly` chmod idiom, extended with the execute bit for the directory. Only
     * this app's own directory and log — never a shared parent.
     */
    internal fun repairAtRestModes() {
        runCatching {
            if (!java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) return
            val f = logFile
            f.parentFile?.takeIf { it.isDirectory }?.let { dir ->
                java.nio.file.Files.setPosixFilePermissions(dir.toPath(), java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
            }
            for (log in listOf(f, File(f.parentFile, f.name + ".1"))) {
                if (log.isFile) java.nio.file.Files.setPosixFilePermissions(log.toPath(), java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))
            }
        }
    }

    /** Rotate `diagnostic.log` → `diagnostic.log.1` (replacing any previous generation) when this
     *  append would push it past [MAX_LOG_BYTES]. Best-effort like everything else here: if the
     *  rename fails the append still happens, and the file is merely over its cap. */
    private fun rotateIfOversized(f: File, incoming: Long) {
        val len = runCatching { if (f.isFile) f.length() else 0L }.getOrDefault(0L)
        if (len + incoming <= MAX_LOG_BYTES) return
        val prev = File(f.parentFile, f.name + ".1")
        runCatching {
            Files.move(f.toPath(), prev.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        }
    }

    /**
     * Runs once at startup, before the first real crypto touch. Confirms the native libsodium
     * layer actually loads on THIS machine (the one thing that differs across a fresh install and
     * the dev/CI boxes where it always works), and records the environment needed to diagnose a
     * native-load failure — notably which MSVC/UCRT runtime DLLs the bundled JDK runtime ships,
     * since the Windows `libsodium.dll` imports `VCRUNTIME140.dll` + the `api-ms-win-crt-*` UCRT.
     *
     * Returns the verdict (audit H15) — the caller MUST act on a [SelfCheck.CryptoUnavailable]
     * (Main hands it to [DesktopState.applySelfCheck]); logging it alone is the defect this
     * used to be. Never throws.
     */
    fun runStartupSelfCheck(): SelfCheck {
        repairAtRestModes() // H11 (recheck R16): before the first append, so a 0.26.3 install is fixed too
        runCatching {
            log("---- startup self-check ----")
            log("os.name=${System.getProperty("os.name")} os.arch=${System.getProperty("os.arch")} java=${System.getProperty("java.version")}")
            log("java.home=${System.getProperty("java.home")}")
            val runtimeBin = File(System.getProperty("java.home"), "bin")
            val rtDlls = runtimeBin.listFiles { f -> f.name.endsWith(".dll") }
                ?.map { it.name }?.sorted() ?: emptyList()
            val crt = rtDlls.filter {
                it.startsWith("vcruntime", true) || it.startsWith("msvcp", true) ||
                    it.startsWith("ucrtbase", true) || it.startsWith("api-ms-win-crt", true)
            }
            log("runtime/bin CRT dlls: ${if (crt.isEmpty()) "NONE FOUND" else crt.joinToString(",")}")
        }
        // Install-location diagnosis (Program Files fails, a writable build folder works): the
        // native libs (libsodium via lazysodium/resource-loader, JNA's jnidispatch, sqlite-jdbc)
        // are extracted at first use — if they land somewhere read-only under Program Files the
        // load throws before login. Record every path they might use and whether it is writable,
        // plus the props that redirect them.
        runCatching {
            val appDir = File(System.getProperty("java.home")).parentFile // <install>, parent of runtime
            for ((label, path) in listOf(
                "java.io.tmpdir" to System.getProperty("java.io.tmpdir"),
                "user.dir(cwd)" to System.getProperty("user.dir"),
                "user.home" to System.getProperty("user.home"),
                "app.install.dir" to appDir?.absolutePath,
                "app.jars.dir" to appDir?.let { File(it, "app").absolutePath },
            )) {
                log("path $label = $path  writable=${path?.let { dirWritable(File(it)) }}")
            }
            for (p in listOf("jna.tmpdir", "jna.boot.library.path", "jna.nounpack", "jna.nosys",
                             "org.sqlite.tmpdir", "java.library.path")) {
                System.getProperty(p)?.let { log("sysprop $p = $it") }
            }
        }
        val sodiumPath = System.getProperty(NATIVE_SODIUM_PATH_PROPERTY)
        log("$NATIVE_SODIUM_PATH_PROPERTY = ${sodiumPath ?: "(unset — using lazysodium's own loader)"}")
        return try {
            val provider = createCryptoProvider()
            val probe = provider.randomBytes(1)
            log("crypto self-check OK: provider=${provider::class.qualifiedName}, randomBytes=${probe.size}")
            // H15/H89 (recheck R14/R20): the property being SET is no longer proof its path was used —
            // core falls back to the bundled loader on a property-path failure. Record which loader
            // actually served the process (the cause chain is allowlisted: a LinkageError).
            val fallback = nativeSodiumFallbackCause()
            when {
                fallback != null -> logThrowable("native libsodium: the property path did NOT load — the bundled loader served this process", fallback)
                sodiumPath != null -> log("native libsodium loaded via the property path")
            }
            SelfCheck.Ok
        } catch (t: Throwable) {
            logThrowable("crypto self-check FAILED (native libsodium did not load)", t)
            SelfCheck.CryptoUnavailable(throwableChain(t))
        }
    }

    /** True iff a file can be created (and is deleted again) in [dir] — the real test, since a
     *  read-only Program Files dir reports exists()/canWrite() inconsistently across Windows. */
    private fun dirWritable(dir: File): Boolean = runCatching {
        if (!dir.isDirectory) return false
        val probe = File(dir, "andvari-wtest-${System.nanoTime()}.tmp")
        probe.writeText("x"); val ok = probe.exists(); probe.delete(); ok
    }.getOrDefault(false)
}

/**
 * Audit H15, the op()-level belt: does this throwable mean the native crypto layer could not be
 * loaded on this machine? The startup self-check catches the common case before any UI exists;
 * this catches the same failure class if it first surfaces INSIDE an op (an AV quarantine of the
 * extracted DLL after the self-check passed, a tmpdir wiped mid-session), so the household canon
 * never gets to render it as "try again". The whole cause chain is walked because JNA and
 * lazysodium wrap the real error in layers (`ExceptionInInitializerError` → `UnsatisfiedLinkError`;
 * `NoClassDefFoundError: Could not initialize class com.sun.jna.Native` on every access after a
 * failed static init; resource-loader's `LibraryLoadingException`; the Program Files
 * `FileSystemNotFoundException` 0.26.3 was written for). None of these five is ever a transient
 * network or user cause, so over-matching among them costs nothing — under-matching costs a
 * member a wrong-password hypothesis.
 */
internal fun isNativeCryptoLoadFailure(t: Throwable): Boolean =
    generateSequence(t as Throwable?) { it.cause }.any { link ->
        // Recheck R15: core now WRAPS every native load failure in CryptoUnavailableException
        // (createCryptoProvider memoizes it for the life of the process) — that type is the
        // signal, whatever it happens to wrap. The loader-type arms below stay as the belt for a
        // failure that surfaces outside core's loader (a quarantined DLL on a later JNA touch).
        link is CryptoUnavailableException ||
            link is UnsatisfiedLinkError ||
            link is ExceptionInInitializerError ||
            // A bare NoClassDefFoundError is any missing class — an unrelated one must NOT strand
            // the app on the "encryption library" screen; only the JNA/sodium shapes count.
            (link is NoClassDefFoundError && NATIVE_CLASS_HINTS.any { (link.message ?: "").contains(it, ignoreCase = true) }) ||
            link is java.nio.file.FileSystemNotFoundException ||
            link::class.simpleName == "LibraryLoadingException"
    }

/** The class-name fragments a native-load NoClassDefFoundError carries (JNA's Native, lazysodium's
 *  Sodium*, the resource-loader) — the comment's own example is `com.sun.jna.Native`. */
private val NATIVE_CLASS_HINTS = listOf("com.sun.jna", "lazysodium", "libsodium", "sodium", "resourceloader")
