package io.silencelen.andvari.app

import android.app.Application
import android.os.Build
import java.io.File

/**
 * Installs a last-resort uncaught-exception handler as the very first app code (before
 * any Activity), so a crash — including one during startup — is written to disk. On the
 * NEXT launch, MainActivity shows it on screen for the user to screenshot. This is a
 * field-diagnostic aid (no adb / logcat needed); harmless to keep.
 */
class AndvariApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // H09: the lock-on-background overlay exemption needs to see EVERY activity start/stop
        // in the process, so it registers here, before any Activity exists.
        InProcessOverlays.install(this)
        // H56: `no_backup/`, not `files/`. The report is a diagnostic about ONE device's crash —
        // it has no business riding Auto Backup or Android 12+ device-to-device transfer onto a
        // second device (data_extraction_rules.xml excludes only the shared-prefs file, and the
        // per-user cache DBs already live here for exactly this reason).
        val crashFile = File(noBackupFilesDir, CRASH_FILE)
        // A report written by a pre-H56 build is an UNSCRUBBED stack trace sitting in the backup
        // domain. Delete it on first run of this build rather than display it: an old crash the
        // user never reported is worth less than getting the unscrubbed text off the device.
        runCatching { File(filesDir, CRASH_FILE).delete() }
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching {
                crashFile.writeText(
                    buildString {
                        appendLine("andvari crash")
                        appendLine("device: ${Build.MANUFACTURER} ${Build.MODEL} · Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
                        appendLine("abis: ${Build.SUPPORTED_ABIS.joinToString()}")
                        appendLine("thread: ${thread.name}")
                        appendLine()
                        append(scrubbedTrace(throwable))
                    },
                )
            }
            prev?.uncaughtException(thread, throwable) // let the system record + kill as usual
        }
    }

    companion object {
        const val CRASH_FILE = "last-crash.txt"

        /** Cause chain depth cap — also the loop guard for a self-referential `cause`. */
        internal const val MAX_CAUSES = 8

        /** Frames kept per throwable: enough to place the fault, short enough to screenshot. */
        internal const val MAX_FRAMES = 24
    }
}

/**
 * The crash report's body: exception CLASS names and stack FRAMES, and never a `message`
 * (audit 2026-09-13 H56).
 *
 * This is the same never-log rule [io.silencelen.andvari.app.autofill.AutofillDebugLog] states
 * for its own EXCEPTION detail, and it exists for the same reason: an exception message quotes
 * its input. A kotlinx `JsonDecodingException` appends an excerpt of the JSON it failed on — and
 * on this client that JSON is a DECRYPTED item document, passwords and all; an
 * `IllegalArgumentException` out of URI parsing quotes the URI; RemoteViews/Parcel errors quote
 * view content. `printStackTrace`, which this replaces, prints every one of those verbatim for
 * the whole cause chain.
 *
 * That would be bad anywhere. It is worse here than in a log file, because this report is the one
 * screen in the app deliberately exempt from FLAG_SECURE (MainActivity keeps crash traces
 * screenshot-able) and its copy actively routes the text off the device: "screenshot this and
 * send it". Scrubbing at the WRITE point, not the display point, is what makes both of those safe
 * — the plaintext never reaches the file, so it cannot reach a backup, a screenshot, or a chat.
 *
 * A [StackTraceElement] carries only class, method, file and line, so frames are safe to keep,
 * and they are the part that actually locates a crash.
 */
internal fun scrubbedTrace(t: Throwable): String = buildString {
    var current: Throwable? = t
    var depth = 0
    while (depth < AndvariApplication.MAX_CAUSES) {
        val e = current ?: break
        // `javaClass.name`, not `::class.qualifiedName`: this runs inside a dying process, so the
        // report is built out of plain JVM reads with no reflection machinery to fail in.
        val name = e.javaClass.name
        appendLine(if (depth == 0) name else "Caused by: $name")
        val frames = e.stackTrace ?: emptyArray()
        for (f in frames.take(AndvariApplication.MAX_FRAMES)) appendLine("\tat $f")
        val hidden = frames.size - AndvariApplication.MAX_FRAMES
        if (hidden > 0) appendLine("\t… $hidden more")
        // `cause` can be the throwable itself (a Throwable whose cause was never set through the
        // constructor answers `this`); the identity check keeps that from looping.
        current = e.cause?.takeIf { it !== e }
        depth++
    }
}
