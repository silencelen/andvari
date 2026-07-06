package io.silencelen.andvari.app

import android.app.Application
import android.os.Build
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

/**
 * Installs a last-resort uncaught-exception handler as the very first app code (before
 * any Activity), so a crash — including one during startup — is written to disk. On the
 * NEXT launch, MainActivity shows it on screen for the user to screenshot. This is a
 * field-diagnostic aid (no adb / logcat needed); harmless to keep.
 */
class AndvariApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val crashFile = File(filesDir, CRASH_FILE)
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching {
                val sw = StringWriter()
                throwable.printStackTrace(PrintWriter(sw))
                crashFile.writeText(
                    buildString {
                        appendLine("andvari crash")
                        appendLine("device: ${Build.MANUFACTURER} ${Build.MODEL} · Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
                        appendLine("abis: ${Build.SUPPORTED_ABIS.joinToString()}")
                        appendLine("thread: ${thread.name}")
                        appendLine()
                        append(sw.toString())
                    },
                )
            }
            prev?.uncaughtException(thread, throwable) // let the system record + kill as usual
        }
    }

    companion object {
        const val CRASH_FILE = "last-crash.txt"
    }
}
