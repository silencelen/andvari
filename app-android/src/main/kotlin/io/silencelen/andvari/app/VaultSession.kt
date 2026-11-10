package io.silencelen.andvari.app

import android.content.ContentResolver
import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import io.silencelen.andvari.core.client.session.Clocks
import io.silencelen.andvari.core.client.session.SessionEndHook
import io.silencelen.andvari.core.client.session.VaultSession as CoreVaultSession

/**
 * The process-wide unlocked vault, shared by the [AndvariViewModel] (main dispatcher) and the
 * autofill service/unlock activity (background). All of the session logic — the auto-lock window,
 * the in-flight deferral, the single token-holder rules — lives in core; this object only binds
 * it to Android's clocks and the usage ledger's teardown flush.
 */
object VaultSession : CoreVaultSession(AndroidClocks, UsageFlushOnSessionEnd) {
    typealias Unlocked = CoreVaultSession.Unlocked
    typealias UnlockProvenance = CoreVaultSession.UnlockProvenance
}

/** The process-wide clocks (see [Clocks]). `elapsedRealtime` counts through deep sleep and doze. */
object AndroidClocks : Clocks {
    @Volatile
    private var resolver: ContentResolver? = null

    /** Called from [AndvariApplication.onCreate], before anything can read [bootId]. */
    fun install(context: Context) {
        resolver = context.applicationContext.contentResolver
    }

    override fun wallMs(): Long = System.currentTimeMillis()

    override fun monotonicMs(): Long = SystemClock.elapsedRealtime()

    /** A12 (row 74): the boot count, the boot identity the wall clock cannot fake. Null when the
     *  platform does not expose it (freshness then fails closed, see [Clocks.bootId]). */
    override fun bootId(): String? = resolver?.let { r ->
        runCatching { Settings.Global.getInt(r, Settings.Global.BOOT_COUNT, -1) }.getOrDefault(-1).takeIf { it >= 0 }?.toString()
    }
}

/** The G03 lock-path flush: the live session's last uses are stored before its transport closes. */
private object UsageFlushOnSessionEnd : SessionEndHook {
    override fun flush(session: CoreVaultSession.Unlocked, closeTransport: () -> Unit) {
        UsageRecorder.flushForSession(session, closeTransport)
    }

    override fun clear() = UsageRecorder.clear()
}
