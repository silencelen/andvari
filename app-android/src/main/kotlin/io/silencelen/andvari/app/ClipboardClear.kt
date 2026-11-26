package io.silencelen.andvari.app

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ProcessLifecycleOwner
import java.io.File
import java.security.SecureRandom

/**
 * A copied secret is cleared after the policy's window whether or not andvari is in front.
 *
 * - **The timer** is two: a main-thread one while the process lives (it survives a lock and a background stay), and an
 *   inexact alarm ([AlarmManager.setAndAllowWhileIdle], no permission) to [ClipboardClearReceiver] for when the system
 *   ended the process meanwhile. Both carry the copy's nonce; the newest copy owns the one pending clear.
 * - **The clear**: when andvari is not in front, the clipboard is cleared WITHOUT reading it (the platform does not
 *   let a background app read it, and the rule takes the risk of clearing something copied since). In front, it is
 *   cleared only when it still holds this copy: the clip's timestamp is the one recorded at the copy (or, in the same
 *   process, its text is the value), so something the person copied since is left alone.
 * - **The record** is [file] in app-private no-backup storage: the nonce, the clip's timestamp and nothing else. No
 *   secret is written anywhere.
 */
internal object ClipboardClear {
    /** What the timer does when it fires ([decide]). */
    enum class Act { CLEAR_WITHOUT_READING, CLEAR, KEEP }

    /**
     * The rule, pure. [pendingNonce]: the record's nonce now (null: none pending); [inFront]: andvari's process is
     * resumed; [clipTimestamp]: the clip's description timestamp as read in front (null: nothing readable);
     * [valueStillThere]: the clip's text is this copy's value (null: not known in this process).
     */
    fun decide(firedNonce: Long, pendingNonce: Long?, inFront: Boolean, recordedTimestamp: Long, clipTimestamp: Long?, valueStillThere: Boolean?): Act = when {
        pendingNonce != firedNonce -> Act.KEEP // a later copy owns the clear, or it ran already
        !inFront -> Act.CLEAR_WITHOUT_READING
        clipTimestamp == null -> Act.CLEAR_WITHOUT_READING // in front but nothing can be read: nothing to tell apart
        recordedTimestamp != 0L && clipTimestamp == recordedTimestamp -> Act.CLEAR
        valueStillThere == true -> Act.CLEAR
        else -> Act.KEEP // something else is on the clipboard now
    }

    /** The record's text: `nonce:timestamp`. */
    fun encode(nonce: Long, timestamp: Long): String = "$nonce:$timestamp"

    fun decode(text: String?): Pair<Long, Long>? {
        val parts = text?.trim()?.split(':') ?: return null
        if (parts.size != 2) return null
        val n = parts[0].toLongOrNull() ?: return null
        val t = parts[1].toLongOrNull() ?: return null
        return n to t
    }

    private val random = SecureRandom()
    private val handler by lazy { android.os.Handler(android.os.Looper.getMainLooper()) }

    private fun file(ctx: Context) = File(ctx.applicationContext.noBackupFilesDir, "clipboard-clear")

    private fun pending(ctx: Context): Pair<Long, Long>? = decode(runCatching { file(ctx).takeIf { it.isFile }?.readText() }.getOrNull())

    /** The copy [value] was just put on the clipboard: schedule its clear after [clearMs]. */
    fun scheduled(ctx: Context, cm: ClipboardManager, value: String, clearMs: Long) {
        val app = ctx.applicationContext
        val nonce = random.nextLong()
        val timestamp = runCatching { cm.primaryClipDescription?.timestamp }.getOrNull() ?: 0L
        runCatching { file(app).writeText(encode(nonce, timestamp)) }
        handler.postDelayed({ fire(app, nonce, value) }, clearMs)
        runCatching {
            val am = app.getSystemService(AlarmManager::class.java)
            am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + clearMs + ALARM_SLACK_MS, alarm(app, nonce))
        }
    }

    private fun alarm(app: Context, nonce: Long): PendingIntent =
        PendingIntent.getBroadcast(
            app, 0,
            Intent(app, ClipboardClearReceiver::class.java).putExtra(EXTRA_NONCE, nonce),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

    /** A timer fired for [nonce]; [value] is the copy's text when this process still has it. */
    fun fire(ctx: Context, nonce: Long, value: String?) {
        val app = ctx.applicationContext
        val cm = app.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val record = pending(app)
        val inFront = runCatching { ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) }.getOrDefault(false)
        // Read only in front: in the background the clipboard is never read.
        val clipTs = if (inFront) runCatching { cm.primaryClipDescription?.timestamp }.getOrNull() else null
        val stillThere = if (inFront && value != null) runCatching { cm.primaryClip?.getItemAt(0)?.text?.toString() == value }.getOrNull() else null
        when (decide(nonce, record?.first, inFront, record?.second ?: 0L, clipTs, stillThere)) {
            Act.KEEP -> if (record?.first == nonce) done(app, nonce)
            Act.CLEAR, Act.CLEAR_WITHOUT_READING -> {
                runCatching { cm.clearPrimaryClip() }
                done(app, nonce)
            }
        }
    }

    /** The clear for [nonce] ran: its record and its alarm go (a later copy's are left alone). */
    private fun done(app: Context, nonce: Long) {
        if (pending(app)?.first != nonce) return
        runCatching { file(app).delete() }
        runCatching { app.getSystemService(AlarmManager::class.java).cancel(alarm(app, nonce)) }
    }

    const val EXTRA_NONCE = "io.silencelen.andvari.clipboard.nonce"

    /** The alarm is inexact; it lands after the main-thread timer, which normally clears first. */
    private const val ALARM_SLACK_MS = 2_000L
}

/** The alarm's end of [ClipboardClear]: the process may have been ended since the copy, so only the record decides. */
class ClipboardClearReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val nonce = intent.getLongExtra(ClipboardClear.EXTRA_NONCE, 0L)
        if (nonce == 0L) return
        ClipboardClear.fire(context, nonce, null)
    }
}
