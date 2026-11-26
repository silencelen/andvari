package io.silencelen.andvari.app.autofill

import android.content.Context
import android.os.Handler
import android.os.Looper
import io.silencelen.andvari.app.trust.TrustModel
import io.silencelen.andvari.app.trust.TrustSeam
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.content.VaultSyncState
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Where autofill finds the vault on the new code: the app's own session ([TrustSeam]'s one process-wide app API).
 * Autofill fills only while that session is unlocked, or after its unlock activity unlocked it; it never opens a
 * session of its own and holds no token.
 */
internal object ContentFillSession {
    sealed interface Access {
        /** No account on this device (or only the journey before one): no row at all, never a dead-end unlock. */
        data object SignedOut : Access

        /** An account whose vault is locked (or still starting): the unlock row. */
        data object Locked : Access

        class Open(val content: VaultContent) : Access
    }

    /** What [s] allows, as a pure rule (tested): only UNLOCKED with a content instance is open. */
    internal fun accessOf(s: AppSnapshot, content: VaultContent?): Access = when (s.phase) {
        AppPhase.UNLOCKED -> if (content != null) Access.Open(content) else Access.Locked
        // Still reading this device's state (a cold start for a fill): the unlock activity waits for it.
        AppPhase.STARTING -> Access.Locked
        AppPhase.LOCKED -> if (s.locked != null) Access.Locked else Access.SignedOut
        AppPhase.ENTRY -> Access.SignedOut
    }

    /**
     * The access now, after the idle lock had its say: an unlocked vault idle past the policy's window is locked here
     * ([TrustModel.tick]), so a fill never reads a vault the app itself would have locked.
     */
    fun access(context: Context): Access {
        val model = TrustSeam.model(context)
        model.tick()
        // The content through the model, every call contained: a fault in one vault's fill read
        // answers "nothing" and never ends the process the other app's fill runs in.
        return accessOf(model.api.snapshot, model.contentNow())
    }

    /**
     * Waits (bounded) for the content's first sync after an unlock, so a fill right after it offers the vault and not
     * an empty list. An offline vault answers with this device's copy; the bound keeps a slow server from holding the
     * other app's fill.
     */
    suspend fun ready(content: VaultContent, timeoutMs: Long = READY_WAIT_MS) {
        withTimeoutOrNull(timeoutMs) { content.states.first { it.sync != VaultSyncState.NOT_YET } }
    }

    private const val READY_WAIT_MS = 8_000L

    /**
     * The app's own session unlocked from autofill stays open only for the policy's idle window, as the main app's
     * own ticker would keep it: nothing else ticks while the app is in the background, so this re-checks then. The same
     * clock holds for a recovery kit in the journey (its keys are open too): behind the system's print screen, after the
     * person left from there, and the kit an unlock from the autofill window leaves in memory, each locked at the kit's
     * own limit where it has one and at the app's window otherwise ([TrustModel.idleLockDueInMs]).
     */
    object HardLock {
        private const val SLACK_MS = 5_000L
        private val handler = Handler(Looper.getMainLooper())
        private var model: TrustModel? = null

        private val check = object : Runnable {
            override fun run() {
                runCatching {
                    val m = model ?: return@runCatching
                    m.tick()
                    nextCheckInMs(m)?.let { handler.postDelayed(this, it) }
                }
            }
        }

        /** (Re)arm after an autofill unlock or serve, or an excursion; one pending check at a time. */
        fun arm(context: Context) {
            runCatching {
                val m = TrustSeam.model(context)
                model = m
                handler.removeCallbacks(check)
                nextCheckInMs(m)?.let { handler.postDelayed(check, it) }
            }
        }

        internal fun nextCheckInMs(m: TrustModel): Long? = hardLockWaitMs(m, SLACK_MS)
    }

    /**
     * When the hard lock's next check is due: [slackMs] after the idle lock is, or null where nothing is under the lock
     * clock; never later than [HARD_LOCK_MAX_WAIT_MS]. The handler's wait stands still while the phone sleeps, but the
     * model's clock counts sleeping time (elapsed realtime), so a lock that fell due during sleep is made at most that
     * long after the phone wakes. Outside [HardLock], whose handler cannot be made on the JVM, so the tests reach it.
     */
    internal fun hardLockWaitMs(m: TrustModel, slackMs: Long): Long? = m.idleLockDueInMs()?.let { minOf(it + slackMs, HARD_LOCK_MAX_WAIT_MS) }

    /** The longest wait between two of the hard lock's checks, in the phone's awake time. */
    internal const val HARD_LOCK_MAX_WAIT_MS = 10_000L
}
