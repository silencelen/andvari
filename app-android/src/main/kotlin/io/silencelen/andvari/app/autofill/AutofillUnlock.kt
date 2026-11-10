package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.core.client.session.*
import android.content.Context
import androidx.fragment.app.FragmentActivity
import io.silencelen.andvari.app.ActivityHost
import io.silencelen.andvari.app.AndroidClocks
import io.silencelen.andvari.app.AndroidHttpClients
import io.silencelen.andvari.app.AndroidNamespaceStorage
import io.silencelen.andvari.app.AndroidOfflineArtifacts
import io.silencelen.andvari.app.AndroidQuickUnlockKeys
import io.silencelen.andvari.app.KdfReKey
import io.silencelen.andvari.app.Session
import io.silencelen.andvari.app.SessionStore
import io.silencelen.andvari.app.VaultSession
import io.silencelen.andvari.core.client.ApiException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * The single, security-critical unlock used by BOTH autofill entry activities (fill:
 * [AutofillUnlockActivity]; save: [SaveConfirmActivity]): core's one unlock ladder ([UnlockLadder]), which the
 * main app climbs too, so the single-token-holder invariant has exactly one implementation.
 *
 * Single token-holder invariant (binding blocker): the api is built by [SessionClients] exactly as the main
 * app's are — the platform HTTP client AND the token persistence callback, bound to the session it was built
 * for — and bound into [VaultSession] so the main app reuses the SAME token-holder. Under the unlock mutex the
 * ladder reuses an already-fresh session (a race with the main app / a prior fill) instead of minting a second
 * holder. The password is used only inside this call and never stored.
 *
 * This process may have no main screen: it has no idle ticker (so it adopts only a FRESH winner) and no policy
 * read of its own (so the ladder reads the policy itself, A4).
 */
object AutofillUnlock {

    /** Detached scope for the A6 KDF re-key: it must OUTLIVE the noHistory activity that finishes
     *  the moment the FillResponse is delivered. Best-effort — if the process dies first, the
     *  upgrade simply retries at the next online full-password unlock (design §4 step 4). */
    private val bgScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** No idle ticker here, and no other policy read: adopt only a fresh winner, and read the policy (A4). */
    private val overlay = UnlockOptions(refreshPolicy = true, adoptOnlyFresh = true)

    /**
     * The ladder this overlay climbs. The same policy and purge rules as the main app, under its own fence-less
     * coordinator; its token callback writes only into the session it was built from, and only while that
     * session still holds the token it started from (the main app may have rotated it since).
     */
    private fun ladder(appContext: Context, store: SessionStore): UnlockLadder {
        val dir = appContext.noBackupFilesDir
        val coordinator = PolicyCoordinator(store, AndroidOfflineArtifacts(dir), VaultSession, AndroidClocks)
        val clients = SessionClients(AndroidHttpClients, store, coordinator)
        val binder = SessionBinder(store, VaultSession, coordinator, AndroidNamespaceStorage(dir), AndroidClocks)
        return UnlockLadder(store, VaultSession, coordinator, clients, binder, AndroidQuickUnlockKeys(appContext, dir), AndroidClocks)
    }

    /** The quick-unlock gates the ladder enforces, for the overlay's offer and its auto-prompt (gap 6: one view). */
    fun quickStatus(context: Context, store: SessionStore, userId: String): QuickStatus =
        ladder(context.applicationContext, store).quickStatus(userId)

    suspend fun unlock(context: Context, store: SessionStore, session: Session, password: String): VaultSession.Unlocked {
        val r = ladder(context.applicationContext, store).unlockWithPassword(session, password, overlay)
        // A1: the ladder stamped the 30-day window (even offline). A6: F61 KDF upgrade runs DETACHED (never blocks
        // the fill), online + policy known + not a recovery temp password (A5). The password is held for the
        // async derivation.
        val policy = (r as? UnlockResult.Unlocked)?.policy
        if (r is UnlockResult.Unlocked && r.online && policy != null && !store.mustChangePassword) {
            val unlocked = r.unlocked
            val keys = r.keys
            bgScope.launch { KdfReKey.maybeUpgrade(unlocked.api, store, session.userId, password, keys, policy, unlocked.account) }
        }
        return landed(r)
    }

    /** What the overlay's quick unlock came to, short of a failure (which throws, as [unlock] does). */
    sealed interface Quick {
        class Unlocked(val unlocked: VaultSession.Unlocked) : Quick

        /** The password card stays; [message], if any, says why the biometric did not open the vault. */
        class Stay(val message: String?) : Quick
    }

    /**
     * Quick-unlock sibling (spec 01 §8): the ladder checks the gates, shows the prompt over [activity] and
     * unlocks from the recovered UVK, with all of [unlock]'s scaffolding — the mutex and winner reuse, the
     * single-token-holder invariant, F74 throw-path hygiene, cache selection, policy and revocation
     * enforcement. It does NOT stamp the 30-day window and does NOT re-key (A1/§7: a quick unlock has no
     * password). [onKey] runs once the prompt released the key, before any server call. The UVK never
     * leaves the ladder: an account takes it, or it is zeroed.
     */
    suspend fun unlockWithQuick(activity: FragmentActivity, store: SessionStore, session: Session, onKey: () -> Unit): Quick =
        when (val r = ladder(activity.applicationContext, store).unlockWithQuick(session, ActivityHost(activity), UnlockOptions(refreshPolicy = true, adoptOnlyFresh = true, onQuickKey = onKey))) {
            is UnlockResult.QuickUnavailable -> Quick.Stay(null)
            is UnlockResult.QuickFallback -> Quick.Stay(r.reason)
            is UnlockResult.QuickWiped -> Quick.Stay(r.reason)
            else -> Quick.Unlocked(landed(r))
        }

    /** The session to fill from, or the throw the overlay maps to its copy. */
    private fun landed(r: UnlockResult): VaultSession.Unlocked = when (r) {
        is UnlockResult.Adopted -> r.unlocked
        is UnlockResult.Unlocked -> r.unlocked
        // Review round 2: a definitive rejection during the first sync ended the session (the coordinator
        // purged it). Never hand a dead session to the fill: the overlay says to open andvari.
        UnlockResult.EndedBeforeLanding -> throw ApiException(401, "session_ended", "the session ended during its first sync")
        // A14 (F8): a stored session's tokens go only to its own origin.
        is UnlockResult.Elsewhere -> throw IllegalStateException(sessionElsewhere(r.sessionOrigin))
        is UnlockResult.Revoked -> throw r.cause // A3: the ladder purged this origin's namespace
        is UnlockResult.Failed -> throw r.cause
        is UnlockResult.QuickUnavailable, is UnlockResult.QuickFallback, is UnlockResult.QuickWiped -> error("not a landing")
    }.also { AutofillHardLock.arm() }
}

/**
 * F12: hygiene hard-lock for the autofill-only process. The main app's ViewModel runs a
 * 1 s idle ticker, but a process where ONLY the autofill service/activities ever ran has
 * no ticker — nothing OBSERVED idle expiry, so an unlocked [VaultSession] kept its keys in
 * RAM indefinitely after the fill that created it (the serve-gate still refused to USE
 * them, spec 01 §8; the keys just lingered). This is the missing observer: a single
 * delayed main-thread check at autoLockMs + slack that calls [VaultSession.getIfFresh] —
 * the exact gate every entry point already trusts — so:
 *  - expired + no op in flight → getIfFresh() hard-locks (keys dropped), done;
 *  - op in flight ([VaultSession.setOperationInProgress]) or touched since arming →
 *    getIfFresh defers/passes, and we re-arm for the REMAINING window (never lock
 *    mid-fill/mid-save);
 *  - autoLockSeconds == 0 (lock disabled) → never armed, no-op.
 * Value-blind + never-crash rails: every entry is runCatching-wrapped, logs nothing, and
 * a failure only means the hygiene lock didn't fire (the serve-gate still holds). In the
 * MAIN app process it's harmless redundancy — the ViewModel's ticker locks sooner.
 */
internal object AutofillHardLock {
    /** Past-the-window grace so the check lands strictly AFTER expiry, never a hair early. */
    private const val SLACK_MS = 5_000L

    private val handler = android.os.Handler(android.os.Looper.getMainLooper())

    private val check = object : Runnable {
        override fun run() {
            runCatching {
                // Enforces expiry itself: locks + returns null when stale (respecting the
                // in-flight-op deferral). Null = locked (by us or already) — done.
                VaultSession.getIfFresh() ?: return@runCatching
                // Still unlocked: touched since arming, or the lock was deferred mid-op.
                // Re-check when the CURRENT idle window would elapse.
                val windowMs = VaultSession.autoLockMillis()
                if (windowMs <= 0) return@runCatching // policy changed to disabled — stand down
                val remainingMs = (windowMs - VaultSession.idleSeconds() * 1000L).coerceAtLeast(0L)
                handler.postDelayed(this, remainingMs + SLACK_MS)
            }
        }
    }

    /** (Re)arm after any autofill-path unlock or serve. One pending check at a time —
     *  re-arming supersedes the previous schedule. Cheap enough to call per fill. */
    fun arm() {
        runCatching {
            handler.removeCallbacks(check)
            val windowMs = VaultSession.autoLockMillis()
            if (windowMs <= 0L || VaultSession.get() == null) return@runCatching // disabled, or nothing to lock
            handler.postDelayed(check, windowMs + SLACK_MS)
        }
    }
}
