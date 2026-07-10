package io.silencelen.andvari.app.autofill

import android.content.Context
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.silencelen.andvari.app.Session
import io.silencelen.andvari.app.SessionStore
import io.silencelen.andvari.app.VaultSession
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.sqliteVaultCache
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.io.IOException

/**
 * The single, security-critical unlock used by BOTH autofill entry activities (fill:
 * [AutofillUnlockActivity]; save: [SaveConfirmActivity]) so the single-token-holder invariant has
 * exactly one implementation and can't drift between them.
 *
 * Single token-holder invariant (binding blocker): the api is built EXACTLY like
 * AndvariViewModel.newApi — an HttpClient engine AND the SessionStore.updateTokens persistence
 * callback — and bound into [VaultSession] so the main app reuses the SAME token-holder. Building a
 * token-carrying api without the onTokens callback would rotate the refresh token in memory only;
 * the next main-app unlock would reuse the consumed token and revoke the whole device. Under the
 * unlock mutex we reuse any already-fresh session (a race with the main app / a prior fill) instead
 * of minting a second holder. The password is used only inside this call and never stored.
 */
object AutofillUnlock {

    suspend fun unlock(context: Context, store: SessionStore, session: Session, password: String): VaultSession.Unlocked =
        VaultSession.unlockMutex.withLock {
            // Inside the lock: reuse the winner's session if the main app (or a prior fill/save)
            // unlocked while we waited — never mint a second token-holder that reuses the now-consumed
            // refresh token (→ device revocation). getIfFresh drops an idle-expired winner (its
            // api/token-holder is CLOSED by lock()) instead of adopting it, and we mint the
            // replacement below while still holding the mutex.
            VaultSession.getIfFresh()?.let { AutofillHardLock.arm(); return@withLock it }
            unlockLocked(context.applicationContext, store, session, password).also { AutofillHardLock.arm() }
        }

    private suspend fun unlockLocked(appContext: Context, store: SessionStore, session: Session, password: String): VaultSession.Unlocked {
        val api = AndvariApi(store.baseUrl, HttpClient(OkHttp), session.tokens(), { store.updateTokens(it) }) // platform "android"
        val keys = try {
            api.accountKeys().also { if (store.cacheAllowed) store.saveAccountKeys(it) else store.clearAccountKeys() }
        } catch (e: IOException) {
            // Offline: fall back to the cached accountKeys (spec 02 §8).
            store.loadAccountKeys() ?: run { api.close(); throw e }
        } catch (t: Throwable) {
            api.close(); throw t // definitive auth failure (401 already tried a token refresh inside the api)
        }
        val acct = try {
            Account.unlock(session.userId, password, keys)
        } catch (t: Throwable) {
            api.close(); throw t // wrong password etc. — never leave the token-holder open unbound
        }

        // F74 (review [1]): cache open + hydrate do raw sqlite reads — a corrupt
        // vault-<userId>.db throws HERE, after the token-holder exists. Close the cache (its
        // sqlite handle) and, unless VaultSession already adopted the api, the api too.
        var cache: VaultCache? = null
        val engine = try {
            cache = if (store.cacheAllowed) {
                sqliteVaultCache(File(appContext.noBackupFilesDir, "vault-${acct.userId}.db").absolutePath, acct.userId)
            } else {
                // Policy forbids the durable cache: delete any existing file (spec 02 §8).
                for (s in listOf("", "-wal", "-shm")) File(appContext.noBackupFilesDir, "vault-${acct.userId}.db$s").delete()
                InMemoryVaultCache()
            }
            SyncEngine(api, acct, cache).also { it.hydrate() }
        } catch (t: Throwable) {
            runCatching { cache?.close() }
            if (VaultSession.get()?.api !== api) api.close()
            throw t
        }
        VaultSession.bind(api, acct, engine, cache!!) // now THE token-holder; the main app reuses it
        runCatching { engine.sync() } // best-effort; hydrate already gave cached items
        return VaultSession.get() ?: VaultSession.Unlocked(api, acct, engine, cache)
    }
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
