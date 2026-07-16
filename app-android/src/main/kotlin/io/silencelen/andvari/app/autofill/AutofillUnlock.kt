package io.silencelen.andvari.app.autofill

import android.content.Context
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.silencelen.andvari.app.KdfReKey
import io.silencelen.andvari.app.OfflineData
import io.silencelen.andvari.app.OriginNamespace
import io.silencelen.andvari.app.Session
import io.silencelen.andvari.app.SessionStore
import io.silencelen.andvari.app.VaultSession
import io.silencelen.andvari.app.clampAutoLockSeconds
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.sqliteVaultCache
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
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

    /** Detached scope for the A6 KDF re-key: it must OUTLIVE the noHistory activity that finishes
     *  the moment the FillResponse is delivered. Best-effort — if the process dies first, the
     *  upgrade simply retries at the next online full-password unlock (design §4 step 4). */
    private val bgScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    suspend fun unlock(context: Context, store: SessionStore, session: Session, password: String): VaultSession.Unlocked =
        VaultSession.unlockMutex.withLock {
            // Inside the lock: reuse the winner's session if the main app (or a prior fill/save)
            // unlocked while we waited — never mint a second token-holder that reuses the now-consumed
            // refresh token (→ device revocation). getIfFresh drops an idle-expired winner (its
            // api/token-holder is CLOSED by lock()) instead of adopting it, and we mint the
            // replacement below while still holding the mutex.
            VaultSession.getIfFresh()?.let { AutofillHardLock.arm(); return@withLock it }
            val appContext = context.applicationContext
            val r = unlockLocked(appContext, store, session, VaultSession.UnlockProvenance.PASSWORD) { keys ->
                Account.unlock(session.userId, password, keys)
            }
            // A1: a real master password was verified — stamp the 30-day window (even offline).
            store.stampFullPasswordUnlock(session.userId)
            // A6: F61 KDF upgrade runs DETACHED (never blocks the fill), online + policy known +
            // not a recovery temp password (A5). The password is held for the async derivation.
            if (r.online && r.policy != null && !store.mustChangePassword) {
                val account = r.unlocked.account
                val keys = r.keys
                val policy = r.policy
                bgScope.launch { KdfReKey.maybeUpgrade(r.unlocked.api, store, session.userId, password, keys, policy, account) }
            }
            AutofillHardLock.arm()
            r.unlocked
        }

    /**
     * Quick-unlock sibling (spec 01 §8): unlock from a biometric-recovered UVK. Shares ALL of
     * [unlockLocked]'s scaffolding — the mutex/winner-reuse, single-token-holder invariant, F74
     * throw-path hygiene, cache selection, policy/revocation enforcement. It does NOT stamp the
     * 30-day window and does NOT re-key (A1/§7: a quick unlock has no password). The caller
     * (AutofillUnlockActivity) recovers the UVK behind BiometricPrompt and hands it here; the
     * `Account` keeps the reference, so the caller must not reuse/zero it after.
     */
    suspend fun unlockWithUvk(context: Context, store: SessionStore, session: Session, uvk: ByteArray): VaultSession.Unlocked =
        VaultSession.unlockMutex.withLock {
            VaultSession.getIfFresh()?.let { AutofillHardLock.arm(); return@withLock it }
            unlockLocked(context.applicationContext, store, session, VaultSession.UnlockProvenance.QUICK) { keys ->
                Account.unlockWithUvk(session.userId, uvk, keys)
            }.unlocked.also { AutofillHardLock.arm() }
        }

    /** What [unlockLocked] surfaces so the password path can stamp + drive the F61 re-key without
     *  a second server round-trip. `online` = the accountKeys/policy came from the network (not the
     *  offline cache fallback). */
    private class Locked(
        val unlocked: VaultSession.Unlocked,
        val keys: AccountKeys,
        val policy: ClientPolicy?,
        val online: Boolean,
    )

    private suspend fun unlockLocked(
        appContext: Context,
        store: SessionStore,
        session: Session,
        provenance: VaultSession.UnlockProvenance,
        buildAccount: (AccountKeys) -> Account,
    ): Locked {
        // §4.2: ONE baseUrl read feeds both the api and the namespace key, so the policy verdict
        // below can only ever be enforced against the namespace of the origin it came from.
        val baseUrl = store.baseUrl
        val originKey = OriginNamespace.originKey(baseUrl)
        val api = AndvariApi(baseUrl, HttpClient(OkHttp), session.tokens(), { store.updateTokens(it) }) // platform "android"

        // A4: the autofill process fetches /client-policy on its ONLINE path (cheap, unauthenticated)
        // so an admin's `offlineCacheAllowed` flip reaches this process too, and persists
        // policyFetchedAt for QuickUnlock.isEligible's 7-day staleness gate. A fetch failure = offline.
        // All persisted mirrors are per-origin (§4.2), and the auto-lock window is CLAMPED (B1-1).
        var policy: ClientPolicy? = null
        runCatching { api.clientPolicy() }.onSuccess { p ->
            policy = p
            store.setCacheAllowed(originKey, p.offlineCacheAllowed)
            val autoLock = clampAutoLockSeconds(p.autoLockSeconds) // §2.3: a server can't disable/stretch the lock
            store.setAutoLockSeconds(originKey, autoLock)
            store.setPolicyFetchedAt(originKey, System.currentTimeMillis())
            store.bumpServerTimeFloor(originKey, p.serverTime) // A2 (review [2]): trusted duration anchor, per-origin
            VaultSession.setAutoLockSeconds(autoLock)
            // Policy forbids durable at-rest key material → drop THIS origin's cache + cached
            // keys + quick-unlock blob (spec 01 §8.1 / A4 / §4.2). Session stays valid; other
            // origins' namespaces are untouched.
            if (!p.offlineCacheAllowed) OfflineData.purgeCacheForbidden(appContext.noBackupFilesDir, store, originKey, session.userId)
        }

        var online = false
        val keys = try {
            api.accountKeys().also {
                online = true
                if (store.cacheAllowed) store.saveAccountKeys(it) else store.clearAccountKeys()
            }
        } catch (e: ApiException) {
            // A3: a definitive 401 (survived the api's own refresh) means this device is revoked —
            // purge the session + THIS origin's namespace (cache + keys + quick-unlock blob +
            // store.clear()) so a stolen, overlay-only device can no longer open the cached
            // vault. Then rethrow.
            if (e.status == 401) OfflineData.purgeRevoked(appContext.noBackupFilesDir, store, originKey, session.userId)
            api.close(); throw e
        } catch (e: IOException) {
            // Offline: fall back to the cached accountKeys (spec 02 §8).
            store.loadAccountKeys() ?: run { api.close(); throw e }
        } catch (t: Throwable) {
            api.close(); throw t
        }
        val acct = try {
            buildAccount(keys)
        } catch (t: Throwable) {
            api.close(); throw t // wrong password / stale-or-foreign UVK / identity mismatch — never leave the holder open
        }

        // F74 (review [1]): cache open + hydrate do raw sqlite reads — a corrupt
        // vault-<userId>.db throws HERE, after the token-holder exists. Close the cache (its
        // sqlite handle) and, unless VaultSession already adopted the api, the api too.
        var cache: VaultCache? = null
        val engine = try {
            cache = if (store.cacheAllowed(originKey)) {
                // §4.2 layout: <noBackup>/ns/<originKey>/<userId>/vault-<userId>.db
                val nsDir = OriginNamespace.dir(appContext.noBackupFilesDir, originKey, acct.userId).apply { mkdirs() }
                sqliteVaultCache(File(nsDir, "vault-${OriginNamespace.pathSafe(acct.userId)}.db").absolutePath, acct.userId)
            } else {
                // Policy forbids the durable cache: delete any existing file (spec 02 §8) — scoped.
                OfflineData.deleteVaultCache(appContext.noBackupFilesDir, originKey, acct.userId)
                InMemoryVaultCache()
            }
            SyncEngine(api, acct, cache).also { it.hydrate() }
        } catch (t: Throwable) {
            runCatching { cache?.close() }
            if (VaultSession.get()?.api !== api) api.close()
            throw t
        }
        VaultSession.bind(api, acct, engine, provenance) // now THE token-holder; the main app reuses it
        runCatching { engine.sync() } // best-effort; hydrate already gave cached items
        val unlocked = VaultSession.get() ?: VaultSession.Unlocked(api, acct, engine, provenance)
        return Locked(unlocked, keys, policy, online)
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
