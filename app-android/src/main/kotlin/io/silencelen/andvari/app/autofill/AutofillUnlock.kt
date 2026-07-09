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
            VaultSession.getIfFresh()?.let { return@withLock it }
            unlockLocked(context.applicationContext, store, session, password)
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

        val cache = if (store.cacheAllowed) {
            sqliteVaultCache(File(appContext.noBackupFilesDir, "vault-${acct.userId}.db").absolutePath, acct.userId)
        } else {
            // Policy forbids the durable cache: delete any existing file (spec 02 §8).
            for (s in listOf("", "-wal", "-shm")) File(appContext.noBackupFilesDir, "vault-${acct.userId}.db$s").delete()
            InMemoryVaultCache()
        }
        val engine = SyncEngine(api, acct, cache).also { it.hydrate() }
        VaultSession.bind(api, acct, engine, cache) // now THE token-holder; the main app reuses it
        runCatching { engine.sync() } // best-effort; hydrate already gave cached items
        return VaultSession.get() ?: VaultSession.Unlocked(api, acct, engine, cache)
    }
}
