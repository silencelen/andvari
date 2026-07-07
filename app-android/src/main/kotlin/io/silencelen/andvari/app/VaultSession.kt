package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.SyncEngine
import kotlinx.coroutines.sync.Mutex

/**
 * Process-wide holder for the unlocked vault (`AndvariApi`/`Account`/`SyncEngine`), shared
 * by the [AndvariViewModel] (main dispatcher) and the autofill service/unlock activity
 * (background). Keys are memory-only; [lock] drops everything. Nothing is persisted here.
 *
 * Thread-safety (binding requirement): [get] hands out an immutable snapshot — the
 * [Unlocked] reference itself — so a concurrent [lock] can only make a mid-flight fill
 * read slightly stale (it reads the in-memory decrypted set from the thread-safe
 * SqliteVaultCache, which survives its own `close()`), never NPE. [bind]/[lock] are
 * @Synchronized and close the previously-bound engine + api.
 *
 * Single token-holder invariant: exactly one token-carrying [AndvariApi] exists at a time
 * (the one inside the live [Unlocked]). Every api that carries tokens MUST persist
 * rotations via `SessionStore.updateTokens`; [bind] closing the previous api guarantees a
 * superseded holder cannot later reuse a consumed refresh token and revoke the device.
 */
object VaultSession {
    class Unlocked(val api: AndvariApi, val account: Account, val engine: SyncEngine)

    @Volatile
    private var state: Unlocked? = null

    /**
     * Serializes the two unlock entry points (main-app unlock + autofill unlock). Both reuse
     * the SAME persisted refresh token; a concurrent refresh would consume it twice and trip
     * the server's reuse-detection → whole-device revocation. Holders acquire this around
     * "build api → accountKeys/refresh → bind" and re-check [get] inside so the loser reuses
     * the winner's session instead of minting a second token-holder.
     */
    val unlockMutex = Mutex()

    /** Bind a freshly-unlocked session, closing any previously-bound engine/api. */
    @Synchronized
    fun bind(api: AndvariApi, account: Account, engine: SyncEngine) {
        val prev = state
        state = Unlocked(api, account, engine)
        prev?.let {
            if (it.engine !== engine) runCatching { it.engine.close() }
            if (it.api !== api) runCatching { it.api.close() } // never close a reused token-holder
        }
    }

    /** Immutable snapshot of the current unlocked session, or null when locked. */
    fun get(): Unlocked? = state

    /** Lock: close the engine (releasing its cache DB handle) then the api, and clear. */
    @Synchronized
    fun lock() {
        val prev = state
        state = null
        prev?.let {
            runCatching { it.engine.close() }
            runCatching { it.api.close() }
        }
    }
}
