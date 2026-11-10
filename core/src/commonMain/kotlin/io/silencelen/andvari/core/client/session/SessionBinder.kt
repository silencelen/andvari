package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.model.AccountKeys

/**
 * What every way into a session shares once an account is open: the engine and its cache for the origin's
 * policy, the bind itself, the offline copy of the account keys and the full-password stamp. Sign-in, enroll,
 * password unlock and quick unlock all bind through here, so the cache rules cannot drift between them.
 */
class SessionBinder(
    private val store: SessionPersistence,
    private val session: VaultSession,
    private val coordinator: PolicyCoordinator,
    private val namespaces: NamespaceStorage,
    private val clocks: Clocks,
) {
    /**
     * Bind [account] with [api] in [originKey]'s namespace. The cache is durable unless that origin's policy
     * forbids it, and is hydrated before the first sync so a cold or offline start shows data. A forbidding
     * policy then purges the namespace, after the bind so an engine this one replaced has released the file.
     *
     * When the cache open or the hydrate throws (a corrupt cache file), the cache is closed and nothing is
     * bound: [api] and [account] are still the caller's.
     */
    fun bind(api: AndvariApi, account: Account, originKey: String, provenance: VaultSession.UnlockProvenance): VaultSession.Unlocked {
        // Prefer the live policy; fall back to the persisted last-known value when offline (a policy-forbidden
        // device cold-starting offline must NOT recreate the cache).
        val allowed = coordinator.cacheAllowed(originKey)
        var cache: VaultCache? = null
        val engine = try {
            cache = if (allowed) namespaces.openVaultCache(originKey, account.userId) else InMemoryVaultCache()
            // A5b (M-1): the personal wrap this device authenticated lives OUTSIDE the cache (which may be in
            // memory, or purged), so a withheld wrap stays an anomaly across restarts.
            SyncEngine(api, account, cache, deviceState = namespaces.deviceState(originKey, account.userId)).also { it.hydrate() }
        } catch (t: Throwable) {
            runCatching { cache?.close() }
            throw t
        }
        // Root cause A §8.5 (A5): once the migration stores the personal wrap, carry it into the cached account
        // keys so an offline cold start knows the personal vault without the network.
        engine.onPersonalWrapStored = { w ->
            store.origin(originKey).loadAccountKeys(account.userId)?.let { persistAccountKeys(originKey, account.userId, it.copy(personalWrap = w)) }
        }
        // The session closes any engine and api it held before (never two connections).
        session.bind(api, account, engine, provenance)
        // Spec 02 §8 / spec 01 §8.1: a forbidding verdict takes the quick-unlock secret, not only the file.
        if (!allowed) coordinator.purgeForbidden(originKey, account.userId)
        return session.get()?.takeIf { it.api === api } ?: VaultSession.Unlocked(api, account, engine, provenance)
    }

    /** Keep [keys] for offline unlock only while [originKey]'s policy permits a durable cache (spec 02 §8). */
    fun persistAccountKeys(originKey: String, userId: String, keys: AccountKeys) {
        val origin = store.origin(originKey)
        if (coordinator.cacheAllowed(originKey)) origin.saveAccountKeys(userId, keys) else origin.clearAccountKeys(userId)
    }

    /**
     * A1: record a real full-password unlock of [userId] at [originKey]: the wall time, the A2 monotonic anchors
     * and the boot identity, and advance the high-water clock. Every full-password unlock stamps, an offline
     * one included; a quick unlock never does.
     */
    fun stampPasswordUnlock(originKey: String, userId: String) {
        val now = clocks.wallMs()
        val elapsed = clocks.monotonicMs()
        store.bumpHighWater(now)
        store.origin(originKey).setPasswordStamp(userId, PasswordStamp(now, elapsed, now - elapsed, clocks.bootId()))
    }
}
