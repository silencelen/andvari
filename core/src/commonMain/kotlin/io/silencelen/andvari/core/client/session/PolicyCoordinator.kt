package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.OriginProbeFence
import io.silencelen.andvari.core.model.ClientPolicy

/**
 * The durable per-(origin, user) artifacts a purge destroys outside [SessionPersistence]: the
 * vault cache and the quick-unlock secret. Both are idempotent and never throw, because they run
 * on fail-closed paths where a throw would leave the rest of the purge undone.
 */
interface OfflineArtifacts {
    /** Delete the durable vault cache (database and sidecars) of one (origin, user). */
    fun deleteVaultCache(originKey: String, userId: String)

    /** Destroy the quick-unlock secret of one (origin, user): the wrapped blob and its key. */
    fun wipeQuickUnlock(originKey: String, userId: String)
}

/**
 * The server-policy half of the session layer, in one place so the rules exist once: the bounded
 * policy fetch, the probe fence, the per-origin mirrors, and the purges (spec 01 §8.1, spec 02 §8).
 *
 * §4.2 (design 2026-07-15, breaker B2-3 — security-load-bearing): every purge takes an EXPLICIT
 * origin key and destroys ONLY that (origin, user) namespace. Callers pass the key of the origin
 * whose verdict they are enforcing — for a policy probe, the origin that was PROBED, captured
 * beside the probe before any await. Before this, the purges were origin-blind and global:
 * merely probing a server whose policy said `offlineCacheAllowed=false` destroyed the home
 * server's offline data and account keys.
 *
 * A purge leaves two things alone by design: the self-identity pins and the device's personal-wrap
 * memory (spec 01 §5). They are public or UVK-sealed, and a device that forgot them would treat a
 * forged recovery or a withheld wrap as a fresh device.
 */
class PolicyCoordinator(
    private val store: SessionPersistence,
    private val artifacts: OfflineArtifacts,
    private val session: VaultSession,
    private val clocks: Clocks,
    private val fence: OriginProbeFence = OriginProbeFence(),
    private val onSessionRejected: () -> Unit = {},
) {
    /** A12 (row 80): one policy fetch under a whole-call bound (a timeout reads as unreachable). */
    suspend fun boundedPolicy(probe: AndvariApi, timeoutMs: Long = POLICY_PROBE_TIMEOUT_MS): ClientPolicy =
        runBounded(timeoutMs) { probe.clientPolicy() }

    /** A12 (row 80): the probe tagged at launch is still the current origin's current visit. */
    fun probeIsCurrent(tag: OriginProbeFence.Tag): Boolean {
        val key = store.baseUrl?.let(OriginCanon::originKey) ?: return false
        return fence.isCurrent(tag, key)
    }

    /**
     * Security review 2026-10 (A12, row 80): every policy reply must belong to the origin the app
     * dials NOW and to the visit it was started in, or a late reply from an abandoned origin lands
     * in the live auto-lock window. Returns false (and writes NOTHING) when [tag] is stale; true
     * means [p] is this client's current policy.
     */
    fun applyPolicy(p: ClientPolicy, tag: OriginProbeFence.Tag): Boolean {
        if (!probeIsCurrent(tag)) return false
        recordPolicy(tag.originKey, p)
        return true
    }

    /**
     * Record a freshly-fetched policy everywhere it is enforced: the per-origin mirrors (the
     * offline fallbacks) and the live auto-lock window. [originKey] is REQUIRED (§4.2): the mirrors
     * are per-origin, and every caller captures the key of the origin it probed beside the probe
     * itself. The window is CLAMPED (§2.3/B1-1) before it is persisted or armed, so a hostile
     * server can neither disable nor stretch the auto-lock.
     */
    fun recordPolicy(originKey: String, p: ClientPolicy) {
        val origin = store.origin(originKey)
        origin.cacheAllowed = p.offlineCacheAllowed
        val autoLock = clampAutoLockSeconds(p.autoLockSeconds) // B1-1: [floor, AUTO_LOCK_MAX_SECONDS]
        origin.autoLockSeconds = autoLock
        origin.policyFetchedAt = clocks.wallMs() // A4: quick-unlock eligibility freshness
        origin.bumpServerTimeFloor(p.serverTime) // A2 (review [2]): the one clock the holder cannot set — per-origin
        session.setAutoLockSeconds(autoLock)
    }

    /**
     * Enforce `offlineCacheAllowed=false` DECLARED BY [originKey]'s server: drop that namespace's
     * vault cache, cached account keys, and quick-unlock secret and its stamp (spec 02 §8, spec 01
     * §8.1) — but KEEP the session (its tokens are still valid; this is not a revocation), and
     * leave other origins' namespaces untouched (§4.2).
     *
     * The verdict is re-evaluated on every successful policy fetch, including the poll of a
     * session that is already unlocked. A live engine has the cache open, so the file goes as
     * soon as that engine closes ([VaultSession.runWhenEngineCloses]) rather than under it; the
     * key material goes now. The file's deletion reads the origin's mirror again when it runs, so
     * a later fetch that allows the cache wins over this verdict. A bind that finds the verdict in
     * the mirror purges the same way, after the bind.
     */
    fun purgeForbidden(originKey: String, userId: String) {
        val origin = store.origin(originKey)
        origin.clearAccountKeys(userId)
        artifacts.wipeQuickUnlock(originKey, userId)
        origin.clearPasswordStamp(userId)
        session.runWhenEngineCloses(originKey, userId) {
            if (!store.origin(originKey).cacheAllowed) artifacts.deleteVaultCache(originKey, userId)
        }
    }

    /**
     * A definitive server rejection (device revoked; an invalid-session 401 that survives a refresh)
     * FROM [originKey]'s server: everything [purgeForbidden] removes, plus the stored session
     * (spec 02 §8, spec 01 §8.1). The session is over, so a live engine closes first and its cache
     * file goes with it, here rather than at a later lock. [originKey] is the origin whose verdict
     * this is, and only its namespace is touched (§4.2).
     */
    fun purgeRevoked(originKey: String, userId: String) {
        if (session.holds(originKey, userId)) session.lock() // the engine releases its DB before we delete it
        artifacts.deleteVaultCache(originKey, userId)
        val origin = store.origin(originKey)
        origin.clearAccountKeys(userId)
        artifacts.wipeQuickUnlock(originKey, userId)
        origin.clearPasswordStamp(userId)
        store.clear() // session identity/tokens/F58 (global) and the current origin's per-session flags
    }

    /**
     * A refresh the server refused with a definitive verdict (a 401 from the refresh endpoint),
     * reported by [AndvariApi] before it drops the tokens. Only a refusal on the LIVE token-holder
     * ends the session here: a refused refresh on any other client (an unlock still in progress,
     * or a superseded holder) is that client's own business, and the unlock paths handle their
     * own 401 where their account context is in scope. The session records the rejection
     * ([VaultSession.markRejected]) for whichever UI layer is showing it, and [onSessionRejected]
     * runs after the purge so this coordinator's own UI layer can look at once.
     */
    fun onRefreshRefused(api: AndvariApi) {
        val live = session.get() ?: return
        if (live.api !== api) return
        purgeRevoked(OriginCanon.originKey(api.baseUrl), live.account.userId)
        session.markRejected()
        onSessionRejected()
    }
}
