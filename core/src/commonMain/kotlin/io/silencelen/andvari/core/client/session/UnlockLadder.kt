package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import kotlinx.coroutines.CancellationException
import kotlinx.io.IOException

/** What one unlock of a stored session came to (spec 01 §8, §8.1). */
sealed interface UnlockResult {
    /** A14 (F8): the stored session belongs to another origin than the one the client dials. Nothing was sent. */
    data class Elsewhere(val sessionOrigin: String) : UnlockResult

    /** Another unlock bound a session while this one waited: that session is the one to use, and this one built nothing. */
    data class Adopted(val unlocked: VaultSession.Unlocked) : UnlockResult

    /**
     * Bound, and the first sync ran. [keys] are the account keys it opened; [online] says they came from the
     * server rather than the offline copy; [policy] is the policy this unlock read itself
     * ([UnlockOptions.refreshPolicy]), if it did.
     */
    data class Unlocked(
        val unlocked: VaultSession.Unlocked,
        val keys: AccountKeys,
        val online: Boolean,
        val policy: ClientPolicy?,
        val firstSync: FirstSync,
    ) : UnlockResult

    /** Bound, but the session ended during its first sync (a definitive rejection, most likely). There is nothing to land on. */
    data object EndedBeforeLanding : UnlockResult

    /**
     * The stored session ended, or became another account's or another origin's, while this unlock waited for the
     * mutex. Nothing was sent; land where the stored state says now (an unlock of it, or the sign-in surface).
     */
    data object SessionChanged : UnlockResult

    /** The server refused the stored session (a 401 that survived the refresh): this origin's namespace was purged and the session is gone. */
    data class Revoked(val cause: ApiException) : UnlockResult

    /** Quick unlock only (survey gap 6): a gate refused it before any prompt. */
    data class QuickUnavailable(val gate: QuickGate) : UnlockResult

    /** Quick unlock only: the prompt was cancelled, declined or locked out. The enrollment is kept. */
    data class QuickFallback(val reason: String?) : UnlockResult

    /** Quick unlock only: a wipe-class failure at the prompt. The enrollment is gone. */
    data class QuickWiped(val reason: String) : UnlockResult

    /**
     * Anything else: a wrong password, offline with no cached keys, a 426, a refusal, a damaged cache. Nothing
     * is bound, and whatever was built was closed and zeroed. When a quick-unlock key did not open the account
     * (stale or foreign), its enrollment was wiped too.
     */
    data class Failed(val cause: Throwable) : UnlockResult
}

/** What turning quick unlock on came to (spec 01 §8.1). */
sealed interface QuickEnrollResult {
    data object Enabled : QuickEnrollResult

    /** The prompt was cancelled: nothing was wrapped. */
    data object Cancelled : QuickEnrollResult

    /** No unlocked session: the key to wrap is not in memory. */
    data object NoSession : QuickEnrollResult

    /** A5: a recovery temporary password is the live credential; it must be changed first. */
    data object MustChangePassword : QuickEnrollResult

    /** A1: a quick-unlocked session with no surviving full-password stamp: unlock with the password first. */
    data object NeedsPasswordUnlock : QuickEnrollResult

    /** The policy, its age or the device's biometrics rule it out. */
    data class Unavailable(val gate: QuickGate) : QuickEnrollResult

    /** The platform wrapped nothing; [reason] says why, when it can. */
    data class Failed(val reason: String?) : QuickEnrollResult
}

/** How one entry point climbs the ladder. The defaults are the main app's. */
class UnlockOptions(
    /**
     * Read this origin's policy under the mutex first and write its mirrors (A4): for an entry point that has
     * no policy read of its own (the Android autofill overlay). A failed read counts as offline.
     */
    val refreshPolicy: Boolean = false,
    /**
     * Adopt only a session still inside its idle window, and lock a stale one and replace it ([VaultSession.getIfFresh]):
     * for an entry point with no idle ticker of its own.
     */
    val adoptOnlyFresh: Boolean = false,
    /** The first sync after the bind. A client that records more around a sync (last-sync time, the usage ledger) passes its own. */
    val firstSync: suspend (SyncEngine) -> Unit = { it.sync() },
    /** Quick unlock: called once the prompt released the key, before any server call (a UI shows its busy state from here). */
    val onQuickKey: () -> Unit = {},
)

/**
 * The one unlock ladder of a stored session (survey step 6), shared by every entry point: on Android the main
 * app's password and biometric unlocks and the autofill overlay's. Each rung is the same for all of them:
 * the origin check, the unlock mutex and adopting a winner, the bounded key fetch with its offline fallback,
 * the purge on a definitive rejection, the open, the bind, the stamp, and the first sync outside the mutex.
 *
 * Survey gap 6: the quick-unlock gates are checked here, before any prompt, not only by the UI that offers
 * the button ([quickStatus] is the same view for both). Survey gap 7: a recovered UVK is zeroed on every path
 * where no account took it, and an account built but never bound is wiped.
 */
class UnlockLadder(
    private val store: SessionPersistence,
    private val session: VaultSession,
    private val coordinator: PolicyCoordinator,
    private val clients: SessionClients,
    private val binder: SessionBinder,
    private val quickKeys: QuickUnlockKeys,
    private val clocks: Clocks,
) {
    /**
     * The quick-unlock gates for [userId] at the origin the client dials (spec 01 §8.1): the policy permits a
     * durable unlock secret and was seen within 7 days (A4), a strong biometric is usable, a key is wrapped, and
     * the last full-password unlock is recent enough (A1/A2). Reading it advances the high-water clock, as every
     * freshness check does.
     */
    fun quickStatus(userId: String?): QuickStatus {
        val originKey = store.baseUrl?.let(OriginCanon::originKey)
        val origin = originKey?.let(store::origin)
        val permits = origin != null && QuickUnlockRules.policyPermits(origin.cacheAllowed, origin.policyFetchedAt, clocks.wallMs())
        val eligible = permits && quickKeys.hasStrongBiometric()
        val enrolled = originKey != null && userId != null && quickKeys.isEnrolled(originKey, userId)
        val fresh = enrolled && isFresh(originKey, userId)
        val refusal = when {
            !permits -> QuickGate.POLICY
            !eligible -> QuickGate.NO_BIOMETRIC
            !enrolled -> QuickGate.NOT_ENROLLED
            !fresh -> QuickGate.EXPIRED
            else -> null
        }
        return QuickStatus(eligible, enrolled, fresh, refusal)
    }

    /**
     * Turn quick unlock on for the live session's account: the platform's prompt consents and the UVK is wrapped under
     * its hardware key. Refused under a recovery temporary password (A5), where [quickStatus] says the policy or the
     * device rule it out, and from a quick-unlocked session with no surviving full-password stamp (A1: enrolling would
     * restart the 30-day window with no password typed).
     */
    suspend fun enableQuick(host: BiometricHost): QuickEnrollResult {
        val live = session.get() ?: return QuickEnrollResult.NoSession
        val originKey = store.baseUrl?.let(OriginCanon::originKey) ?: return QuickEnrollResult.NoSession
        val userId = live.account.userId
        if (store.mustChangePassword) return QuickEnrollResult.MustChangePassword
        val status = quickStatus(userId)
        if (!status.eligible) return QuickEnrollResult.Unavailable(status.refusal ?: QuickGate.NO_BIOMETRIC)
        if (live.provenance != VaultSession.UnlockProvenance.PASSWORD && store.origin(originKey).passwordStamp(userId) == null) {
            return QuickEnrollResult.NeedsPasswordUnlock
        }
        return when (val r = quickKeys.enroll(host, originKey, userId, live.account)) {
            QuickEnroll.Ok -> QuickEnrollResult.Enabled
            QuickEnroll.Cancelled -> QuickEnrollResult.Cancelled
            is QuickEnroll.Failed -> QuickEnrollResult.Failed(r.reason)
        }
    }

    /** Unlock [stored] with the master password. Stamps the full-password window (A1). */
    suspend fun unlockWithPassword(stored: StoredSession, password: String, options: UnlockOptions = UnlockOptions()): UnlockResult {
        val dialed = store.baseUrl
        // A14 (F8): a stored session's tokens go only to its own origin. Refuse, never "repair".
        if (dialed == null || !sessionBelongsTo(stored.baseUrl, dialed)) return UnlockResult.Elsewhere(stored.baseUrl)
        val originKey = OriginCanon.originKey(dialed) // §4.2: the server this unlock talks to, and the namespace it opens
        return climb(stored, dialed, originKey, VaultSession.UnlockProvenance.PASSWORD, options) { keys ->
            // The KDF runs off the caller's thread (argon2id at 64 MiB or more: a UI must keep animating), and an account
            // the caller no longer waits for is wiped.
            handOff({ Account.unlock(stored.userId, password, keys, selfIdentityPub = pinFor(originKey, stored)) }, Account::wipe)
        }
    }

    /**
     * Unlock [stored] with the quick-unlock key, behind the platform's biometric prompt over [host]. The same
     * ladder minus the KDF and the stamp (a quick unlock is never a full-password unlock, A1/§7). The
     * identityPub check runs inside [Account.unlockWithUvk]: a mismatch hard-fails.
     */
    suspend fun unlockWithQuick(stored: StoredSession, host: BiometricHost, options: UnlockOptions = UnlockOptions()): UnlockResult {
        val dialed = store.baseUrl
        if (dialed == null || !sessionBelongsTo(stored.baseUrl, dialed)) return UnlockResult.Elsewhere(stored.baseUrl)
        val originKey = OriginCanon.originKey(dialed)
        // Gap 6: the gates hold here, whatever a UI chose to show.
        quickStatus(stored.userId).refusal?.let { return UnlockResult.QuickUnavailable(it) }
        val uvk = when (val r = quickKeys.recover(host, originKey, stored.userId)) {
            is QuickRecover.Ok -> r.uvk
            is QuickRecover.Fallback -> return UnlockResult.QuickFallback(r.reason)
            is QuickRecover.Wiped -> return UnlockResult.QuickWiped(r.reason)
        }
        // Gap 7: the recovered UVK is this call's until an account takes it. Every other way out zeroes it:
        // adopting a winner, an unreachable server, a refusal, a key that does not open the account.
        var taken = false
        try {
            options.onQuickKey()
            return climb(stored, dialed, originKey, VaultSession.UnlockProvenance.QUICK, options) { keys ->
                try {
                    Account.unlockWithUvk(stored.userId, uvk, keys, selfIdentityPub = pinFor(originKey, stored)).also { taken = true }
                } catch (e: CryptoException) {
                    // §5: a seed that will not open under the recovered UVK means a stale or foreign key: wipe it, so
                    // the next attempt goes to the password. An identityPub MISMATCH is a security fault instead:
                    // the enrollment stays as evidence and the unlock hard-fails.
                    if (e.message?.contains("identity key mismatch") != true) quickKeys.wipe(originKey, stored.userId)
                    throw e
                }
            }
        } finally {
            if (!taken) uvk.fill(0)
        }
    }

    private sealed interface Held {
        class Done(val result: UnlockResult) : Held

        class Bound(val unlocked: VaultSession.Unlocked, val keys: AccountKeys, val online: Boolean, val policy: ClientPolicy?) : Held
    }

    private suspend fun climb(
        stored: StoredSession,
        dialed: String,
        originKey: String,
        provenance: VaultSession.UnlockProvenance,
        options: UnlockOptions,
        open: suspend (AccountKeys) -> Account,
    ): UnlockResult {
        // Serialized with every other unlock in the process: they all reuse this session's refresh token, and two
        // concurrent refreshes would consume it twice, which revokes the whole device. H10: the wait is bounded too.
        val held = session.withUnlockMutex { underMutex(stored, dialed, originKey, provenance, options, open) }
        val bound = when (held) {
            is Held.Done -> return held.result
            is Held.Bound -> held
        }
        // H10: the first sync runs outside the mutex, under its own bound; nothing it does keeps the user from landing.
        val first = firstSyncAfterBind { options.firstSync(bound.unlocked.engine) }
        // Review round 2: a definitive rejection during that sync ended the session (the coordinator purged it).
        if (!session.isLive(bound.unlocked.api)) return UnlockResult.EndedBeforeLanding
        return UnlockResult.Unlocked(bound.unlocked, bound.keys, bound.online, bound.policy, first)
    }

    private suspend fun underMutex(
        stored: StoredSession,
        dialed: String,
        originKey: String,
        provenance: VaultSession.UnlockProvenance,
        options: UnlockOptions,
        open: suspend (AccountKeys) -> Account,
    ): Held {
        // Another unlock bound a session while this one waited: adopt it, never mint a second token-holder that
        // reuses the now-consumed refresh token.
        (if (options.adoptOnlyFresh) session.getIfFresh() else session.get())?.let { return Held.Done(UnlockResult.Adopted(it)) }
        // Review 3: the caller read [stored] before the mutex, and an unlock that held it meanwhile may have rotated the
        // refresh token without binding (a wrong password, an overlay the user left): the rotation is stored either way.
        // Presenting the token from before it would be a reuse, which revokes the device. So the client is built from
        // the session as stored now, and only while it is still the caller's: the same account at the same origin.
        val current = store.load()
        if (current == null || current.userId != stored.userId || !sessionBelongsTo(current.baseUrl, stored.baseUrl)) {
            return Held.Done(UnlockResult.SessionChanged)
        }
        val api = clients.forSession(current, dialed)
        var online = false
        var policy: ClientPolicy? = null
        val keys = try {
            if (options.refreshPolicy) policy = refreshPolicy(api, originKey, stored.userId)
            // H10: bounded, since it runs under the mutex; a stall reads as offline and opens on the cached keys.
            runBounded(BoundedOps.FLAT_MS) { api.accountKeys() }.also {
                online = true
                binder.persistAccountKeys(originKey, stored.userId, it)
            }
        } catch (e: IOException) {
            // Offline unlock (spec 02 §8): the keys kept at the last online unlock, if the policy let it keep them.
            store.origin(originKey).loadAccountKeys(stored.userId) ?: run {
                api.close()
                return Held.Done(UnlockResult.Failed(e))
            }
        } catch (e: ApiException) {
            api.close()
            // F26/A3: a definitive 401 (it survived the client's own refresh) means this device's session is dead,
            // for instance after a password change elsewhere revoked it (spec 03 §3). §4.2: the 401 came from THIS
            // origin, so only its namespace is purged.
            if (e.status == 401) {
                coordinator.purgeRevoked(originKey, stored.userId)
                return Held.Done(UnlockResult.Revoked(e))
            }
            return Held.Done(UnlockResult.Failed(e))
        } catch (t: Throwable) {
            api.close() // F74: a throw must never leak the client
            if (t is CancellationException) throw t
            return Held.Done(UnlockResult.Failed(t))
        }
        val account = try {
            open(keys)
        } catch (t: Throwable) {
            api.close() // a wrong password, a stale or foreign key, an identity mismatch: never leave the holder open
            if (t is CancellationException) throw t
            return Held.Done(UnlockResult.Failed(t))
        }
        // From here the account holds its keys: whatever stops short of the bind wipes them (gap 7).
        return try {
            store.origin(originKey).identityPins().record(stored.userId, stored.email, account)
            val unlocked = binder.bind(api, account, originKey, provenance)
            // A1: every full-password unlock stamps the window, an offline one included.
            if (provenance == VaultSession.UnlockProvenance.PASSWORD) binder.stampPasswordUnlock(originKey, stored.userId)
            Held.Bound(unlocked, keys, online, policy)
        } catch (t: Throwable) {
            // F74: the bind can throw (a corrupt cache file). Once the session adopted the api and the account it
            // owns them, and its lock closes the one and wipes the other.
            if (session.get()?.api !== api) api.close()
            if (session.get()?.account !== account) account.wipe()
            if (t is CancellationException) throw t
            Held.Done(UnlockResult.Failed(t))
        }
    }

    /**
     * A4: the policy read of an entry point that has no other (the autofill overlay). It is cheap and
     * unauthenticated, so an admin's `offlineCacheAllowed` flip reaches that entry point too, and the 7-day
     * staleness gate gets its timestamp. The mirrors are per origin (§4.2) and the auto-lock window is clamped
     * (B1-1). A failed read counts as offline: null.
     */
    private suspend fun refreshPolicy(api: AndvariApi, originKey: String, userId: String): ClientPolicy? {
        val p = try {
            coordinator.boundedPolicy(api) // H10: under the unlock mutex, so bounded
        } catch (c: CancellationException) {
            throw c
        } catch (_: Throwable) {
            return null
        }
        coordinator.recordPolicy(originKey, p)
        // The policy forbids durable key material: drop THIS origin's cache, cached keys and quick-unlock key
        // (spec 01 §8.1, A4, §4.2). The session stays valid; other origins' namespaces are untouched.
        if (!p.offlineCacheAllowed) coordinator.purgeForbidden(originKey, userId)
        return p
    }

    /** The self-identity pin of [stored]'s account at [originKey] (design §2.4): this device's record wins over the server's. */
    private fun pinFor(originKey: String, stored: StoredSession): ByteArray? =
        store.origin(originKey).identityPins().pinFor(stored.email, stored.userId)

    /** A1/A2 freshness of [userId]'s last full-password unlock at [originKey], against the monotonic high-water clock. */
    private fun isFresh(originKey: String, userId: String): Boolean {
        val now = clocks.wallMs()
        val elapsedNow = clocks.monotonicMs()
        val highWater = store.bumpHighWater(now) // monotonically non-decreasing
        val origin = store.origin(originKey)
        val stamp = origin.passwordStamp(userId)
        return QuickUnlockRules.isFreshPure(
            QuickUnlockRules.FreshnessInputs(
                nowMs = now,
                elapsedNowMs = elapsedNow,
                stampWallMs = stamp?.wallMs ?: 0L,
                stampElapsedMs = stamp?.monotonicMs ?: 0L,
                stampBootRefMs = stamp?.bootRefMs ?: 0L,
                highWaterWallMs = highWater,
                serverFloorMs = origin.serverTimeFloorMs,
                bootIdNow = clocks.bootId(),
                stampBootId = stamp?.bootId,
            ),
        )
    }
}
