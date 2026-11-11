package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.SelfIdentityPin
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.model.AccountKeys
import kotlin.concurrent.Volatile
import kotlin.math.max

/**
 * The session persisted across launches. Tokens are stored here (spec 05 T5 trust class); the
 * vault KEY is NEVER stored — a relaunch re-prompts for the master password (spec 01 §8;
 * quick unlock is the separate, platform-wrapped path of §8.1).
 *
 * [baseUrl] is the origin that issued these tokens: the session owns its origin (security review
 * 2026-10, F8; desktop has always stored it this way). It is what the [sessionBelongsTo] gate
 * checks against the origin the client dials, so a stored session's tokens are only ever sent to
 * the origin that issued them.
 */
data class StoredSession(
    val baseUrl: String,
    val userId: String,
    val email: String,
    val accessToken: String,
    val refreshToken: String,
) {
    fun tokens() = Tokens(accessToken, refreshToken)
}

/**
 * A1/A2: the record of the last REAL full-master-password unlock for one (origin, user) (spec 01
 * §8.1). Lives outside the wrapped blob, so it survives blob wipes and cannot be edited via the
 * blob. Written by a genuine full-password unlock only, never by a quick unlock.
 */
data class PasswordStamp(
    val wallMs: Long,
    val monotonicMs: Long,
    /** Wall − monotonic at the stamp: the fallback boot reference for stamps with no [bootId]. */
    val bootRefMs: Long,
    /** A12 (row 74): the boot identity at the stamp ([Clocks.bootId]); null = unknown. */
    val bootId: String?,
)

/**
 * The per-origin half of the persisted state (design 2026-07-15 §4.2). Everything a server can
 * influence lives here, keyed by that server's origin, so one origin's policy or purge can never
 * reach another's: probing server B must not touch what server A left on this device.
 */
interface OriginStore {
    /**
     * Last-known org `offlineCacheAllowed` for this origin, persisted so a forbidding policy is
     * still honored when the client cold-starts offline (spec 02 §8).
     */
    var cacheAllowed: Boolean

    /**
     * Last-known org `autoLockSeconds` (spec 01 §8), persisted so the idle window is enforced on
     * offline cold starts and on paths that never fetch policy themselves. Writers persist the
     * clamped value ([clampAutoLockSeconds]); the arm site re-clamps regardless.
     */
    var autoLockSeconds: Int

    /** A4: when this origin's client policy was last fetched, unix ms; 0 = never. */
    var policyFetchedAt: Long

    /**
     * A2 hardening (review 2026-07-10 [2]): the last SERVER-ATTESTED wall time, monotonically
     * non-decreasing, and per-origin on purpose: only an origin's OWN attestation may anchor that
     * origin's quick-unlock stamps (spec 01 §8.1 cross-boot rule).
     */
    var serverTimeFloorMs: Long

    /** Advance the floor from a fetched policy; never decreases, ignores nonsense. */
    fun bumpServerTimeFloor(serverTimeMs: Long) {
        if (serverTimeMs > serverTimeFloorMs) serverTimeFloorMs = serverTimeMs
    }

    /** The account keys cached for offline unlock (spec 02 §8), or null. */
    fun loadAccountKeys(userId: String): AccountKeys?

    fun saveAccountKeys(userId: String, keys: AccountKeys)

    fun clearAccountKeys(userId: String)

    /** The last full-password unlock of [userId] at this origin, or null if there is none. */
    fun passwordStamp(userId: String): PasswordStamp?

    fun setPasswordStamp(userId: String, stamp: PasswordStamp)

    fun clearPasswordStamp(userId: String)

    /** The self-identity pins of this origin (design §2.4). Public data, and they survive purges. */
    fun identityPins(): SelfIdentityPin.KeyValueStore
}

/**
 * The persisted session state a client shares with the session layer. Global state lives here;
 * per-origin state lives behind [origin].
 *
 * The shape follows Android's `SessionStore`, its first implementation. An implementation must
 * drop a session's tokens before it changes the origin the client dials (§4.1 rule 1), so a crash
 * between the two leaves no live token paired with another origin.
 */
interface SessionPersistence {
    /** The origin this client dials, or null where no origin has been chosen yet (iOS first launch). */
    val baseUrl: String?

    /** Point the client at [origin]. Only [ServerSwitch.moveTo] calls this, after it dropped the session. */
    fun moveOrigin(origin: String)

    /**
     * The uncommitted invite-switch marker, or null. Global: one switch can be in flight, and it
     * is about the identity of the current default origin, not any origin's cached material.
     */
    var pendingServer: PendingServer?

    /** The stored session, or null. Carries its own origin; see [StoredSession.baseUrl]. */
    fun load(): StoredSession?

    /**
     * Whose session is stored, read without its tokens: for a process that must never hold them (the iOS extensions),
     * which fills only for the account that is signed in now. Null when no session is stored.
     */
    fun storedIdentity(): StoredIdentity? = load()?.let { StoredIdentity(it.baseUrl, it.userId, it.email) }

    fun save(s: StoredSession)

    /** Persist a rotation; null is the refused-refresh path: the stored session is over. */
    fun updateTokens(t: Tokens?)

    /**
     * Compare-and-write for one client's token callback ([updateTokensFor]): if the stored session is
     * [userId]'s at [origin] and still holds [expectedRefreshToken], replace its pair with [t], or end
     * it ([clear]) when [t] is null. Returns whether it wrote. Implementations make the compare and the
     * write one step against [save], [clear], [clearSessionTokens] and each other.
     */
    fun replaceTokensIf(origin: String, userId: String, expectedRefreshToken: String, t: Tokens?): Boolean

    /** Kill the stored session and the per-origin state that dies with it. Global + session origin only. */
    fun clear()

    /** Drop only the session itself (§4.1 rule 1); per-origin material survives a server switch. */
    fun clearSessionTokens()

    /** F58: a recovery TEMP password is the live credential. Belongs to the session. */
    var mustChangePassword: Boolean

    /**
     * A2 (quick unlock clock safety): a monotonically non-decreasing wall clock. Device-global: it
     * ratchets from the device's own observed time, and can only ever make quick unlock expire
     * sooner.
     */
    var highWaterWallMs: Long

    /** Advance and return the high-water mark; never decreases. */
    fun bumpHighWater(nowMs: Long): Long {
        val hw = max(highWaterWallMs, nowMs)
        if (hw != highWaterWallMs) highWaterWallMs = hw
        return hw
    }

    /** When the last successful sync finished (unix ms; 0 = unknown). */
    var lastSyncAt: Long

    /** The per-origin store for an origin key ([io.silencelen.andvari.core.client.OriginCanon.originKey]). */
    fun origin(key: String): OriginStore
}

/**
 * The stored session one client's token callback writes for: its origin, its user once known, and the
 * refresh token the client holds now. A client built from a stored session is that session's from the
 * start; a client that signs in or enrolls has no session until its caller commits one, and names the
 * user then.
 */
class TokenOwner(val origin: String, userId: String? = null, heldRefreshToken: String? = null) {
    @Volatile
    var userId: String? = userId

    /** The refresh token this client holds: the one its next rotation replaces, and the one a drop may clear. */
    @Volatile
    var heldRefreshToken: String? = heldRefreshToken
}

/**
 * Persist [t] — a rotation, or the null of a refused refresh or a logout — only into the stored session
 * this client holds: same origin, same user, AND the refresh token this client rotated from (review round
 * 2). Matching the user alone let a superseded client of the same account — an autofill overlay built
 * from the session it saw when it opened — overwrite or clear the session another client had rotated
 * since. A client with no committed session yet writes nothing (its caller saves the pair it commits).
 * The compare and the write are one atomic step in the store ([SessionPersistence.replaceTokensIf]).
 * A token callback goes through here, never [SessionPersistence.updateTokens].
 */
fun SessionPersistence.updateTokensFor(owner: TokenOwner, t: Tokens?) {
    val held = owner.heldRefreshToken
    owner.heldRefreshToken = t?.refreshToken // what the client holds now, whether or not it is stored
    val user = owner.userId ?: return
    val from = held ?: return
    replaceTokensIf(owner.origin, user, from, t)
}

/**
 * Security review 2026-10, F8 (the session owns its origin): the origin to record for a stored
 * session written by a build that did not keep one. Such a session was saved against the global
 * base URL, and every path that moved that URL also dropped the session's tokens, so the base URL
 * is the session's origin except across one narrow window: a server switch that wrote the new
 * origin and died before the tokens were dropped. A build that keeps the session's origin drops
 * the tokens first, so that window only exists for sessions written before it.
 *
 * A manual switch leaves no trace of the window, so a legacy session with no marker is taken to
 * be the base URL's. An invite switch does leave one, the [pending] marker. While a marker points
 * at the current base URL, a stored session may be the invite origin's (register succeeded and
 * the crash came before the commit) or the previous origin's (the crash came before the tokens
 * were dropped), and nothing tells them apart. Guessing either way can pair one origin's tokens
 * with the other, so the answer is null: the caller drops the session and the user signs in again.
 */
fun sessionOriginForBackfill(baseUrl: String, pending: PendingServer?): String? =
    if (pending != null && !switchDropsSession(pending.origin, baseUrl)) null else baseUrl

/** The account a stored session belongs to, without its tokens ([SessionPersistence.storedIdentity]). */
data class StoredIdentity(val baseUrl: String, val userId: String, val email: String)
