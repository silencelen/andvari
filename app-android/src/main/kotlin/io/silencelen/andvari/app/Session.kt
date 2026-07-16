package io.silencelen.andvari.app

import android.content.Context
import android.os.SystemClock
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.model.AccountKeys
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.math.max

/**
 * Non-secret session persisted across launches (SharedPreferences). Tokens are here
 * (MVP); the vault KEY is NEVER stored — a relaunch re-prompts for the master
 * password (spec 01 §8; Keystore-wrapped quick-unlock is a follow-up).
 */
data class Session(
    val baseUrl: String,
    val userId: String,
    val email: String,
    val accessToken: String,
    val refreshToken: String,
) {
    fun tokens() = Tokens(accessToken, refreshToken)
}

/**
 * The persisted "an invite-driven server switch is UNCOMMITTED" marker (design 2026-07-15
 * §4.3, breaker B2-6/B2-9). Its mere presence is the source of truth for "pending": while it
 * exists the switch to [origin] is NOT trusted as the new default — enrollment success clears it
 * (the commit, §4.1 rule 3) and a Discard reverts to [previousOrigin] and clears it.
 *
 * Written BEFORE `register` so a crash between register and the commit is reconciled at the next
 * launch ("Finish setting up at <origin> / Discard"). [previousOrigin] is the Android-specific
 * addition to the design's `{origin, email?, ts}` — this app keeps a single global session slot,
 * so a revert needs to know where to return. [email] is captured at register time (the address to
 * sign in as if register already succeeded before the crash).
 */
@Serializable
data class PendingServer(
    val origin: String,
    val previousOrigin: String,
    val email: String? = null,
    val ts: Long,
)

/**
 * Persistence layout (design 2026-07-15 §4.2 — (origin, userId) namespacing):
 *
 *  - GLOBAL keys: the single active session (`userId`/`email`/tokens/`mustChangePassword`),
 *    `baseUrl`, the device-clock high-water ratchet (`qu_highWater` — it measures the DEVICE's
 *    own observed clock, origin-independent, and only ever ratchets toward "expire sooner"),
 *    export/sync bookkeeping, and the one-shot migration flags.
 *  - PER-ORIGIN keys, under an `ns.<originKey>.` prefix (originKey = [OriginNamespace.originKey]
 *    of the CURRENT `baseUrl` unless a caller passes one explicitly): `cacheAllowed`, the cached
 *    policy mirrors (`autoLockSeconds`, `policyFetchedAt`, `qu_serverFloor`), the cached
 *    `accountKeys`, and the quick-unlock meta (per-user freshness stamps + the offer flag).
 *    `qu_serverFloor` is per-origin ON PURPOSE: it is a SERVER-attested duration anchor, and
 *    under endpoint-agnosticism only an origin's OWN attestations may anchor that origin's
 *    quick-unlock stamps — a foreign (possibly hostile) server's `serverTime` must never
 *    re-open another origin's expired cross-boot window.
 *
 * The implicit `var` accessors read/write the CURRENT origin's namespace; the explicit
 * `(originKey, …)` variants exist for the purge paths ([OfflineData]) and for policy-probe
 * callbacks that captured their origin BEFORE an await (a probe of server B landing after the
 * user re-pointed at C must still write/purge under B — never under whatever is current).
 */
class SessionStore(context: Context) {
    private val prefs = context.getSharedPreferences("andvari", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    /** Memo for [currentOriginKey] (SHA-256 is cheap, but some readers sit on 1 s ticks) — a
     *  benign racy cache of a pure function. Declared BEFORE the init block: Kotlin runs
     *  initializers in declaration order, and init's adoption path is the first caller. */
    @Volatile
    private var originKeyMemo: Pair<String, String>? = null

    init {
        // ORDER IS LOAD-BEARING (design 2026-07-15 §4.2 adoption + §6 migration — both one-shot):
        // the shipped-default rewrite MUST run BEFORE the namespace adoption, so the adoption
        // files the legacy unscoped data under the POST-rewrite origin's key.
        //
        // ── WAVE-4 COUPLING — read before touching either call ──────────────────────────────
        // Wave 4 replaces migrateDefaultOnce() with v2 (LAN|tailnet → the public default,
        // new `baseUrlMigratedPublic` flag, §6). v2 MUST slot exactly HERE, still ahead of
        // adoptNamespacesOnce(), so a pre-namespacing install's first run of the release build
        // rewrites baseUrl first and then adopts its unscoped data under the PUBLIC origin key.
        // AND: if a build carrying THIS adoption ever ships BEFORE the Wave-4 default swap,
        // fielded installs will already have adopted under the TAILNET origin key — Wave 4 must
        // then ALSO move ns/<originKey(tailnet)>/ → ns/<originKey(public)>/ (same instance, two
        // fronts, §6.2), not just rewrite baseUrl. Flagged here instead of guessed at.
        // ─────────────────────────────────────────────────────────────────────────────────────
        //
        // Living in the constructor (not MainActivity.onCreate) is deliberate: the autofill
        // entry points build their own SessionStore and may be the FIRST code to run after an
        // app update — every reader of the scoped layout must be preceded by the adoption, and
        // the constructor is the one choke point all of them share.
        migrateDefaultOnce()
        adoptNamespacesOnce(context.noBackupFilesDir)
    }

    var baseUrl: String
        get() = prefs.getString("baseUrl", DEFAULT_BASE_URL) ?: DEFAULT_BASE_URL
        set(v) = prefs.edit().putString("baseUrl", v).apply()

    /**
     * The uncommitted invite-switch marker ([PendingServer]) or null. GLOBAL (not namespaced):
     * exactly one switch can be in flight, and it is about the identity of the current default
     * origin, not any origin's cached material — so the §4.2 adoption sweep deliberately leaves it
     * alone. Null clears it; a non-null value round-trips as JSON.
     */
    var pendingServer: PendingServer?
        get() = prefs.getString("pendingServer", null)
            ?.let { runCatching { json.decodeFromString(PendingServer.serializer(), it) }.getOrNull() }
        set(v) = if (v == null) prefs.edit().remove("pendingServer").apply()
            else prefs.edit().putString("pendingServer", json.encodeToString(PendingServer.serializer(), v)).apply()

    /** [OriginNamespace.originKey] of the current [baseUrl] — the namespace the implicit
     *  accessors below address. */
    fun currentOriginKey(): String {
        val url = baseUrl
        originKeyMemo?.let { if (it.first == url) return it.second }
        return OriginNamespace.originKey(url).also { originKeyMemo = url to it }
    }

    private fun ns(originKey: String, key: String) = "ns.$originKey.$key"

    /**
     * Last-known org `offlineCacheAllowed` FOR AN ORIGIN, persisted so a forbidding policy is
     * still honored when the app cold-starts OFFLINE (policy fetch fails → this is the fallback,
     * spec 02 §8). Fail-open default true until that origin's first policy is seen. Per-origin
     * (§4.2): server B declaring false must not flip server A's fallback.
     */
    var cacheAllowed: Boolean
        get() = cacheAllowed(currentOriginKey())
        set(v) = setCacheAllowed(currentOriginKey(), v)

    fun cacheAllowed(originKey: String): Boolean = prefs.getBoolean(ns(originKey, "cacheAllowed"), true)
    fun setCacheAllowed(originKey: String, v: Boolean) {
        prefs.edit().putBoolean(ns(originKey, "cacheAllowed"), v).apply()
    }

    /**
     * Last-known org `autoLockSeconds` (spec 01 §8), persisted so the idle window is enforced on
     * OFFLINE cold starts and on the autofill unlock path (which never fetches policy itself).
     * Per-origin cached-policy mirror (§4.2). Writers persist the CLAMPED effective value
     * (design 2026-07-15 §2.3/B1-1 — see [clampAutoLockSeconds]); [VaultSession.setAutoLockSeconds]
     * re-clamps on arm regardless, so a pre-clamp persisted value (old build) can't disable the
     * lock either. Default 0 until the origin's first policy is seen — the arm-site clamp turns
     * that into the ceiling, and nothing can be unlocked before a first online contact anyway.
     */
    var autoLockSeconds: Int
        get() = autoLockSeconds(currentOriginKey())
        set(v) = setAutoLockSeconds(currentOriginKey(), v)

    fun autoLockSeconds(originKey: String): Int = prefs.getInt(ns(originKey, "autoLockSeconds"), 0)
    fun setAutoLockSeconds(originKey: String, v: Int) {
        prefs.edit().putInt(ns(originKey, "autoLockSeconds"), v).apply()
    }

    /**
     * F58: the last login/register response's `mustChangePassword` — true while a recovery
     * TEMP password is the live credential. Only a SessionResponse carries the flag (sync
     * and accountKeys don't), so it is persisted here for the Unlock path / relaunches and
     * drives the non-dismissable "set a new password in the web app" banner. Clears
     * naturally: the web password change (spec 03 §3) revokes every OTHER session, so this
     * device's next unlock 401s → sign-out → a fresh login returns false and overwrites it.
     * GLOBAL: it belongs to the single active session, and dies with it in [clear].
     */
    var mustChangePassword: Boolean
        get() = prefs.getBoolean("mustChangePassword", false)
        set(v) = prefs.edit().putBoolean("mustChangePassword", v).apply()

    /**
     * A4 (quick unlock): when AN ORIGIN's client-policy was last successfully FETCHED (unix ms;
     * 0 = never). Persisted so the autofill-only process — which fetches policy on its own
     * online path — and the main app share one freshness view; [QuickUnlock.isEligible] refuses
     * quick unlock once this is older than 7 days so an admin's `offlineCacheAllowed` flip can't
     * be ignored indefinitely by an idle overlay-only device. Per-origin (§4.2) — probing server
     * B must NOT refresh server A's staleness ceiling (that would let a foreign probe keep A's
     * durable unlock secret alive past A's policy-refresh window).
     */
    var policyFetchedAt: Long
        get() = policyFetchedAt(currentOriginKey())
        set(v) = setPolicyFetchedAt(currentOriginKey(), v)

    fun policyFetchedAt(originKey: String): Long = prefs.getLong(ns(originKey, "policyFetchedAt"), 0L)
    fun setPolicyFetchedAt(originKey: String, v: Long) {
        prefs.edit().putLong(ns(originKey, "policyFetchedAt"), v).apply()
    }

    /**
     * A2 (quick unlock clock safety): a monotonically non-decreasing high-water wall clock. The
     * 30-day freshness window is evaluated on `max(now, highWater)`, so setting the device clock
     * BACKWARD can never re-open an expired window (it only ever makes the vault ask for the
     * password sooner — the safe direction). GLOBAL (device clock), not per-account and not
     * per-origin: it ratchets from the device's own observed time, and cross-origin influence
     * can only push it FORWARD — toward expiry, the safe direction.
     */
    var highWaterWallMs: Long
        get() = prefs.getLong("qu_highWater", 0L)
        set(v) = prefs.edit().putLong("qu_highWater", v).apply()

    /** Advance and return the high-water mark; never decreases. */
    fun bumpHighWater(nowMs: Long): Long {
        val hw = max(highWaterWallMs, nowMs)
        if (hw != highWaterWallMs) highWaterWallMs = hw
        return hw
    }

    /**
     * A2 hardening (review 2026-07-10 [2]): the last SERVER-ATTESTED wall time (`ClientPolicy
     * .serverTime`), monotonically non-decreasing. `highWaterWallMs` only ratchets from the
     * DEVICE clock as the app observes it, so a phone left dormant (app never foregrounded)
     * freezes it — and a reboot voids the elapsedRealtime cross-check. An attacker could then
     * roll the clock to a moment INSIDE the window and quick-unlock forever. Server time is the
     * one clock the device holder cannot set; it is the only thing that can prove duration
     * across a reboot. PER-ORIGIN (§4.2, deliberate tightening): only an origin's OWN
     * attestation may anchor that origin's stamps — otherwise a hostile foreign server could
     * attest a just-after-the-stamp "now" and falsely satisfy the cross-boot duration proof for
     * the home origin's expired window.
     */
    var serverTimeFloorMs: Long
        get() = serverTimeFloorMs(currentOriginKey())
        set(v) = prefs.edit().putLong(ns(currentOriginKey(), "qu_serverFloor"), v).apply()

    fun serverTimeFloorMs(originKey: String): Long = prefs.getLong(ns(originKey, "qu_serverFloor"), 0L)

    /** Advance an origin's server-time floor from a fetched policy; never decreases, ignores nonsense. */
    fun bumpServerTimeFloor(originKey: String, serverTimeMs: Long) {
        if (serverTimeMs > serverTimeFloorMs(originKey)) {
            prefs.edit().putLong(ns(originKey, "qu_serverFloor"), serverTimeMs).apply()
        }
    }

    /** Current-origin convenience of [bumpServerTimeFloor]. */
    fun bumpServerTimeFloor(serverTimeMs: Long) = bumpServerTimeFloor(currentOriginKey(), serverTimeMs)

    /**
     * A1 (quick unlock provenance): the wall-clock time of the last REAL full-master-password
     * unlock for a user AT THE CURRENT ORIGIN (unix ms; 0 = never). Written ONLY by
     * [stampFullPasswordUnlock], i.e. ONLY by a genuine password unlock — never by a quick
     * unlock and never minted at enrollment, so "re-enroll" or a Settings off/on toggle cannot
     * silently reset the 30-day clock. Lives OUTSIDE the wrapped blob (per-(origin,userId) key)
     * so it survives blob wipes and can't be edited via the blob. Per-origin (§4.2): a password
     * typed at origin A must not freshen origin B's quick-unlock window — the same account id
     * can exist at two fronts of one instance.
     */
    fun lastFullPasswordUnlockAt(userId: String): Long =
        prefs.getLong(ns(currentOriginKey(), "qu_stampWall_$userId"), 0L)

    /** A2: the `elapsedRealtime` captured at the last full-password stamp (monotonic same-boot check). */
    fun stampElapsedMs(userId: String): Long =
        prefs.getLong(ns(currentOriginKey(), "qu_stampElapsed_$userId"), 0L)

    /** A2: the boot reference (`wall − elapsedRealtime`) at the last stamp — lets freshness tell
     *  "same boot, clock steady" (trust the monotonic clock) from "rebooted or clock stepped". */
    fun stampBootRefMs(userId: String): Long =
        prefs.getLong(ns(currentOriginKey(), "qu_stampBoot_$userId"), 0L)

    /**
     * Record a genuine full-password unlock (A1) against the CURRENT origin: the wall time plus
     * the A2 monotonic anchors, and bump the high-water mark. Call from EVERY full-password
     * unlock (sign-in, main-app unlock, autofill overlay unlock — including offline ones). A
     * quick unlock must NEVER call this.
     */
    fun stampFullPasswordUnlock(userId: String) {
        val ok = currentOriginKey()
        val now = System.currentTimeMillis()
        val elapsed = SystemClock.elapsedRealtime()
        bumpHighWater(now)
        prefs.edit()
            .putLong(ns(ok, "qu_stampWall_$userId"), now)
            .putLong(ns(ok, "qu_stampElapsed_$userId"), elapsed)
            .putLong(ns(ok, "qu_stampBoot_$userId"), now - elapsed)
            .apply()
    }

    /** Drop a user's full-password stamp in the CURRENT origin's namespace (sign-out / revocation). */
    fun clearFullPasswordStamp(userId: String) = clearFullPasswordStamp(currentOriginKey(), userId)

    /** Explicit-origin form — the purge paths ([OfflineData]) scope by the key they were given. */
    fun clearFullPasswordStamp(originKey: String, userId: String) {
        prefs.edit()
            .remove(ns(originKey, "qu_stampWall_$userId"))
            .remove(ns(originKey, "qu_stampElapsed_$userId"))
            .remove(ns(originKey, "qu_stampBoot_$userId"))
            .apply()
    }

    /**
     * The one-time post-unlock "Unlock with fingerprint next time?" offer card has been dismissed
     * (design §8 default: one dismissible re-offer, then Settings-only — no nag loop). Cleared by
     * [clear] on sign-out so a fresh account is offered again. Per-origin quick-unlock meta (§4.2).
     */
    var quickUnlockOfferDismissed: Boolean
        get() = prefs.getBoolean(ns(currentOriginKey(), "quickUnlockOfferDismissed"), false)
        set(v) = prefs.edit().putBoolean(ns(currentOriginKey(), "quickUnlockOfferDismissed"), v).apply()

    /**
     * When the last spec 07 backup was produced (unix ms; 0 = never). Recorded LOCALLY
     * only — the server is never told an export happened (spec 07 §2.6). Drives the
     * "Last backup: N days ago" line + the >90-day nudge in Settings. Global: it describes
     * this DEVICE's export hygiene, not any server's state.
     */
    var lastExportAt: Long
        get() = prefs.getLong("lastExportAt", 0L)
        set(v) = prefs.edit().putLong("lastExportAt", v).apply()

    /** When the last SUCCESSFUL sync finished (unix ms; 0 = unknown) — the timestamp the
     *  spec 07 offline-export note shows ("vault as of last sync <time>"). */
    var lastSyncAt: Long
        get() = prefs.getLong("lastSyncAt", 0L)
        set(v) = prefs.edit().putLong("lastSyncAt", v).apply()

    /**
     * Absolute expiry (unix ms; 0 = off) of the "Debug autofill (24h)" toggle on the
     * Autofill-status screen. While `> now`, AutofillDebugLog appends fill events to its
     * ring buffer; past it the toggle self-disarms — recording is checked against the
     * clock on every event, so no alarm/job is needed. Value-free diagnostics only.
     */
    var autofillDebugUntil: Long
        get() = prefs.getLong("autofillDebugUntil", 0L)
        set(v) = prefs.edit().putLong("autofillDebugUntil", v).apply()

    fun load(): Session? {
        val userId = prefs.getString("userId", null) ?: return null
        return Session(
            baseUrl = baseUrl,
            userId = userId,
            email = prefs.getString("email", "") ?: "",
            accessToken = prefs.getString("accessToken", "") ?: "",
            refreshToken = prefs.getString("refreshToken", "") ?: "",
        )
    }

    fun save(s: Session) {
        prefs.edit()
            .putString("baseUrl", s.baseUrl)
            .putString("userId", s.userId)
            .putString("email", s.email)
            .putString("accessToken", s.accessToken)
            .putString("refreshToken", s.refreshToken)
            .apply()
    }

    fun updateTokens(t: Tokens?) {
        if (t == null) { clear(); return }
        prefs.edit().putString("accessToken", t.accessToken).putString("refreshToken", t.refreshToken).apply()
    }

    /**
     * The server's accountKeys payload — all ciphertext/public (wrappedUvk,
     * encryptedIdentitySeed, identityPub) + salts/params, same trust class as the tokens
     * already here. Enables offline unlock (spec 02 §8); wiped on sign-out / revocation.
     * Stored in the CURRENT origin's namespace (§4.2): this is exactly the "account keys"
     * material the origin-blind purge used to destroy cross-server.
     */
    fun saveAccountKeys(keys: AccountKeys) {
        prefs.edit().putString(ns(currentOriginKey(), "accountKeys"), json.encodeToString(AccountKeys.serializer(), keys)).apply()
    }

    fun loadAccountKeys(): AccountKeys? =
        prefs.getString(ns(currentOriginKey(), "accountKeys"), null)?.let { runCatching { json.decodeFromString(AccountKeys.serializer(), it) }.getOrNull() }
            // H1 cache belt (spec 05 T1): evict a cache poisoned pre-fix with sub-floor / absurd KDF
            // params -> null = cache miss -> the caller refetches through the fenced AndvariApi.
            ?.takeIf { runCatching { io.silencelen.andvari.core.client.KdfUpgrade.requireServerKdfParams(it.kdfParams) }.isSuccess }

    /** Drop the CURRENT origin's cached accountKeys. */
    fun clearAccountKeys() = clearAccountKeys(currentOriginKey())

    /** Explicit-origin form — the purge paths scope by the key they were given (§4.2). */
    fun clearAccountKeys(originKey: String) {
        prefs.edit().remove(ns(originKey, "accountKeys")).apply()
    }

    /**
     * Kill the persisted session. The identity/tokens/F58 flag are GLOBAL (single active
     * session); the cached accountKeys + offer flag live in the session's origin's namespace —
     * "the session's origin" is the current `baseUrl` (nothing changes it mid-session today;
     * wave 3's switch flow clears tokens itself before any repoint).
     */
    fun clear() {
        val ok = currentOriginKey()
        prefs.edit().remove("userId").remove("email").remove("accessToken").remove("refreshToken")
            .remove(ns(ok, "accountKeys")).remove("mustChangePassword").remove(ns(ok, "quickUnlockOfferDismissed")).apply()
    }

    /**
     * §4.1 rule 1 (B1-5): drop ONLY the single global active session — identity + access/refresh
     * tokens + the F58 flag — so a client rebuilt for a DIFFERENT origin can carry no old bearer
     * token to the new one. Unlike [clear], this touches NO per-origin namespace: a server switch
     * is not a wipe, so the old origin's cached account keys / vault cache / quick-unlock survive
     * for an A→B→A round trip (§4.2/B2-7). Callers change [baseUrl] around this.
     */
    fun clearSessionTokens() {
        prefs.edit().remove("userId").remove("email").remove("accessToken").remove("refreshToken")
            .remove("mustChangePassword").apply()
    }

    /**
     * One-time bump of the persisted server URL from the old VLAN-2 LAN default to the
     * tailnet HTTPS default (reachable from any Tailscale device; the LAN IP isn't, off-VLAN-2).
     * Only rewrites the exact legacy default, so a deliberate custom URL is left alone.
     * Invoked from `init` — BEFORE [adoptNamespacesOnce], see the ordering note there.
     */
    private fun migrateDefaultOnce() {
        if (prefs.getBoolean("baseUrlMigratedTailnet", false)) return
        if (prefs.getString("baseUrl", null) == LEGACY_LAN_DEFAULT) {
            prefs.edit().putString("baseUrl", DEFAULT_BASE_URL).apply()
        }
        prefs.edit().putBoolean("baseUrlMigratedTailnet", true).apply()
    }

    /**
     * Adoption one-shot (design 2026-07-15 §4.2, `nsAdoptedOnce`): on the first run of a
     * namespacing-aware build, move the legacy UNSCOPED layout into the CURRENT origin's
     * namespace — the pre-namespacing install only ever talked to its `baseUrl` server, so
     * everything it persisted belongs to that origin by construction. Runs AFTER
     * [migrateDefaultOnce] (see the init-block ordering + Wave-4 coupling note).
     *
     * Two halves, files first: a death between them leaves the flag UNSET and the next start
     * re-runs both (file moves are rename-only + skip-if-destination-exists, so the retry is
     * idempotent; pref moves are copy-if-absent + remove, same property). Failure is SOFT by
     * design: an unmoved straggler is simply invisible to the scoped readers (cache re-syncs,
     * quick unlock re-offers) — never a crash, never another namespace's data.
     *
     * The adopted quick-unlock blob keeps riding its LEGACY Keystore alias (aliases cannot be
     * renamed, and the key is hardware-bound) — [QuickUnlock] accepts the legacy alias for a
     * blob that records it, and its wipe destroys that alias only with the owning blob.
     */
    private fun adoptNamespacesOnce(noBackupDir: File) {
        if (prefs.getBoolean("nsAdoptedOnce", false)) return
        val ok = currentOriginKey()

        // ---- files: vault caches + quick-unlock blobs → ns/<originKey>/<userId>/ ----
        for (f in noBackupDir.listFiles().orEmpty()) {
            if (!f.isFile) continue
            val name = f.name
            if (name.startsWith("quick-unlock-") && name.endsWith(".json.tmp")) {
                runCatching { f.delete() } // stale atomic-swap leftover — never adopt a torn write
                continue
            }
            val userId = legacyUserIdOf(name) ?: continue
            runCatching {
                val destDir = OriginNamespace.dir(noBackupDir, ok, userId)
                destDir.mkdirs()
                val dest = File(destDir, name)
                if (!dest.exists()) f.renameTo(dest) // rename-only: idempotent, never clobbers
            }
        }

        // ---- SharedPreferences: legacy unscoped keys → the ns.<originKey>. prefix ----
        val all = prefs.all
        val edit = prefs.edit()
        for ((key, value) in all) {
            val scoped = key in ADOPT_FIXED_KEYS || ADOPT_PER_USER_PREFIXES.any { key.startsWith(it) }
            if (!scoped) continue
            val target = ns(ok, key)
            if (!all.containsKey(target)) {
                when (value) {
                    is Boolean -> edit.putBoolean(target, value)
                    is Int -> edit.putInt(target, value)
                    is Long -> edit.putLong(target, value)
                    is String -> edit.putString(target, value)
                    else -> {} // no float/set-typed keys exist in the adopted set
                }
            }
            edit.remove(key)
        }
        edit.putBoolean("nsAdoptedOnce", true)
        edit.apply()
    }

    /** The userId embedded in a legacy unscoped filename, or null when the file isn't ours. */
    private fun legacyUserIdOf(name: String): String? {
        for ((prefix, suffix) in LEGACY_FILE_SHAPES) {
            if (name.startsWith(prefix) && name.endsWith(suffix) && name.length > prefix.length + suffix.length) {
                return name.substring(prefix.length, name.length - suffix.length)
            }
        }
        return null
    }

    companion object {
        const val DEFAULT_BASE_URL = "https://andvari.taila2dff2.ts.net"
        private const val LEGACY_LAN_DEFAULT = "http://192.168.2.122:8080"

        /** Unscoped keys the §4.2 adoption moves under the origin prefix (see the class doc). */
        private val ADOPT_FIXED_KEYS = setOf(
            "cacheAllowed", "autoLockSeconds", "policyFetchedAt", "qu_serverFloor",
            "accountKeys", "quickUnlockOfferDismissed",
        )
        private val ADOPT_PER_USER_PREFIXES = listOf("qu_stampWall_", "qu_stampElapsed_", "qu_stampBoot_")

        /** (prefix, suffix) shapes of the legacy unscoped per-user files. */
        private val LEGACY_FILE_SHAPES = listOf(
            "vault-" to ".db",
            "vault-" to ".db-wal",
            "vault-" to ".db-shm",
            "quick-unlock-" to ".json",
        )
    }
}
