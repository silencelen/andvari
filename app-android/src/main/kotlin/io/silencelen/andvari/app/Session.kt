package io.silencelen.andvari.app

import android.content.Context
import android.os.SystemClock
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.model.AccountKeys
import kotlinx.serialization.json.Json
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

class SessionStore(context: Context) {
    private val prefs = context.getSharedPreferences("andvari", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    var baseUrl: String
        get() = prefs.getString("baseUrl", DEFAULT_BASE_URL) ?: DEFAULT_BASE_URL
        set(v) = prefs.edit().putString("baseUrl", v).apply()

    /**
     * Last-known org `offlineCacheAllowed`, persisted so a forbidding policy is still
     * honored when the app cold-starts OFFLINE (policy fetch fails → this is the fallback,
     * spec 02 §8). Fail-open default true until the first policy is seen.
     */
    var cacheAllowed: Boolean
        get() = prefs.getBoolean("cacheAllowed", true)
        set(v) = prefs.edit().putBoolean("cacheAllowed", v).apply()

    /**
     * Last-known org `autoLockSeconds` (spec 01 §8; 0 = disabled), persisted so the idle
     * window is enforced on OFFLINE cold starts and on the autofill unlock path (which
     * never fetches policy itself). Default 0 until the first policy is seen — nothing can
     * be unlocked before a first online contact anyway (no cached accountKeys yet).
     */
    var autoLockSeconds: Int
        get() = prefs.getInt("autoLockSeconds", 0)
        set(v) = prefs.edit().putInt("autoLockSeconds", v).apply()

    /**
     * F58: the last login/register response's `mustChangePassword` — true while a recovery
     * TEMP password is the live credential. Only a SessionResponse carries the flag (sync
     * and accountKeys don't), so it is persisted here for the Unlock path / relaunches and
     * drives the non-dismissable "set a new password in the web app" banner. Clears
     * naturally: the web password change (spec 03 §3) revokes every OTHER session, so this
     * device's next unlock 401s → sign-out → a fresh login returns false and overwrites it.
     */
    var mustChangePassword: Boolean
        get() = prefs.getBoolean("mustChangePassword", false)
        set(v) = prefs.edit().putBoolean("mustChangePassword", v).apply()

    /**
     * A4 (quick unlock): when the client-policy was last successfully FETCHED from the server
     * (unix ms; 0 = never). Persisted so the autofill-only process — which fetches policy on its
     * own online path — and the main app share one freshness view; [QuickUnlock.isEligible]
     * refuses quick unlock once this is older than 7 days so an admin's `offlineCacheAllowed`
     * flip can't be ignored indefinitely by an idle overlay-only device.
     */
    var policyFetchedAt: Long
        get() = prefs.getLong("policyFetchedAt", 0L)
        set(v) = prefs.edit().putLong("policyFetchedAt", v).apply()

    /**
     * A2 (quick unlock clock safety): a monotonically non-decreasing high-water wall clock. The
     * 30-day freshness window is evaluated on `max(now, highWater)`, so setting the device clock
     * BACKWARD can never re-open an expired window (it only ever makes the vault ask for the
     * password sooner — the safe direction). Global (device clock), not per-account.
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
     * across a reboot. Global, not per-account.
     */
    var serverTimeFloorMs: Long
        get() = prefs.getLong("qu_serverFloor", 0L)
        set(v) = prefs.edit().putLong("qu_serverFloor", v).apply()

    /** Advance the server-time floor from a fetched policy; never decreases, ignores nonsense. */
    fun bumpServerTimeFloor(serverTimeMs: Long) {
        if (serverTimeMs > serverTimeFloorMs) serverTimeFloorMs = serverTimeMs
    }

    /**
     * A1 (quick unlock provenance): the wall-clock time of the last REAL full-master-password
     * unlock for a user (unix ms; 0 = never). Written ONLY by [stampFullPasswordUnlock], i.e.
     * ONLY by a genuine password unlock — never by a quick unlock and never minted at enrollment,
     * so "re-enroll" or a Settings off/on toggle cannot silently reset the 30-day clock. Lives
     * OUTSIDE the wrapped blob (per-userId key) so it survives blob wipes and can't be edited via
     * the blob.
     */
    fun lastFullPasswordUnlockAt(userId: String): Long = prefs.getLong("qu_stampWall_$userId", 0L)

    /** A2: the `elapsedRealtime` captured at the last full-password stamp (monotonic same-boot check). */
    fun stampElapsedMs(userId: String): Long = prefs.getLong("qu_stampElapsed_$userId", 0L)

    /** A2: the boot reference (`wall − elapsedRealtime`) at the last stamp — lets freshness tell
     *  "same boot, clock steady" (trust the monotonic clock) from "rebooted or clock stepped". */
    fun stampBootRefMs(userId: String): Long = prefs.getLong("qu_stampBoot_$userId", 0L)

    /**
     * Record a genuine full-password unlock (A1): the wall time plus the A2 monotonic anchors, and
     * bump the high-water mark. Call from EVERY full-password unlock (sign-in, main-app unlock,
     * autofill overlay unlock — including offline ones). A quick unlock must NEVER call this.
     */
    fun stampFullPasswordUnlock(userId: String) {
        val now = System.currentTimeMillis()
        val elapsed = SystemClock.elapsedRealtime()
        bumpHighWater(now)
        prefs.edit()
            .putLong("qu_stampWall_$userId", now)
            .putLong("qu_stampElapsed_$userId", elapsed)
            .putLong("qu_stampBoot_$userId", now - elapsed)
            .apply()
    }

    /** Drop a user's full-password stamp (sign-out / revocation). */
    fun clearFullPasswordStamp(userId: String) {
        prefs.edit()
            .remove("qu_stampWall_$userId")
            .remove("qu_stampElapsed_$userId")
            .remove("qu_stampBoot_$userId")
            .apply()
    }

    /**
     * The one-time post-unlock "Unlock with fingerprint next time?" offer card has been dismissed
     * (design §8 default: one dismissible re-offer, then Settings-only — no nag loop). Cleared by
     * [clear] on sign-out so a fresh account is offered again.
     */
    var quickUnlockOfferDismissed: Boolean
        get() = prefs.getBoolean("quickUnlockOfferDismissed", false)
        set(v) = prefs.edit().putBoolean("quickUnlockOfferDismissed", v).apply()

    /**
     * When the last spec 07 backup was produced (unix ms; 0 = never). Recorded LOCALLY
     * only — the server is never told an export happened (spec 07 §2.6). Drives the
     * "Last backup: N days ago" line + the >90-day nudge in Settings.
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
     */
    fun saveAccountKeys(keys: AccountKeys) {
        prefs.edit().putString("accountKeys", json.encodeToString(AccountKeys.serializer(), keys)).apply()
    }

    fun loadAccountKeys(): AccountKeys? =
        prefs.getString("accountKeys", null)?.let { runCatching { json.decodeFromString(AccountKeys.serializer(), it) }.getOrNull() }

    fun clearAccountKeys() { prefs.edit().remove("accountKeys").apply() }

    fun clear() {
        prefs.edit().remove("userId").remove("email").remove("accessToken").remove("refreshToken")
            .remove("accountKeys").remove("mustChangePassword").remove("quickUnlockOfferDismissed").apply()
    }

    /**
     * One-time bump of the persisted server URL from the old VLAN-2 LAN default to the
     * tailnet HTTPS default (reachable from any Tailscale device; the LAN IP isn't, off-VLAN-2).
     * Only rewrites the exact legacy default, so a deliberate custom URL is left alone.
     */
    fun migrateDefaultOnce() {
        if (prefs.getBoolean("baseUrlMigratedTailnet", false)) return
        if (prefs.getString("baseUrl", null) == LEGACY_LAN_DEFAULT) {
            prefs.edit().putString("baseUrl", DEFAULT_BASE_URL).apply()
        }
        prefs.edit().putBoolean("baseUrlMigratedTailnet", true).apply()
    }

    companion object {
        const val DEFAULT_BASE_URL = "https://andvari.taila2dff2.ts.net"
        private const val LEGACY_LAN_DEFAULT = "http://192.168.2.122:8080"
    }
}
