package io.silencelen.andvari.server

import java.util.concurrent.ConcurrentHashMap

/**
 * Minimal fixed-window limiter for the auth endpoints (spec 03 §8). Not distributed
 * — one process, one server; that's the whole deployment.
 *
 * [clock] is the time source, defaulting to the real one. It exists so a test can pin
 * window expiry to an EXPLICIT advance instead of a wall-clock sleep (H97): the old
 * "four calls must land inside one 50 ms window" shape went red on a JIT-cold or loaded
 * host — a false red over no regression at all, which is how a manual gate gets re-run
 * until it passes. Production passes nothing and gets [now] verbatim.
 */
class RateLimiter(private val clock: () -> Long = ::now) {
    /** One window of one key. A window that lapses is replaced by a new object, so an object is exactly one window. */
    internal class Window(var windowStart: Long, var count: Int, val windowMs: Long)

    /**
     * A call [draw] admitted, with the very window it was counted in, so [refund] gives it back there and nowhere else, and
     * at most once ([givenBack]).
     */
    class Admitted internal constructor(internal val window: Window) {
        internal val givenBack = java.util.concurrent.atomic.AtomicBoolean(false)
    }

    /** What [draw] did: [admitted] when the call was counted, else [waitMs], the milliseconds until its window resets. */
    class Draw internal constructor(val admitted: Admitted?, val waitMs: Long?)
    private val windows = ConcurrentHashMap<String, Window>()
    private val callsSincePrune = java.util.concurrent.atomic.AtomicInteger()

    /**
     * [retryAfterMs] as a yes or no. [at] is the reading of the clock the call is counted at; a caller that draws two
     * budgets for one event passes the same reading to both, so that windows started by the same event start together.
     */
    fun allow(key: String, limit: Int, windowMs: Long, at: Long = clock()): Boolean = retryAfterMs(key, limit, windowMs, at) == null

    /**
     * Admits one call under [key], or returns the milliseconds until its window resets (for `Retry-After`). A window
     * starts at the first call it counts and lasts [windowMs] from then: a budget "a day" is a budget per window of 24
     * hours that starts at its first call, not per calendar day.
     */
    fun retryAfterMs(key: String, limit: Int, windowMs: Long, at: Long = clock()): Long? = draw(key, limit, windowMs, at).waitMs

    /** [retryAfterMs], and for an admitted call the window it was counted in, which [refund] takes. */
    fun draw(key: String, limit: Int, windowMs: Long, at: Long = clock()): Draw {
        prune()
        val now = at
        val w = windows.compute(key) { _, existing ->
            if (existing == null || now - existing.windowStart >= windowMs) Window(now, 0, windowMs) else existing
        }!!
        synchronized(w) {
            if (w.count >= limit) return Draw(null, (w.windowStart + windowMs - now).coerceAtLeast(1))
            w.count++
            return Draw(Admitted(w), null)
        }
    }

    /**
     * Amortized eviction (polish audit 2026-07-27 bug-server--3): the keys include per-IP buckets
     * on public-reachable routes, so the key space is attacker-expandable (a botnet, one IPv6 /64)
     * and the map would otherwise grow for the process lifetime — the same reasoning that gave
     * sibling [EmailBackoff] its prune (review 2026-07-16 D2). An EXPIRED window is semantically
     * absent already ([allow] resets it in place), so dropping one changes no admission decision;
     * the worst race (removeIf vs a concurrent same-key reset) fails open for at most one window —
     * the trade EmailBackoff documents. Between sweeps at most [PRUNE_EVERY] entries can be
     * inserted, so the map stays bounded by live-window keys + PRUNE_EVERY.
     */
    private fun prune() {
        if (callsSincePrune.incrementAndGet() < PRUNE_EVERY) return
        callsSincePrune.set(0)
        val now = clock()
        windows.entries.removeIf { now - it.value.windowStart >= it.value.windowMs }
    }

    /**
     * The milliseconds until [key]'s live window resets when it already holds [limit] calls, else null. Draws nothing:
     * it lets a refusal by one budget name the longer wait of a second budget the same call also needs ([drawDevice]).
     */
    fun waitIfFull(key: String, limit: Int): Long? {
        val w = windows[key] ?: return null
        synchronized(w) {
            val now = clock()
            if (now - w.windowStart >= w.windowMs || w.count < limit) return null
            return (w.windowStart + w.windowMs - now).coerceAtLeast(1)
        }
    }

    /**
     * Give back the call [admitted] names, when a second budget the same call also needs refused it ([drawDevice]): a
     * refused call spends nothing. It goes back to the window it was counted in and to no other: when that window lapsed
     * in between and another request's call started the key's next window, the next window keeps every call it counted.
     * (Until 2026-11-17 the give-back went to whichever window of the key was current, so a window that started between
     * a draw and its give-back lost a call it had counted and admitted one more than its limit.)
     *
     * A give-back is good for one use (decided on 2026-11-17): a second give-back of the same draw does nothing, so no
     * caller, present or future, can give one call back twice and so admit more than the limit.
     */
    fun refund(admitted: Admitted) {
        if (!admitted.givenBack.compareAndSet(false, true)) return
        val w = admitted.window
        synchronized(w) { if (w.count > 0) w.count-- }
    }

    /**
     * A removed device takes its budgets with it: every window kept for [deviceId] ([Bucket.deviceKey]) goes. Its
     * account's ceilings keep what the device spent, as they are the account's. A device id is never reused, so this
     * changes no admission; it keeps the rule the device's back-offs follow, and the map holds no dead device.
     */
    fun forgetDevice(deviceId: String) {
        val suffix = ":device:$deviceId"
        windows.keys.removeIf { it.endsWith(suffix) }
    }

    /** Test hook: the calls counted in [key]'s live window (0 when it has none or it lapsed). */
    internal fun count(key: String): Int {
        val w = windows[key] ?: return 0
        synchronized(w) { return if (clock() - w.windowStart >= w.windowMs) 0 else w.count }
    }

    /** Test hook: when [key]'s live window started (null when it has none or it lapsed). */
    internal fun windowStart(key: String): Long? {
        val w = windows[key] ?: return null
        synchronized(w) { return if (clock() - w.windowStart >= w.windowMs) null else w.windowStart }
    }

    /** Test hook: live entry count (RateLimiterTest pins the eviction bound). */
    internal fun size(): Int = windows.size

    /** Test hook: forget every window, so a route test can walk past a small bucket it is not testing. */
    internal fun clear() = windows.clear()

    internal companion object {
        const val PRUNE_EVERY = 4096
    }
}

/**
 * Per-account exponential backoff for login/recovery (design 2026-07-15 §2.5, B1-3/B1-6), keyed on
 * the NORMALIZED submitted email — existing account or not. Extending the prelogin fake-salt
 * anti-enumeration discipline: real and invented emails get byte-identical throttle behavior, so the
 * throttle is never an account oracle; per-IP limiting alone is botnet-bypassable. After [threshold]
 * consecutive failures, failure n locks the key for 2^(n-threshold) seconds, capped at [capMs]; any
 * success clears the key. A blocked attempt is refused up front (429) and does NOT extend the lock.
 * In-memory, single-process — the same deployment shape as [RateLimiter].
 *
 * The server keeps three of these, never sharing a count: `loginBackoff`, keyed on the
 * submitted address, armed only by sign-ins (and device-link pickups, which are sign-ins) and refusing only them;
 * `proofBackoff`, keyed on the session's device (`Services.deviceCounterKey`), armed only by password proofs made on
 * that device's own sessions and refusing only them; and `codeBackoff`, keyed on the device too, armed only by
 * two-step codes checked on that device's own sessions and refusing only the checking of a code. The key strings
 * differ in kind, but each
 * instance hashes whatever it is given.
 */
class EmailBackoff(private val threshold: Int = 5, private val capMs: Long = 900_000) {
    private class State(var failures: Int = 0, var lockedUntil: Long = 0, var touchedAt: Long = 0)
    private val states = ConcurrentHashMap<String, State>()
    private val failsSincePrune = java.util.concurrent.atomic.AtomicInteger()

    /**
     * The time source. A settable seam rather than a constructor arg because the instance a test
     * needs to steer is the one [Service] built for itself, reached through `services.service
     * .loginBackoff` — the same "mutable so tests can force it" shape [AttachmentStore.orphanTtlMs]
     * already uses.
     *
     * Why it exists (H97): the endpoint test for the 5th-failure lock used to `Thread.sleep(1200)`
     * past a real 1 s lock — a 200 ms margin over wall clock, which a GC pause or a loaded build
     * host can eat, turning a correct server red. A test now ADVANCES this instead and the
     * assertion is about the lock, not about the scheduler. Never set in production.
     */
    @Volatile internal var clock: () -> Long = ::now

    /**
     * The state key is a SHA-256 of the normalised email, never the email itself (server scan
     * 2026-10-26, F3): the email is attacker-chosen and was bounded only by the login route's 256 KiB
     * body cap, and the sweep below does not engage until [PRUNE_AT] entries — so a few thousand
     * unique ~250 KB "emails" pinned gigabytes of heap. A digest key is 64 chars whatever arrives,
     * and the route additionally refuses an email over [EMAIL_MAX_CHARS] before it gets here.
     */
    private fun key(email: String): String {
        val normalised = email.trim().lowercase().encodeToByteArray()
        return io.silencelen.andvari.core.crypto.Bytes.toHexLower(java.security.MessageDigest.getInstance("SHA-256").digest(normalised))
    }

    /** True while the key is locked out — check BEFORE any verifier work (it's the cheap gate). */
    fun blocked(email: String): Boolean {
        val s = states[key(email)] ?: return false
        synchronized(s) { return clock() < s.lockedUntil }
    }

    /** Record a failed attempt; from the [threshold]th consecutive failure on, arm/extend the lock. */
    fun fail(email: String) {
        prune()
        val s = states.computeIfAbsent(key(email)) { State() }
        synchronized(s) {
            s.failures++
            s.touchedAt = clock()
            if (s.failures >= threshold) {
                val exp = (s.failures - threshold).coerceAtMost(20) // 2^20 s already ≫ the cap
                s.lockedUntil = clock() + (1000L shl exp).coerceAtMost(capMs)
            }
        }
    }

    /**
     * Reserve one attempt before any verifier work: atomically, false while the key is locked,
     * else the attempt is counted as a failure NOW (arming the lock at the threshold). A verified attempt then
     * calls [success], which clears it; an attempt that fails stays counted. Checking first and counting
     * after the verify let every request sent at the same moment pass the check, so a caller with many
     * client addresses got five guesses per address per lock period instead of one.
     */
    fun reserve(email: String): Boolean = reserveOrWait(email) == null

    /**
     * [reserve], returning null when the attempt was reserved and otherwise the milliseconds until the lock lapses (at
     * least 1). Only the back-offs a session's own device keeps name this wait (spec 03 §8, decided on 2026-11-17): the
     * session can count it for itself. The sign-in's back-off, keyed by an address anyone can type, answers a fixed
     * 60 seconds instead, since the real wait would tell how many wrong tries were made for that address lately.
     */
    fun reserveOrWait(email: String): Long? {
        prune()
        val s = states.computeIfAbsent(key(email)) { State() }
        synchronized(s) {
            val now = clock()
            if (now < s.lockedUntil) return (s.lockedUntil - now).coerceAtLeast(1)
            s.failures++
            s.touchedAt = now
            if (s.failures >= threshold) {
                val exp = (s.failures - threshold).coerceAtMost(20)
                s.lockedUntil = now + (1000L shl exp).coerceAtMost(capMs)
            }
            return null
        }
    }

    /** A successful attempt clears the consecutive-failure state entirely (§2.5: reset on success); also how a removed device's counters go. */
    fun success(email: String) { states.remove(key(email)) }

    /** Test hook: when the lock on [email] lapses (0 when there is none), so a test can walk a day of the curve. */
    internal fun lockedUntil(email: String): Long = states[key(email)]?.let { synchronized(it) { it.lockedUntil } } ?: 0

    /**
     * Bound the map against junk-email stuffing (emails are attacker-chosen strings, unlike the IP
     * keys of [RateLimiter]): once past [PRUNE_AT] entries, every [PRUNE_EVERY]th failure sweeps
     * entries idle beyond the cap window whose lock has lapsed. Amortized so a full scan can't be
     * turned into per-request work by the same flood it defends against.
     */
    private fun prune() {
        if (states.size < PRUNE_AT || failsSincePrune.incrementAndGet() < PRUNE_EVERY) return
        failsSincePrune.set(0)
        val cutoff = clock() - capMs
        states.entries.removeIf { e -> synchronized(e.value) { e.value.touchedAt < cutoff && clock() >= e.value.lockedUntil } }
        // Hard ceiling (review 2026-07-16 D2): the idle-sweep above only evicts idle-AND-unlocked
        // entries, so a sustained flood of UNIQUE fresh emails (every entry recent) could still grow the
        // map unbounded. Above HARD_CAP, evict the OLDEST-touched UNLOCKED entries — NEVER a currently
        // locked (actively-attacked) victim, so eviction can never become a lock-bypass. Amortized with
        // the sweep; the upstream per-IP 5/min + Argon2 dummy-verify cost already throttle the fill rate.
        if (states.size <= HARD_CAP) return
        val n = clock()
        states.entries
            .mapNotNull { e -> synchronized(e.value) { if (n >= e.value.lockedUntil) e.key to e.value.touchedAt else null } }
            .sortedBy { it.second }
            .take(states.size - HARD_CAP)
            .forEach { states.remove(it.first) }
    }

    private companion object {
        const val PRUNE_AT = 100_000
        const val PRUNE_EVERY = 4096
        const val HARD_CAP = 200_000
    }
}
