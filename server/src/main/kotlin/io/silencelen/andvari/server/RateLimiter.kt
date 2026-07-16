package io.silencelen.andvari.server

import java.util.concurrent.ConcurrentHashMap

/**
 * Minimal fixed-window limiter for the auth endpoints (spec 03 §8). Not distributed
 * — one process, one server; that's the whole deployment.
 */
class RateLimiter {
    private class Window(var windowStart: Long, var count: Int)
    private val windows = ConcurrentHashMap<String, Window>()

    fun allow(key: String, limit: Int, windowMs: Long): Boolean {
        val now = now()
        val w = windows.compute(key) { _, existing ->
            if (existing == null || now - existing.windowStart >= windowMs) Window(now, 0) else existing
        }!!
        synchronized(w) {
            if (w.count >= limit) return false
            w.count++
            return true
        }
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
 */
class EmailBackoff(private val threshold: Int = 5, private val capMs: Long = 900_000) {
    private class State(var failures: Int = 0, var lockedUntil: Long = 0, var touchedAt: Long = 0)
    private val states = ConcurrentHashMap<String, State>()
    private val failsSincePrune = java.util.concurrent.atomic.AtomicInteger()

    private fun key(email: String) = email.trim().lowercase()

    /** True while the key is locked out — check BEFORE any verifier work (it's the cheap gate). */
    fun blocked(email: String): Boolean {
        val s = states[key(email)] ?: return false
        synchronized(s) { return now() < s.lockedUntil }
    }

    /** Record a failed attempt; from the [threshold]th consecutive failure on, arm/extend the lock. */
    fun fail(email: String) {
        prune()
        val s = states.computeIfAbsent(key(email)) { State() }
        synchronized(s) {
            s.failures++
            s.touchedAt = now()
            if (s.failures >= threshold) {
                val exp = (s.failures - threshold).coerceAtMost(20) // 2^20 s already ≫ the cap
                s.lockedUntil = now() + (1000L shl exp).coerceAtMost(capMs)
            }
        }
    }

    /** A successful attempt clears the consecutive-failure state entirely (§2.5: reset on success). */
    fun success(email: String) { states.remove(key(email)) }

    /**
     * Bound the map against junk-email stuffing (emails are attacker-chosen strings, unlike the IP
     * keys of [RateLimiter]): once past [PRUNE_AT] entries, every [PRUNE_EVERY]th failure sweeps
     * entries idle beyond the cap window whose lock has lapsed. Amortized so a full scan can't be
     * turned into per-request work by the same flood it defends against.
     */
    private fun prune() {
        if (states.size < PRUNE_AT || failsSincePrune.incrementAndGet() < PRUNE_EVERY) return
        failsSincePrune.set(0)
        val cutoff = now() - capMs
        states.entries.removeIf { e -> synchronized(e.value) { e.value.touchedAt < cutoff && now() >= e.value.lockedUntil } }
        // Hard ceiling (review 2026-07-16 D2): the idle-sweep above only evicts idle-AND-unlocked
        // entries, so a sustained flood of UNIQUE fresh emails (every entry recent) could still grow the
        // map unbounded. Above HARD_CAP, evict the OLDEST-touched UNLOCKED entries — NEVER a currently
        // locked (actively-attacked) victim, so eviction can never become a lock-bypass. Amortized with
        // the sweep; the upstream per-IP 5/min + Argon2 dummy-verify cost already throttle the fill rate.
        if (states.size <= HARD_CAP) return
        val n = now()
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
