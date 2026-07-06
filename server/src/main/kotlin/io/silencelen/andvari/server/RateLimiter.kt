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
