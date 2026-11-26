package io.silencelen.andvari.server

import java.io.File
import java.time.Instant
import java.time.ZoneOffset

/** Wall-clock milliseconds. Services use their injected [Clock]; this is for code with no service at hand. */
fun now(): Long = System.currentTimeMillis()

/**
 * The server's notion of "now" (spec 03 §14.4, design §7.1). Every expiry, hold, rate window and
 * timestamp a service writes reads it, so the hostile-server harness can move time with the test clock.
 */
fun interface Clock {
    fun now(): Long

    companion object {
        val SYSTEM: Clock = Clock { System.currentTimeMillis() }

        /** UTC `YYYY-MM-DD` of [ms] (sign-up proof of work, the daily account maximum). */
        fun utcDate(ms: Long): String = Instant.ofEpochMilli(ms).atZone(ZoneOffset.UTC).toLocalDate().toString()

        /** Start of the UTC day containing [ms]. */
        fun utcDayStart(ms: Long): Long = ms - Math.floorMod(ms, DAY_MS)

        const val MINUTE_MS = 60_000L
        const val HOUR_MS = 3_600_000L
        const val DAY_MS = 86_400_000L
    }
}

/**
 * `ANDVARI_TEST_CLOCK` (test mode only, spec 03 §14.4): a file holding a millisecond timestamp the server
 * uses as "now". Re-read when its modification time changes, so a harness moves time by rewriting it.
 * An unreadable or malformed file falls back to the wall clock rather than freezing the server.
 */
class FileClock(private val file: File) : Clock {
    @Volatile private var cachedMtime = -1L
    @Volatile private var cachedValue = 0L

    override fun now(): Long {
        val m = file.lastModified()
        if (m != cachedMtime || m == 0L) {
            val v = runCatching { file.readText().trim().toLong() }.getOrNull()
            if (v == null || v <= 0) return System.currentTimeMillis()
            cachedValue = v
            cachedMtime = m
        }
        return cachedValue
    }
}

/** A clock a test moves by hand. */
class MutableClock(start: Long = 1_800_000_000_000L) : Clock {
    @Volatile var ms: Long = start
    override fun now(): Long = ms
    fun advance(deltaMs: Long) { ms += deltaMs }
}
