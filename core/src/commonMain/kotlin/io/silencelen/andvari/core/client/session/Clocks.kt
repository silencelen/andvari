package io.silencelen.andvari.core.client.session

/**
 * The clocks a session reads, supplied by the platform (design 2026-11-09, "Monotonic time" and
 * "Boot identity"; spec 01 §8.1 "Clock-tamper safety"). A rule that cares which clock it reads
 * states it against this seam, so the security argument is made once and every platform has to
 * meet it.
 */
interface Clocks {
    /** Wall time in unix ms. The device holder can set it, so on its own it never proves a duration. */
    fun wallMs(): Long

    /**
     * Milliseconds on a monotonic clock that **keeps counting while the device sleeps** (Android
     * `SystemClock.elapsedRealtime`, Darwin `CLOCK_MONOTONIC`), so a phone left in a drawer past
     * the window is expired the moment anything looks. A clock that stops during sleep
     * (`uptimeMillis`, `NSProcessInfo.systemUptime`) would under-count idle time, and wall time can
     * be set backwards to postpone the lock indefinitely. The origin is arbitrary and changes on
     * reboot, so a value is only comparable within one boot.
     */
    fun monotonicMs(): Long

    /**
     * The identity of this boot, from a source the device holder cannot set (Android
     * `Settings.Global.BOOT_COUNT`, iOS `kern.bootsessionuuid`), or null when the platform exposes
     * none. Null fails closed: [QuickUnlockRules.isFreshPure] then takes the cross-boot path, so a
     * quick unlock needs a server contact newer than the last password unlock.
     */
    fun bootId(): String?
}
