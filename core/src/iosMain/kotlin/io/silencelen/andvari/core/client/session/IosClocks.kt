@file:OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)

package io.silencelen.andvari.core.client.session

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.toKString
import kotlinx.cinterop.value
import platform.darwin.*
import platform.posix.*

/**
 * The iOS clocks. `CLOCK_MONOTONIC` counts through device sleep, which
 * `NSProcessInfo.systemUptime` does not, and the idle lock needs a clock that does (see
 * [Clocks.monotonicMs]). Boot identity comes from `kern.bootsessionuuid`; if that cannot be read,
 * [bootId] returns null and every freshness check takes the cross-boot path, which fails closed.
 */
object IosClocks : Clocks {
    private const val BOOT_SESSION_SYSCTL = "kern.bootsessionuuid"

    override fun wallMs(): Long = kotlinx.datetime.Clock.System.now().toEpochMilliseconds()

    override fun monotonicMs(): Long = memScoped {
        val now = alloc<timespec>()
        // Cannot fail for a valid clock id. A silent 0 here would freeze the idle timer, so fail loudly.
        check(clock_gettime(CLOCK_MONOTONIC.convert(), now.ptr) == 0) { "CLOCK_MONOTONIC unavailable" }
        now.tv_sec.convert<Long>() * 1000L + now.tv_nsec.convert<Long>() / 1_000_000L
    }

    override fun bootId(): String? = memScoped {
        val size = alloc<size_tVar>()
        if (sysctlbyname(BOOT_SESSION_SYSCTL, null, size.ptr, null, 0.convert()) != 0) return@memScoped null
        val length = size.value.convert<Int>()
        if (length <= 0) return@memScoped null
        val buffer = allocArray<ByteVar>(length)
        if (sysctlbyname(BOOT_SESSION_SYSCTL, buffer, size.ptr, null, 0.convert()) != 0) return@memScoped null
        buffer.toKString().takeIf { it.isNotBlank() }
    }
}
