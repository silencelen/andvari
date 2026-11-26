package io.silencelen.andvari.server

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A floor the operator set never falls back quietly (decided on 2026-11-17). A value for the hashing cost's floor that the
 * server cannot apply stops the start with a line that names the value and the range. Before, a value the configuration
 * did not accept (not a whole number, or outside its range) was replaced by the default, which LOWERED the floor the
 * operator meant to raise, and a value above what the server or the clients take was served as it was, so every
 * registration, recovery and password change was refused.
 */
class KdfFloorConfigTest {
    private val base = mapOf("ANDVARI_CANONICAL_ORIGIN" to "http://127.0.0.1:8080", "ANDVARI_ENUM_SECRET" to "A".repeat(43))

    private fun start(vararg set: Pair<String, String>): Config = (base + set).let { env -> Config.fromEnv { env[it] } }

    private fun refused(vararg set: Pair<String, String>): String = assertFailsWith<ConfigError> { start(*set) }.message!!

    @Test
    fun aValueTheConfigurationDoesNotAccept_stopsTheStart_andNeverTakesTheDefault() {
        val word = refused("ANDVARI_MIN_KDF_OPS" to "four")
        assertTrue("ANDVARI_MIN_KDF_OPS='four'" in word && "0..1000000" in word, word)
        val mem = refused("ANDVARI_MIN_KDF_MEM" to "128MiB")
        assertTrue("ANDVARI_MIN_KDF_MEM='128MiB'" in mem && "0..1099511627776" in mem, mem)
        val outside = refused("ANDVARI_MIN_KDF_OPS" to "2000000")
        assertTrue("ANDVARI_MIN_KDF_OPS=2000000" in outside && "outside the range the configuration accepts (0..1000000 passes)" in outside, outside)
        val negative = refused("ANDVARI_MIN_KDF_MEM" to "-1")
        assertTrue("ANDVARI_MIN_KDF_MEM=-1" in negative && "0..1099511627776 bytes" in negative, negative)
    }

    @Test
    fun aFloorAboveTheServersOwnLimit_stopsTheStart() {
        val ops = refused("ANDVARI_MIN_KDF_OPS" to "65")
        assertTrue("ANDVARI_MIN_KDF_OPS=65" in ops && "server's own upper limit" in ops && "(64 passes)" in ops, ops)
        val mem = refused("ANDVARI_MIN_KDF_MEM" to "${(4L shl 30) + 1}")
        assertTrue("ANDVARI_MIN_KDF_MEM=${(4L shl 30) + 1}" in mem && "server's own upper limit" in mem && "(4294967296 bytes)" in mem, mem)
    }

    @Test
    fun aFloorAboveWhatTheClientsAccept_stopsTheStart_andTheFigureIsTheSharedCodes() {
        assertEquals(io.silencelen.andvari.core.client.KdfUpgrade.MAX_OPS, KdfLimits.CLIENT_MAX_OPS)
        assertEquals(io.silencelen.andvari.core.client.KdfUpgrade.MAX_MEM_BYTES, KdfLimits.CLIENT_MAX_MEM_BYTES)
        val ops = refused("ANDVARI_MIN_KDF_OPS" to "11")
        assertTrue("ANDVARI_MIN_KDF_OPS=11" in ops && "above what the clients accept (at most 10 passes" in ops, ops)
        // The memory floor is served rounded up to a whole KiB: one byte over 1 GiB is served as 1 GiB and 1 KiB.
        val mem = refused("ANDVARI_MIN_KDF_MEM" to "${(1L shl 30) + 1}")
        assertTrue("above what the clients accept (at most 1073741824 bytes" in mem, mem)
        // A configuration built directly (the tests' way) is held to the same limits.
        assertFailsWith<ConfigError> { TestKit.config(minKdfOps = 11) }
    }

    @Test
    fun aFloorInsideEveryLimit_isTakenAsSet_andUnsetOrBlankIsTheDefault() {
        val at = start("ANDVARI_MIN_KDF_OPS" to "10", "ANDVARI_MIN_KDF_MEM" to "${1L shl 30}")
        assertEquals(10L, at.minKdfOps); assertEquals(1L shl 30, at.minKdfMemBytes)
        val unset = start()
        assertEquals(3L, unset.minKdfOps); assertEquals(67_108_864L, unset.minKdfMemBytes)
        val blank = start("ANDVARI_MIN_KDF_OPS" to " ", "ANDVARI_MIN_KDF_MEM" to "")
        assertEquals(3L, blank.minKdfOps); assertEquals(67_108_864L, blank.minKdfMemBytes)
    }
}
