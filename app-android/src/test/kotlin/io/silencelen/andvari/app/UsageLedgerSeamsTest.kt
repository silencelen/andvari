package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 — the two usage-ledger seams in `AndvariViewModel.kt` that a JVM test cannot
 * drive (they live inside `viewModelScope.launch` against a live VaultSession), pinned on the
 * shipped source the way HealthVerdictGatesTest and SurfacePinsTest do:
 *
 *  - H33: `signOut()` AWAITS the bounded usage flush BEFORE `api.logout()`. logout() revokes the
 *    session the flush's GET+PUT ride on; the old order let VaultSession.lock()'s teardown flush
 *    run against a revoked pair (401 → dropped, and not re-armed — the catch is session-gated).
 *    The desktop had this right (DesktopState.signOut); the phone now has the same shape.
 *  - H36: the post-sync prune keep-set is `e.liveItemIds()` — every live ENVELOPE, decryptable or
 *    not — never `e.items()`, the decrypted working set that omits newer-formatVersion envelopes
 *    and unopened-grant vaults and so erased those live items' usage on every poll. The
 *    behaviour is proven against the real engine in core's SyncEngineLiveItemIdsTest; this pins
 *    that the phone CALLS it.
 */
class UsageLedgerSeamsTest {
    private fun repoFile(relative: String): File =
        listOf(File("../$relative"), File(relative)).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    private val vm by lazy { repoFile("app-android/src/main/kotlin/io/silencelen/andvari/app/AndvariViewModel.kt").readText() }

    /** The slice of the source from [from] to the next [to], both asserted present and in order
     *  so a renamed anchor fails loudly instead of emptying the span. */
    private fun span(from: String, to: String): String {
        val a = vm.indexOf(from)
        assertTrue(a > -1, "span start missing: $from")
        val b = vm.indexOf(to, a)
        assertTrue(b > a, "span end missing or out of order: $to")
        return vm.substring(a, b)
    }

    // ---- H33 ----

    @Test
    fun signOutAwaitsTheBoundedUsageFlushBeforeRevokingTheSession() {
        val signOut = span("fun signOut(reason: String? = null)", "pendingBackupRequest = null // never carry a stashed export")
        val flush = "withTimeoutOrNull(UsageRecorder.LOCK_FLUSH_TIMEOUT_MS) { UsageRecorder.flush() }"
        assertTrue(signOut.contains(flush), "sign-out must flush the usage buffer, bounded by the lock-path constant")
        assertTrue(
            signOut.indexOf(flush) < signOut.indexOf("current.api.logout()"),
            "the flush must be AWAITED before logout() — logout revokes the tokens the flush rides on",
        )
    }

    // ---- H36 ----

    @Test
    fun thePostSyncPruneIsFedTheLiveEnvelopeSetNotTheDecryptedItems() {
        val syncNow = span("private suspend fun syncNow(e: SyncEngine)", "private fun refreshItems()")
        assertTrue(syncNow.contains("UsageRecorder.flushWithPrune(s, e.liveItemIds())"), "the keep-set must be engine.liveItemIds()")
        assertFalse(syncNow.contains("e.items()"), "items() is the decrypted working set — pruning against it drops live-but-unreadable items' usage")
    }
}
