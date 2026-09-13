package io.silencelen.andvari.desktop

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 — the desktop's two usage-ledger seams in `DesktopState.kt`, pinned on the
 * shipped source (the SurfacePinsTest idiom; both live inside Main-confined launches that
 * DesktopAsyncFlowsTest would need a full fake server to drive):
 *
 *  - H33 names this file's `signOut` as the sibling that is right — the bounded usage flush is
 *    AWAITED before `logout()` revokes the tokens it rides on. Pinned so it stays right while the
 *    phone and the extension are brought to the same shape.
 *  - H36: the post-sync prune keep-set is `e.liveItemIds()` — every live ENVELOPE, decryptable or
 *    not — never `e.items()`, the decrypted working set that omits newer-formatVersion envelopes
 *    and unopened-grant vaults and so erased those live items' usage on every poll. Proven against
 *    the real engine in core's SyncEngineLiveItemIdsTest; this pins that the desktop CALLS it.
 */
class UsageLedgerSeamsTest {
    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-desktop/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    private val state by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/desktop/DesktopState.kt").readText() }

    private fun span(from: String, to: String): String {
        val a = state.indexOf(from)
        assertTrue(a > -1, "span start missing: $from")
        val b = state.indexOf(to, a)
        assertTrue(b > a, "span end missing or out of order: $to")
        return state.substring(a, b)
    }

    @Test
    fun signOutAwaitsTheBoundedUsageFlushBeforeRevokingTheSession() {
        val signOut = span("fun signOut() {", "private fun clearSecondary()")
        val flush = "withTimeoutOrNull(USAGE_FLUSH_TIMEOUT_MS) { flushUsage() }"
        assertTrue(signOut.contains(flush), "sign-out must flush the usage buffer, bounded")
        assertTrue(signOut.indexOf(flush) < signOut.indexOf("a.logout()"), "the flush must be AWAITED before logout()")
    }

    @Test
    fun thePostSyncPruneIsFedTheLiveEnvelopeSetNotTheDecryptedItems() {
        val syncNow = span("private suspend fun syncNow(e: SyncEngine)", "private fun restrictToOwner")
        assertTrue(syncNow.contains("flushUsageWithPrune(UsageSession(a, acct), e.liveItemIds())"), "the keep-set must be engine.liveItemIds()")
        assertFalse(syncNow.contains("e.items()"), "items() is the decrypted working set — pruning against it drops live-but-unreadable items' usage")
    }
}
