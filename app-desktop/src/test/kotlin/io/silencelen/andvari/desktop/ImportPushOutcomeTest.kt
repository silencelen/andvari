package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.KdfPolicyViolationException
import io.silencelen.andvari.core.client.UpgradeRequiredException
import io.silencelen.andvari.core.crypto.KdfParams
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * ux-error--1 (polish audit 2026-07-27): every import PUSH failure used to collapse into ONE
 * retryable sentence — "Import interrupted — press Retry to finish (no duplicates will be
 * created)." — so a 403, a weakened-KDF block, or a version pin replayed the same doomed push
 * forever under copy that promised it would finish. [importPushRetryable] / [importPushError] are
 * that split; android's twin pair is pinned by its PureGatesTest. The 426 escape (the catch-all
 * ALSO swallowed [UpgradeRequiredException], which drives the blocking upgrade screen everywhere
 * else) is control flow in importConfirm, asserted here as the contract this pair relies on.
 */
class ImportPushOutcomeTest {

    // ---- transient: the Retry affordance and its promise are honest ----

    @Test
    fun transportFailureKeepsTheRetryPromise() {
        val t = java.io.IOException("Connection reset by peer")
        assertTrue(importPushRetryable(t))
        assertEquals(IMPORT_INTERRUPTED, importPushError(t))
    }

    /** The server's own two retry-flavoured verdicts — its copy says "try again", so does ours. */
    @Test
    fun rateLimitAndServerHiccupStayRetryable() {
        assertTrue(importPushRetryable(ApiException(429, "rate_limited", "slow down")))
        assertTrue(importPushRetryable(ApiException(500, "internal", "boom")))
        assertTrue(importPushRetryable(ApiException(503, "unavailable", "restarting")))
        assertEquals(IMPORT_INTERRUPTED, importPushError(ApiException(500, "internal", "boom")))
    }

    /** An unclassified throw: the plan's itemIds double as push mutationIds, so the replay
     *  converges rather than duplicating — the one case where "no duplicates" is still true. */
    @Test
    fun unclassifiedThrowStaysRetryable() {
        assertTrue(importPushRetryable(IllegalStateException("mid-chunk")))
        assertEquals(IMPORT_INTERRUPTED, importPushError(IllegalStateException("mid-chunk")))
    }

    // ---- terminal: no Retry, and the copy names the refusal ----

    @Test
    fun permissionRefusalIsTerminalAndSaysSo() {
        val t = ApiException(403, "forbidden", "forbidden")
        assertFalse(importPushRetryable(t))
        assertEquals(HouseholdCopy.forError(t), importPushError(t))
        assertEquals("You don't have permission to do that.", importPushError(t))
    }

    @Test
    fun weakenedKdfPushIsTerminalAndKeepsTheSecurityWarning() {
        val t = KdfPolicyViolationException("kdf_below_floor", KdfParams())
        assertFalse(importPushRetryable(t))
        assertEquals(HouseholdCopy.WEAK_KDF_ACTION, importPushError(t))
    }

    @Test
    fun otherServerRefusalsAreTerminalWithCanonCopy() {
        for (t in listOf(
            ApiException(401, "unauthorized", "authentication failed"),
            ApiException(404, "not_found", "no such vault"),
            ApiException(409, "vault_state_changed", "rev mismatch"),
            ApiException(410, "gone", "purged"),
            ApiException(413, "too_large", "quota"),
        )) {
            assertFalse(importPushRetryable(t), "${t.status} replays as the same refusal")
            assertEquals(HouseholdCopy.forError(t), importPushError(t))
        }
    }

    /** The audited leak shape: a refusal's copy must never carry the server's raw message. */
    @Test
    fun terminalCopyNeverLeaksWireText() {
        val raw = "SQLITE_CONSTRAINT: UNIQUE constraint failed: mutations.id"
        val mapped = importPushError(ApiException(400, "bad_request", raw))
        assertFalse(mapped.contains("SQLITE"), "raw wire text leaked: $mapped")
    }

    /**
     * The 426 contract: a version pin must NOT be classified here at all — importConfirm catches
     * [UpgradeRequiredException] ahead of this pair and raises the blocking upgrade screen (op() /
     * runSync parity). This asserts the classifier would otherwise have called it terminal, so a
     * future refactor that drops that catch cannot quietly land back on a Retry prompt.
     */
    @Test
    fun upgradeRequiredIsNeverRetryable() {
        val t = UpgradeRequiredException("upgrade_required", "min version 0.22.0")
        assertFalse(importPushRetryable(t))
        assertEquals(HouseholdCopy.UPGRADE_REQUIRED, importPushError(t))
    }
}
