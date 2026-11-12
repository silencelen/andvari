package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.LifecycleNotice
import io.silencelen.andvari.core.client.LifecycleNoticeCopy
import io.silencelen.andvari.core.client.SyncEngine
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The iOS app says what Android says about a vault's lifecycle (spec 03 §11): core's [LifecycleNoticeCopy] is pinned
 * here to this app's own `noticeBody`, kind by kind, so neither can drift from the other.
 */
class LifecycleNoticeParityTest {
    private fun notice(kind: String, reason: String? = null, parked: Int? = null, purgeAt: Long? = null, mine: Boolean = false, by: String? = null) =
        LifecycleNotice("n1", "v1", "Household", kind, purgeAt = purgeAt, parkedCount = parked, reason = reason, becameMine = mine, byLabel = by)

    @Test
    fun everyKindSaysTheSameOnBothApps() {
        val notices = listOf(
            notice("deleted"), notice("deleted", purgeAt = 1_794_355_200_000, parked = 3),
            notice("removed"), notice("removed", SyncEngine.ALREADY_RECORDED), notice("removed", SyncEngine.REMOVED_LEGACY),
            notice("left"), notice("left", SyncEngine.LEFT_UNPROVEN), notice("left", SyncEngine.ALREADY_RECORDED),
            notice("restored"), notice("transfer-complete"), notice("transfer-complete", mine = true), notice("transfer-anomaly"),
            notice("replay-denied", parked = 2), notice("replay-denied", SyncEngine.REMOVAL_REPLAY),
            notice("added"), notice("added", by = "Alice"), notice("grant-anomaly", "signer_not_pinned_key"), notice("grant-anomaly", "vk_mismatch"),
            notice("write-rejected", "unknown_attachment", parked = 2), notice("vk-mismatch"), notice("key-unreadable"),
            notice("wrong-vault"), notice("bad-id"), notice("anomaly"),
            LifecycleNotice("n2", "v2", "", "restored"),
        )
        for (n in notices) {
            assertEquals(noticeBody(n), LifecycleNoticeCopy.body(n, ::fmtDay, "Sharing → the trash icon"), "${n.kind} / ${n.reason}")
        }
    }
}
