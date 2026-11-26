package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.client.items.ItemNotice
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Recovered edits the server refused when their vault came back: "…while the vault was deleted" only where it was. A
 * vault the server took away with no verified reason, or one the account is a member of again after a removal or a
 * departure, has a line of its own.
 */
class ReplayDeniedLinesTest {
    private fun line(reason: String?, count: Int) =
        ContentCopy.notice(ItemNotice("n1", "00000000-0000-4000-8000-0000000000aa", "Family", ItemNotice.REPLAY_DENIED, count, reason)).first

    private val family = ContentCopy.Slot("Family", true)

    @Test
    fun onlyADeletedVaultsRefusedEditsSayTheVaultWasDeleted() {
        assertEquals(ContentCopy.fillNames(CopyKey.NOTICE_REPLAY_DENIED_ONE, family), line(ItemNotice.DELETED, 1))
        assertEquals(ContentCopy.fillNames(CopyKey.NOTICE_REPLAY_DENIED_MANY, ContentCopy.Slot("3", true), family), line(ItemNotice.DELETED, 3))
        for (reason in listOf(ItemNotice.WITHHELD, ItemNotice.REMOVED, ItemNotice.LEFT, null)) {
            assertEquals(ContentCopy.fillNames(CopyKey.NOTICE_REPLAY_DENIED_BACK_ONE, family), line(reason, 1), "$reason")
            assertEquals(ContentCopy.fillNames(CopyKey.NOTICE_REPLAY_DENIED_BACK_MANY, ContentCopy.Slot("3", true), family), line(reason, 3), "$reason")
        }
    }
}
