package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.ok
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A restore or a delete for good the server answered as done and did not perform is said: the next read of the trash
 * still lists the item, and a notice of its own kind says the action did not happen on the server, once, by name.
 */
class TrashNotDoneTest {
    private class Host(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
    }

    /** Two items this device held, deleted on the server and pulled as tombstones; the content over the engine. */
    private fun rig(): Triple<ItemRig, EngineVaultContent, List<String>> {
        val r = ItemRig()
        val ids = listOf(r.id(), r.id())
        val live = ids.mapIndexed { i, id -> r.itemRow(id, r.personal, r.personalKey, ItemDoc(type = "login", name = "Bank $i", login = LoginData(username = "ana", password = "made-up")), rev = 10L + i) }
        live.forEach { r.server.itemRows[it.itemId] = it }
        r.server.rev = 100
        r.server.queue.add(r.response(100, items = live))
        runBlocking { r.engine.sync().ok() }
        val tombs = ids.mapIndexed { i, id -> r.tombstone(id, r.personal, 200L + i) }
        tombs.forEach { r.server.itemRows[it.itemId] = it }
        r.server.rev = 300
        r.server.queue.add(r.response(300, items = tombs))
        runBlocking { r.engine.sync().ok() }
        r.server.echo = true
        return Triple(r, EngineVaultContent(r.engine, r.crypto, Host(r)), ids)
    }

    @Test
    fun aRestoreTheServerAnsweredDoneAndDidNotStore_isSaidAtTheNextReadOfTheTrash_once() = runBlocking<Unit> {
        val (r, c, ids) = rig()
        r.server.trashActionsStoreNothing = true
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ActionResult.Ok, c.restoreFromTrash(ids[0]))
        assertEquals(ContentNoticeKind.DONE, c.state.noticeKind, "the server said done")
        c.dismissNotice()

        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ContentNoticeKind.NOT_DONE_ON_SERVER, c.state.noticeKind)
        assertEquals(ContentCopy.trashNotDone(listOf(true to "Bank 0")), c.state.notice)
        assertTrue(c.state.trash!!.any { it.itemId == ids[0] }, "it is still in the trash")
        c.dismissNotice()

        assertEquals(ActionResult.Ok, c.openTrash())
        assertNull(c.state.notice, "said once")
    }

    @Test
    fun aDeleteForGoodTheServerAnsweredDoneAndDidNotPerform_isSaid() = runBlocking<Unit> {
        val (r, c, ids) = rig()
        r.server.trashActionsStoreNothing = true
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ActionResult.Ok, c.purgeFromTrash(ids[1]))
        assertTrue(c.state.trash!!.none { it.itemId == ids[1] }, "the open trash takes the server's word")
        c.dismissNotice()
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ContentNoticeKind.NOT_DONE_ON_SERVER, c.state.noticeKind)
        assertEquals(ContentCopy.trashNotDone(listOf(false to "Bank 1")), c.state.notice)
    }

    @Test
    fun aRestoreThatAnotherDeviceDeletedAgain_isSaidAsInTheTrashAgain_andAccusesNobody() = runBlocking<Unit> {
        val (r, c, ids) = rig()
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ActionResult.Ok, c.restoreFromTrash(ids[0]))
        assertEquals(listOf("Bank 0"), c.state.items.map { it.name }, "the restore was stored and served live")
        c.dismissNotice()

        // A second device of the account (or another member) deletes it again, after the restore.
        r.server.rev += 1
        r.server.itemRows[ids[0]] = r.tombstone(ids[0], r.personal, r.server.rev)
        r.engine.sync().ok()
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ContentNoticeKind.IN_TRASH_AGAIN, c.state.noticeKind, "not the server's fault")
        assertEquals(ContentCopy.trashInAgain(listOf("Bank 0")), c.state.notice)
        c.dismissNotice()
        assertEquals(ActionResult.Ok, c.openTrash())
        assertNull(c.state.notice, "said once")
    }

    @Test
    fun theRecordOfARestoreOutlivesALockBeforeTheNextReadOfTheTrash() = runBlocking<Unit> {
        val (r, c, ids) = rig()
        r.server.trashActionsStoreNothing = true
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ActionResult.Ok, c.restoreFromTrash(ids[0]))
        assertEquals(ActionResult.Ok, c.purgeFromTrash(ids[1]))
        // A lock between the actions and the next read of the trash; the next unlock opens the same account's cache.
        c.close()
        r.engine.close()
        val after = EngineVaultContent(r.restarted(), r.crypto, Host(r))
        assertEquals(ActionResult.Ok, after.openTrash())
        assertEquals(ContentNoticeKind.NOT_DONE_ON_SERVER, after.state.noticeKind)
        // The kept record holds no name, and the envelopes kept for the trash went when the server answered "done".
        assertEquals(ContentCopy.trashNotDone(listOf(true to null, false to null)), after.state.notice, "both checked after the lock")
        assertTrue("an item" in after.state.notice.orEmpty() && "“an item”" !in after.state.notice.orEmpty(), "no name is known, and the plain words stand unquoted")
    }

    @Test
    fun anHonestServer_raisesNoSuchNotice() = runBlocking<Unit> {
        val (_, c, ids) = rig()
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ActionResult.Ok, c.restoreFromTrash(ids[0]))
        assertEquals(ActionResult.Ok, c.purgeFromTrash(ids[1]))
        c.dismissNotice()
        assertEquals(ActionResult.Ok, c.openTrash())
        assertNull(c.state.notice)
        assertTrue(c.state.trash!!.isEmpty())
        assertEquals(listOf("Bank 0"), c.state.items.map { it.name })
    }

    @Test
    fun theFakePlaysAServerThatStoresNothing() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val id = c.seedDeleted(FakeVaultContent.PERSONAL_VAULT_ID, "Old bank", "ana", 2)
        c.trashActionsStoreNothing(true)
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ActionResult.Ok, c.restoreFromTrash(id))
        c.dismissNotice()
        assertEquals(ActionResult.Ok, c.openTrash())
        assertEquals(ContentNoticeKind.NOT_DONE_ON_SERVER, c.state.noticeKind)
        assertEquals(ContentCopy.trashNotDone(listOf(true to "Old bank")), c.state.notice)
    }
}
