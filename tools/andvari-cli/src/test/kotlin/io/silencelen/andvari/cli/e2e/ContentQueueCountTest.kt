package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.content.ContentCopy
import io.silencelen.andvari.core.app.content.ContentHost
import io.silencelen.andvari.core.app.content.EngineVaultContent
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * "Changes waiting to send" on the content, over the real item engine and the real server: after each kind of write,
 * online, the count is 0; a write made offline is counted, and the next sync after the network returns brings it to 0.
 */
class ContentQueueCountTest {
    private fun content(s: TestServer, a: AccountSession): EngineVaultContent = EngineVaultContent(a.items, a.host.crypto, object : ContentHost {
        override fun wallMs(): Long = s.now()
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = a.origin
        override fun userId(): String = a.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = true
    })

    private fun login(name: String) = LoginInput(name, "u", "p-$name", listOf("https://$name.test"), "", "", false)

    private fun EngineVaultContent.idOf(name: String): String = assertNotNull(state.items.firstOrNull { it.name == name }, name).itemId

    @Test fun aDeleteOnline_andOneOfflineThenSynced_leaveNothingWaiting() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val ah = s.switchedDevice("alice desktop")
            Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)
            val a = ah.account(s.origin)!!
            val c = content(s, a)
            assertEquals(ActionResult.Ok, c.refresh())
            assertEquals(ActionResult.Ok, c.saveLogin(null, login("router"), null))
            assertEquals(ActionResult.Ok, c.saveLogin(null, login("nas"), null))
            assertEquals(0, c.state.queued, "two saves online")

            // Online: the delete is sent and settled; nothing waits.
            assertEquals(ActionResult.Ok, c.deleteItem(c.idOf("router")))
            assertEquals(listOf("nas"), c.state.items.map { it.name })
            assertEquals(0, c.state.queued, "a delete online leaves nothing waiting")
            assertTrue(a.items.pendingSyncItemIds().isEmpty())

            // Offline: the delete waits and says so; when the network returns, the next sync sends it.
            val nas = c.idOf("nas")
            s.cut += "alice desktop"
            assertEquals(ActionResult.Ok, c.deleteItem(nas))
            assertEquals(ContentCopy.SAVE_OFFLINE, c.state.notice)
            assertEquals(1, c.state.queued, "a delete offline waits")
            assertTrue(c.state.items.isEmpty(), "and is shown at once")
            s.cut -= "alice desktop"
            assertEquals(ActionResult.Ok, c.syncQuietly())
            assertEquals(0, c.state.queued, "the sync after the network returned sent it")
            assertTrue(a.items.pendingSyncItemIds().isEmpty())
            assertTrue(c.state.items.isEmpty())

            // An edit made offline and then a delete, offline too: the delete is what the server ends with.
            assertEquals(ActionResult.Ok, c.saveLogin(null, login("vpn"), null))
            val vpn = c.idOf("vpn")
            s.cut += "alice desktop"
            assertEquals(ActionResult.Ok, c.saveLogin(vpn, login("vpn"), null))
            assertEquals(ActionResult.Ok, c.deleteItem(vpn))
            assertEquals(1, c.state.queued)
            s.cut -= "alice desktop"
            assertEquals(ActionResult.Ok, c.syncQuietly())
            assertEquals(0, c.state.queued, "an offline edit and delete, sent")
            assertTrue(c.state.items.isEmpty(), "the delete won over the edit made before it")

            // An edit made offline, then a delete once the network is back but before any sync.
            assertEquals(ActionResult.Ok, c.saveLogin(null, login("wifi"), null))
            val wifi = c.idOf("wifi")
            s.cut += "alice desktop"
            assertEquals(ActionResult.Ok, c.saveLogin(wifi, login("wifi"), null))
            s.cut -= "alice desktop"
            assertEquals(ActionResult.Ok, c.deleteItem(wifi))
            assertEquals(0, c.state.queued, "a delete after an offline edit")
            assertTrue(c.state.items.isEmpty())

            // A new item made offline and deleted before it was ever sent: nothing is left to send.
            s.cut += "alice desktop"
            assertEquals(ActionResult.Ok, c.saveLogin(null, login("draft"), null))
            assertEquals(1, c.state.queued)
            assertEquals(ActionResult.Ok, c.deleteItem(c.idOf("draft")))
            assertEquals(0, c.state.queued, "a never-sent item deleted")
            s.cut -= "alice desktop"
            assertEquals(ActionResult.Ok, c.syncQuietly())
            assertEquals(0, c.state.queued)
            assertTrue(c.state.items.isEmpty())
            c.close()
        } }
    }

    /**
     * The desktop's first run: the detail view leaves the moment the item it shows is deleted, which cancels the scope
     * running the delete while its push is on the wire. The delete still finishes, and nothing waits.
     */
    @Test fun aDeleteWhoseScreenLeavesMidPush_isSettled() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val ah = s.switchedDevice("alice desktop")
            Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)
            val a = ah.account(s.origin)!!
            val c = content(s, a)
            assertEquals(ActionResult.Ok, c.refresh())
            assertEquals(ActionResult.Ok, c.saveLogin(null, login("router"), null))
            val router = c.idOf("router")
            coroutineScope {
                // Runs until the push's first real suspension, on the wire; then its screen goes.
                val screen = launch(start = CoroutineStart.UNDISPATCHED) { c.deleteItem(router) }
                screen.cancel()
                screen.join()
            }
            // The intent ran to its end in the background: wait for it, as the next screen would.
            Await.untilSuspending("the delete its screen left behind to finish (the content no longer busy)", there = { "busy, ${c.state.queued} queued, items ${c.state.items.size}" }) {
                if (c.state.busy) null else Unit
            }
            assertTrue(c.state.items.isEmpty())
            assertEquals(0, c.state.queued, "the delete was sent and settled after its screen left")
            assertTrue(a.items.pendingSyncItemIds().isEmpty())
            c.close()
        } }
    }

    @Test fun everyOtherWrite_leavesNothingWaiting() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val ah = s.switchedDevice("alice desktop")
            Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)
            val a = ah.account(s.origin)!!
            val c = content(s, a)
            assertEquals(ActionResult.Ok, c.refresh())
            fun nothingWaiting(after: String) {
                assertEquals(0, c.state.queued, "after $after")
                assertTrue(a.items.pendingSyncItemIds().isEmpty(), "the engine's queue after $after")
            }
            assertEquals(ActionResult.Ok, c.saveLogin(null, login("router"), null))
            assertEquals(ActionResult.Ok, c.saveLogin(null, login("nas"), null))
            nothingWaiting("two saves")

            // An edit, then a delete and a restore from Recently deleted.
            val router = c.idOf("router")
            assertEquals(ActionResult.Ok, c.saveLogin(router, login("router"), null))
            nothingWaiting("an edit")
            assertEquals(ActionResult.Ok, c.deleteItem(router))
            nothingWaiting("a delete")
            assertEquals(ActionResult.Ok, c.openTrash())
            assertEquals(ActionResult.Ok, c.restoreFromTrash(router))
            nothingWaiting("a restore from Recently deleted")
            assertEquals(listOf("nas", "router"), c.state.items.map { it.name }.sorted())

            // A delete and a purge.
            val nas = c.idOf("nas")
            assertEquals(ActionResult.Ok, c.deleteItem(nas))
            assertEquals(ActionResult.Ok, c.openTrash())
            assertEquals(ActionResult.Ok, c.purgeFromTrash(nas))
            nothingWaiting("a purge")
            c.closeTrash()

            // A file added in the editor, then taken off.
            c.openAttachmentDraft(router)
            assertEquals(ActionResult.Ok, c.addAttachment("a.txt", "hello".encodeToByteArray()))
            assertEquals(ActionResult.Ok, c.saveLogin(router, login("router"), null))
            nothingWaiting("a file added")
            val file = assertNotNull(a.items.item(router)).doc.attachments.single()
            c.openAttachmentDraft(router)
            c.removeAttachment(file.id)
            assertEquals(ActionResult.Ok, c.saveLogin(router, login("router"), null))
            nothingWaiting("a file removed")
            assertTrue(assertNotNull(a.items.item(router)).doc.attachments.isEmpty())

            // A move into a shared vault, and a copy back.
            val family = a.ok(null, io.silencelen.andvari.core.client.log.LogAction.Create("Family"))
            assertEquals(ActionResult.Ok, c.syncQuietly())
            assertEquals(ActionResult.Ok, c.moveOrCopyItem(router, family, move = true))
            nothingWaiting("a move")
            val moved = c.state.items.single { it.name == "router" }
            assertEquals(family, assertNotNull(a.items.item(moved.itemId)).vaultId)
            assertEquals(ActionResult.Ok, c.moveOrCopyItem(moved.itemId, assertNotNull(a.personalVaultId), move = false))
            nothingWaiting("a copy")
            c.close()
        } }
    }
}
