package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.client.items.DurableCache
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Lock notices the apps can tell apart (one of the Android app's needs from core): the content's notice has a kind,
 * and what a lock cut short before it finished (a copy into a vault with its counts, a move, a delete, a file, a
 * restore) is told at the next unlock, each as a [LockCut], so an app keeps no line of its own for it. And a save
 * refused for space says whose space it is.
 */
class LockCutNoticeTest {
    private class Disk : KeptStorage {
        val records = HashMap<String, InMemoryFillSnapshots>()
        val blobSets = HashMap<String, InMemoryBlobs>()
        override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { InMemoryFillSnapshots() }
        override fun blobs(name: String): BlobStore = blobSets.getOrPut(name) { InMemoryBlobs() }
    }

    private class TestHost(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = ORIGIN
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = true
    }

    private fun unlock(r: ItemRig): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = r.crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(r.userId, Bytes.toB64(identity.publicKey), "instance", r.personal, 0), "00".repeat(32))
        return OpenedAccount(r.userId, ByteArray(32) { 1 }, identity, r.crypto.signKeypairFromSeed(seed), genesis, r.personal, ByteArray(32) { 7 })
    }

    private inner class Ctx {
        val r = ItemRig(DurableCache())
        val stores = ContentStores(r.crypto, Disk(), InMemorySaveQueue())
        val account = unlock(r)
        val c: EngineVaultContent = run {
            r.server.echo = true
            r.server.journal = true
            EngineVaultContent(r.engine, r.crypto, TestHost(r), stores.keeping(account, ORIGIN, offlineCacheAllowed = true))
        }

        fun lock() {
            c.close()
            r.engine.close()
            account.wipe()
        }

        fun reopened(): EngineVaultContent = EngineVaultContent(r.restarted(), r.crypto, TestHost(r), stores.keeping(unlock(r), ORIGIN, offlineCacheAllowed = true))

        suspend fun saved(name: String): String {
            check(c.saveLogin(null, login(name), null) == ActionResult.Ok)
            return c.state.items.first { it.name == name }.itemId
        }

        /** [call], with a lock landing while the first server call on [route] waits; its answer. */
        suspend fun lockedDuring(route: String, call: suspend () -> ActionResult): ActionResult = kotlinx.coroutines.coroutineScope {
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            var held = false
            r.server.hold = { which ->
                if (which == route && !held) {
                    held = true
                    entered.complete(Unit)
                    release.await()
                }
            }
            val run = async { call() }
            entered.await()
            lock()
            release.complete(Unit)
            run.await().also { r.server.hold = null }
        }
    }

    private fun login(name: String) = LoginInput(name, "me", "a-secret-pw", listOf("https://example.com"), "", "", false)

    private fun cutsOf(c: VaultContent): List<LockCut> = c.state.lockCut

    private fun kindOf(c: VaultContent): ContentNoticeKind? = c.state.noticeKind

    private fun assertSaid(c: VaultContent, kind: LockCutKind, name: String, key: CopyKey) {
        assertEquals(ContentNoticeKind.LOCK, kindOf(c))
        val cut = cutsOf(c).single()
        assertEquals(kind, cut.kind)
        assertEquals(name, cut.name)
        val said = c.state.notice!!
        assertEquals(cut.line, said)
        assertTrue(said.contains(name), said)
        assertTrue(said.startsWith(key.english.substringBefore("{")), said)
        assertTrue(!said.contains("a-secret-pw"), said)
    }

    @Test
    fun aDeleteAMoveACopyAndARestoreALockCutShort_areEachToldAtTheNextUnlock_once() = runBlocking<Unit> {
        Ctx().run {
            val id = saved("Bin me")
            assertEquals(ActionResult.NotDone(null), lockedDuring("push") { c.deleteItem(id) })
            val next = reopened()
            assertSaid(next, LockCutKind.ITEM_DELETE, "Bin me", CopyKey.LOCK_CUT_DELETE)
            next.dismissNotice()
            assertNull(next.state.noticeKind)
            assertEquals(emptyList(), cutsOf(next))
            assertNull(reopened().state.notice, "said once")
        }
        Ctx().run {
            r.openShared()
            c.refresh()
            val id = saved("Mover")
            lockedDuring("push") { c.moveOrCopyItem(id, r.shared, true) }
            val next = reopened()
            assertSaid(next, LockCutKind.MOVE, "Mover", CopyKey.LOCK_CUT_MOVE)
            assertTrue(cutsOf(next).single().target.isNotEmpty())
        }
        Ctx().run {
            r.openShared()
            c.refresh()
            val id = saved("Copier")
            lockedDuring("push") { c.moveOrCopyItem(id, r.shared, false) }
            assertSaid(reopened(), LockCutKind.ITEM_COPY, "Copier", CopyKey.LOCK_CUT_COPY_ITEM)
        }
        Ctx().run {
            val id = saved("Back again")
            c.deleteItem(id)
            c.openTrash()
            lockedDuring("restore") { c.restoreFromTrash(id) }
            assertSaid(reopened(), LockCutKind.RESTORE, "Back again", CopyKey.LOCK_CUT_RESTORE)
        }
    }

    @Test
    fun aCopyIntoThePersonalVaultALockCutShort_isToldWithItsCounts() = runBlocking<Unit> {
        Ctx().run {
            r.openShared(items = listOf(r.itemRow(r.id(), r.shared, r.sharedKey), r.itemRow(r.id(), r.shared, r.sharedKey)))
            c.refresh()
            lockedDuring("push") { c.saveVaultItemsToPersonal(r.shared) }
            val next = reopened()
            assertEquals(ContentNoticeKind.LOCK, kindOf(next))
            val cut = cutsOf(next).single()
            assertEquals(LockCutKind.PERSONAL_COPY, cut.kind)
            assertEquals(2, cut.total)
            assertTrue(cut.done in 0..2)
            // Its own line (a count of one has its own key, CountOfOneLinesTest), never the one that promises no duplicates.
            assertEquals(ContentCopy.lockCut(cut), next.state.notice)
            if (cut.done != 1) assertTrue(next.state.notice!!.contains("${cut.done} of 2"), next.state.notice)
        }
    }

    @Test
    fun aFileALockTookWhileItWasBeingAdded_isToldByItsName_andASaveStillByItsOwnLine() = runBlocking<Unit> {
        Ctx().run {
            c.openAttachmentDraft(null)
            val adding = async { c.addAttachment("passport.pdf", ByteArray(4 * 1024 * 1024) { 3 }) }
            yield()
            lock()
            assertEquals(ActionResult.NotDone(null), adding.await())
            // A save asked for once the content closed is the save's own line, of the same kind.
            c.saveLogin(null, login("Typed last"), null)
            val next = reopened()
            assertEquals(ContentNoticeKind.LOCK, kindOf(next))
            assertEquals(listOf(LockCutKind.SAVE to "Typed last", LockCutKind.FILE to "passport.pdf"), cutsOf(next).map { it.kind to it.name })
            assertEquals(cutsOf(next).joinToString(" ") { it.line }, next.state.notice)
        }
    }

    @Test
    fun theFakeRaisesEachNotice_andItsContentSurvivesALock() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val id = c.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Kept", "me", "pw", "")
        c.setOffline(true)
        c.saveLogin(id, login("Kept, edited"), FakeVaultContent.PERSONAL_VAULT_ID)
        c.close()
        // Each kind of item 2, raised by a screen test, said once at the next unlock.
        // An import with 200 of 203 saved (one saved has its own line: ImportCutShortTest).
        for (kind in LockCutKind.entries) c.raiseLockCut(kind, "N-$kind", "Personal", if (kind == LockCutKind.CSV_IMPORT) 200 else 1, if (kind == LockCutKind.CSV_IMPORT) 203 else 3)
        val next = c.reopened()
        assertEquals(ContentNoticeKind.LOCK, kindOf(next))
        assertEquals(LockCutKind.entries.toList(), cutsOf(next).map { it.kind })
        assertTrue(next.state.notice!!.contains(ContentCopy.unsavedAtLock(emptyList(), 200, 3)), next.state.notice)
        // LOCK_CUT_COPY's count, whatever its words: a lower bound, never an exact number.
        assertTrue(next.state.notice!!.contains("at least 1 of 3", ignoreCase = true), next.state.notice)
        assertNull(next.reopened().state.notice, "said once")
        // The device copy and the queue survived the lock.
        assertEquals("Kept, edited", next.itemDetail(id)?.name)
        assertEquals(1, next.state.queued)

        next.raisePersonalKept()
        assertEquals(ContentCopy.PERSONAL_KEPT, next.state.vaultNotices.single().text)
        next.setOffline(false)
        next.failNextTrashRead()
        assertEquals(ActionResult.Failed(ContentCopy.TRASH_LIST_INCOMPLETE), next.openTrash())
    }

    @Test
    fun noticesHaveKinds() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.refresh()
        assertEquals(ContentNoticeKind.DONE, kindOf(c))
        c.setOffline(true)
        c.saveLogin(null, login("Queued"), null)
        assertEquals(ContentNoticeKind.QUEUED, kindOf(c))
        assertEquals(ContentCopy.SAVE_OFFLINE, c.state.notice)
        c.dismissNotice()
        assertNull(kindOf(c))
    }

    @Test
    fun aSaveRefusedForSpace_saysWhoseSpaceItIs() = runBlocking<Unit> {
        val family = "00000000-0000-4000-8000-0000000000aa"
        val mine = "00000000-0000-4000-8000-0000000000cc"
        val c = FakeVaultContent()
        c.addSharedVault(family, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        c.addSharedVault(mine, "Mine", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        val full = ItemFailure.Refused("quota_exceeded", 413)
        fun said(r: ActionResult) = (r as ActionResult.Failed).message

        c.failNextWith(full)
        val personal = said(c.saveLogin(null, login("P"), null))
        assertEquals(ContentCopy.OUT_OF_SPACE + " " + CopyKey.OWNER_OUT_OF_SPACE_YOURS.english, personal)
        assertTrue(ContentCopy.isOutOfSpace(personal))
        c.failNextWith(full)
        assertEquals(ContentCopy.OUT_OF_SPACE + " " + CopyKey.OWNER_OUT_OF_SPACE_YOURS.english, said(c.saveLogin(null, login("M"), mine)))
        c.failNextWith(full)
        assertEquals(ContentCopy.OUT_OF_SPACE + " " + CopyKey.OWNER_OUT_OF_SPACE_THEIRS.english, said(c.saveLogin(null, login("F"), family)))
    }

    private companion object {
        const val ORIGIN = "https://vault.example.com"
    }
}
