package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.client.items.DurableCache
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A copy into the personal vault that a lock cut short is told with a line of its own, never "that makes no
 * duplicates": each copy gets a fresh id, so a run after the unlock copies every item again, the ones copied before the
 * lock too, and the device shows exactly the copies the server holds.
 */
class CopyAgainAfterLockTest {
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

    @Test
    fun aCopyIntoThePersonalVaultALockCutShort_isSaidAsCopyingEverythingAgain_andCopiedAgainShowsOnlyWhatTheServerHolds() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val stores = ContentStores(r.crypto, Disk(), InMemorySaveQueue())
        val account = unlock(r)
        r.server.echo = true
        r.server.journal = true
        r.openShared(items = (1..3).map { r.itemRow(r.id(), r.shared, r.sharedKey) })
        val c = EngineVaultContent(r.engine, r.crypto, TestHost(r), stores.keeping(account, ORIGIN, offlineCacheAllowed = true))
        c.refresh()

        // The lock lands while the second item's copy goes to the server: that copy lands, and its answer is lost.
        var pushes = 0
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        r.server.hold = { route ->
            if (route == "push" && ++pushes == 2) {
                entered.complete(Unit)
                release.await()
            }
        }
        coroutineScope {
            val run = async { c.saveVaultItemsToPersonal(r.shared) }
            entered.await()
            c.close()
            r.engine.close()
            account.wipe()
            release.complete(Unit)
            run.await()
        }
        r.server.hold = null
        val copiedFirst = r.server.itemRows.values.count { it.vaultId == r.personal && !it.deleted }
        assertTrue(copiedFirst in 1..2, "the first run copied part: $copiedFirst")

        val next = EngineVaultContent(r.restarted(), r.crypto, TestHost(r), stores.keeping(unlock(r), ORIGIN, offlineCacheAllowed = true))
        val cut = next.state.lockCut.single()
        assertEquals(LockCutKind.PERSONAL_COPY, cut.kind)
        // Its own line (CountOfOneLinesTest names its keys), never the one that promises no duplicates.
        assertEquals(ContentCopy.lockCut(cut), next.state.notice)

        // Copied again, as the line says: every item again, the ones copied before the lock too.
        assertEquals(ActionResult.Ok, next.saveVaultItemsToPersonal(r.shared))
        val onServer = r.server.itemRows.values.filter { it.vaultId == r.personal && !it.deleted }.map { it.itemId }.toSet()
        assertEquals(copiedFirst + 3, onServer.size, "every item copied again")
        next.syncQuietly()
        val shown = next.state.items.filter { next.itemDetail(it.itemId)!!.vaultId == r.personal }.map { it.itemId }.toSet()
        assertEquals(onServer, shown, "the device shows what the server holds, no more")
    }

    private companion object {
        const val ORIGIN = "https://vault.example.com"
    }
}
