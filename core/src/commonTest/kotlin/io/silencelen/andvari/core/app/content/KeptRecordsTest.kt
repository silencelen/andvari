package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.PendingSave
import io.silencelen.andvari.core.app.VaultMoves
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the vault's content keeps across a lock, sealed to the new account type ([OpenedAccount]): an unfinished move
 * and a save with files a lock cut short are finished by the next unlock's instance. A locked (wiped) account is
 * never an unreadable record: nothing kept is dropped, replaced or carried over because the app locked.
 */
class KeptRecordsTest {
    private class Stores {
        val moves = InMemoryFillSnapshots()
        val keptSaves = InMemoryFillSnapshots()
        val files = InMemoryBlobs()
        val applied = InMemoryFillSnapshots()
        val queue = InMemorySaveQueue()
    }

    /** One unlock of the same account: the same UVK and identity, a new object (the session keeper opens it anew). */
    private fun unlock(r: ItemRig): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = r.crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(r.userId, Bytes.toB64(identity.publicKey), "instance", r.personal, 0), "00".repeat(32))
        return OpenedAccount(r.userId, ByteArray(32) { 1 }, identity, r.crypto.signKeypairFromSeed(seed), genesis, r.personal, ByteArray(32) { 7 })
    }

    private class TestHost(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
    }

    private fun content(r: ItemRig, account: OpenedAccount, s: Stores, restarted: Boolean): EngineVaultContent {
        r.server.echo = true
        r.server.journal = true
        val engine = if (restarted) r.restarted() else r.engine
        return EngineVaultContent(engine, r.crypto, TestHost(r), ContentKeeping(account, s.moves, s.keptSaves, s.files, s.applied, s.queue))
    }

    private fun login(name: String) = LoginInput(name, "me", "pw", listOf("https://example.com"), "", "", false)

    @Test
    fun aMoveALockCutShort_isReplayedUnderTheSamePlan_andALockedAccountLeavesItsRecordAlone() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared()
        val s = Stores()
        val first = unlock(r)
        val a = content(r, first, s, restarted = false)
        a.saveLogin(null, login("Wifi"), null)
        val id = a.state.items.single().itemId
        r.server.offlineAfterNextPush = true // the copy lands; the delete leg gets no answer
        assertEquals(ContentCopy.MOVE_RETRY, (a.moveOrCopyItem(id, r.shared, true) as ActionResult.Failed).message)
        val copyId = r.server.pushes.last().single().mutationId
        val kept = assertNotNull(s.moves.bytes, "the unfinished move is kept, sealed")

        // The app locks: the instance closes and the account's keys are wiped.
        a.close()
        first.wipe()
        r.server.offline = false
        // Anything that still runs on the locked account reads nothing, writes nothing and removes nothing.
        val stale = content(r, first, s, restarted = false)
        stale.cancelMove(id)
        assertEquals(ActionResult.NotDone(null), stale.moveOrCopyItem(id, r.shared, true))
        assertContentEquals(kept, s.moves.bytes, "a lock is not a cancel, and not an unreadable record")
        assertNull(stale.state.notice)
        stale.close()

        // The next unlock finishes it: the same plan, so the copy is not made twice.
        val b = content(r, unlock(r), s, restarted = true)
        b.syncQuietly()
        val before = r.server.pushes.size
        assertEquals(ActionResult.Ok, b.moveOrCopyItem(id, r.shared, true))
        val replay = r.server.pushes.drop(before).flatten()
        assertEquals(listOf(copyId), replay.filter { it.op == MutationOp.PUT }.map { it.mutationId }, "the kept copy leg is replayed, and no other copy made")
        assertEquals(listOf(id), replay.filter { it.op == MutationOp.DELETE }.map { it.itemId })
        assertEquals(1, b.state.items.size)
        assertEquals(r.shared, b.itemDetail(b.state.items.single().itemId)!!.vaultId)
        assertNull(s.moves.bytes, "done: the record goes")
    }

    @Test
    fun aKeptMoveWhoseCopyWasDeletedSince_isPlannedAfresh() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared()
        val s = Stores()
        val a = content(r, unlock(r), s, restarted = false)
        a.saveLogin(null, login("Wifi"), null)
        val id = a.state.items.single().itemId
        r.server.offlineAfterNextPush = true
        a.moveOrCopyItem(id, r.shared, true)
        val copyId = r.server.pushes.last().single().mutationId
        r.server.offline = false
        a.syncQuietly()
        val copy = a.state.items.single { a.itemDetail(it.itemId)!!.vaultId == r.shared }.itemId
        assertEquals(ActionResult.Ok, a.deleteItem(copy))
        a.close()
        val b = content(r, unlock(r), s, restarted = true)
        val before = r.server.pushes.size
        assertEquals(ActionResult.Ok, b.moveOrCopyItem(id, r.shared, true))
        val puts = r.server.pushes.drop(before).flatten().filter { it.op == MutationOp.PUT }
        assertEquals(1, puts.size)
        assertTrue(puts.single().mutationId != copyId, "a plan whose copy is gone is never replayed (M3)")
        assertEquals(1, b.state.items.size)
    }

    @Test
    fun aSaveWithFilesALockCutShort_isFinishedAfterTheNextUnlocksFirstSync() = runBlocking<Unit> {
        val r = ItemRig()
        val s = Stores()
        val first = unlock(r)
        val a = content(r, first, s, restarted = false)
        a.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, a.addAttachment("scan.pdf", "page one".encodeToByteArray()))
        r.server.offline = true
        assertEquals(ContentCopy.SAVE_FAILED_OFFLINE, (a.saveLogin(null, login("Passport"), null) as ActionResult.Failed).message)
        val kept = assertNotNull(s.keptSaves.bytes)
        assertEquals(1, s.files.ids().size, "the file is set aside, encrypted")
        a.close()
        first.wipe()
        r.server.offline = false

        // A sync on the locked account decides nothing about the kept save.
        val stale = content(r, first, s, restarted = false)
        stale.syncQuietly()
        assertContentEquals(kept, s.keptSaves.bytes)
        assertEquals(1, s.files.ids().size)
        assertTrue(r.server.attachments.isEmpty())
        stale.close()

        val b = content(r, unlock(r), s, restarted = true)
        assertEquals(ActionResult.Ok, b.syncQuietly())
        assertEquals(ContentCopy.KEPT_SAVE_DONE, b.state.notice)
        val item = b.state.items.single()
        assertEquals("Passport", item.name)
        assertEquals(listOf("scan.pdf"), b.itemDetail(item.itemId)!!.attachments.map { it.name })
        assertEquals("page one", b.readAttachment(item.itemId, r.server.attachments.keys.single()).bytes!!.decodeToString())
        assertNull(s.keptSaves.bytes, "done: the record goes")
        assertTrue(s.files.ids().isEmpty(), "and the files set aside for it")
    }

    @Test
    fun closingTheEditor_givesItsKeptSaveUp() = runBlocking<Unit> {
        val r = ItemRig()
        val s = Stores()
        val a = content(r, unlock(r), s, restarted = false)
        a.openAttachmentDraft(null)
        a.addAttachment("a.txt", "x".encodeToByteArray())
        r.server.offline = true
        a.saveLogin(null, login("Doc"), null)
        assertNotNull(s.keptSaves.bytes)
        a.closeAttachmentDraft()
        assertNull(s.keptSaves.bytes)
        assertTrue(s.files.ids().isEmpty())
    }

    @Test
    fun aRecordThisVersionCannotRead_isRemovedAndSaid_butOnlyWhileUnlocked() = runBlocking<Unit> {
        val r = ItemRig()
        val s = Stores()
        s.moves.write(ByteArray(80) { 3 })
        val locked = unlock(r).also { it.wipe() }
        content(r, locked, s, restarted = false).syncQuietly()
        assertNotNull(s.moves.bytes, "locked: nothing is told about it, and it stays")
        val b = content(r, unlock(r), s, restarted = false)
        b.syncQuietly()
        assertNull(s.moves.bytes)
        assertEquals(ContentCopy.earlierRecords(1), b.state.notice)
    }

    @Test
    fun aSealedBoxToTheIdentityKey_isNeverTakenForAKeptMove() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared()
        val s = Stores()
        val a = content(r, unlock(r), s, restarted = false)
        a.saveLogin(null, login("Wifi"), null)
        a.saveLogin(null, login("Decoy"), r.shared)
        val id = a.state.items.single { it.name == "Wifi" }.itemId
        val decoy = a.state.items.single { it.name == "Decoy" }.itemId
        a.close()
        // Anyone holding the account's public identity key can seal a "kept move" whose copy is an item in the target.
        val account = unlock(r)
        val plan = io.silencelen.andvari.core.client.items.MovePlan("g", id, r.personal, 1, r.shared, decoy, true, emptyList())
        val plans = Json.encodeToString(MapSerializer(String.serializer(), KeptMove.serializer()), mapOf("$id|${r.shared}|true" to KeptMove(KeptGesture.of(plan))))
        s.moves.write(r.crypto.sealTo(account.identityPub(), plans.encodeToByteArray()))

        val b = content(r, account, s, restarted = true)
        b.syncQuietly()
        assertNull(s.moves.bytes, "not a record: removed")
        assertEquals(ContentCopy.earlierRecords(1), b.state.notice)
        assertEquals(ActionResult.Ok, b.moveOrCopyItem(id, r.shared, true), "the forged record never answers \"already copied\"")
        assertEquals(r.shared, b.itemDetail(id)?.vaultId ?: b.itemDetail(b.state.items.single { it.name == "Wifi" }.itemId)!!.vaultId)
    }

    @Test
    fun theKeptShapesAreTheOldControllersFieldForField() {
        val json = Json { ignoreUnknownKeys = true }
        val plan = io.silencelen.andvari.core.client.items.MovePlan("g", "i", "v1", 4, "v2", "n", true, listOf(io.silencelen.andvari.core.client.items.MovedAttachment("a", "b", "k", "f.txt", 3)))
        val mine = json.encodeToString(MapSerializer(String.serializer(), KeptMove.serializer()), mapOf("i|v2|true" to KeptMove(KeptGesture.of(plan), copySeen = true)))
        val old = json.decodeFromString(MapSerializer(String.serializer(), VaultMoves.Kept.serializer()), mine).getValue("i|v2|true")
        assertEquals("g", old.gesture.gestureId)
        assertEquals("n", old.gesture.newItemId)
        assertTrue(old.gesture.del && old.copySeen)
        val back = json.decodeFromString(MapSerializer(String.serializer(), KeptMove.serializer()), json.encodeToString(MapSerializer(String.serializer(), VaultMoves.Kept.serializer()), mapOf("k" to old)))
        assertEquals(plan, back.getValue("k").gesture.plan())

        val save = KeptSave("s", null, "n", "v", 0, ItemDoc(type = "login", name = "x"), listOf("f"), listOf("r"))
        val oldSave = json.decodeFromString(ListSerializer(PendingSave.serializer()), json.encodeToString(ListSerializer(KeptSave.serializer()), listOf(save))).single()
        assertEquals(listOf("f"), oldSave.newFiles)
        assertEquals(listOf("r"), oldSave.removedFiles)
        assertEquals("n", oldSave.newItemId)
    }
}
