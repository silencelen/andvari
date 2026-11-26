package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.CoreLog
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.ItemVersion
import io.silencelen.andvari.core.model.wire.SyncItem
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Pull, tombstones, conflicts, the holding area, trash, history, attachments, moves and the halted mode: the item-plane
 * assertions of `SyncEngineLifecycleTest`, `SyncEngineMetaVTest`, `SyncEngineLiveItemIdsTest` and
 * `SyncEnginePersonalVaultRelabelTest`, on [ItemEngine] with a fake transport. Where the old tests verified a MAC proof,
 * these read the key source's verdict: the proof was the old trust plane, the consequence for items is what is kept.
 */
class ItemEngineLifecycleTest {
    // ==== pull: cursor, resync, rollback, tombstones, ids, homes ====

    @Test
    fun pullsFromTheCursor_andAResyncReplacesRowsButKeepsTheQueue() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val id = r.id()
        r.serve(r.itemRow(id, r.personal, r.personalKey, rev = 8))
        r.engine.sync().ok()
        assertEquals(listOf(0L, 5L), r.server.pullsSince, "the second pull starts at the first one's rev")
        r.server.offline = true
        val queued = r.engine.save(null, r.doc.copy(name = "offline")).ok()
        r.server.offline = false

        // 410: the cursor predates retained history. The snapshot is fetched first, then replaces the rows.
        val other = r.id()
        r.server.goneOnce = true
        r.server.queue.add(r.response(20, full = true, vaults = listOf(r.vaultRow(r.personal, r.personalKey, "personal", "Personal")), items = listOf(r.itemRow(other, r.personal, r.personalKey, r.doc.copy(name = "fresh"), rev = 19))))
        r.engine.sync().ok()
        assertEquals(listOf(8L, 0L), r.server.pullsSince.takeLast(2), "410, then a pull from 0")
        assertNull(r.engine.item(id), "a row the snapshot no longer lists is gone")
        assertEquals("fresh", r.engine.item(other)?.doc?.name)
        assertEquals(20, r.cache.cursor())
        assertTrue(r.server.pushes.flatten().any { it.itemId == queued.itemId }, "the offline queue survived and drained")
    }

    @Test
    fun aRevBelowTheCursor_orAnUnsolicitedFullSnapshot_isARollback_andNothingIsApplied() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.server.queue.add(r.response(3, items = listOf(r.itemRow(id, r.personal, r.personalKey))))
        assertEquals(ItemFailure.Rollback(unsolicitedFull = false), r.engine.sync().failure())
        r.server.queue.add(r.response(9, full = true, items = listOf(r.itemRow(id, r.personal, r.personalKey))))
        assertEquals(ItemFailure.Rollback(unsolicitedFull = true), r.engine.sync().failure())
        assertNull(r.engine.item(id))
        assertEquals(5, r.cache.cursor(), "local state kept")
        assertEquals(1, r.keys.reports.size, "a rolled-back answer is not even reported to the trust engine")
    }

    @Test
    fun tombstonesDelete_badIdsAreDropped_andARowUnderAnotherVaultIsQuarantinedWithOneNotice() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        assertEquals(r.shared, r.cache.itemHome(id), "the first row applied is the item's home")

        // The server re-sends the item under the personal vault (INV-HOME), twice, with a row whose id is no UUID.
        val moved = r.itemRow(id, r.personal, r.personalKey, r.doc.copy(name = "teleported"), rev = 12)
        val bad = moved.copy(itemId = "../admin")
        r.server.queue.add(r.response(13, items = listOf(moved, moved.copy(rev = 13), bad)))
        r.engine.sync().ok()
        assertEquals("Router", r.engine.item(id)?.doc?.name, "the row under another vault is not applied")
        assertEquals(r.shared, r.engine.item(id)?.vaultId)
        assertEquals(2, r.engine.quarantinedItems().size)
        val kinds = r.engine.notices().map { it.kind }
        assertEquals(1, kinds.count { it == ItemNotice.WRONG_VAULT }, "one notice per pull, however many rows")
        assertEquals(2, r.engine.notices().single { it.kind == ItemNotice.WRONG_VAULT }.count)
        assertEquals(1, r.engine.notices().single { it.kind == ItemNotice.BAD_ID }.count)

        r.server.queue.add(r.response(14, items = listOf(r.tombstone(id, r.shared, 14))))
        r.engine.sync().ok()
        assertNull(r.engine.item(id), "a tombstone under the home deletes")
        assertTrue(id !in r.engine.liveItemIds())
    }

    @Test
    fun liveItemIdsKeepsWhatItemsCannotDecrypt() = runBlocking<Unit> {
        val r = ItemRig()
        val readable = r.id()
        val newer = r.id()
        val unheld = r.id()
        val row = r.itemRow(newer, r.personal, r.personalKey)
        r.server.queue.add(
            r.response(
                9, vaults = listOf(r.vaultRow(r.shared, r.sharedKey, "shared", "Family")),
                items = listOf(r.itemRow(readable, r.personal, r.personalKey), row.copy(formatVersion = 99), r.itemRow(unheld, r.shared, r.sharedKey)),
            ),
        )
        r.engine.sync().ok()
        assertEquals(setOf(readable), r.engine.items().map { it.itemId }.toSet())
        assertEquals(setOf(readable, newer, unheld), r.engine.liveItemIds(), "a newer format and a vault with no key are still live")
        assertEquals(1, r.engine.needsUpdateCount())
    }

    @Test
    fun aServedPersonalLabel_neverMakesAVaultPersonal() = runBlocking<Unit> {
        val r = ItemRig()
        r.keys.put(r.shared, r.sharedKey, "writer")
        r.server.queue.add(r.response(9, vaults = listOf(r.vaultRow(r.shared, r.sharedKey, "personal", "Personal")), grants = listOf(r.grantRow(r.shared))))
        r.engine.sync().ok()
        val v = r.engine.vaults().single { it.vaultId == r.shared }
        assertEquals("shared", v.type, "the type follows the account genesis, never the served label")
        assertEquals(r.personal, r.engine.personalVaultId)
        assertEquals(r.personal, r.server.pushes.let { r.engine.save(null, r.doc).ok(); r.server.pushes.last().single().vaultId })
    }

    // ==== vault metadata (spec 02 §4) ====

    @Test
    fun aReplayedOlderMetaV_keepsTheNewerName_andSaysSo_butAResyncAppliesAsServed() = runBlocking<Unit> {
        val warned = ArrayList<String>()
        val r = ItemRig()
        val engine = r.restarted(CoreLog { event, _ -> warned += event })
        r.keys.put(r.shared, r.sharedKey, "owner")
        val v0 = r.vaultRow(r.shared, r.sharedKey, "shared", "Old name", rev = 2)
        val renamed = v0.copy(rev = 3, metaBlob = r.codec.renamedMeta(r.sharedKey, r.shared, v0.metaBlob, "New name"))
        r.server.queue.add(r.response(9, vaults = listOf(v0), grants = listOf(r.grantRow(r.shared, "owner"))))
        engine.sync().ok()
        r.server.queue.add(r.response(10, vaults = listOf(renamed)))
        engine.sync().ok()
        assertEquals("New name", engine.vaults().single { it.vaultId == r.shared }.name)

        r.server.queue.add(r.response(11, vaults = listOf(v0.copy(rev = 4))))
        engine.sync().ok()
        assertEquals("New name", engine.vaults().single { it.vaultId == r.shared }.name, "the replayed blob is not applied")
        assertEquals(4, engine.vaultRows().single { it.vaultId == r.shared }.rev, "the rev still applies")
        assertEquals(listOf(CoreLog.EVENT_VAULT_META_REPLAY), warned)
        assertEquals(1, engine.notices().count { it.kind == ItemNotice.META_REPLAY })

        // A resync has no held row to compare with: the snapshot applies as served.
        r.server.goneOnce = true
        r.server.queue.add(r.response(30, full = true, vaults = listOf(r.vaultRow(r.personal, r.personalKey, "personal", "Personal"), v0.copy(rev = 5)), grants = listOf(r.grantRow(r.shared, "owner"))))
        engine.sync().ok()
        assertEquals("Old name", engine.vaults().single { it.vaultId == r.shared }.name)
    }

    @Test
    fun metaV_countsOnlyAsANonNegativeInteger_andARenameCountsUpFromIt() {
        for ((text, want) in listOf("0" to 0L, "7" to 7L, "9007199254740991" to 9007199254740991L, "9007199254740992" to 0L, "-1" to 0L, "1.5" to 0L, "1e3" to 1000L, "abc" to 0L, "NaN" to 0L)) {
            assertEquals(want, ItemCodec.parseMetaV(text), text)
        }
        val r = ItemRig(firstPull = false)
        val first = r.codec.sealVaultMeta(r.sharedKey, r.shared, "A")
        val second = r.codec.renamedMeta(r.sharedKey, r.shared, first, "B")
        val third = r.codec.renamedMeta(r.sharedKey, r.shared, second, "C")
        assertEquals(listOf(0L, 1L, 2L), listOf(first, second, third).map { ItemCodec.metaVOf(r.codec.vaultMeta(r.sharedKey, r.shared, it)!!) })
        assertEquals("C", r.codec.vaultName(r.sharedKey, r.shared, third))
    }

    @Test
    fun aRenameIsSealedUnderTheVaultKeyAtTheHeldRev() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared(role = "owner")
        r.engine.renameVault(r.shared, "Household").ok()
        val (vaultId, blob, base) = r.server.metaPuts.single()
        assertEquals(r.shared, vaultId)
        assertEquals("Household", r.codec.vaultName(r.sharedKey, r.shared, blob))
        assertEquals(1L, base)
        r.keys.open.getValue(r.shared).standing = VaultStanding.FROZEN
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_READ_ONLY), r.engine.renameVault(r.shared, "x").failure())
    }

    // ==== conflicts (spec 03 §5) ====

    @Test
    fun aFlaggedRowFromThePull_getsItsCopyAndAFlagClearingPut_butNotFromAReader() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.openShared(role = "reader")
        r.server.queue.add(r.response(12, items = listOf(r.itemRow(id, r.shared, r.sharedKey, rev = 12, conflict = true))))
        r.engine.sync().ok()
        assertTrue(r.server.pushes.isEmpty(), "a reader must not materialize: its push would be denied")

        r.keys.open.getValue(r.shared).role = "writer"
        r.engine.sync().ok()
        val sent = r.server.pushes.single()
        val copy = sent.single { it.itemId != id }
        assertEquals(io.silencelen.andvari.core.client.ConflictCopy.id(r.crypto, id, 12), copy.itemId)
        assertEquals(0, copy.baseItemRev)
        assertTrue(r.pushedDoc(copy, r.sharedKey).name.startsWith("Router (conflict "))
        assertEquals(12, sent.single { it.itemId == id }.baseItemRev, "the winner is re-put at its rev: that clears the flag")
        assertTrue(sent.all { it.vaultId == r.shared })
    }

    @Test
    fun aDeleteThatLosesToANewerEdit_materializesNoCopy() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.server.rev = 6
        r.serve(r.itemRow(id, r.personal, r.personalKey, rev = 6))
        r.engine.sync().ok()
        // A peer edited the item at rev 9; our delete still carries base 6: edit beats delete.
        r.server.itemRows[id] = r.itemRow(id, r.personal, r.personalKey, r.doc.copy(name = "peer"), rev = 9)
        r.server.rev = 9
        r.engine.remove(id).ok()
        assertEquals(1, r.server.pushes.flatten().size, "only the delete was pushed: the returned row is the survivor, not a loser")
    }

    // ==== the holding area (spec 02 §10.6) ====

    @Test
    fun aVerifiedDeparture_movesTheCopyToTheHoldingArea_andARestoreReplaysItsParkedWrites() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        // An edit made while the owner's delete was already in force: the server denies it.
        r.server.denyVaults.add(r.shared)
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.DELETED) }
        r.server.queue.add(r.response(r.server.rev + 5, removed = listOf(r.shared)))
        val saved = r.engine.save(id, r.doc.copy(name = "edited"), r.shared)
        assertEquals(Written.APPLIED, saved.ok().outcome, "a denial explained by the vault's departure is parked, not thrown")
        val mutationId = r.server.pushes.last().single().mutationId

        assertNull(r.engine.item(id), "the vault left the live view")
        assertTrue(r.engine.vaults().none { it.vaultId == r.shared })
        val held = r.engine.heldVaults().single()
        assertEquals("deleted", held.reason)
        assertEquals(1, held.itemCount)
        assertEquals(1, held.parkedCount)
        assertEquals("Family", held.name)
        assertEquals(r.now + ItemEngine.HOLDING_MS, held.expungeAt)
        assertEquals(listOf("Router"), r.engine.heldItems(r.shared).map { it.doc.name }, "the held copy can still be read and copied out")
        val n = r.engine.notices().single()
        assertEquals(ItemNotice.DELETED, n.kind)
        assertEquals("Family", n.vaultName)
        assertEquals(1, n.count)
        assertTrue(r.cache.pending().isEmpty() && r.cache.stagedDenied().isEmpty())

        // The owner restores: the grant and the rows arrive again, and the parked edit is sent with its ORIGINAL id.
        r.server.denyVaults.clear()
        r.keys.onServed = { report -> if (report.grants.any { it.vaultId == r.shared }) r.keys.put(r.shared, r.sharedKey, "writer", head = LogHeadStamp(5, "ef".repeat(32))) }
        r.server.queue.add(r.response(r.server.rev + 5, vaults = listOf(r.vaultRow(r.shared, r.sharedKey, "shared", "Family", rev = 3)), grants = listOf(r.grantRow(r.shared)), items = listOf(r.itemRow(id, r.shared, r.sharedKey))))
        r.engine.sync().ok()
        assertTrue(r.engine.heldVaults().isEmpty())
        assertEquals(mutationId, r.server.pushes.last().single().mutationId, "replayed under the same mutationId")
        assertEquals("edited", r.pushedDoc(r.server.pushes.last().single(), r.sharedKey).name)
        assertEquals(ItemNotice.RESTORED, r.engine.notices().last().kind)
        assertNotNull(r.engine.item(id))
    }

    @Test
    fun aReplayedEditDeniedOnALiveVault_isACalmNotice() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        r.server.offline = true
        r.engine.save(id, r.doc.copy(name = "offline edit"), r.shared).ok()
        r.server.offline = false
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.REMOVED) }
        r.server.denyVaults.add(r.shared)
        r.server.queue.add(r.response(r.server.rev + 5, removed = listOf(r.shared)))
        r.engine.sync().ok()
        assertEquals(ItemNotice.REMOVED, r.engine.notices().single().kind)
        assertEquals(1, r.engine.heldVaults().single().parkedCount)

        // Added again as a reader: the recovered edit is refused, calmly, and dropped.
        r.keys.onServed = { report -> if (report.grants.any { it.vaultId == r.shared }) r.keys.put(r.shared, r.sharedKey, "reader") }
        r.server.queue.add(r.response(r.server.rev + 5, vaults = listOf(r.vaultRow(r.shared, r.sharedKey, "shared", "Family")), grants = listOf(r.grantRow(r.shared, "reader")), items = listOf(r.itemRow(id, r.shared, r.sharedKey))))
        r.engine.sync().ok()
        r.engine.sync().ok()
        val denied = r.engine.notices().single { it.kind == ItemNotice.REPLAY_DENIED }
        assertEquals(1, denied.count)
        // The notice says why the vault had gone: removed, not deleted, so its line never says "while the vault was deleted".
        assertEquals(ItemNotice.REMOVED, denied.reason)
        assertEquals(
            io.silencelen.andvari.core.app.content.ContentCopy.fillNames(
                io.silencelen.andvari.core.app.CopyKey.NOTICE_REPLAY_DENIED_BACK_ONE, io.silencelen.andvari.core.app.content.ContentCopy.Slot("Family", true),
            ),
            io.silencelen.andvari.core.app.content.ContentCopy.notice(denied).first,
        )
        assertTrue(r.cache.pending().isEmpty() && r.cache.stagedDenied().isEmpty())
    }

    @Test
    fun aLossTheLogDoesNotExplain_keepsTheCopyReadOnly_andAVaultNeverReadHereIsDroppedSilently() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        val unknown = r.id()
        // The server says both are gone. The trust engine verifies nothing: the copy is withheld, not removed.
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.open.getValue(r.shared).standing = VaultStanding.WITHHELD }
        r.server.queue.add(r.response(r.server.rev + 5, removed = listOf(r.shared, unknown)))
        r.engine.sync().ok()
        assertEquals("Router", r.engine.item(id)?.doc?.name, "a server cannot make this device drop its copy")
        assertEquals(VaultStanding.WITHHELD, r.engine.vaults().single { it.vaultId == r.shared }.standing)
        assertEquals(listOf(ItemNotice.WITHHELD), r.engine.notices().map { it.kind }, "one notice, and none for the vault this device never held")
        assertTrue(r.engine.heldVaults().isEmpty())

        // "Remove from this device" is the person's own, local action.
        r.engine.removeFromDevice(r.shared).ok()
        assertNull(r.engine.item(id))
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.VAULT_READ_ONLY), r.engine.removeFromDevice(r.personal).failure())
    }

    @Test
    fun aVaultMissingFromAResyncSnapshot_isKept_untilTheTrustEngineSaysWhy() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        r.server.goneOnce = true
        r.server.queue.add(r.response(40, full = true, vaults = listOf(r.vaultRow(r.personal, r.personalKey, "personal", "Personal"))))
        r.engine.sync().ok()
        assertEquals(setOf(r.shared), r.keys.reports.last().lostAccess, "a vault the snapshot dropped is reported as lost")
        assertEquals("Router", r.engine.item(id)?.doc?.name, "and kept: vanishing is not a verified reason")

        r.keys.onServed = { r.keys.depart(r.shared, VaultDeparture.PURGED) }
        r.server.queue.add(r.response(41, removed = listOf(r.shared)))
        r.engine.sync().ok()
        assertNull(r.engine.item(id))
        assertEquals("purged", r.engine.heldVaults().single().reason)
    }

    @Test
    fun aFirstPull_raisesNoNotice_andTheHoldingAreaExpires() = runBlocking<Unit> {
        val r = ItemRig(firstPull = false)
        r.keys.depart(r.shared, VaultDeparture.REMOVED)
        r.server.queue.add(r.response(5, full = true, vaults = listOf(r.vaultRow(r.personal, r.personalKey, "personal", "Personal"), r.vaultRow(r.shared, r.sharedKey, "shared", "Family")), grants = listOf(r.personalGrant), removed = listOf(r.shared)))
        r.engine.sync().ok()
        assertTrue(r.engine.notices().isEmpty(), "no ghost banner on a fresh device")
        assertTrue(r.engine.heldVaults().isEmpty(), "and nothing to hold for a vault this device never read")

        val s = ItemRig(DurableCache())
        s.openShared(items = listOf(s.itemRow(s.id(), s.shared, s.sharedKey)))
        s.keys.onServed = { s.keys.depart(s.shared, VaultDeparture.LEFT) }
        s.engine.expectDeparture(s.shared)
        s.server.queue.add(s.response(s.server.rev + 1, removed = listOf(s.shared)))
        s.engine.sync().ok()
        assertTrue(s.engine.notices().isEmpty(), "this device left the vault itself")
        assertEquals("left", s.engine.heldVaults().single().reason)
        s.now += ItemEngine.HOLDING_MS + 1
        s.engine.sync().ok()
        assertTrue(s.engine.heldVaults().isEmpty(), "30 days")
    }

    @Test
    fun aStagedDenial_survivesARestart_andIsParkedByTheNextPull() = runBlocking<Unit> {
        val cache = DurableCache()
        val r = ItemRig(cache)
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        r.server.denyVaults.add(r.shared)
        r.server.offlineAfterNextPush = true
        assertEquals(Written.APPLIED, r.engine.save(id, r.doc.copy(name = "edited"), r.shared).ok().outcome)
        assertEquals(1, cache.stagedDenied().size, "denied, and no pull has judged it yet")

        // The process dies. A new engine over the same cache reloads the staged row and the next pull parks it.
        r.server.offline = false
        val engine2 = r.restarted()
        engine2.hydrate()
        assertEquals("Router", engine2.item(id)?.doc?.name, "the working set is rebuilt from ciphertext")
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.DELETED) }
        r.server.queue.add(r.response(r.server.rev + 5, removed = listOf(r.shared)))
        engine2.sync().ok()
        assertEquals(1, engine2.heldVaults().single().parkedCount)
        assertTrue(cache.stagedDenied().isEmpty())
    }

    // ==== history, trash, attachments, moves ====

    @Test
    fun historyAndTrash_decryptUnderTheVaultKey_andRestoreGoesThroughTheDedicatedRoute() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.server.rev = 6
        r.serve(r.itemRow(id, r.personal, r.personalKey, rev = 6))
        r.engine.sync().ok()
        r.engine.save(id, r.doc.copy(name = "second"), r.personal).ok()
        r.server.versions.getValue(id).add(ItemVersion(2, "AAAA", 1, 0)) // one that does not open: dropped
        val versions = r.engine.itemVersions(id, r.personal).ok()
        assertEquals(listOf("Router"), versions.map { it.doc.name }, "newest first, unreadable ones dropped")

        r.serve(r.server.itemRows.getValue(id))
        r.engine.sync().ok()
        r.engine.remove(id).ok()
        val trashed = r.engine.deletedItems().ok().single()
        assertEquals(id, trashed.itemId)
        assertEquals("second", trashed.doc?.name, "named from its last archived version")

        val ref = AttachmentRef(r.id(), "f", 1, "k")
        r.engine.restoreDeleted(id, r.personal, trashed.doc!!.copy(attachments = listOf(ref))).ok()
        val (restoredId, upload) = r.server.restored.single()
        assertEquals(id, restoredId)
        assertTrue(upload.attachmentIds.isEmpty(), "a deleted item's files went with its tombstone")
        r.engine.purgeDeleted(id, r.personal).ok()
        assertEquals(listOf(id), r.server.purged)
    }

    @Test
    fun anAttachmentGoesUpEncrypted_andComesDownOnlyAtItsClaimedSize() = runBlocking<Unit> {
        val r = ItemRig()
        val data = ByteArray(70_000) { (it % 251).toByte() }
        val ref = AttachmentRef(r.id(), "scan.pdf", data.size.toLong(), Bytes.toB64(r.crypto.randomBytes(32)))
        val saved = r.engine.save(null, r.doc.copy(attachments = listOf(ref)), uploads = listOf(NewAttachment(ref, data))).ok()
        val stored = r.server.attachments.getValue(ref.id)
        assertEquals(Attachments.wireLength(data.size.toLong()), stored.size.toLong(), "the header and the ciphertext chunks, nothing else")
        assertEquals(listOf(ref.id), r.server.pushes.last().single { it.itemId == saved.itemId }.item!!.attachmentIds)
        assertContentEquals(data, r.engine.downloadAttachment(ref).ok())

        assertEquals(ItemFailure.Corrupt("size"), r.engine.downloadAttachment(ref.copy(size = ref.size + 1)).failure(), "the ref's size is a claim the body must meet")
        r.server.attachments[ref.id] = stored.copyOf().also { it[100] = (it[100] + 1).toByte() }
        assertEquals(ItemFailure.Corrupt("content"), r.engine.downloadAttachment(ref).failure())
    }

    @Test
    fun aMoveCopiesFirst_deletesAtTheRevItCopied_andARetryReusesItsIds() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey, rev = 6)))
        r.server.itemRows[id] = r.itemRow(id, r.shared, r.sharedKey, rev = 6)
        val plan = r.engine.planMove(id, r.personal, deleteSource = true).ok()

        // The destination denies the copy: the source is untouched and no delete leg is sent.
        r.server.denyVaults.add(r.personal)
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.COPY_DENIED), r.engine.runMove(plan).failure())
        assertEquals(1, r.server.pushes.size)
        assertNotNull(r.engine.item(id))
        r.server.denyVaults.clear()

        r.engine.runMove(plan, finalSync = false).ok()
        val (copyAgain, delete) = r.server.pushes.takeLast(2).map { it.single() }
        assertEquals(r.server.pushes.first().single().mutationId, copyAgain.mutationId, "a retry replays the same mutationId")
        assertEquals(plan.targetItemId, copyAgain.itemId)
        assertEquals("delete", delete.op)
        assertEquals(6, delete.baseItemRev, "the rev of the content copied, not whatever the cache holds now")
        assertNull(r.engine.item(id))
        assertEquals(r.personal, r.engine.item(plan.targetItemId)?.vaultId)

        // A source that changed since it was planned: the copy is made, nothing is deleted.
        val id2 = r.id()
        r.serve(r.itemRow(id2, r.shared, r.sharedKey, rev = 20))
        r.engine.sync().ok()
        val stale = r.engine.planMove(id2, r.personal, deleteSource = true).ok()
        r.server.itemRows[id2] = r.itemRow(id2, r.shared, r.sharedKey, r.doc.copy(name = "changed"), rev = 30)
        r.server.rev = 30
        assertEquals(ItemFailure.NotAllowed(ItemRefusal.ITEM_CHANGED), r.engine.runMove(stale).failure())
        assertNotNull(r.engine.item(id2))
    }

    // ==== halted (design §4.4: a fork stops traffic, not reading) ====

    @Test
    fun halted_nothingIsSentAcceptedOrWritten() = runBlocking<Unit> {
        val cache = DurableCache()
        val r = ItemRig(cache)
        val id = r.id()
        r.serve(r.itemRow(id, r.personal, r.personalKey))
        r.engine.sync().ok()
        r.server.offline = true
        r.engine.save(null, r.doc.copy(name = "queued before the fork")).ok()
        r.server.offline = false
        val calls = r.server.calls
        val reports = r.keys.reports.size
        val cursor = cache.cursor()
        val queue = cache.pending().map { it.mutationId }

        r.engine.halt()
        r.server.queue.add(r.response(99, items = listOf(r.itemRow(r.id(), r.personal, r.personalKey))))
        val ref = AttachmentRef(r.id(), "f", 1, Bytes.toB64(r.crypto.randomBytes(32)))
        val refused = listOf(
            r.engine.sync().failure(), r.engine.save(null, r.doc).failure(), r.engine.save(id, r.doc, r.personal).failure(), r.engine.remove(id).failure(),
            r.engine.importAll(listOf(r.planned("x"))).failure(), r.engine.itemVersions(id, r.personal).failure(), r.engine.deletedItems().failure(),
            r.engine.restoreDeleted(id, r.personal, r.doc).failure(), r.engine.purgeDeleted(id, r.personal).failure(), r.engine.downloadAttachment(ref).failure(),
            r.engine.renameVault(r.personal, "x").failure(), r.engine.runMove(r.engine.planMove(id, r.personal, false).ok()).failure(),
            r.engine.rescueToPersonal(r.personal).failure(), r.engine.removeFromDevice(r.shared).failure(), r.engine.uploadEncryptedAttachment(ref.id, id, r.personal, ByteArray(1)).failure(),
        )
        assertTrue(refused.all { it == ItemFailure.Halted }, "every path that sends or writes answers Halted: $refused")
        assertEquals(calls, r.server.calls, "nothing was sent")
        assertEquals(reports, r.keys.reports.size, "nothing served was accepted or passed on")
        assertEquals(cursor, cache.cursor())
        assertEquals(queue, cache.pending().map { it.mutationId }, "the queue is neither drained nor grown")
    }

    @Test
    fun everySyncJudgesTheCardChainFirst_andAForkStopsItBeforeAnythingIsSent() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val id = r.id()
        r.serve(r.itemRow(id, r.personal, r.personalKey))
        var callsAtJudge = -1
        r.gate.onJudge = { callsAtJudge = r.server.calls }
        val before = r.server.calls
        r.engine.sync().ok()
        assertEquals(before, callsAtJudge, "the card chain is judged before the first request of the sync")
        assertEquals(2, r.gate.judged, "once per sync, the first pull included")

        // The served chain forks. An ordinary sync notices it and stops there: no push, no pull, nothing accepted.
        r.server.offline = true
        r.engine.save(null, r.doc.copy(name = "queued")).ok()
        r.server.offline = false
        r.server.queue.add(r.response(50, items = listOf(r.itemRow(r.id(), r.personal, r.personalKey, r.doc.copy(name = "served after the fork")))))
        val calls = r.server.calls
        val reports = r.keys.reports.size
        r.gate.forkOnJudge = true
        assertEquals(ItemFailure.Halted, r.engine.sync().failure())
        assertTrue(r.engine.halted)
        assertEquals(calls, r.server.calls, "nothing was sent with the session's token")
        assertEquals(reports, r.keys.reports.size)
        assertEquals(1, r.cache.pending().size, "the queued write stays where it is")
        assertEquals(setOf("Router", "queued"), r.engine.items().map { it.doc.name }.toSet(), "reading goes on")
        // For good: the engine does not ask again and does not thaw.
        r.gate.forkOnJudge = false
        r.gate.forked = false
        assertEquals(ItemFailure.Halted, r.engine.sync().failure())
        assertEquals(calls, r.server.calls)
    }

    @Test
    fun aPinThatForkedSinceTheLastSync_stopsAWriteBeforeItIsTried() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val calls = r.server.calls
        r.gate.forked = true // another flow's refresh saw the fork and marked the pin
        assertEquals(ItemFailure.Halted, r.engine.save(null, r.doc).failure())
        assertEquals(calls, r.server.calls, "the engine does not try: the transport's own guard is only the second lock")
        assertTrue(r.cache.pending().isEmpty(), "and queues nothing")
    }

    @Test
    fun aReplayedOlderPage_doesNotMakeTheDeviceForgetNewerItems() = runBlocking<Unit> {
        val r = ItemRig()
        val first = r.id()
        val second = r.id()
        val firstPage = r.response(8, full = true, vaults = listOf(r.vaultRow(r.personal, r.personalKey, "personal", "Personal")), items = listOf(r.itemRow(first, r.personal, r.personalKey, r.doc.copy(name = "first"), rev = 8)))
        r.server.queue.add(r.response(8, items = firstPage.items))
        r.engine.sync().ok()
        r.server.queue.add(r.response(12, items = listOf(r.itemRow(second, r.personal, r.personalKey, r.doc.copy(name = "second"), rev = 12))))
        r.engine.sync().ok()

        // The server replays the earlier full page, and then an earlier delta.
        r.server.queue.add(firstPage)
        assertEquals(ItemFailure.Rollback(unsolicitedFull = true), r.engine.sync().failure(), "a sync that went backwards says so")
        r.server.queue.add(r.response(8, items = listOf(r.tombstone(second, r.personal, 8))))
        assertEquals(ItemFailure.Rollback(unsolicitedFull = false), r.engine.sync().failure())
        assertEquals(setOf("first", "second"), r.engine.items().map { it.doc.name }.toSet(), "newer local state is kept")
        assertEquals(12, r.cache.cursor())
        assertEquals(1, r.engine.notices().count { it.kind == ItemNotice.ROLLBACK }, "the person is warned, once")
        // An honest answer afterwards applies as usual.
        r.server.queue.add(r.response(13, items = listOf(r.tombstone(first, r.personal, 13))))
        r.engine.sync().ok()
        assertEquals(setOf("second"), r.engine.items().map { it.doc.name }.toSet())
    }

    @Test
    fun halted_whatTheCacheHoldsStaysReadable() = runBlocking<Unit> {
        val cache = DurableCache()
        val r = ItemRig(cache)
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        r.server.offline = true
        r.engine.save(null, r.doc.copy(name = "unsent")).ok()
        val homes = cache.itemHome(id)

        // The next launch finds the origin's pin forked: the engine is halted from the start and reads from the cache.
        r.gate.forked = true
        val halted = r.restarted()
        val calls = r.server.calls
        halted.hydrate()
        assertTrue(halted.halted)
        assertEquals(setOf("Router", "unsent"), halted.items().map { it.doc.name }.toSet(), "the copy, and what had not synced, can be read and exported")
        assertEquals(listOf("personal", "shared"), halted.vaults().map { it.type })
        assertEquals("Router", halted.item(id)?.doc?.name)
        assertEquals(calls, r.server.calls, "reading sends nothing")
        assertEquals(homes, cache.itemHome(id))
        assertIs<ItemResult.Failed>(halted.sync())
    }
}
