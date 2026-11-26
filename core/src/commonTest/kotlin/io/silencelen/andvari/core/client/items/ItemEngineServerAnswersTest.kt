package io.silencelen.andvari.core.client.items

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** What the engine makes of server answers the hostile-server harness found or the server changed. */
class ItemEngineServerAnswersTest {
    /** H9 (spec 05 T1, spec 03 §4): a rev only grows, so an older snapshot is a rollback even after a resync demand. */
    @Test
    fun anOlderWholeSnapshotAfterAResyncDemand_isStillARollback() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.serve(r.itemRow(id, r.personal, r.personalKey, rev = 8))
        r.engine.sync().ok()
        val cursor = r.cache.cursor()
        r.server.goneOnce = true
        r.server.queue.add(r.response(3, full = true, vaults = listOf(r.vaultRow(r.personal, r.personalKey, "personal", "Personal"))))
        assertEquals(ItemFailure.Rollback(unsolicitedFull = false), r.engine.sync().failure())
        assertNotNull(r.engine.item(id), "nothing of the older snapshot was applied")
        assertEquals(cursor, r.cache.cursor())
        assertEquals(1, r.engine.notices().count { it.kind == ItemNotice.ROLLBACK })
    }

    /**
     * H10 (spec 03 §4): an edit the server denies while it takes the vault away, with no removal in the log, is held
     * back while the vault is withheld and sent again once the vault is back, never dropped as a genuine denial.
     */
    @Test
    fun anEditDeniedWhileTheVaultWasTakenAway_isReplayedWhenItComesBack() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey)))
        r.server.denyVaults.add(r.shared)
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.put(r.shared, r.sharedKey, VaultAccess.ROLE_WRITER, VaultStanding.WITHHELD) }
        r.server.queue.add(r.response(r.server.rev + 1, removed = listOf(r.shared)))
        r.engine.save(id, r.doc.copy(name = "edited"), r.shared).ok()
        val denied = r.server.pushes.last().single()
        r.engine.sync().ok()
        assertNotNull(r.engine.item(id), "the copy stays readable")
        assertEquals(1, r.server.pushes.flatten().count { it.mutationId == denied.mutationId }, "held back, not re-sent, while the vault is away")

        // The server serves the vault again.
        r.server.denyVaults.clear()
        r.keys.onServed = null
        r.keys.put(r.shared, r.sharedKey, VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(r.vaultRow(r.shared, r.sharedKey, "shared", "Family")), grants = listOf(r.grantRow(r.shared))))
        r.engine.sync().ok()
        r.engine.sync().ok()
        val replay = r.server.pushes.flatten().filter { it.mutationId == denied.mutationId }
        assertEquals(2, replay.size, "the held-back edit was sent again")
        assertEquals("edited", r.pushedDoc(replay.last(), r.sharedKey).name)
        assertEquals(0, r.engine.notices().count { it.kind == ItemNotice.WRITE_REJECTED })
    }

    @Test
    fun aDisplacedValueThePushResultLeftOut_isReadFromTheItemsHistory() = runBlocking<Unit> {
        val r = ItemRig(DurableCache())
        val id = r.id()
        r.serve(r.itemRow(id, r.personal, r.personalKey, rev = 6))
        r.engine.sync().ok()
        // A peer's edit lands on the server while this device edits offline from rev 6.
        r.server.offline = true
        r.engine.save(id, r.doc.copy(name = "mine"), r.personal).ok()
        r.server.itemRows[id] = r.itemRow(id, r.personal, r.personalKey, r.doc.copy(name = "peer edit"), rev = 9)
        r.server.rev = 9
        r.server.offline = false
        r.server.omitServerItems = true
        r.engine.sync().ok()
        assertTrue(r.server.itemRows.getValue(id).conflict, "a genuine conflict")
        val copy = assertNotNull(r.server.pushes.flatten().find { it.itemId != id && it.op == "put" }, "the displaced edit is kept as a conflict copy")
        assertTrue(r.pushedDoc(copy).name.startsWith("peer edit (conflict "), "built from the displaced value in the history: ${r.pushedDoc(copy).name}")
        assertEquals(listOf(id), r.server.versionsRead.distinct())
    }
}
