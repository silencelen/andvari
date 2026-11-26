package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.model.wire.QuotaMeter
import io.silencelen.andvari.core.model.wire.QuotaName
import io.silencelen.andvari.core.model.wire.QuotaUse
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The check before a large copy, through to the screens (spec 03 §14.4, design §3.13 "the app checks first and says
 * so"): an import, a copy into the personal vault, a copy or move into a vault the account owns, and the call "Move
 * everything" makes before it starts; and Settings' storage line. Through the fake, whose controller is the real one.
 */
class SpaceCheckContentTest {
    private val personal = FakeVaultContent.PERSONAL_VAULT_ID
    private val family = "00000000-0000-4000-8000-0000000000aa"
    private val mine = "00000000-0000-4000-8000-0000000000cc"

    private val csv = "name,url,username,password,note\nGH,https://gh.test,jordan,pw,hi\nNT,https://n.test,ana,pw2,\n".encodeToByteArray()

    private fun ActionResult.message(): String = (this as? ActionResult.Failed)?.message ?: error("expected Failed, got $this")

    private fun spaceOf(c: FakeVaultContent): SpaceCheck? = c.state.space

    /** Typed on purpose (a just-added state property can read as `Nothing?` to the test compiler otherwise). */
    private fun storageOf(c: FakeVaultContent): AccountStorage? = c.state.storage

    private fun FakeVaultContent.countIn(vaultId: String): Int = state.items.count { itemDetail(it.itemId)?.vaultId == vaultId }

    private val ample = 1L shl 40

    @Test
    fun anImportIntoTheAccountsOwnVault_doesNotStartWhenShort_onEachMeter_andStartsExactlyAtTheLimit() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.setRoomLeft(0, 0, 0)
        assertEquals(ActionResult.Ok, c.importCsv(csv.copyOf()))
        // The plan says it before the person confirms, from the last use and limits this device holds (no call).
        assertEquals(SpaceVerdict.NOT_ENOUGH, spaceOf(c)?.verdict)
        assertEquals(SpaceFor.CSV_IMPORT, spaceOf(c)?.forWhat)
        assertEquals(0, c.spaceChecks)

        assertEquals(ActionResult.Ok, c.confirmImport())
        assertEquals(1, c.spaceChecks, "checked again on a fresh sync")
        val size = assertNotNull(c.lastSpaceAsked)
        assertEquals(2L, size.items)
        assertTrue(size.bytes > 0)
        assertEquals(0, c.state.items.size, "nothing was sent")

        // One byte short.
        c.setRoomLeft(size.bytes - 1, ample, 0)
        c.confirmImport()
        val bytes = assertNotNull(spaceOf(c))
        assertEquals(SpaceVerdict.NOT_ENOUGH, bytes.verdict)
        assertEquals(QuotaName.ACCOUNT_BYTES, bytes.limits.single().quota)
        assertEquals(1L, bytes.limits.single().by)
        assertEquals(1000L + size.bytes - 1, bytes.limits.single().limit)
        assertEquals(CopyKey.SPACE_SHORT_BYTES, bytes.line?.key)
        assertEquals(listOf(AttachmentRules.size(1000L + size.bytes - 1), AttachmentRules.size(1)), bytes.line?.values)
        val error = assertNotNull(c.state.csvImport?.error)
        assertTrue(ContentCopy.isOutOfSpace(error), error)
        assertTrue(error.endsWith(bytes.line!!.english), error)
        assertTrue(c.state.csvImport!!.retryable, "Retry checks again")
        assertEquals(0, c.state.items.size)

        // One item short.
        c.setRoomLeft(ample, 1, 0)
        c.confirmImport()
        assertEquals(QuotaName.ITEMS, spaceOf(c)?.limits?.single()?.quota)
        assertEquals(CopyKey.SPACE_SHORT_ITEMS_ONE_OVER, spaceOf(c)?.line?.key, "one item over has its own key")
        assertEquals(listOf("11"), spaceOf(c)?.line?.values)
        assertEquals(0, c.state.items.size)

        // Exactly at the limit on both: it fits, and the import lands.
        c.setRoomLeft(size.bytes, 2, 0)
        assertEquals(ActionResult.Ok, c.confirmImport())
        assertNull(spaceOf(c))
        assertNotNull(c.state.csvImport?.done)
        assertEquals(2, c.state.items.size)
        c.closeImport()
        assertNull(c.state.csvImport)
    }

    @Test
    fun unknownStartsTheImport_andAnImportIntoAnotherOwnersVaultIsLeftToTheServer() = runBlocking<Unit> {
        // No quota at all (an older server).
        val c = FakeVaultContent()
        c.importCsv(csv.copyOf())
        c.confirmImport()
        assertEquals(2, c.state.items.size)
        assertNull(spaceOf(c))
        assertNull(storageOf(c), "Settings shows nothing when the server gave nothing")

        // Numbers that cannot be meters are unknown too.
        val d = FakeVaultContent()
        d.setQuota(QuotaUse(QuotaMeter(-1, 10), QuotaMeter(0, 0), QuotaMeter(0, 0), QuotaMeter(0, 0)))
        d.importCsv(csv.copyOf())
        d.confirmImport()
        assertEquals(2, d.state.items.size)
        assertNull(storageOf(d))

        // Into a shared vault someone else owns, this account's meters are not what the server counts.
        val e = FakeVaultContent()
        e.addSharedVault(family, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        e.setRoomLeft(0, 0, 0)
        e.importCsv(csv.copyOf())
        e.setImportVault(family)
        assertNull(spaceOf(e))
        e.confirmImport()
        assertEquals(0, e.spaceChecks)
        assertEquals(2, e.countIn(family))
    }

    @Test
    fun aCopyIntoThePersonalVault_isCheckedFirst_andShortOnlyOnDeclaredSizes_goesOnAndSaysSo() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(family, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        c.seedLogin(family, "A", "a", "pa", "")
        c.seedLogin(family, "B", "b", "pb", "")
        c.setRoomLeft(ample, 1, 0)
        val r = c.saveVaultItemsToPersonal(family)
        assertTrue(ContentCopy.isOutOfSpace(r.message()), r.message())
        assertEquals(SpaceFor.INTO_PERSONAL, spaceOf(c)?.forWhat)
        assertEquals(QuotaName.ITEMS, spaceOf(c)?.limits?.single()?.quota)
        assertEquals(0, c.countIn(personal), "nothing was copied")
        assertNull(c.state.copying)

        c.setRoomLeft(ample, 2, 0)
        assertEquals(ActionResult.Ok, c.saveVaultItemsToPersonal(family))
        assertEquals(2, c.countIn(personal))
        assertNull(spaceOf(c))

        // A file a co-member says is huge: capped at the policy's limit for one file, and short only on it.
        val d = FakeVaultContent()
        d.addSharedVault(family, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        val item = d.seedLogin(family, "Big", "b", "pb", "")
        d.seedDeclaredFile(item, "huge.bin", 1L shl 45)
        d.setRoomLeft(64 * 1024, ample, 0)
        assertEquals(ActionResult.Ok, d.saveVaultItemsToPersonal(family))
        val declared = assertNotNull(spaceOf(d))
        assertEquals(SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES, declared.verdict)
        assertEquals(CopyKey.SPACE_SHORT_DECLARED, declared.line?.key)
        assertTrue(declared.started)
        val asked = assertNotNull(d.lastSpaceAsked)
        assertTrue(asked.declaredBytes in 1..(AttachmentRules.DEFAULT_FILE_BYTES + 1024 * 1024), "capped: ${asked.declaredBytes}")
        assertEquals(1, d.countIn(personal), "it went on: the server decides")
        d.dismissError()
        assertNull(spaceOf(d))
    }

    @Test
    fun aMoveIntoAVaultTheAccountOwns_isRefusedWhenShort_andOnlyAShortCostsASync() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(family, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        c.addSharedVault(mine, "Mine", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        val a = c.seedLogin(family, "A", "a", "pa", "")
        val b = c.seedLogin(family, "B", "b", "pb", "")

        c.setRoomLeft(ample, 0, 0)
        c.refresh()
        val syncs = c.syncCount
        val r = c.moveOrCopyItem(a, personal, move = true)
        assertTrue(ContentCopy.isOutOfSpace(r.message()), "the Move everything flow reads it as a refusal for space: ${r.message()}")
        assertEquals(SpaceFor.MOVE_OR_COPY, spaceOf(c)?.forWhat)
        assertEquals(personal, spaceOf(c)?.vaultId)
        assertEquals(family, c.itemDetail(a)?.vaultId, "the original is untouched")
        assertEquals(syncs + 1, c.syncCount, "a short on the held value is checked once more, fresh")
        assertEquals(ActionResult.Failed::class, c.moveOrCopyItem(a, mine, move = false)::class, "a shared vault it owns counts too")

        // With room, the move costs no extra sync for its check.
        c.setRoomLeft(ample, 5, 0)
        c.refresh()
        val before = c.spaceChecks
        assertEquals(ActionResult.Ok, c.moveOrCopyItem(b, mine, move = false))
        assertEquals(before, c.spaceChecks)

        // Into a vault another account owns, this account's meters say nothing.
        val d = FakeVaultContent()
        d.addSharedVault(family, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        val p = d.seedLogin(personal, "P", "p", "pp", "")
        d.setRoomLeft(0, 0, 0)
        assertEquals(ActionResult.Ok, d.moveOrCopyItem(p, family, move = false))
        assertEquals(0, d.spaceChecks)
    }

    @Test
    fun moveEverythingsCheck_countsTheItemsLeftAndTheNewVault() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(mine, "Mine", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        val ids = (1..3).map { c.seedLogin(mine, "I$it", "u", "p$it", "") }

        c.setRoomLeft(ample, ample, 0)
        val vaults = assertNotNull(c.spaceForMoveEverything(mine, "Mine again", emptyList()))
        assertEquals(SpaceVerdict.NOT_ENOUGH, vaults.verdict)
        assertEquals(SpaceFor.MOVE_EVERYTHING, vaults.forWhat)
        assertEquals(QuotaName.OWNED_SHARED_VAULTS, vaults.limits.single().quota)
        assertEquals(CopyKey.SPACE_SHORT_VAULTS_ONE, vaults.line?.key, "a limit of one shared vault has its own key")
        assertEquals(emptyList(), vaults.line?.values)
        assertEquals(true, c.lastSpaceAsked?.newSharedVault)
        assertTrue(c.lastSpaceAsked!!.metaBytes > 0)
        // A run that already made its vault adds none.
        assertEquals(SpaceVerdict.ROOM, c.spaceForMoveEverything(mine, null, emptyList())?.verdict)

        c.setRoomLeft(ample, 2, 1)
        assertEquals(SpaceVerdict.NOT_ENOUGH, c.spaceForMoveEverything(mine, "Mine again", emptyList())?.verdict)
        assertEquals(3L, c.lastSpaceAsked?.items)
        assertEquals(SpaceVerdict.ROOM, c.spaceForMoveEverything(mine, "Mine again", ids.take(1))?.verdict, "exactly at the limit")
        assertNull(spaceOf(c), "the content's own state is not the Move everything screen's")

        c.setQuota(null)
        assertEquals(SpaceVerdict.UNKNOWN, c.spaceForMoveEverything(mine, "Mine again", emptyList())?.verdict)
        c.setOffline(true)
        assertNull(c.spaceForMoveEverything(mine, "Mine again", emptyList()), "no answer: no check")
    }

    @Test
    fun settingsStorageLine_carriesTheFourMeters_orNothing() = runBlocking<Unit> {
        val c = FakeVaultContent()
        assertNull(storageOf(c))
        c.setQuota(QuotaUse(QuotaMeter(5, 100), QuotaMeter(6, 50), QuotaMeter(1, 3), QuotaMeter(0, 20)))
        c.refresh()
        val s: AccountStorage = assertNotNull(storageOf(c))
        assertEquals(listOf(5L to 100L, 6L to 50L, 1L to 3L, 0L to 20L),
            listOf(s.accountBytes, s.items, s.ownedSharedVaults, s.openLinks).map { it.used to it.limit })
        c.setQuota(null)
        assertNull(storageOf(c))
    }
}
