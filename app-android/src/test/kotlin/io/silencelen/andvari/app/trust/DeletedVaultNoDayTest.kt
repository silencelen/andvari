package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A deleted shared vault, as the phone draws its row: "deleted" is read from the shared code's own field
 * ([io.silencelen.andvari.core.app.SharedVaultRow.deleted]) and never from the day; the day its grace ends is drawn only
 * where the server served one, else the shared code's line that names no day; Restore is offered from "deleted"; Delete,
 * Rename and "Move everything" are not offered on a deleted vault. Walked over the stand-in with a server that serves no
 * day ([io.silencelen.andvari.core.app.fake.FakeScript.servesGraceDay] false) and with one that does.
 */
class DeletedVaultNoDayTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private fun FakeAppApi.family() = assertNotNull(snapshot.account).vaults.first { it.name == "Family" }

    @Test
    fun aDeletedVaultWhoseDayTheServerDidNotServeIsDrawnAsDeletedWithTheLineThatNamesNoDay() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        assertTrue(moveEverythingOffered(api.family()), "offered on the live vault, so its absence below is the deletion's")
        assertNull(deletedLine(api.family()), "a live vault says nothing of a grace")
        api.script.servesGraceDay = false
        assertEquals(VaultActionResult.DONE, runBlocking { api.vaults.deleteVault(api.family()) })
        val v = api.family()
        assertTrue(v.deleted)
        assertEquals(0L, v.purgeAtMs, "no day served")
        assertEquals(UiText.of(assertNotNull(v.deletedNoDayLine)).shown(), deletedLine(v)?.shown(), "the line that names no day, as handed")
        assertFalse(moveEverythingOffered(v), "no \"Move everything\" on a deleted vault")

        // Restored: a live vault again, nothing said of a grace.
        assertEquals(VaultActionResult.DONE, runBlocking { api.vaults.restoreVault(v) })
        assertNull(deletedLine(api.family()))
        assertTrue(moveEverythingOffered(api.family()))
    }

    @Test
    fun aDeletedVaultWhoseDayTheServerServedNamesThatDay() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        assertEquals(VaultActionResult.DONE, runBlocking { api.vaults.deleteVault(api.family()) })
        val v = api.family()
        assertTrue(v.deleted)
        assertTrue(v.purgeAtMs > 0)
        assertNull(v.deletedNoDayLine)
        assertEquals(UiText.ph(Placeholder.VAULT_DELETED_IN_GRACE, Dates.date(v.purgeAtMs)).shown(), deletedLine(v)?.shown())
        assertFalse(moveEverythingOffered(v))
    }

    /**
     * "Recently deleted" (the owner's list of deleted shared vaults): a vault the server listed with no day is drawn with
     * the shared code's line that names no day, never a date made of an empty day (1970); one with a day names it; the
     * list reads the day only where it draws it.
     */
    @Test
    fun recentlyDeletedDrawsTheDayOnlyWhereTheServerServedOneElseTheLineThatNamesNoDay() {
        val noDay = io.silencelen.andvari.core.app.DeletedVaultView("v1", "Old", deletedAtMs = 0L, purgeAtMs = 0L)
        val line = assertNotNull(deletedVaultListLine(noDay), "a line for every deleted row")
        WalkPrint.draws("Recently deleted, a vault the server gave no day", listOf(line))
        assertEquals(UiText.of(assertNotNull(noDay.deletedNoDayLine)).shown(), line.shown(), "the line that names no day, as handed")
        assertFalse(line.shown().contains(Dates.date(0L)), "never the empty day as a date: ${line.shown()}")
        val day = 1_800_000_000_000L
        val withDay = io.silencelen.andvari.core.app.DeletedVaultView("v2", "Older", deletedAtMs = day - 1, purgeAtMs = day)
        assertEquals(UiText.ph(Placeholder.VAULT_DELETED_IN_GRACE, Dates.date(day)).shown(), deletedVaultListLine(withDay)?.shown())
        assertNull(deletedVaultListLine(noDay.copy(deleted = false)), "a vault not deleted says nothing of a grace")
        val list = src("VaultItemsScreens.kt").substringAfter("internal fun DeletedVaultsView(").substringBefore("\n}\n")
        assertTrue("deletedVaultListLine(v)?.let { Quiet(it) }" in list, "the list draws that line")
        assertFalse("v.purgeAtMs" in list, "the list never reads the day itself")
    }

    /** The row's offers read "deleted", never the day: Restore from it, Delete and Rename only without it. */
    @Test
    fun theRowsOffersReadDeletedNeverTheDay() {
        val screens = src("VaultScreens.kt")
        assertTrue("if (owner && v.deleted) {\n        Quieter(UiText.ph(Placeholder.VAULT_RESTORE)" in screens, "Restore from \"deleted\"")
        assertTrue("if (owner && !v.deleted && v.writable) {" in screens, "Delete only on a vault that is not deleted")
        assertTrue("v.role == RoleInVault.OWNER && v.writable && !v.deleted" in screens, "Rename only on a vault that is not deleted")
        assertTrue("deletedLine(v)?.let { Quiet(it) }" in screens, "the row draws the deleted vault's line")
        val reads = Regex("""v\.purgeAtMs""").findAll(screens).count()
        assertEquals(2, reads, "the day is read only where it is drawn (deletedLine), never to tell whether the vault is deleted")
    }
}
