package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.SharedVaultRow
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.text.DateFormat
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A deleted shared vault on the Sharing page is read from its row's own field ([SharedVaultRow.deleted]), never from the
 * day: the day is drawn only where the server served one, else the shared code's line that names none; Restore is
 * offered from "deleted"; Rename, Delete and Move everything are not offered on a deleted vault.
 */
class DeletedVaultRowTest {
    private val date = DateFormat.getDateInstance(DateFormat.MEDIUM)
    private val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultScreens.kt").readText()
    private fun body(head: String) = src.substringAfter(head).substringBefore("\n}\n")

    private fun deletedFamily(servesDay: Boolean): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        api.script.servesGraceDay = servesDay
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        assertNull(deletedVaultLine(family(api), date), "a live vault has no such line")
        m.run({ vaults.deleteVault(family(api)) })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun family(api: FakeDesktopAppApi): SharedVaultRow = assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }

    @Test
    fun aDeletedVaultWhoseDayWasNotServedSaysTheLineWithoutADayAndCanBeRestored() {
        val (api, m) = deletedFamily(servesDay = false)
        val row = family(api)
        assertTrue(row.deleted)
        assertEquals(0L, row.purgeAtMs, "no day served")
        val handed = assertNotNull(row.deletedNoDayLine)
        assertEquals(UiText.of(handed).shown(), assertNotNull(deletedVaultLine(row, date)).shown(), "the line as handed")
        // While its deletion stands the row is not writable, so no write is offered on it (Rename, Delete and Move
        // everything each need it); Restore is offered from "deleted" and makes it writable again at once.
        assertFalse(row.writable, "no write on a vault whose deletion stands")
        m.run({ vaults.restoreVault(row) })
        m.onSnapshot(api.snapshot)
        assertFalse(family(api).deleted)
        assertTrue(family(api).writable, "writable again after the restore")
        assertNull(deletedVaultLine(family(api), date))
    }

    @Test
    fun aDeletedVaultWithAServedDaySaysThatDay() {
        val (api, _) = deletedFamily(servesDay = true)
        val row = family(api)
        assertTrue(row.deleted)
        assertTrue(row.purgeAtMs > 0)
        assertEquals(Placeholder.VAULT_DELETED_IN_GRACE, assertIs<UiText.Ph>(deletedVaultLine(row, date)).placeholder)
        assertEquals(UiText.ph(Placeholder.VAULT_DELETED_IN_GRACE, date.format(java.util.Date(row.purgeAtMs))).shown(), deletedVaultLine(row, date)?.shown())
    }

    /** The Sharing page, drawn: each deleted vault's line as the page draws it, by the vault's name. */
    private fun drawnDeletedLines(api: FakeDesktopAppApi, m: TrustModel): Map<String, String> {
        val seen = LinkedHashMap<String, String>()
        val s = api.snapshot
        val account = assertNotNull(s.account)
        val scene = androidx.compose.ui.ImageComposeScene(600, 4000, androidx.compose.ui.unit.Density(1f)) {
            androidx.compose.runtime.CompositionLocalProvider(LocalDeletedVaultDrawn provides { v, line -> seen[v.name ?: v.vaultId] = line.shown() }) {
                androidx.compose.material3.MaterialTheme { androidx.compose.foundation.layout.Column { SharedVaultsSection(m, s, account) } }
            }
        }
        try {
            scene.render()
        } finally {
            scene.close()
        }
        return seen
    }

    /**
     * Drawn: a deleted vault for which the server served no day says the shared code's line without a day, never a date
     * (no 1970); one with a served day says that day; a live vault draws no such line.
     */
    @Test
    fun theSharingPageDrawsNoDayWhereTheServerServedNone() {
        val (api, m) = deletedFamily(servesDay = false)
        val row = family(api)
        assertTrue(row.deleted)
        assertEquals(0L, row.purgeAtMs)
        val drawn = drawnDeletedLines(api, m)
        println("WALK|item 3 no day served|$drawn")
        assertEquals(UiText.of(assertNotNull(row.deletedNoDayLine)).shown(), drawn["Family"], "the line without a day, drawn")
        assertFalse(assertNotNull(drawn["Family"]).contains("1970"))
        assertEquals(setOf("Family"), drawn.keys, "only the deleted vault has such a line")

        val (served, sm) = deletedFamily(servesDay = true)
        val withDay = family(served)
        val drawnWithDay = drawnDeletedLines(served, sm)
        println("WALK|item 3 a day served|$drawnWithDay")
        assertEquals(UiText.ph(Placeholder.VAULT_DELETED_IN_GRACE, date.format(java.util.Date(withDay.purgeAtMs))).shown(), drawnWithDay["Family"])
    }

    /** What the row draws and offers reads "deleted", never the day. */
    @Test
    fun theRowReadsDeletedNeverTheDay() {
        val section = body("internal fun SharedVaultsSection(")
        assertTrue(section.contains("deletedVaultLine(v, date)?.let { line ->\n                Quiet(line)"))
        assertFalse(section.contains("purgeAtMs"), "the section reads no day itself")
        val actions = body("private fun VaultActions(")
        assertTrue(actions.contains("if (owner && v.deleted) {"), "Restore from deleted")
        // Delete and Move everything stand in the branch after it, so never on a deleted vault.
        assertTrue(actions.indexOf("if (owner && v.deleted) {") < actions.indexOf("Placeholder.VAULT_DELETE"))
        assertTrue(actions.contains("if (owner && !v.deleted && v.writable) RenameVaultControl(model, s, v)"), "no Rename on a deleted vault")
        assertFalse(actions.contains("purgeAtMs"))
    }
}
