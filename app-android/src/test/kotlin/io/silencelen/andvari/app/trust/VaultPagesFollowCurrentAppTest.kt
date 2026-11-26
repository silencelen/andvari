package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.HealthTilesView
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The trash, vault health, the import, an item's history and the lock screen, set beside the current (0.30.0) app's
 * screens: the trash and health are pages of their own with their title and the way back in the top bar (so is the
 * import here), the history opens in place on the item's detail, health's summary is the current app's tiles, and the
 * lock screen says what the last try answered above the field. The images are trash-empty, trash-items, health,
 * history and locked-wrong-password.
 */
class VaultPagesFollowCurrentAppTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private fun body(text: String, fn: String): String {
        val start = text.indexOf(fn)
        assertTrue(start >= 0, "$fn is gone")
        val end = Regex("""\n(@Composable|internal fun|private fun|fun |/\*\*)""").find(text, start + fn.length)?.range?.first ?: text.length
        return text.substring(start, end)
    }

    private fun open(): VaultContent {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return assertNotNull(m.content.value)
    }

    @Test
    fun theTrashAndHealthArePagesOfTheirOwnInTheOrderTheyAreShown() {
        val c = open()
        assertNull(subPage(c.state), "the list is under the vault's own bar")
        runBlocking { c.openTrash() }
        assertEquals(VaultSubPage.TRASH, subPage(c.state))
        c.openHealth()
        assertEquals(VaultSubPage.HEALTH, subPage(c.state), "health is drawn over the trash, so its bar is the one on show")
        c.closeHealth()
        assertEquals(VaultSubPage.TRASH, subPage(c.state))
        c.closeTrash()
        assertNull(subPage(c.state))
        assertEquals(UiText.ph(Placeholder.TRASH).shown(), subPageTitle(VaultSubPage.TRASH).shown())
        assertEquals(UiText.ph(Placeholder.HEALTH).shown(), subPageTitle(VaultSubPage.HEALTH).shown())
        // The import is the current app's dialog over the vault, never a page.
        runBlocking { c.importCsv("name,url,username,password\nShop,https://shop.example,ada,pw1\n".encodeToByteArray()) }
        assertNotNull(c.state.csvImport)
        assertNull(subPage(c.state), "the import is a dialog over the list, under the vault's own bar")
        c.closeImport()
    }

    /** The import's plan as the current app's dialog: its title, the plan scrolling, the import or Try again, and Cancel. */
    @Test
    fun theImportIsADialogOverTheVault() {
        val section = body(src("VaultItemsScreens.kt"), "internal fun VaultItemsSection(")
        assertTrue("importing?.let { ImportDialog(c, state, it) }" in section)
        assertFalse("ImportView(c, state, importing)" in section, "never drawn as a page")
        val dialog = body(src("VaultTransferScreens.kt"), "internal fun ImportDialog(")
        assertTrue("onDismissRequest = { if (!v.busy) c.closeImport() }" in dialog, "Back does nothing while it runs")
        assertTrue("title = { Say(UiText.ph(Placeholder.IMPORT_CSV)) }" in dialog)
        assertTrue("text = { Column(Modifier.verticalScroll(rememberScrollState())) { ImportView(c, state, v) } }" in dialog)
        assertTrue("Say(UiText.ph(importRunLabel(v)))" in dialog)
        assertTrue("TextButton(onClick = { c.closeImport() }, enabled = !v.busy) { Say(CopyKey.CANCEL) }" in dialog)
    }

    /**
     * Seen in the drawing: before any run the button read "Try again" (the content's retryable starts true); and after
     * a stop that is not retryable it offered Import again, which could add the same items twice.
     */
    @Test
    fun theImportSaysImportBeforeItsFirstRunAndIsNotRunAgainAfterAStopThatCannotBeRetried() {
        val c = open()
        runBlocking { c.importCsv("name,url,username,password\nShop,https://shop.example,ada,pw1\n".encodeToByteArray()) }
        val before = assertNotNull(c.state.csvImport)
        assertNull(before.error)
        assertTrue(importCanRun(before))
        assertEquals(Placeholder.IMPORT_CONFIRM, importRunLabel(before), "never Try again before a first run")
        runBlocking { c.confirmImport() }
        val after = c.state.csvImport
        if (after != null) {
            if (after.done != null) assertFalse(importCanRun(after), "done: only Close")
            if (after.error != null) {
                assertEquals(after.retryable, importCanRun(after))
                if (after.retryable) assertEquals(Placeholder.TRY_AGAIN, importRunLabel(after))
            }
        }
        c.closeImport()
    }

    @Test
    fun thePagesHaveTheirTitleAndTheWayBackInTheTopBarAndTheSystemBackToo() {
        val items = src("VaultItemsScreens.kt")
        val section = body(items, "internal fun VaultItemsSection(")
        assertTrue("topBar = { if (page != null) PageTopBar(subPageTitle(page), closePage) else VaultTopBar(bar, working = state.busy) }" in section)
        assertTrue("ActiveBackHandler(model, enabled = page != null) { closePage() }" in section)
        // No second way back, and no second title, in the pages' bodies.
        assertFalse("c.closeTrash()" in body(items, "private fun TrashView("))
        assertFalse("Placeholder.TRASH," in body(items, "private fun TrashView("))
        assertFalse("c.closeHealth()" in body(src("VaultHealthScreens.kt"), "internal fun HealthPanel("))
        assertFalse("c.closeImport()" in body(src("VaultTransferScreens.kt"), "internal fun ImportView("))
    }

    @Test
    fun anItemsHistoryOpensInPlaceOnItsDetail() {
        val items = src("VaultItemsScreens.kt")
        val detail = body(items, "private fun ItemDetailView(")
        assertTrue("if (history != null && history.itemId == d.itemId) HistoryView(model, c, state, history, inline = true)" in detail)
        val section = body(items, "internal fun VaultItemsSection(")
        assertTrue("history != null && (detail == null || detail.itemId != history.itemId) -> HistoryView(model, c, state, history)" in section)
        val history = body(items, "private fun HistoryView(")
        assertTrue("if (inline) Quieter(UiText.ph(Placeholder.HISTORY_HIDE)) { c.closeItemHistory() }" in history)
        assertTrue("if (!inline) Quieter(UiText.ph(Placeholder.ITEM_BACK)) { c.closeItemHistory() }" in history)
        // A version's password stays hidden until shown.
        assertTrue("shown[v.rev] ?: MASK" in history)
        // At the largest font the date stands on its own line (in its column it broke a word a line), and a shared
        // vault's Rename goes under its name (beside it, it squeezed the name to a few letters a line).
        assertTrue("val stacked = largeFont()" in history)
        val head = src("VaultScreens.kt").substringAfter("private fun VaultSettingsHead(").substringBefore("\n}\n")
        assertTrue("if (largeFont()) {\n            Text(vaultRowName(v), style = MaterialTheme.typography.titleLarge)\n            rename()" in head)
    }

    @Test
    fun healthsSummaryIsTheCurrentAppsSevenTilesInItsOrder() {
        val never = healthTiles(HealthTilesView(logins = 4, weak = 1, reused = 0, breached = null, breachedHint = "run a scan", duplicates = 2, unchecked = 0, failing = 3))
        assertEquals(
            listOf(
                Placeholder.HEALTH_TILE_LOGINS, Placeholder.HEALTH_TILE_WEAK, Placeholder.HEALTH_TILE_REUSED, Placeholder.HEALTH_TILE_BREACHED,
                Placeholder.HEALTH_TILE_DUPLICATES, Placeholder.HEALTH_TILE_UNCHECKED, Placeholder.HEALTH_TILE_FAILING,
            ),
            never.map { it.label },
        )
        assertEquals(listOf("4", "1", "0", "?", "2", "0", "3"), never.map { it.value })
        assertEquals(listOf(null, true, false, null, true, false, true), never.map { it.bad }, "the logins count is no verdict; nought is good")
        assertEquals("run a scan", never[3].hint, "the content's hint stands under the Breached tile")

        val clean = healthTiles(HealthTilesView(4, 0, 0, 0, null, 0, 0, 0))[3]
        assertEquals(false, clean.bad, "a scan with a verdict of nought is good")
        val partial = healthTiles(HealthTilesView(4, 0, 0, 0, "incomplete", 0, 0, 0))[3]
        assertNull(partial.bad, "a nought the content qualifies is never drawn as good")
        assertEquals(true, healthTiles(HealthTilesView(4, 0, 0, 2, "incomplete", 0, 0, 0))[3].bad)
    }

    @Test
    fun theLockScreenSaysWhatTheLastTryAnsweredAboveTheField() {
        val lock = src("AccountScreens.kt").substringAfter("internal fun LockScreen(").substringBefore("internal fun lockTitle(")
        val said = lock.indexOf("SaidHere(model, s)")
        val field = lock.indexOf("SecretField(")
        val unlock = lock.indexOf("Main(UiText.ph(Placeholder.UNLOCK_BUTTON)")
        val busy = lock.indexOf("if (s.busy) Quiet(UiText.ph(Placeholder.UNLOCKING))")
        val quick = lock.indexOf("if (locked.quickUnlock)")
        assertTrue(said in 0 until field && field < unlock && unlock < busy && busy < quick, "$said $field $unlock $busy $quick")
        assertEquals(1, Regex("SaidHere\\(").findAll(lock).count())
    }
}
