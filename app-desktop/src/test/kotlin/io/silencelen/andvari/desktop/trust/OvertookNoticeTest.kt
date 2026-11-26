package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.content.ContentNoticeKind
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.content.LockCutKind
import io.silencelen.andvari.core.app.content.SpaceFor
import io.silencelen.andvari.core.app.content.SpaceVerdict
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the vault content's side now offers in place of the desktop's earlier notice. What a lock cut short
 * is the shared code's own notice at the next unlock, by kind and with counts, and the desktop's own lines for it are
 * gone; the line at the moment of the lock stays. "Short of space" before an import, with the limit and the amount; the
 * informational line when a copy or a move went on on sizes a co-member declared; and Settings' four meters.
 */
class OvertookNoticeTest {
    private fun open(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        unlock(api, m)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        return api to m
    }

    private fun unlock(api: FakeDesktopAppApi, m: TrustModel) {
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
    }

    private fun lockWhenBusy(api: FakeDesktopAppApi, c: VaultContent) {
        var fired = false
        c.observe { s -> if (s.busy && !fired) { fired = true; api.lock() } }
    }

    @Test
    fun whatALockCutShortIsTheSharedCodesNoticeAndTheLineAtTheLockStays() {
        val (api, m) = open()
        val fake = assertNotNull(api.fakeContent)
        val id = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "https://bank.example")
        val c = assertNotNull(m.content.value)
        lockWhenBusy(api, c)
        runBlocking { c.deleteItem(id) }
        m.onSnapshot(api.snapshot)
        // At the moment of the lock: the desktop's one line, kept. Whether the change went through is not known, so it is
        // the line that says to check, never "do it again".
        assertEquals(Placeholder.CHANGE_CUT_BY_LOCK, assertIs<UiText.Ph>(assertNotNull(m.said.value).text).placeholder)
        // After the unlock, the desktop says nothing of its own (the fake's content notes no cut for its own delete;
        // what core says is raised through the fake's switch in the next test).
        unlock(api, m)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertNull(m.said.value?.text?.let { (it as? UiText.Ph)?.placeholder?.takeIf { p -> p.name.startsWith("LOCK_OVERTOOK_") } })
    }

    @Test
    fun eachKindTheFakeRaisesIsSaidInTheVaultWithItsCounts() {
        val (api, m) = open()
        val fake = assertNotNull(api.fakeContent)
        for (kind in LockCutKind.entries) {
            fake.raiseLockCut(kind, "Trips", "Personal", 3, 9)
            val state = assertNotNull(m.content.value).state
            assertEquals(ContentNoticeKind.LOCK, state.noticeKind, "$kind: ${state.notice}")
            val cut = state.lockCut.single()
            assertEquals(kind, cut.kind)
            assertTrue(assertNotNull(state.notice).contains(cut.line), "$kind: the notice holds core's line, which the vault list shows")
            assertNotNull(m.content.value).dismissNotice()
        }
    }

    @Test
    fun theDesktopsOwnLockNoticeAndItsPlaceholdersAreGone() {
        val model = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/TrustModel.kt").readText()
        for (gone in listOf("overtookNotice", "dismissOvertook", "lockOvertookWords", "overtookFlow")) assertFalse(model.contains(gone), gone)
        assertFalse(File("src/main/kotlin/io/silencelen/andvari/desktop/trust/AccountScreens.kt").readText().contains("overtook"))
        for (gone in listOf("LOCK_OVERTOOK_IMPORT", "LOCK_OVERTOOK_COPY", "LOCK_OVERTOOK_CHANGE")) assertTrue(Placeholder.entries.none { it.name == gone }, gone)
        val items = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultItemsScreens.kt").readText()
        val list = items.substringAfter("private fun VaultItemsList(").substringBefore("\n}\n")
        val said = items.substringAfter("internal fun ContentSaid(").substringBefore("\n}\n")
        assertTrue(list.contains("ContentSaid(c, state)") && said.contains("state.notice?.let {") && said.contains("c.dismissNotice()"))
    }

    @Test
    fun anImportShortOfSpaceSaysTheLimitAndTheAmountBeforeAnythingIsSent() {
        val (api, m) = open()
        val fake = assertNotNull(api.fakeContent)
        val c = assertNotNull(m.content.value)
        fake.setRoomLeft(bytesLeft = 1_000_000, itemsLeft = 1, sharedVaultsLeft = 1)
        val rows = (1..5).joinToString("") { "Site $it,https://s$it.example,me,pw$it\n" }
        runBlocking { c.importCsv(("name,url,username,password\n" + rows).toByteArray()) }
        val space = assertNotNull(c.state.space)
        assertEquals(SpaceFor.CSV_IMPORT, space.forWhat)
        assertEquals(SpaceVerdict.NOT_ENOUGH, space.verdict)
        assertEquals(space.line, spaceLine(c.state, informational = false))
        assertNull(spaceLine(c.state, informational = true), "not the informational line")
        val screen = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultTransferScreens.kt").readText()
            .substringAfter("internal fun ImportView(").substringBefore("\n}\n")
        assertTrue(screen.indexOf("spaceLine(state, informational = false)") in 0 until screen.indexOf("Main(UiText.ph(label)"))
        // With room, nothing is said.
        fake.setRoomLeft(bytesLeft = 1_000_000, itemsLeft = 100, sharedVaultsLeft = 1)
        runBlocking { c.closeImport(); c.importCsv(("name,url,username,password\n" + rows).toByteArray()) }
        assertNull(spaceLine(c.state, informational = false))
    }

    @Test
    fun theInformationalLineIsForACopyOrMoveShortOnlyOnDeclaredSizes() {
        val list = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultItemsScreens.kt").readText()
            .substringAfter("private fun VaultItemsList(").substringBefore("\n}\n")
        assertTrue(list.contains("spaceLine(state, informational = true)?.let { Quiet(UiText.of(it)) }"))
        val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultItemsScreens.kt").readText()
            .substringAfter("internal fun spaceLine(").substringBefore("\n}\n")
        assertTrue(src.contains("SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES && space.forWhat != io.silencelen.andvari.core.app.content.SpaceFor.CSV_IMPORT"))
    }

    @Test
    fun settingsShowsTheFourMetersAndNothingWhenTheServerGaveNone() {
        val (api, m) = open()
        val fake = assertNotNull(api.fakeContent)
        val c = assertNotNull(m.content.value)
        fake.setQuota(null)
        assertTrue(storageLines(c.state.storage).isEmpty())
        fake.setRoomLeft(bytesLeft = 4000, itemsLeft = 90, sharedVaultsLeft = 2)
        runBlocking { c.refresh() }
        val lines = storageLines(assertNotNull(c.state.storage)).map { assertIs<UiText.Ph>(it) }
        assertEquals(listOf(Placeholder.STORAGE_BYTES, Placeholder.STORAGE_ITEMS, Placeholder.STORAGE_VAULTS, Placeholder.STORAGE_LINKS), lines.map { it.placeholder })
        assertEquals(listOf("10", "100"), lines[1].args)
        assertEquals(listOf("1", "3"), lines[2].args)
        assertEquals(listOf("2", "20"), lines[3].args)
        assertEquals(listOf(sizeText(1000), sizeText(5000)), lines[0].args)
        val settings = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/SettingsScreens.kt").readText()
        assertTrue(settings.substringAfter("internal fun StorageSection(").substringBefore("\n}\n").contains("if (lines.isEmpty()) return"))
    }
}
