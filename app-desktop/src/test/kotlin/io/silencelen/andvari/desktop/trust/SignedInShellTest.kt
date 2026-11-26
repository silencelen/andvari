package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.ConnectResult
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
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
 * The signed-in area on the desktop: shared vaults, what the interface gained (an
 * unfinished move, a device link with no answer, a connection not made, a two-step set-up left open), the pages and
 * the top bar, and the menu's commands, over the fake.
 */
class SignedInShellTest {
    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun unlocked(): Pair<FakeDesktopAppApi, TrustModel> {
        val (api, m) = at(FakeScene.LOCKED)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()

    // ---- shared vaults ----

    @Test
    fun aSharedVaultIsCreatedAndItsMembersOpenAndClose() {
        val (api, m) = at(FakeScene.VAULTS)
        val before = assertNotNull(api.snapshot.account).vaults.size
        m.run({ vaults.createVault("Trips") })
        val vaults = assertNotNull(api.snapshot.account).vaults
        assertEquals(before + 1, vaults.size)
        val trips = vaults.first { it.name == "Trips" }
        m.run({ this.vaults.openMembers(trips) })
        assertNotNull(assertNotNull(api.snapshot.account).members)
        m.act { this.vaults.closeMembers() }
        assertNull(assertNotNull(api.snapshot.account).members)
        val screens = src("VaultScreens.kt")
        for (call in listOf(
            "vaults.createVault(n)", "vaults.openMembers(v)", "vaults.restoreVault(v)", "vaults.deleteVault(v)", "vaults.openMoveEverything(v)", "vaults.openMoveEverythingRemoving(m)",
            "vaults.leaveVault(v)", "vaults.saveItemsElsewhere(v, null)", "vaults.removeFromThisDevice(v)", "vaults.acceptOwnership(v)",
            "vaults.cancelOffer(v)", "contacts.confirmOnThisDevice(c)", "vaults.changeRole(m, next)", "vaults.removeMember(m)",
            "vaults.offerOwnership(m)", "vaults.addMember(screen, c, MemberRole.READER)", "vaults.tickMember(screen, m, it)",
            "vaults.moveEverything(screen, n)", "vaults.closeMoveEverything()",
        )) {
            assertTrue(screens.contains(call), call)
        }
    }

    @Test
    fun everyHistoryStateHasALineAndACopyOutOfAnUntrustedVaultWarnsFirst() {
        val (api, _) = at(FakeScene.VAULT_STATES)
        val rows = assertNotNull(api.snapshot.account).vaults
        for (row in rows.filter { it.log != VaultLogState.VERIFIED && it.log != VaultLogState.CONNECT_FIRST }) {
            assertNotNull(logStateLine(row), row.log.name)
        }
        for (row in rows) {
            val expect = row.log in setOf(VaultLogState.FROZEN, VaultLogState.FAILED, VaultLogState.WITHHELD) || row.heldUntilMs > 0
            assertEquals(expect, mustWarnBeforeCopy(row), row.log.name)
        }
        val removed = rows.first { it.log == VaultLogState.REMOVED }
        assertEquals(Placeholder.VAULT_REMOVED_BY_OWNER, (assertIs<UiText.Ph>(logStateLine(removed))).placeholder)
        val screens = src("VaultScreens.kt")
        assertTrue(screens.contains("if (mustWarnBeforeCopy(v)) confirmCopy = true else model.run({ vaults.saveItemsElsewhere(v, null) })"))
    }

    @Test
    fun anOwnerRenamesThroughTheContentAndOthersAreRefusedInItsWords() {
        val (api, m) = unlocked()
        val fake = assertNotNull(api.fakeContent)
        fake.addSharedVault("shared-1", "Family", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        fake.addSharedVault("shared-2", "Work", VaultAccess.ROLE_READER, VaultStanding.VERIFIED)
        val c = assertNotNull(m.content.value)
        assertNull(renameSentence(runBlocking { c.renameSharedVault("shared-1", "  Household  ") }))
        assertTrue(c.state.vaults.any { it.vaultId == "shared-1" && it.name == "Household" })
        val reader = assertIs<ActionResult.Failed>(runBlocking { c.renameSharedVault("shared-2", "Mine now") })
        assertEquals(reader.message, renameSentence(reader))
        assertTrue(src("VaultScreens.kt").contains("c.renameSharedVault(v.vaultId, name)"))
        assertTrue(src("VaultScreens.kt").contains("if (owner && !v.deleted && v.writable) RenameVaultControl(model, s, v)"))
        assertTrue(FakeVaultContent.PERSONAL_VAULT_ID.isNotEmpty())
    }

    // ---- what the interface gained ----

    @Test
    fun aConnectionNotMadeSaysWhoAndOffersRetryWhileTheLinkHolds() {
        val (api, m) = at(FakeScene.PROMPT_CONNECTION_NOT_MADE)
        val p = assertIs<AccountPrompt.ConnectionNotMade>(assertNotNull(api.snapshot.account).prompts.single { it is AccountPrompt.ConnectionNotMade })
        assertTrue(p.canRetry)
        val line = assertIs<UiText.Ph>(promptLine(p))
        assertEquals(Placeholder.CONNECTION_NOT_MADE_RETRY, line.placeholder)
        assertEquals(listOf(p.from), line.args)
        var answered: ConnectResult? = null
        m.run({ links.retryConnection(p) }) { answered = it }
        assertNotNull(answered)
        // Through the name the links carry: with none kept here, its window asks first (LinkNameTest).
        assertTrue(src("PeopleScreens.kt").contains("if (p.canRetry) Second(UiText.ph(Placeholder.TRY_AGAIN), enabled = !s.busy) { model.linkName.go(NamedLinkAct.Retry(p)) }"))
    }

    @Test
    fun aDeviceLinkWithNoAnswerSaysNothingWasLinked() {
        assertEquals(Placeholder.LINK_DEVICE_NO_ANSWER, assertIs<UiText.Ph>(linkDeviceEndLine(LinkDeviceEnd.NO_ANSWER)).placeholder)
        assertIs<UiText.Plain>(linkDeviceEndLine(LinkDeviceEnd.CANCELLED), "the design's sentence where it gives one")
        assertEquals(Placeholder.REFUSAL, assertIs<UiText.Ph>(linkDeviceEndLine(LinkDeviceEnd.EXPIRED)).placeholder)
    }

    @Test
    fun anUnfinishedMoveIsCheckedBeforeTheCardAndOffersTryAgainAndForget() {
        val entry = src("EntryScreens.kt")
        val card = entry.substringAfter("internal fun InstanceCard(")
        assertTrue(card.indexOf("instance.unfinishedMove?.let { return UnfinishedMoveCard(") < card.indexOf("when (val card = instance.card)"))
        val move = entry.substringAfter("internal fun UnfinishedMoveCard(").substringBefore("\n}")
        assertTrue(move.contains("this.instance.finishMove(move)"))
        assertTrue(move.contains("ForgetServerButton(model, s, instance)"))
        // The lock screen shows it too: the vault does not open until the move is finished.
        assertTrue(src("AccountScreens.kt").contains("if (instance != null && unfinished != null) UnfinishedMoveCard(model, s, instance, unfinished)"))
    }

    @Test
    fun aTwoStepSetUpLeftOnItsConfirmStepIsPointedToFromEveryPage() {
        val (api, m) = unlocked()
        assertFalse(twoStepWaiting(assertNotNull(api.snapshot.account)))
        m.run({ settings.openTwoStep() })
        val screen = assertNotNull(assertNotNull(api.snapshot.account).twoStep)
        m.run({ settings.startTwoStep(screen, FakeScenes.PASSWORD) })
        assertTrue(twoStepWaiting(assertNotNull(api.snapshot.account)))
        val shell = src("AccountScreens.kt")
        assertTrue(shell.contains("if (page != SignedInPage.SETTINGS && twoStepWaiting(account)) {"))
    }

    // ---- the pages ----

    @Test
    fun theVaultIsHomeAndEachPageHoldsItsSections() {
        assertEquals(SignedInPage.VAULT, SignedInPage.entries.first())
        val shell = src("AccountScreens.kt")
        assertTrue(shell.contains("remember(account.accountId, unlocks) { mutableStateOf(SignedInPage.VAULT) }"), "every unlock starts at home")
        // The vault page also carries the live-updates line above the items.
        assertTrue(shell.substringAfter("SignedInPage.VAULT -> {").substringBefore("SignedInPage.SHARING ->").contains("VaultItemsSection(model)"))
        val sharing = shell.substringAfter("SignedInPage.SHARING -> {").substringBefore("SignedInPage.SETTINGS ->")
        assertTrue(sharing.indexOf("SharedVaultsSection(") in 0 until sharing.indexOf("PeopleSection("))
        assertTrue(sharing.indexOf("PeopleSection(") < sharing.indexOf("LinksSection("))
        assertTrue(shell.contains("SignedInPage.SETTINGS -> AccountSettingsPage(model, s, account)"))
        // What needs the person shows above every page: the card, what was said, the prompts.
        val above = shell.substringAfter("private fun AttentionArea(").substringBefore("\n}\n")
        for (part in listOf("InstanceCard(", "SaidHere(", "KitAfterMoveCard(", "PromptsSection(")) assertTrue(above.contains(part), part)
        // Every page draws it: the vault at the top of its list, the others under their header (what was said there
        // stands over the foot of the window instead, LockNamesOnceTest).
        val pages = shell.substringAfter("private fun SignedInPages(").substringBefore("\n}\n")
        assertEquals(2, Regex("AttentionArea\\(model, s, account, page, fork, go[,)]").findAll(pages).count())
        // Nothing is marked with a bar.
        assertFalse(Regex("drawBehind|border\\(|VerticalDivider").containsMatchIn(shell))
    }

    // ---- the menu ----

    @Test
    fun syncNowAndImportActOnlyOnAnOpenVault() {
        val (api, m) = at(FakeScene.LOCKED)
        assertNull(m.syncNow(), "nothing to sync while locked")
        m.requestImport()
        assertFalse(m.importRequested.value)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        val c = assertNotNull(m.content.value)
        assertNotNull(m.syncNow())
        assertNotNull(c.state.notice ?: c.state.error, "a sync the person asked for says how it went")
        m.requestImport()
        assertTrue(m.importRequested.value)
        m.lockNow()
        m.onSnapshot(api.snapshot)
        assertFalse(m.importRequested.value, "an import asked for is not carried past a lock")
        assertTrue(src("VaultTransferScreens.kt").contains("model.importTaken()"))
    }

    @Test
    fun theMenuCarriesTheOldAppsItemsTheInterfaceOffers() {
        val main = File("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt").readText()
        for (item in listOf(
            "Item(\"Sync now\", shortcut = KeyShortcut(Key.R, ctrl = true), enabled = unlocked) { model?.syncNow() }",
            "Item(\"Import passwords…\", enabled = unlocked) { model?.requestImport() }",
            "RadioButtonItem(mode.label, selected = theme == mode)",
            "prefs.themeMode = mode.storeValue",
            "Item(\"Open web vault\", enabled = webVault != null) { webVault?.let { openInBrowser(it) } }",
            "Item(\"About andvari\") { aboutOpen = true }",
            "AndvariDesktopTheme(theme)",
        )) {
            assertTrue(main.contains(item), item)
        }
        assertEquals("linux", if (System.getProperty("os.name").lowercase().contains("win")) "linux" else desktopPlatform())
    }
}
