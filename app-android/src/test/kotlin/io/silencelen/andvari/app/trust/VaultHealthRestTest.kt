package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeAppApi
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

/** Vault health's check run, staleness and snoozing, the two offers, and "not duplicates" put back, over the fake. */
class VaultHealthRestTest {
    private fun open(): Triple<FakeAppApi, FakeVaultContent, VaultContent> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return Triple(api, assertNotNull(api.fakeContent), assertNotNull(m.content.value))
    }

    private val panel = File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultHealthScreens.kt").readText()

    @Test
    fun theCheckRunTakesThePersonsVerdictsAndAGoneLoginIsOfferedForTheTrash() {
        val (_, fake, c) = open()
        val bank = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "Bank-pass-1!", "https://bank.example")
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Mail", "me", "Mail-pass-2!", "https://mail.example")
        c.openHealth()
        val h = assertNotNull(c.state.health)
        assertEquals(2, h.staleness.size)
        assertTrue(h.staleness.all { it.neverChecked })

        c.checkLogin(bank)
        val run = assertNotNull(c.state.health?.run)
        assertEquals(bank, run.itemId)
        assertEquals("https://bank.example", run.site?.let { webAddress(it) })
        assertFalse(runBlocking { c.recordCheck(bank, "gone") } is ActionResult.Failed)
        val offer = assertNotNull(c.state.health?.offerDelete, "a gone login is offered for the trash")
        assertEquals("Bank", offer.name)
        assertFalse(runBlocking { c.trashGoneLogin() } is ActionResult.Failed)
        assertNull(c.state.health?.offerDelete)
        assertTrue(c.state.health!!.staleness.none { it.itemId == bank }, "in the trash now")
    }

    @Test
    fun aRefusedPasswordIsOfferedAndTakingTheOfferEndsTheRun() {
        val (_, fake, c) = open()
        val bank = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "Bank-pass-1!", "https://bank.example")
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Mail", "me", "Mail-pass-2!", "https://mail.example")
        c.openHealth()
        c.startCheckRun(false)
        val first = assertNotNull(c.state.health?.run)
        assertEquals(2, first.total)
        runBlocking { c.recordCheck(first.itemId, "bad") }
        assertEquals(first.itemId, assertNotNull(c.state.health?.offerBad).itemId)
        c.answerBadOffer(true)
        assertNull(c.state.health?.offerBad)
        assertNull(c.state.health?.run, "taking the offer ends the run")
        assertTrue(c.state.health!!.staleness.first { it.itemId == first.itemId }.failing)
        // The panel opens the item through the vault page, which closes health first.
        assertTrue(panel.contains("c.answerBadOffer(true)\n                onOpenItem(o.itemId, true)"))
        assertTrue(File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultItemsScreens.kt").readText()
            .contains("if (generate) editing = Editing(\"login\", itemId, generate = true) else open = itemId"))
        assertTrue(bank.isNotEmpty())
    }

    @Test
    fun aLoginThatCouldNotBeCheckedIsSnoozedShownOnRequestAndUnsnoozed() {
        val (_, fake, c) = open()
        val bank = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "Bank-pass-1!", "https://bank.example")
        c.openHealth()
        c.checkLogin(bank)
        runBlocking { c.recordCheck(bank, "blocked") }
        val h = assertNotNull(c.state.health)
        assertTrue(h.staleness.none { it.itemId == bank }, "snoozed logins are not listed by default")
        assertTrue(h.allSnoozed)
        c.setHealthShowSnoozed(true)
        assertTrue(assertNotNull(c.state.health).staleness.single { it.itemId == bank }.snoozed)
        assertFalse(runBlocking { c.unsnoozeLogin(bank) } is ActionResult.Failed)
        c.setHealthShowSnoozed(false)
        assertFalse(assertNotNull(c.state.health).staleness.single { it.itemId == bank }.snoozed)
    }

    @Test
    fun skipWritesNothingAndStopEndsTheRun() {
        val (_, fake, c) = open()
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "Bank-pass-1!", "https://bank.example")
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Mail", "me", "Mail-pass-2!", "https://mail.example")
        c.openHealth()
        c.startCheckRun(true)
        assertEquals(1, assertNotNull(c.state.health?.run).position)
        c.skipCheck()
        assertEquals(2, assertNotNull(c.state.health?.run).position)
        assertTrue(c.state.health!!.staleness.all { it.neverChecked }, "skip wrote nothing")
        c.stopCheckRun()
        assertNull(c.state.health?.run)
    }

    @Test
    fun copiesMarkedNotDuplicatesArePutBack() {
        val (_, fake, c) = open()
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "Old-pass-1!", "https://bank.example")
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "New-pass-2!", "https://bank.example")
        c.openHealth()
        val group = assertNotNull(c.state.health?.duplicates?.singleOrNull())
        assertFalse(runBlocking { c.markNotDuplicates(group.signature) } is ActionResult.Failed)
        assertTrue(c.state.health!!.duplicates.isEmpty())
        val marked = c.state.health!!.notDuplicates.single()
        assertFalse(runBlocking { c.restoreDuplicates(marked.signature) } is ActionResult.Failed)
        assertEquals(1, c.state.health!!.duplicates.size)
        assertTrue(c.state.health!!.notDuplicates.isEmpty())
    }

    @Test
    fun theFourVerdictsAreTheContentsAndASavedSiteOpensOnlyAsAWebAddress() {
        assertEquals(listOf("ok", "bad", "gone", "blocked"), CHECK_VERDICTS)
        assertEquals("https://bank.example/login", webAddress("https://bank.example/login"))
        assertEquals("http://router.lan", webAddress(" http://router.lan "))
        assertEquals("https://bank.example", webAddress("bank.example"))
        for (bad in listOf("javascript:alert(1)", "intent://x#Intent;end", "file:///sdcard/x", "", "bank example.com", "content://x")) {
            assertNull(webAddress(bad), bad)
        }
    }

    @Test
    fun thePanelOffersEveryRemainingHealthAction() {
        for (call in listOf(
            "c.restoreDuplicates(", "c.unsnoozeLogin(", "c.trashGoneLogin()", "c.keepGoneLogin()", "c.answerBadOffer(false)",
            "c.startCheckRun(false)", "c.startCheckRun(true)", "c.checkLogin(", "c.skipCheck()", "c.stopCheckRun()",
            "c.recordCheck(", "c.setHealthShowSnoozed(", "ExternalExcursion.begin()",
        )) {
            assertTrue(panel.contains(call), call)
        }
        assertIs<String>(panel.substringAfter("internal fun HealthPanel("))
    }
}
