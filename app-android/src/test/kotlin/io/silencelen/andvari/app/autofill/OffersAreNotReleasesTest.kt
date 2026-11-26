package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.app.trust.BuildConstants
import io.silencelen.andvari.app.trust.TrustModel
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.autofill.AppFillGate
import io.silencelen.andvari.core.client.autofill.FieldKind
import io.silencelen.andvari.core.client.autofill.FillTarget
import io.silencelen.andvari.core.client.autofill.FormKind
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Offers are not releases. The service used to ask the shared code for every
 * matching login's credentials and every card's fields while it built the rows it offers, so each offer was a release
 * (and, once a session records uses, a recorded use). Now an offer reads no secret, and an item's values are asked for
 * only for a row that must carry them (the platform fills it on a pick) or for the item the person picked in andvari's
 * own window.
 */
class OffersAreNotReleasesTest {
    /**
     * The shared code's content, counting each release of a value: [released] counts every read that hands a value out,
     * the reads that record a use and the reads that record none alike ("released" means a value left
     * the shared code). [uses] is what the shared code itself recorded as uses (its fake's own record).
     */
    private class Counting(private val inner: VaultContent, private val fake: FakeVaultContent) : VaultContent by inner {
        val released = mutableListOf<String>()
        val recordingReads = mutableListOf<String>()
        override fun fillCredential(itemId: String) = inner.fillCredential(itemId).also { released += itemId; recordingReads += itemId }
        override fun fillCardField(itemId: String, field: String) = inner.fillCardField(itemId, field).also { released += itemId; recordingReads += itemId }
        override fun fillCredentialUnrecorded(itemId: String) = inner.fillCredentialUnrecorded(itemId).also { released += itemId }
        override fun fillCardFieldUnrecorded(itemId: String, field: String) = inner.fillCardFieldUnrecorded(itemId, field).also { released += itemId }
        val uses: List<String> get() = fake.recordedUses
        val useTimes: List<Long> get() = fake.recordedUseTimes
        var nowMs: Long
            get() = fake.nowMs
            set(v) {
                fake.nowMs = v
            }
    }

    private val app = "com.example.app"
    private val chrome = "com.android.chrome"
    private val text = 1

    private fun content(cards: Int = 2): Counting {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        val c = assertNotNull(api.content)
        val vault = assertNotNull(c.vaultsForNewItems().firstOrNull { it.personal }).vaultId
        runBlocking {
            assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Own A", "a@example.com", "pass-a", listOf("androidapp://$app"), "", "", false), vault))
            assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Own B", "b@example.com", "pass-b", listOf("androidapp://$app"), "", "", false), vault))
            assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Shop", "s@example.com", "pass-s", listOf("https://shop.example"), "", "", false), vault))
            for (i in 1..cards) assertEquals(ActionResult.Ok, c.saveCard(null, CardInput("Card $i", "Holder", "4242424242424242", "07", "2031", "123", "90210", "", false), vault))
        }
        val fake = assertNotNull(api.fakeContent)
        assertTrue(fake.recordedUses.isEmpty(), "saving is not a use")
        return Counting(c, fake)
    }

    private fun field(id: String, kind: FieldKind, domain: String? = null) = FieldOf(id, kind, domain, autofillType = text)

    private fun form(pkg: String, focus: String, domain: String? = null) = FormOf(
        listOf(field("user", FieldKind.USERNAME, domain), field("pass", FieldKind.PASSWORD, domain)), pkg,
        ccFields = listOf(field("pan", FieldKind.CC_NUMBER, domain), field("csc", FieldKind.CC_CSC, domain), field("exp", FieldKind.CC_EXP, domain)),
        formKind = FormKind.MIXED, focusedId = focus,
    )

    private fun offers(c: Counting, pkg: String, domain: String?) =
        ContentFill.offersFor(c, listOf(FillTarget(webHost = domain, packageName = pkg)), listOfNotNull(domain), cards = true)

    @Test
    fun offeringReleasesNothingWhereNoRowCarriesValues() {
        val c = content()
        val offered = offers(c, app, null)
        assertEquals(listOf("Own A", "Own B", "Card 1", "Card 2"), offered.map { it.doc.name })
        assertTrue(c.released.isEmpty(), "offering reads no secret: ${c.released}")
        val release = { id: String -> ContentFill.release(c, id) }
        for (verdict in listOf(AppFillGate.Verdict.CONFIRM, AppFillGate.Verdict.CONFIRM_SIGNER_CHANGED)) {
            val rows = FillPlan.rows(offered, form(app, "pan"), FillPlan.Asker.App(verdict), release = release)
            assertEquals(4, rows.size)
            assertTrue(rows.all { it is FillRow.LoginConfirm || it is FillRow.CardConfirm })
        }
        for (verdict in AppFillGate.Verdict.entries) {
            FillPlan.resultRows(offered, form(app, "pan"), FillPlan.Asker.App(verdict), release = release)
            FillPlan.chooserRows(offered, form(app, "pan"), FillPlan.Asker.App(verdict), ChooserKind.LOGINS)
            FillPlan.chooserRows(offered, form(app, "pan"), FillPlan.Asker.App(verdict), ChooserKind.CARDS)
        }
        assertTrue(c.released.isEmpty(), "no confirm row, no result through an app and no chooser list releases anything: ${c.released}")
        // The pick inside andvari (the chooser, a confirm): exactly the picked item is released, and it is one use.
        val picked = offered.first { it.doc.name == "Card 2" }.itemId
        assertNotNull(ContentFill.cardById(c, picked)?.doc?.card)
        assertEquals(setOf(picked), c.released.toSet())
        assertEquals(listOf(picked), c.uses, "six fields read at one pick are one use")
    }

    @Test
    fun aRowThatMustCarryValuesReleasesOnlyItsOwnItem() {
        // A vetted app's own logins fill on a pick: their values ride the rows, released for those rows only.
        val c = content()
        val offered = offers(c, app, null)
        val rows = FillPlan.rows(offered, form(app, "user"), FillPlan.Asker.App(AppFillGate.Verdict.SILENT)) { id -> ContentFill.release(c, id) }
        val logins = rows.map { assertIs<FillRow.Login<String>>(it) }
        assertEquals(listOf("user" to "a@example.com", "pass" to "pass-a"), logins.first().values)
        assertEquals(logins.map { it.itemId }.toSet(), c.released.toSet(), "no card released: the focus is not on a card field")
        assertTrue(logins.all { DatasetBuilder.carriesOnlyReleasedValues(it) })
        assertTrue(c.recordingReads.isEmpty(), "rows built before a pick use the reads that record nothing: ${c.recordingReads}")
        assertTrue(c.uses.isEmpty(), "two rows offered with their values are no use: ${c.uses}")
        // The platform's record says the person picked the second row: that one, once.
        ContentFill.recordPicked(c, FillPicks.picked(listOf(FillPicks.DATASET_SELECTED to logins[1].itemId)), c.nowMs)
        assertEquals(listOf(logins[1].itemId), c.uses)
    }

    @Test
    fun aPickIsRecordedAtTheTimeOfTheOfferNotAtTheTimeThePlatformSaysSo() {
        val c = content()
        val (a, b) = offers(c, app, null).filter { it.doc.type == "login" }.map { it.itemId }
        // Rows offered at T; the platform's record of the pick is read at the next fill request, three days later.
        val offeredAt = c.nowMs
        c.nowMs += 3 * 86_400_000L
        ContentFill.recordPicked(c, listOf(a), offeredAtMs = offeredAt)
        assertEquals(listOf(a), c.uses)
        assertEquals(listOf(offeredAt), c.useTimes, "the use is at the offer's time, which is no later than the pick")
        // With no time of an offer kept (the process started after it), the pick is recorded now, as before.
        c.nowMs += 120_000
        ContentFill.recordPicked(c, listOf(b), offeredAtMs = 0L)
        assertEquals(listOf(a, b), c.uses)
        assertEquals(c.nowMs, c.useTimes.last())
    }

    @Test
    fun theServiceGivesTheTimeOfItsLastReplyAndKeepsItAtEveryReply() {
        FillPicks.replied(1_234L)
        assertEquals(1_234L, FillPicks.lastReplyAtMs)
        val svc = File("src/main/kotlin/io/silencelen/andvari/app/autofill/AndvariAutofillService.kt").readText()
        // The record is read inside handleFill, with the previous reply's time; the time moves only after handleFill
        // returned, just before the reply itself.
        val handle = svc.indexOf("private fun handleFill")
        val moved = svc.indexOf("FillPicks.replied(System.currentTimeMillis())")
        assertTrue(moved in 0 until handle && svc.indexOf("runCatching { handleFill(") < moved)
        assertTrue(moved < svc.indexOf("callback.onSuccess(response)"))
        assertTrue(svc.indexOf("FillPicks.lastReplyAtMs)") > handle)
        assertEquals(1, Regex("FillPicks\\.replied\\(").findAll(svc).count())
        FillPicks.replied(0L)
    }

    @Test
    fun eachWayOfFillingIsOneUseOfThePickedItemOnly() {
        val c = content()
        val offered = offers(c, app, null)
        val (a, b) = offered.filter { it.doc.type == "login" }.map { it.itemId }
        val (card1, card2) = offered.filter { it.doc.type == "card" }.map { it.itemId }
        // 1. A direct pick from rows that carry values: the offer records nothing, the platform's record of the pick one use.
        offered.forEach { ContentFill.release(c, it.itemId) }
        assertTrue(c.uses.isEmpty(), "${c.uses}")
        val offeredAt = c.nowMs
        ContentFill.recordPicked(c, listOf(card1), offeredAt)
        assertEquals(listOf(card1), c.uses)
        // The same pick reported again within the content's window is the same use.
        ContentFill.recordPicked(c, listOf(card1), offeredAt)
        assertEquals(listOf(card1), c.uses)
        // 2. andvari's chooser and 3. a confirm both read the picked item with the recording read: one use, at the read.
        c.nowMs += 120_000
        assertNotNull(ContentFill.loginById(c, a))
        assertEquals(listOf(card1, a), c.uses)
        // 4. A card picked in andvari: six fields, one use.
        assertNotNull(ContentFill.cardById(c, card2))
        assertEquals(listOf(card1, a, card2), c.uses)
        assertTrue(b !in c.uses, "never picked, never a use")
        // A picked id that is not a login or card of the working set records nothing.
        ContentFill.recordPicked(c, listOf("00000000-0000-4000-8000-00000000dead", ""), c.nowMs)
        assertEquals(listOf(card1, a, card2), c.uses)
    }

    @Test
    fun onlyThePathsWhereThePersonPicksInsideAndvariUseTheRecordingReads() {
        val dir = File("src/main/kotlin/io/silencelen/andvari/app/autofill")
        fun src(name: String) = File(dir, name).readText()
        for (name in listOf("FillChooserActivity.kt", "AppFillConfirmActivity.kt", "CardFillConfirmActivity.kt")) {
            assertFalse(src(name).contains("ContentFill.release("), "$name: a pick inside andvari is a use")
        }
        assertTrue(src("FillChooserActivity.kt").contains("ContentFill.loginById(") && src("FillChooserActivity.kt").contains("ContentFill.cardById("))
        assertTrue(src("AppFillConfirmActivity.kt").contains("ContentFill.loginById("))
        assertTrue(src("CardFillConfirmActivity.kt").contains("ContentFill.cardById("))
        for (name in listOf("AndvariAutofillService.kt", "AutofillUnlockActivity.kt", "TrustBrowserActivity.kt", "FillPlan.kt", "DatasetBuilder.kt")) {
            assertFalse(Regex("ContentFill\\.(loginById|cardById)\\(").containsMatchIn(src(name)), "$name builds rows before a pick: no use")
        }
        val cf = src("ContentFill.kt")
        assertEquals(1, Regex("content\\.fillCredential\\(").findAll(cf).count())
        assertEquals(1, Regex("content\\.fillCardField\\(").findAll(cf).count())
        // The service reads the platform's record before any reply: the platform clears it at every reply.
        val svc = src("AndvariAutofillService.kt")
        assertTrue(svc.indexOf("ContentFill.recordPicked(") < svc.indexOf("FillReason.NO_FIELDS"))
    }

    @Test
    fun aVerifiedBrowserReleasesOnlyTheRowsItIsShown() {
        val c = content(cards = 12)
        val offered = offers(c, chrome, "shop.example")
        val rows = FillPlan.rows(offered, form(chrome, "pan", "shop.example"), FillPlan.Asker.VerifiedBrowser) { id -> ContentFill.release(c, id) }
        assertEquals(DatasetBuilder.MAX_DATASETS, rows.size, "one login row and nine card rows, under the cap")
        assertEquals(rows.map { it.itemId }.toSet(), c.released.toSet(), "the cards past the cap are not released")
        assertEquals(1, rows.filterIsInstance<FillRow.Login<String>>().size)
        assertTrue(c.uses.isEmpty(), "ten rows shown are no use: ${c.uses}")
    }

    @Test
    fun anOffersStandInNeverBecomesAValueAndThePlatformsRecordSaysWhatWasPicked() {
        assertFalse(DatasetBuilder.carriesOnlyReleasedValues(FillRow.Login("x", "t", null, listOf("pass" to ContentFill.UNRELEASED))))
        assertEquals(listOf("a", "c"), FillPicks.picked(listOf(0 to "a", 1 to "b", 0 to "a", 2 to null, 0 to "c", 0 to "")))
        val svc = File("src/main/kotlin/io/silencelen/andvari/app/autofill/AndvariAutofillService.kt").readText()
        assertTrue(svc.contains("ContentFill.recordPicked(access.content, FillPicks.picked(FillPicks.eventsOf(fillEventHistory)), FillPicks.lastReplyAtMs)"))
        assertTrue(svc.contains("release = { id -> ContentFill.release(content, id) }"))
        val src = File("src/main/kotlin/io/silencelen/andvari/app/autofill").listFiles()!!.joinToString("\n") { it.readText() }
        assertFalse(src.contains("ContentFill.itemsFor("), "nothing offers by releasing any more")
        val db = File("src/main/kotlin/io/silencelen/andvari/app/autofill/DatasetBuilder.kt").readText()
        assertEquals(4, Regex("b\\.setId\\(").findAll(db).count(), "each row that carries values names its item")
    }
}
