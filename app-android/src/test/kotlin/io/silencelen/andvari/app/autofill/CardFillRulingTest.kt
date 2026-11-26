package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.AppFillGate
import io.silencelen.andvari.core.client.autofill.CardFill
import io.silencelen.andvari.core.client.autofill.FieldKind
import io.silencelen.andvari.core.client.autofill.FormKind
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Android review 1, finding 1 (HIGH) and ruling 1: an app that is not a browser took every saved card after one
 * unlock, because card rows carried their values and an authentication result travels through the requesting app.
 * These are the rules as plain functions ([FillPlan], [OneUseTokens]); what only a phone can show is not tested here.
 */
class CardFillRulingTest {
    private val text = 1 // View.AUTOFILL_TYPE_TEXT

    private fun field(id: String, kind: FieldKind, domain: String? = null) = FieldOf(id = id, kind = kind, webDomain = domain, autofillType = text)

    /** The reviewer's form: a sign-in screen with user name and password, plus card fields. */
    private fun form(pkg: String, focused: String, domain: String? = null) = FormOf(
        fields = listOf(field("user", FieldKind.USERNAME, domain), field("pass", FieldKind.PASSWORD, domain)),
        appPackage = pkg,
        ccFields = listOf(field("pan", FieldKind.CC_NUMBER, domain), field("csc", FieldKind.CC_CSC, domain), field("exp", FieldKind.CC_EXP, domain)),
        formKind = FormKind.MIXED,
        focusedId = focused,
    )

    private fun card(id: String, name: String, number: String, cvv: String, mm: String, yyyy: String, holder: String, postal: String) = VaultItem(
        id, "", 0L, 0L, ItemDoc(type = "card", name = name, card = CardData(cardholderName = holder, number = number, expMonth = mm, expYear = yyyy, securityCode = cvv, postalCode = postal)),
    )

    private fun login(id: String, name: String, user: String, pw: String, uri: String) =
        VaultItem(id, "", 0L, 0L, ItemDoc(type = "login", name = name, login = LoginData(username = user, password = pw, uris = listOf(uri))))

    private val visa = card("c1", "Visa", "4242424242424242", "987", "07", "2031", "Card Holder", "90210")
    private val second = card("c2", "Second", "5555555555554444", "654", "01", "2030", "Other Holder", "10001")
    private val evil = "com.evil.flashlight"
    private val items = listOf(login("l1", "Own", "own-user", "own-pass", "androidapp://$evil"), visa, second)

    /** Every card value in [items]: none may appear in a row an app that is not a verified browser receives. */
    private val cardSecrets = listOf("4242424242424242", "5555555555554444", "987", "654", "07/31", "01/30", "0731", "0130", "Card Holder", "Other Holder", "90210", "10001")

    private fun valuesOf(rows: List<FillRow<String>>): List<String> = rows.flatMap { r ->
        when (r) {
            is FillRow.Login -> r.values.map { it.second }
            is FillRow.LoginConfirm -> emptyList()
            is FillRow.Card -> r.values.map { it.second.toString() }
            is FillRow.CardConfirm -> emptyList()
            is FillRow.Choose -> emptyList()
        }
    }

    private fun assertNoCardValue(rows: List<FillRow<String>>) {
        val shown = rows.joinToString("\n") { it.toString() } + "\n" + valuesOf(rows).joinToString("\n")
        for (s in cardSecrets) assertFalse(shown.contains(s), "a card value ($s) rides a row: $rows")
    }

    @Test
    fun aResponseForAnAppThatIsNotABrowserCarriesNoCardValue() {
        for (verdict in AppFillGate.Verdict.entries) {
            val rows = FillPlan.rows(items, form(evil, focused = "pan"), FillPlan.Asker.App(verdict))
            assertNoCardValue(rows)
            val cards = rows.filter { it is FillRow.Card || it is FillRow.CardConfirm }
            assertEquals(listOf("c1", "c2"), cards.map { it.itemId }, "verdict $verdict")
            // Every card row leads to the confirm, SILENT included: an app is never remembered for cards.
            cards.forEach { assertIs<FillRow.CardConfirm<String>>(it, "verdict $verdict") }
            cards.forEach { assertEquals(FillPlan.CONFIRM_CARD_SUBTITLE, it.subtitle) }
            assertEquals(listOf("pan", "csc", "exp"), (cards.first() as FillRow.CardConfirm).fieldIds, "the ids it would fill, no values")
        }
        // The asker for any package outside the browser table is an app, even with no verdict at all.
        assertEquals(FillPlan.Asker.App(AppFillGate.Verdict.CONFIRM), FillPlan.asker(evil, trusted = false, verdict = null))
    }

    @Test
    fun cardRowsAreOfferedOnlyWhenTheFieldInFocusIsACardField() {
        // The reviewer's attack taps the user-name field: no card row at all, in an app or in a verified browser.
        for (asker in listOf(FillPlan.Asker.App(AppFillGate.Verdict.SILENT), FillPlan.Asker.VerifiedBrowser)) {
            val pkg = if (asker is FillPlan.Asker.App) evil else "com.android.chrome"
            for (focus in listOf("user", "pass", "nothing-we-classified")) {
                val rows = FillPlan.rows(items, form(pkg, focused = focus, domain = if (asker is FillPlan.Asker.App) null else "shop.example"), asker)
                assertTrue(rows.none { it is FillRow.Card || it is FillRow.CardConfirm }, "$asker focus=$focus: $rows")
            }
        }
        assertNull(form(evil, focused = "user").cardFillFrame)
        assertNotNull(form(evil, focused = "csc").cardFillFrame)
    }

    @Test
    fun aVerifiedBrowserKeepsTheWalletPostureAndAnUnverifiedOneGetsNoCard() {
        val chrome = "com.android.chrome"
        val rows = FillPlan.rows(items, form(chrome, focused = "pan", domain = "shop.example"), FillPlan.Asker.VerifiedBrowser)
        val cards = rows.filterIsInstance<FillRow.Card<String>>()
        assertEquals(listOf("c1", "c2"), cards.map { it.itemId }, "one pick fills: the values ride the row")
        assertEquals(CardFill.Value.Text("4242424242424242"), cards.first().values.first { it.first == "pan" }.second)
        assertTrue(cards.first().title.contains("4242") && !cards.first().title.contains("424242424242"), "the row names the brand and last four only")
        val unverified = FillPlan.rows(items, form(chrome, focused = "pan", domain = "shop.example"), FillPlan.Asker.UnverifiedBrowser)
        assertTrue(unverified.none { it is FillRow.Card || it is FillRow.CardConfirm })
        assertEquals(FillPlan.Asker.UnverifiedBrowser, FillPlan.asker(chrome, trusted = false, verdict = null))
        assertEquals(FillPlan.Asker.VerifiedBrowser, FillPlan.asker(chrome, trusted = true, verdict = null))
    }

    /**
     * The unlock's result is built by the same rows (the unlock activity's finishFromContent goes through
     * DatasetBuilder.responseForUnlocked, whose datasets are FillPlan.rows): in an app that is not a verified browser
     * it holds values only for what the app-fill gate lets fill silently, a vetted app's own logins.
     */
    @Test
    fun theUnlocksResultHoldsOnlyWhatTheAppIsEntitledTo() {
        val f = form(evil, focused = "user")
        val silent = FillPlan.rows(items, f, FillPlan.Asker.App(AppFillGate.Verdict.SILENT))
        assertEquals(listOf(FillRow.Login("l1", "Own", "own-user", listOf("user" to "own-user", "pass" to "own-pass"))), silent)
        for (verdict in listOf(AppFillGate.Verdict.CONFIRM, AppFillGate.Verdict.CONFIRM_SIGNER_CHANGED)) {
            val rows = FillPlan.rows(items, f, FillPlan.Asker.App(verdict))
            assertTrue(valuesOf(rows).isEmpty(), "verdict $verdict: no value at all rides the result: $rows")
            assertIs<FillRow.LoginConfirm<String>>(rows.single())
            assertFalse(rows.toString().contains("own-pass"))
        }
        // With the focus on a card field the result still carries no card value, whatever the verdict.
        assertNoCardValue(FillPlan.rows(items, form(evil, focused = "pan"), FillPlan.Asker.App(AppFillGate.Verdict.SILENT)))

        // The wiring: the unlock activity builds its result through the same planner, on the fast path too. A result
        // goes through FillPlan.resultRows, which for an app carries only generic rows
        // over these same rows (ResultNamesNothingTest); the direct response goes through FillPlan.rows.
        val unlock = code("AutofillUnlockActivity.kt")
        assertEquals(1, Regex("DatasetBuilder\\.responseForUnlocked\\(").findAll(unlock).count())
        val db = code("DatasetBuilder.kt")
        assertTrue(db.contains("val asker = FillPlan.asker(form.appPackage, trusted, appGate?.verdict)"))
        assertTrue(db.contains("val rows = if (throughApp) FillPlan.resultRows(items, form, asker, release = release) else FillPlan.rows(items, form, asker, release = release)"))
        assertFalse(db.contains("CardFill.plan("), "card values are planned only in FillPlan")
    }

    @Test
    fun theCardConfirmReturnsThatOneCardAndNothingElse() {
        val f = form(evil, focused = "pan")
        val result = assertNotNull(FillPlan.cardResult(visa, f))
        assertEquals(listOf("pan", "csc", "exp"), result.map { it.first })
        assertEquals(CardFill.Value.Text("4242424242424242"), result.first().second)
        assertEquals(CardFill.Value.Text("987"), result[1].second)
        val shown = result.toString()
        for (s in listOf("5555555555554444", "654", "Other Holder", "own-pass")) assertFalse(shown.contains(s), "nothing of another item: $s")
        assertNull(FillPlan.cardResult(items.first(), f), "a login is not a card")
        assertNull(FillPlan.cardResult(visa, form(evil, focused = "user")), "focus off the card fields: nothing")

        // The activity: a secure window with the three defences, the identity re-read at the tap, nothing remembered.
        val activity = code("CardFillConfirmActivity.kt")
        assertTrue(activity.contains("window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)"))
        assertTrue(activity.contains("window.decorView.filterTouchesWhenObscured = true"))
        assertTrue(activity.contains("view.filterTouchesWhenObscured = true"))
        assertTrue(activity.contains("if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)"))
        assertTrue(activity.contains("if (!armed.value) return"))
        val fill = activity.substringAfter("private fun confirmAndFill(").substringBefore("override fun onWindowFocusChanged(")
        assertTrue(fill.contains("AppFillGate.unchangedSince(bake.identity, AppIdentityLookup.lookup(applicationContext, bake.identity.pkg))"))
        assertTrue(fill.contains("DatasetBuilder.cardResultDataset(it, form)"))
        assertFalse(activity.contains("AppSignerBindings"), "an app is never remembered for cards")
        assertTrue(File("src/main/AndroidManifest.xml").readText().contains("io.silencelen.andvari.app.autofill.CardFillConfirmActivity"))
    }

    @Test
    fun aSecondUseOfTheUnlockSenderReturnsNothing() {
        var n = 0
        val tokens = OneUseTokens(cap = 3) { "t${n++}" }
        val first = tokens.mint()
        assertTrue(tokens.isLive(first), "the first launch is shown")
        // A cancelled prompt does not retire it: the same row can be tried again.
        assertTrue(tokens.isLive(first))
        assertTrue(tokens.retire(first), "the first result is delivered")
        assertFalse(tokens.isLive(first), "a second launch shows nothing")
        assertFalse(tokens.retire(first), "and returns nothing")
        assertFalse(tokens.isLive(null) || tokens.retire(null), "a launch without a nonce gets nothing")
        assertFalse(tokens.isLive("never-minted"))
        // Bounded: the oldest live nonce beyond the cap is dropped (that row refuses; the person taps again).
        val a = tokens.mint(); tokens.mint(); tokens.mint(); tokens.mint()
        assertFalse(tokens.isLive(a))

        val svc = code("AndvariAutofillService.kt")
        assertTrue(svc.contains("FillBinding.bake(UnlockNonces.bake(Intent(this, AutofillUnlockActivity::class.java)), form)"), "the nonce rides the BASE intent")
        val unlock = code("AutofillUnlockActivity.kt")
        assertTrue(unlock.contains("if (!UnlockNonces.tokens.isLive(nonce))"), "a used sender shows nothing")
        val finish = unlock.substringAfter("private fun finishWithResponse(").substringBefore("private fun Intent.inlineRequest(")
        assertTrue(finish.indexOf("UnlockNonces.tokens.retire(nonce)") in 0 until finish.indexOf("setResult(RESULT_OK"), "retired before a result is set")
        assertEquals(1, Regex("setResult\\(RESULT_OK").findAll(unlock).count(), "one place delivers")
    }

    private fun code(name: String): String = File("src/main/kotlin/io/silencelen/andvari/app/autofill/$name").readText()
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }
}
