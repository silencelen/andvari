package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.AppFillGate
import io.silencelen.andvari.core.client.autofill.FieldKind
import io.silencelen.andvari.core.client.autofill.FormKind
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Nothing that names an item rides a
 * result that passes through an app that is not a verified browser. Not a card's name, not how many there are, not a
 * login's name, never a user name. Such a result carries at most one generic row for logins and one for cards; the
 * choosing happens in andvari's own window, and with one generic row an app cannot raise a confirm for an item of its
 * choosing.
 *
 * The review's probe first: what exactly rides the unlock's result ([FillPlan.resultRows], which
 * [DatasetBuilder.responseForUnlocked] turns into the result's datasets) for a login field, a card field, a form with
 * both, and a login whose name is blank. Each case prints what it found.
 */
class ResultNamesNothingTest {
    private val text = 1 // View.AUTOFILL_TYPE_TEXT
    private val evil = "com.social.app"

    private fun field(id: String, kind: FieldKind) = FieldOf(id = id, kind = kind, webDomain = null, autofillType = text)

    private fun loginForm(focus: String = "user") = FormOf(listOf(field("user", FieldKind.USERNAME), field("pass", FieldKind.PASSWORD)), evil, focusedId = focus)

    private fun cardForm(focus: String = "pan") = FormOf(
        emptyList(), evil,
        ccFields = listOf(field("pan", FieldKind.CC_NUMBER), field("csc", FieldKind.CC_CSC), field("exp", FieldKind.CC_EXP)),
        formKind = FormKind.CARD, focusedId = focus,
    )

    private fun bothForm(focus: String) = FormOf(
        listOf(field("user", FieldKind.USERNAME), field("pass", FieldKind.PASSWORD)), evil,
        ccFields = listOf(field("pan", FieldKind.CC_NUMBER), field("csc", FieldKind.CC_CSC), field("exp", FieldKind.CC_EXP)),
        formKind = FormKind.MIXED, focusedId = focus,
    )

    private fun login(id: String, name: String, user: String, pw: String) =
        VaultItem(id, "", 0L, 0L, ItemDoc(type = "login", name = name, login = LoginData(username = user, password = pw, uris = listOf("androidapp://$evil"))))

    private fun card(id: String, name: String, number: String) =
        VaultItem(id, "", 0L, 0L, ItemDoc(type = "card", name = name, card = CardData(cardholderName = "Holder $id", number = number, expMonth = "07", expYear = "2031", securityCode = "987", postalCode = "90210")))

    private val own = login("l1", "Social main", "me@example.com", "social-pass-1")
    private val blank = login("l2", "", "second@example.com", "social-pass-2")
    private val dad = card("c1", "Chase Sapphire - Dad", "4242424242424242")
    private val mum = card("c2", "Amex - Mum", "378282246310005")
    private val items = listOf(own, blank, dad, mum)

    /** Everything that names an item, or is a value: none of it may appear anywhere in such a result. */
    private val naming = listOf(
        "Social main", "me@example.com", "second@example.com", "social-pass-1", "social-pass-2",
        "Chase Sapphire - Dad", "Amex - Mum", "4242", "0005", "Holder", "987", "90210", "l1", "l2", "c1", "c2",
    )

    /** What the probe prints for one row: its kind, everything a person or the app could read, and its values. */
    private fun describe(r: FillRow<String>): String = when (r) {
        is FillRow.Login -> "Login item=${r.itemId} title='${r.title}' subtitle='${r.subtitle}' VALUES=${r.values}"
        is FillRow.LoginConfirm -> "LoginConfirm item=${r.itemId} title='${r.title}' subtitle='${r.subtitle}' fields=${r.fieldIds}"
        is FillRow.Card -> "Card item=${r.itemId} title='${r.title}' subtitle='${r.subtitle}' VALUES=${r.values}"
        is FillRow.CardConfirm -> "CardConfirm item=${r.itemId} title='${r.title}' subtitle='${r.subtitle}' fields=${r.fieldIds}"
        is FillRow.Choose -> "Choose ${r.kind} item='${r.itemId}' title='${r.title}' subtitle='${r.subtitle}' fields=${r.fieldIds}"
    }

    private fun probe(case: String, rows: List<FillRow<String>>): String {
        val shown = rows.joinToString("\n") { describe(it) }
        println("PROBE $case (${rows.size} row(s)):\n" + shown.prependIndent("  "))
        return shown
    }

    private fun assertNamesNothing(case: String, rows: List<FillRow<String>>) {
        val shown = probe(case, rows)
        for (s in naming) assertFalse(shown.contains(s), "$case: '$s' rides the result:\n$shown")
        assertTrue(rows.all { it is FillRow.Choose }, "$case: only generic rows ride a result through an app:\n$shown")
        assertTrue(rows.count { (it as FillRow.Choose).kind == ChooserKind.LOGINS } <= 1, "$case: at most one generic row for logins")
        assertTrue(rows.count { (it as FillRow.Choose).kind == ChooserKind.CARDS } <= 1, "$case: at most one generic row for cards")
        assertTrue(rows.all { it.itemId.isEmpty() }, "$case: no row names an item it could raise a confirm for")
    }

    @Test
    fun theReviewsProbeAResultThroughAnAppNamesNothing() {
        for (verdict in AppFillGate.Verdict.entries) {
            val asker = FillPlan.Asker.App(verdict)
            // A login field: one generic login row over the fields the logins would have filled, no card row.
            val onLogin = FillPlan.resultRows(items, loginForm(), asker)
            assertNamesNothing("login field, $verdict", onLogin)
            assertEquals(listOf(FillRow.Choose(ChooserKind.LOGINS, listOf("user", "pass"))), onLogin)
            // A card field: one generic card row, whatever the number of cards.
            val onCard = FillPlan.resultRows(items, cardForm(), asker)
            assertNamesNothing("card field, $verdict", onCard)
            assertEquals(listOf(FillRow.Choose(ChooserKind.CARDS, listOf("pan", "csc", "exp"))), onCard)
            // Both kinds of field on one form: the login row, and the card row only while the focus is on a card field.
            assertNamesNothing("both, focus on the password, $verdict", FillPlan.resultRows(items, bothForm("pass"), asker))
            val bothOnCard = FillPlan.resultRows(items, bothForm("csc"), asker)
            assertNamesNothing("both, focus on the card's code, $verdict", bothOnCard)
            assertEquals(listOf(ChooserKind.LOGINS, ChooserKind.CARDS), bothOnCard.map { (it as FillRow.Choose).kind })
            // A login whose name is blank: its user name used to stand in for the name.
            assertNamesNothing("blank-named login, $verdict", FillPlan.resultRows(listOf(blank), loginForm("pass"), asker))
        }
    }

    @Test
    fun howManyThereAreDoesNotShow() {
        val asker = FillPlan.Asker.App(AppFillGate.Verdict.CONFIRM)
        assertEquals(FillPlan.resultRows(listOf(dad), cardForm(), asker), FillPlan.resultRows(listOf(dad, mum), cardForm(), asker))
        assertEquals(FillPlan.resultRows(listOf(own), loginForm(), asker), FillPlan.resultRows(listOf(own, blank), loginForm(), asker))
        val one = FillPlan.resultRows(listOf(own), loginForm(), asker).single()
        assertEquals(FillPlan.resultRows(listOf(own, blank), loginForm(), asker).single().title, one.title, "the same words for one login or many")
        assertTrue(FillPlan.resultRows(emptyList(), loginForm(), asker).isEmpty(), "nothing to offer: no row")
    }

    @Test
    fun aVerifiedBrowserKeepsItsRowsAndAnUnverifiedOneGetsNoneInAResult() {
        val chrome = "com.android.chrome"
        val web = VaultItem("w", "", 0L, 0L, ItemDoc(type = "login", name = "Shop", login = LoginData(username = "u", password = "p", uris = listOf("https://shop.example"))))
        val form = FormOf(
            listOf(FieldOf("user", FieldKind.USERNAME, "shop.example", autofillType = text), FieldOf("pass", FieldKind.PASSWORD, "shop.example", autofillType = text)),
            chrome, focusedId = "user",
        )
        assertEquals(FillPlan.rows(listOf(web), form, FillPlan.Asker.VerifiedBrowser), FillPlan.resultRows(listOf(web), form, FillPlan.Asker.VerifiedBrowser))
        assertTrue(FillPlan.resultRows(items + web, form, FillPlan.Asker.UnverifiedBrowser).isEmpty())
    }

    @Test
    fun andvarisOwnChooserListsTheItemsAndReleasesOnlyThePickedOne() {
        // The chooser lists what the direct response would have offered this app, of one kind, with no cap.
        val asker = FillPlan.Asker.App(AppFillGate.Verdict.CONFIRM)
        assertEquals(listOf("l1", "l2"), FillPlan.chooserRows(items, bothForm("csc"), asker, ChooserKind.LOGINS).map { it.itemId })
        assertEquals(listOf("c1", "c2"), FillPlan.chooserRows(items, bothForm("csc"), asker, ChooserKind.CARDS).map { it.itemId })
        assertTrue(FillPlan.chooserRows(items, bothForm("csc"), FillPlan.Asker.VerifiedBrowser, ChooserKind.LOGINS).isEmpty(), "never for a browser")

        // The wiring: an authentication result goes through resultRows, the direct response through rows.
        val db = code("DatasetBuilder.kt")
        assertTrue(db.contains("val rows = if (throughApp) FillPlan.resultRows(items, form, asker, release = release) else FillPlan.rows(items, form, asker, release = release)"))
        assertTrue(db.substringAfter("fun responseForUnlocked(").substringBefore("fun buildUnlockedResponse(").contains("throughApp = true"))
        assertTrue(code("AndvariAutofillService.kt").contains("throughApp = false"), "only the direct response")
        assertTrue(db.contains("is FillRow.Choose -> appGate?.let { chooseDataset(context, row, form, it, spec) }"))

        // The chooser: its bake from the base intent, a secure window with the defences, the confirm armed, one item out.
        val chooser = code("FillChooserActivity.kt")
        assertTrue(chooser.contains("window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)"))
        assertTrue(chooser.contains("window.decorView.filterTouchesWhenObscured = true"))
        assertTrue(chooser.contains("if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)"))
        assertTrue(chooser.contains("val gate = AppFillBinding.resolveGate(intent)") && chooser.contains("val form = FillBinding.resolve(intent)"))
        assertTrue(chooser.contains("if (confirmed && !armed.value) return") && chooser.contains("if (!armed.value) return"))
        assertEquals(1, Regex("setResult\\(RESULT_OK").findAll(chooser).count(), "one place delivers")
        assertFalse(chooser.contains("EXTRA_ASSIST_STRUCTURE"), "nothing the host delivers is read")
        val manifest = File("src/main/AndroidManifest.xml").readText()
        val decl = manifest.substringAfter("io.silencelen.andvari.app.autofill.FillChooserActivity\"").substringBefore("/>")
        assertTrue(decl.contains("android:exported=\"false\""))
    }

    private fun code(name: String): String = File("src/main/kotlin/io/silencelen/andvari/app/autofill/$name").readText()
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }
}
