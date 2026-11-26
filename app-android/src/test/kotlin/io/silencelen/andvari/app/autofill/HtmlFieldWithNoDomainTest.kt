package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.AppFillGate
import io.silencelen.andvari.core.client.autofill.FieldKind
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * An HTML field that reports no web domain, inside an app, is
 * a page of unknown address. It is never filled directly and never matched to the app's own login. The review's case:
 * a WebView in a Play-installed app shows a `blob:` page (which reports no origin), and the app's own saved login was
 * offered there with its values (`Login title='Social' … VALUES=[(user, me@example.com), (pass, social-pass-1)]`).
 */
class HtmlFieldWithNoDomainTest {
    private val app = "com.social.app"

    private fun field(id: String, kind: FieldKind, html: Boolean, domain: String? = null) = FieldOf(id, kind, domain, isHtml = html)

    private fun form(html: Boolean) = FormOf(listOf(field("user", FieldKind.USERNAME, html), field("pass", FieldKind.PASSWORD, html)), app, focusedId = "user")

    private val social = VaultItem(
        "Social", "", 0L, 0L,
        ItemDoc(type = "login", name = "Social", login = LoginData(username = "me@example.com", password = "social-pass-1", uris = listOf("androidapp://$app"))),
    )

    @Test
    fun theReviewsCaseAPageThatReportsNoDomainGetsNothing() {
        for (verdict in AppFillGate.Verdict.entries) {
            val rows = FillPlan.rows(listOf(social), form(html = true), FillPlan.Asker.App(verdict))
            println("PROBE html field, no domain, $verdict: $rows")
            assertTrue(rows.isEmpty(), "$verdict: neither filled at once nor offered through a confirm: $rows")
            assertTrue(FillPlan.resultRows(listOf(social), form(html = true), FillPlan.Asker.App(verdict)).isEmpty(), "$verdict: nor in a result")
        }
        // No confirm releases it there either, whatever page a bake names.
        assertNull(FillPlan.appLoginResult(social, form(html = true)))
        assertNull(FillPlan.appLoginResult(social, form(html = true), "evil.example"))
        for (f in form(html = true).fields) {
            assertEquals(FillPlan.Fit.NONE, FillPlan.fieldFit(social.doc.login!!.uris, f, form(html = true), trusted = false))
        }
    }

    @Test
    fun theAppsOwnNativeScreenStillFillsAndOnlyItsNativeFields() {
        val native = FillPlan.rows(listOf(social), form(html = false), FillPlan.Asker.App(AppFillGate.Verdict.SILENT))
        assertEquals(listOf("user" to "me@example.com", "pass" to "social-pass-1"), assertIs<FillRow.Login<String>>(native.single()).values)
        // A native user-name field beside an HTML password field with no domain: only the native field is filled.
        val mixed = FormOf(listOf(field("user", FieldKind.USERNAME, html = false), field("pass", FieldKind.PASSWORD, html = true)), app, focusedId = "user")
        assertEquals(listOf("user" to "me@example.com"), assertIs<FillRow.Login<String>>(FillPlan.rows(listOf(social), mixed, FillPlan.Asker.App(AppFillGate.Verdict.SILENT)).single()).values)
        assertEquals(listOf("user" to "me@example.com"), FillPlan.appLoginResult(social, mixed))
        // A page that does report its domain keeps the page confirm (AppLoginWebPageTest).
        val named = FormOf(listOf(field("user", FieldKind.USERNAME, true, "evil.example"), field("pass", FieldKind.PASSWORD, true, "evil.example")), app, focusedId = "user")
        assertEquals("evil.example", assertIs<FillRow.LoginConfirm<String>>(FillPlan.rows(listOf(social), named, FillPlan.Asker.App(AppFillGate.Verdict.SILENT)).single()).pageDomain)
    }

    @Test
    fun aVerifiedBrowserIsUnchangedAndSuchAPageOffersNoSave() {
        val chrome = "com.android.chrome"
        val web = VaultItem("w", "", 0L, 0L, ItemDoc(type = "login", name = "Shop", login = LoginData(username = "u", password = "p", uris = listOf("https://shop.example"))))
        val page = FormOf(listOf(field("user", FieldKind.USERNAME, true, "shop.example"), field("pass", FieldKind.PASSWORD, true, "shop.example")), chrome, focusedId = "user")
        assertIs<FillRow.Login<String>>(FillPlan.rows(listOf(web), page, FillPlan.Asker.VerifiedBrowser).single())
        // The save side's twin (A2): a form with HTML fields is a web page even when it reports no domain.
        assertTrue(DatasetBuilder.isWebPage(form(html = true)))
        assertFalse(DatasetBuilder.isWebPage(form(html = false)))
        assertFalse(DatasetBuilder.offersSave(app, trusted = false, sessionTakes = true, webPage = DatasetBuilder.isWebPage(form(html = true))))

        // "This is an HTML field" is carried from the structure, inherited down an HTML subtree.
        val parser = File("src/main/kotlin/io/silencelen/andvari/app/autofill/StructureParser.kt").readText()
        assertTrue(parser.contains("val html = node.htmlInfo != null || inheritedHtml"))
        assertTrue(parser.contains("c.scheme, c.html))"))
        // ...and through the service's bake, so the unlock, the confirms and the chooser read the same field (a bake
        // without it is refused, never read as a native field).
        val binding = File("src/main/kotlin/io/silencelen/andvari/app/autofill/FillBinding.kt").readText()
        assertTrue(binding.contains("putBoolean(F_HTML, f.isHtml)") && binding.contains("isHtml = b.getBoolean(F_HTML)"))
        assertTrue(binding.contains("if (!b.containsKey(F_HTML)) return null"))
    }
}
