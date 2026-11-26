package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.AppFillGate
import io.silencelen.andvari.core.client.autofill.FieldKind
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Android review 1, finding 3 and ruling 3: a login saved for an app (`androidapp://`) was offered to any web page that
 * app showed (the reviewer's P1: `offered to a field in frame evil.example inside com.social.app`). In an app that is
 * not a verified browser, such a login fills a field that carries a web domain at once only when that domain also
 * matches one of the same login's own web addresses.
 *
 * A web page inside an app: on any other page inside the app, the login is offered only through the
 * app-fill confirm, which names the page, is shown every time (whatever the gate's verdict) and remembers nothing.
 */
class AppLoginWebPageTest {
    private val app = "com.social.app"

    private fun form(domain: String?) = FormOf(
        fields = listOf(FieldOf("user", FieldKind.USERNAME, domain), FieldOf("pass", FieldKind.PASSWORD, domain)),
        appPackage = app,
        focusedId = "user",
    )

    private fun login(id: String, vararg uris: String) =
        VaultItem(id, "", 0L, 0L, ItemDoc(type = "login", name = id, login = LoginData(username = "me@example.com", password = "$id-pass", uris = uris.toList())))

    private fun rows(items: List<VaultItem>, f: FormOf<String>, verdict: AppFillGate.Verdict = AppFillGate.Verdict.SILENT) =
        FillPlan.rows(items, f, FillPlan.Asker.App(verdict))

    private fun offered(items: List<VaultItem>, domain: String?): List<String> = rows(items, form(domain)).map { it.itemId }

    private fun src(path: String) = File("src/main/kotlin/io/silencelen/andvari/app/$path").readText()

    @Test
    fun anAppLoginOnAnotherPageInsideThatAppIsOnlyAConfirmThatNamesThePage() {
        val social = login("Social", "androidapp://$app")
        // The reviewer's P1: never filled at once, even for an app the gate lets fill silently.
        for (verdict in AppFillGate.Verdict.entries) {
            val row = assertIs<FillRow.LoginConfirm<String>>(rows(listOf(social), form("evil.example"), verdict).single(), "$verdict")
            assertEquals("evil.example", row.pageDomain)
            assertEquals(listOf("user", "pass"), row.fieldIds)
            assertTrue(row.subtitle!!.contains("evil.example"), "the row names the page")
        }
        // The confirm with no page named releases nothing there; the confirm that named it releases this login only.
        assertNull(FillPlan.appLoginResult(social, form("evil.example")))
        assertNull(FillPlan.appLoginResult(social, form("evil.example"), "other.example"), "another page's confirm releases nothing")
        assertEquals(
            listOf("user" to "me@example.com", "pass" to "Social-pass"),
            FillPlan.appLoginResult(social, form("evil.example"), "evil.example"),
        )
        // The app's own native screen still fills at once.
        val native = assertIs<FillRow.Login<String>>(rows(listOf(social), form(null)).single())
        assertEquals("Social", native.itemId)
    }

    @Test
    fun theConfirmReleasesOnlyTheNamedPagesFields() {
        val social = login("Social", "androidapp://$app")
        // A native user-name field and a password field on a page: the page confirm covers both; another page's
        // password field gets nothing.
        val mixed = FormOf(
            fields = listOf(
                FieldOf("user", FieldKind.USERNAME, null),
                FieldOf("pass", FieldKind.PASSWORD, "login.social-cdn.example"),
                FieldOf("pass2", FieldKind.PASSWORD, "evil.example"),
            ),
            appPackage = app,
            focusedId = "pass",
        )
        val row = assertIs<FillRow.LoginConfirm<String>>(rows(listOf(social), mixed).single())
        assertEquals("login.social-cdn.example", row.pageDomain)
        assertEquals(listOf("user", "pass"), row.fieldIds)
        assertEquals(listOf("user" to "me@example.com", "pass" to "Social-pass"), FillPlan.appLoginResult(social, mixed, "login.social-cdn.example"))
        // Focus on the native field: no page is in focus, so only the direct match fills.
        val onNative = mixed.copy(focusedId = "user")
        val direct = assertIs<FillRow.Login<String>>(rows(listOf(social), onNative).single())
        assertEquals(listOf("user" to "me@example.com"), direct.values)
    }

    @Test
    fun anAppWhoseSignInIsAWebPageKeepsWorkingWhenTheLoginHoldsBothAddresses() {
        val both = login("Both", "androidapp://$app", "https://social.example")
        assertIs<FillRow.Login<String>>(rows(listOf(both), form("login.social.example")).single(), "the page is one of the login's own sites")
        val other = assertIs<FillRow.LoginConfirm<String>>(rows(listOf(both), form("evil.example")).single(), "any other page asks")
        assertEquals("evil.example", other.pageDomain)
        assertTrue(FillPlan.appLoginResult(both, form("social.example")) != null)
    }

    @Test
    fun thePagesClaimOnlyNarrowsNeverWidens() {
        // A web login for the claimed domain, without the app's address, still never fills an app, not even by confirm.
        val web = login("Web", "https://social.example")
        assertEquals(emptyList(), offered(listOf(web), "social.example"))
        assertNull(FillPlan.appLoginResult(web, form("social.example"), "social.example"))
        // A login for another app with the right web address is not offered either: the package must match first.
        val other = login("Other", "androidapp://com.other.app", "https://social.example")
        assertEquals(emptyList(), offered(listOf(other), "social.example"))
        assertEquals(emptyList(), offered(listOf(other), "evil.example"))
        // A verified browser is unchanged: the frame's domain is what matches, and no page row is made.
        val rows = FillPlan.rows(listOf(web), form("social.example").copy(appPackage = "com.android.chrome"), FillPlan.Asker.VerifiedBrowser)
        assertEquals(listOf("Web"), rows.map { it.itemId })
        assertIs<FillRow.Login<String>>(rows.single())
        // A browser is never an app here: a login saved under a browser's package is never offered to its pages.
        val chrome = login("Chrome", "androidapp://com.android.chrome")
        val inChrome = form("bank.example").copy(appPackage = "com.android.chrome")
        assertEquals(emptyList(), FillPlan.rows(listOf(chrome), inChrome, FillPlan.Asker.UnverifiedBrowser))
        assertEquals(emptyList(), FillPlan.rows(listOf(chrome), inChrome, FillPlan.Asker.VerifiedBrowser).filterIsInstance<FillRow.LoginConfirm<String>>())
        assertNull(FillPlan.appLoginResult(chrome, inChrome, "bank.example"))
    }

    @Test
    fun aPageIsNeverRememberedAndTheConfirmNamesIt() {
        val activity = src("autofill/AppFillConfirmActivity.kt")
        assertTrue(activity.contains("DatasetBuilder.appLoginResultDataset(it, form, bake.pageDomain)"), "the result is the named page's")
        assertTrue(
            activity.contains("if (bake.pageDomain == null) bake.identity.signerDigest?.let { digest -> AppSignerBindings.remember("),
            "a fill into a page inside the app is never remembered",
        )
        assertTrue(activity.contains("Text(confirmTitle(bake.pageDomain)"))
        assertTrue(activity.contains("bake.pageDomain?.let { page ->"), "the page line is shown whenever a page is baked")
        assertEquals("Fill this login into an app?", confirmTitle(null))
        assertTrue(confirmTitle("evil.example").contains("web page"))
        // The page comes from the service's bake, never the host: a present but empty page key is malformed.
        val binding = src("autofill/AppFillBinding.kt")
        assertTrue(binding.contains("pageDomain?.let { putString(K_PAGE, it) }"))
        assertTrue(binding.contains("b.getString(K_PAGE)?.takeIf { it.isNotBlank() } ?: return null"))
        // The page subtitle is escaped like every line the app supplies (a right-to-left override in the claim).
        val claim = "a" + Char(0x202E) + "b.example"
        val subtitle = FillPlan.pageSubtitle(claim)
        assertEquals("On the page ${AppFillGate.oneLine(claim)} — tap to confirm", subtitle)
        assertTrue(Char(0x202E) !in subtitle, "the override is escaped, not shown")
    }
}
