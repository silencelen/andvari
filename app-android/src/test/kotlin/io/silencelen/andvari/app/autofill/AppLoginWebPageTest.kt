package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.AppFillGate
import io.silencelen.andvari.core.client.autofill.FieldKind
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Android review 1, finding 3 and ruling 3: a login saved for an app (`androidapp://`) was offered to any web page that
 * app showed (the reviewer's P1: `offered to a field in frame evil.example inside com.social.app`); the released 0.29.1
 * code matched such a field on the package alone. In an app that is not a verified browser, such a login matches a
 * field that carries a web domain only when that domain also matches one of the same login's own web addresses.
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

    private fun offered(items: List<VaultItem>, domain: String?, verdict: AppFillGate.Verdict = AppFillGate.Verdict.SILENT): List<String> =
        FillPlan.rows(items, form(domain), FillPlan.Asker.App(verdict)).map { it.itemId }

    @Test
    fun anAppLoginIsNotOfferedToAWebPageInsideThatApp() {
        val social = login("Social", "androidapp://$app")
        for (verdict in AppFillGate.Verdict.entries) {
            assertEquals(emptyList(), offered(listOf(social), "evil.example", verdict), "the reviewer's P1, now refused ($verdict)")
        }
        assertNull(FillPlan.appLoginResult(social, form("evil.example")), "and the app-fill confirm returns nothing for it")
        // The app's own native screen still fills.
        assertEquals(listOf("Social"), offered(listOf(social), null))
    }

    @Test
    fun anAppWhoseSignInIsAWebPageKeepsWorkingWhenTheLoginHoldsBothAddresses() {
        val both = login("Both", "androidapp://$app", "https://social.example")
        assertEquals(listOf("Both"), offered(listOf(both), "login.social.example"), "the page is one of the login's own sites")
        assertEquals(emptyList(), offered(listOf(both), "evil.example"), "any other page is not")
        assertTrue(FillPlan.appLoginResult(both, form("social.example")) != null)
    }

    @Test
    fun thePagesClaimOnlyNarrowsNeverWidens() {
        // A web login for the claimed domain, without the app's address, still never fills an app.
        val web = login("Web", "https://social.example")
        assertEquals(emptyList(), offered(listOf(web), "social.example"))
        // A login for another app with the right web address is not offered either: the package must match first.
        val other = login("Other", "androidapp://com.other.app", "https://social.example")
        assertEquals(emptyList(), offered(listOf(other), "social.example"))
        // A verified browser is unchanged: the frame's domain is what matches.
        val rows = FillPlan.rows(listOf(web), form("social.example").copy(appPackage = "com.android.chrome"), FillPlan.Asker.VerifiedBrowser)
        assertEquals(listOf("Web"), rows.map { it.itemId })
    }
}
