package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.FieldKind
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * An https login was offered to the plain-http page of the same site (the
 * reviewer's P2: `android offers=bank-pass-1 core.fillMatches(http page)=false`). The frame's scheme is carried, and
 * on an http frame only an address saved as http matches, the same as core's page rule.
 */
class HttpFrameTest {
    private val chrome = "com.android.chrome"

    private fun form(scheme: String?) = FormOf(
        fields = listOf(FieldOf("user", FieldKind.USERNAME, "bank.example", webScheme = scheme), FieldOf("pass", FieldKind.PASSWORD, "bank.example", webScheme = scheme)),
        appPackage = chrome,
        focusedId = "user",
    )

    private fun login(id: String, uri: String) =
        VaultItem(id, "", 0L, 0L, ItemDoc(type = "login", name = id, login = LoginData(username = "me", password = "$id-pass", uris = listOf(uri))))

    private fun offered(items: List<VaultItem>, scheme: String?) =
        FillPlan.rows(items, form(scheme), FillPlan.Asker.VerifiedBrowser).map { it.itemId }

    @Test
    fun anHttpsLoginIsNotOfferedToThePlainHttpPage() {
        val https = login("bank", "https://bank.example")
        val http = login("intranet", "http://bank.example")
        assertEquals(emptyList(), offered(listOf(https), "http"), "the reviewer's P2, now refused")
        assertEquals(listOf("intranet"), offered(listOf(https, http), "http"), "a login saved as http still fills its http page")
        assertEquals(listOf("bank", "intranet"), offered(listOf(https, http), "https"))
        assertEquals(emptyList(), offered(listOf(https), "HTTP"), "the scheme's case does not matter")
        // A frame that reports no scheme stays as it was (a remaining risk).
        assertEquals(listOf("bank"), offered(listOf(https), null))
    }

    @Test
    fun theSchemeIsReadWithTheDomainAndSurvivesTheBinding() {
        fun code(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/autofill/$name").readText()
        val parser = code("StructureParser.kt")
        assertTrue(parser.contains("val scheme = node.webScheme?.takeIf { it.isNotEmpty() } ?: inheritedScheme"))
        assertTrue(parser.contains("c.isNewPassword, c.scheme, c.html)"))
        val binding = code("FillBinding.kt")
        assertTrue(binding.contains("putString(F_SCHEME, f.webScheme)") && binding.contains("webScheme = b.getString(F_SCHEME)"))
        assertTrue(code("FillPlan.kt").contains("val offered = forScheme(uris, field.webScheme)"))
    }
}
