package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.app.trust.BuildConstants
import io.silencelen.andvari.app.trust.TrustModel
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.autofill.FillTarget
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
 * Autofill on the new code: it fills from the app's own session only while it is unlocked, only from the vault
 * content's working set, and reads a login's secrets only for a login that matches the form.
 */
class ContentFillTest {
    private fun unlocked(): Pair<FakeAppApi, VaultContent> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        return api to assertNotNull(api.content)
    }

    private fun VaultContent.personal(): String = assertNotNull(vaultsForNewItems().firstOrNull { it.personal }).vaultId

    private fun login(c: VaultContent, name: String, user: String, pw: String, uri: String) =
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(null, LoginInput(name, user, pw, listOf(uri), "", "", false), c.personal()) })

    private val chrome = "com.android.chrome"

    @Test
    fun onlyAnUnlockedSessionWithContentIsOpen() {
        val (api, c) = unlocked()
        assertIs<ContentFillSession.Access.Open>(ContentFillSession.accessOf(api.snapshot, c))
        assertIs<ContentFillSession.Access.Locked>(ContentFillSession.accessOf(api.snapshot, null), "no content: never a fill")
        api.lock()
        assertIs<ContentFillSession.Access.Locked>(ContentFillSession.accessOf(api.snapshot, api.content), "locked: the unlock row")
        val first = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.FIRST_RUN)
        assertIs<ContentFillSession.Access.SignedOut>(ContentFillSession.accessOf(first.snapshot, null), "no account: no row at all")
    }

    @Test
    fun onlyLoginsMatchingAFieldOfTheFormAreReadWithTheirSecrets() {
        val (_, c) = unlocked()
        login(c, "Bank", "me", "bank-pass-1", "https://bank.example")
        login(c, "Shop", "you", "shop-pass-2", "https://shop.example")
        login(c, "App", "app-user", "app-pass-3", "androidapp://com.example.app")

        val bank = ContentFill.offersFor(c, listOf(FillTarget(webHost = "bank.example", packageName = chrome)), listOf("bank.example"), cards = false)
        assertEquals(listOf("Bank"), bank.map { it.doc.name })
        assertEquals("me", bank.single().doc.login?.username)
        // Item 6: an offer carries no secret; the password is read only when it is released.
        assertEquals(ContentFill.UNRELEASED, bank.single().doc.login?.password)
        assertEquals("bank-pass-1", ContentFill.release(c, bank.single().itemId)?.doc?.login?.password)
        assertEquals(listOf("https://bank.example"), bank.single().doc.login?.uris)

        // An untrusted browser has no web host: only androidapp:// logins could match, and none is for the browser.
        assertTrue(ContentFill.offersFor(c, listOf(FillTarget(webHost = null, packageName = chrome)), emptyList(), cards = false).isEmpty())
        // A native app matches its own androidapp:// login only.
        val app = ContentFill.offersFor(c, listOf(FillTarget(webHost = null, packageName = "com.example.app")), emptyList(), cards = false)
        assertEquals(listOf("App"), app.map { it.doc.name })
        // A form with no login field reads nothing.
        assertTrue(ContentFill.offersFor(c, emptyList(), emptyList(), cards = false).isEmpty())
    }

    @Test
    fun cardsAreReadOnlyWhereACardFormAllowsThem() {
        val (_, c) = unlocked()
        assertEquals(ActionResult.Ok, runBlocking { c.saveCard(null, CardInput("Visa", "Me", "4242424242424242", "07", "2031", "123", "90210", "", false), c.personal()) })
        assertTrue(ContentFill.offersFor(c, emptyList(), emptyList(), cards = false).isEmpty(), "not a card form: no card is offered")
        val offer = ContentFill.offersFor(c, emptyList(), emptyList(), cards = true).single()
        assertEquals("card", offer.doc.type)
        assertNull(offer.doc.card, "an offered card carries no value (item 6)")
        val card = assertNotNull(ContentFill.release(c, offer.itemId))
        val data = assertNotNull(card.doc.card)
        assertEquals("4242424242424242", data.number)
        assertEquals("07", data.expMonth)
        assertEquals("2031", data.expYear)
        assertEquals("123", data.securityCode)
        assertEquals("Me", data.cardholderName)
        assertEquals("90210", data.postalCode)
    }

    @Test
    fun aLockedSessionGivesTheConfirmNothing() {
        val (api, c) = unlocked()
        login(c, "App", "app-user", "app-pass-3", "androidapp://com.example.app")
        val id = c.state.items.single().itemId
        // The app's address comes along: the working set's own list keeps web addresses only.
        assertEquals(listOf("androidapp://com.example.app"), assertNotNull(ContentFill.loginById(c, id)).doc.login?.uris)
        assertNull(ContentFill.loginById(c, "no-such-item"))
        api.lock()
        // After a lock the content is gone from the API; the confirm reads only through an Open access.
        assertNull(api.content)
        assertFalse(ContentFillSession.accessOf(api.snapshot, api.content) is ContentFillSession.Access.Open)
    }

    /** The working set carries a login's app addresses itself; a fill never reads an item's detail. */
    @Test
    fun aLoginsAddressesAreTheWorkingSetsWebAndAppAddresses() {
        val (_, c) = unlocked()
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(null, LoginInput("Both", "u", "p-both-1", listOf("https://shop.example", "androidapp://com.example.shop"), "", "", false), c.personal()) })
        val l = c.fillLogins(emptyList()).single()
        assertEquals(listOf("androidapp://com.example.shop"), l.appUris)
        assertEquals(l.uris + l.appUris, ContentFill.addresses(l))
        assertTrue(ContentFill.addresses(l).contains("androidapp://com.example.shop"))
        val src = File("src/main/kotlin/io/silencelen/andvari/app/autofill/ContentFill.kt").readText()
        assertFalse(src.contains("itemDetail("), "the itemDetail workaround is gone")
        assertTrue(src.contains("(l.uris + l.appUris).distinct()"))
    }

    /** The service, the unlock activity and the app-fill confirm read the vault only through the new session. */
    @Test
    fun theFillPathRunsOnTheNewCodeOnly() {
        fun code(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/autofill/$name").readText()
            .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "").lines().joinToString("\n") { it.substringBefore("//") }
        for (name in listOf("AndvariAutofillService.kt", "AutofillUnlockActivity.kt", "AppFillConfirmActivity.kt", "TrustBrowserActivity.kt")) {
            val c = code(name)
            assertFalse(c.contains("VaultSession") || c.contains("SessionStore"), "$name no longer reads the old session")
            assertTrue(c.contains("ContentFillSession.access("), "$name reads the access after the idle lock")
        }
        val svc = code("AndvariAutofillService.kt")
        assertTrue(svc.contains("ContentFill.offersFor(content, form, trusted)"))
        assertTrue(svc.contains("ContentFillSession.HardLock.arm(ctx)"))
        val unlock = code("AutofillUnlockActivity.kt")
        assertTrue(unlock.contains("overlayUnlock(model.api, locked, password)") && unlock.contains("model.api.quickUnlock(locked)"))
        assertTrue(unlock.contains("ContentFillSession.ready(access.content)"))
        val session = code("ContentFillSession.kt")
        assertTrue(session.contains("model.tick()"), "the idle lock runs before every access")
    }
}
