package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultClosedReason
import io.silencelen.andvari.core.client.items.VaultStanding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A vault closed for writing on this device says why, in the vault filter and above its items when the list is
 * filtered to it; and a login without a password has its age and last use as every login does, in the staleness list
 * and in its own view, as the current app's has them.
 */
class ClosedVaultAndLoginAgesTest {
    private val family = "00000000-0000-4000-8000-0000000fa111"

    private fun open(): Triple<FakeAppApi, VaultContent, FakeVaultContent> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return Triple(api, assertNotNull(m.content.value), assertNotNull(api.fakeContent))
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun aVaultClosedForWritingSaysWhyInTheFilterAndAboveItsItems() {
        val (_, c, fake) = open()
        fake.addSharedVault(family, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        fake.seedLogin(family, "Family router", "admin", "router-pw", "https://router.example")
        val personal = c.state.vaults.first { it.personal }.vaultId
        assertNull(closedFilterLine(ListControls(vaultId = family), c.state.vaults), "open: nothing to say")

        c.markVaultClosedForWriting(family, VaultClosedReason.DELETION_WAITING)
        val shut = c.state.vaults.first { it.vaultId == family }
        val line = assertNotNull(shut.closedLine, "the shared code's sentence for it")
        assertEquals(line, closedFilterLine(ListControls(vaultId = family), c.state.vaults), "filtered to it: the line above its items")
        assertNull(closedFilterLine(ListControls(), c.state.vaults), "every vault: the header's lines say it already")
        assertNull(closedFilterLine(ListControls(vaultId = personal), c.state.vaults))
        // Its rows are still listed under the filter.
        assertTrue(listView(c.state.items, ListControls(vaultId = family), c.state.vaults).any { it.name == "Family router" })

        val home = src("VaultHome.kt")
        assertTrue("closedFilterLine(controls, state.vaults)?.let { Quiet(UiText.Plain(it)) }" in home)
        assertTrue(home.indexOf("ListControlsRow(state, controls, onControls)\n") < home.indexOf("closedFilterLine(controls, state.vaults)?.let"), "under the filter, above the items")
        val menu = home.substringAfter("if (state.vaults.size > 1) {").substringBefore("\n}\n")
        assertTrue("v.closedLine?.let" in menu, "the filter's row of a closed vault says why")
    }

    @Test
    fun aLoginWithoutAPasswordHasItsAgeInTheStalenessListAndInItsView() {
        val (_, c, fake) = open()
        val personal = c.state.vaults.first { it.personal }.vaultId
        val id = fake.seedLogin(personal, "Single sign-on", "ada", "", "https://sso.example")
        assertNull(c.itemHealth()[id], "no password, so no health line")
        val age = assertNotNull(c.loginAges()[id], "but an age and a last use")
        assertEquals(Placeholder.ITEM_HEALTH_NO_USE_RECORD, (lastUsedLine(age) as UiText.Ph).placeholder)

        c.openHealth()
        val h = assertNotNull(c.state.health)
        assertTrue(h.staleness.any { it.itemId == id }, "the staleness list lists every login, as the current app's")
        assertTrue(c.loginAges().keys.containsAll(h.staleness.map { it.itemId }), "the same logins as their ages")

        val view = src("VaultItemsScreens.kt").substringAfter("private fun LoginHealthLine(").substringBefore("\n}\n")
        assertTrue("c.loginAges()[itemId]" in view && "Say(lastUsedLine(age)" in view, "the view says it for a login with no password")
        assertTrue("override fun loginAges()" in src("Contained.kt"), "a fault there is contained like the health line's")
    }
}
