package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Filling in and a shared vault whose log is withheld. Since 23 November 2026 every device of the account holds the key
 * of a vault whose account record stands above the log the server serves, and reads it; such a vault is not filled from,
 * exactly like a frozen one: its logins and cards are not offered, no value of them is released to a fill, and no use of
 * them is recorded. Reading it is untouched: its items list, open and copy out. The person's own vault and a verified
 * shared vault are filled from as before, a frozen and a failed vault are not, and a vault served its whole log again is
 * filled from again. Over the real content controller and item engine.
 */
class WithheldVaultFillTest {
    private class Host(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = true
        val uses = ArrayList<String>()
        override fun recordUse(itemId: String, atMs: Long) {
            uses += itemId
        }
    }

    private class Rig(val r: ItemRig, val host: Host, val c: EngineVaultContent, val mine: String, val myCard: String, val ours: String, val ourCard: String)

    /** The person's own login and card, and a login and a card in the shared vault, which this device holds the key of. */
    private fun rig(): Rig = runBlocking {
        val r = ItemRig().also { it.openShared() }
        r.server.echo = true
        val host = Host(r)
        val c = EngineVaultContent(r.engine, r.crypto, host)
        c.syncQuietly()
        assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Mine", "me", "pw-Mine", listOf("https://mine.test"), "", "", false), null))
        assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Ours", "me", "pw-Ours", listOf("https://ours.test"), "", "", false), r.shared))
        assertEquals(ActionResult.Ok, c.saveCard(null, CardInput("My card", "Ana", "4111111111111111", "07", "31", "123", "", "", false), null))
        assertEquals(ActionResult.Ok, c.saveCard(null, CardInput("Our card", "Ana", "5555555555554444", "08", "32", "456", "", "", false), r.shared))
        fun id(name: String) = c.state.items.single { it.name == name }.itemId
        Rig(r, host, c, id("Mine"), id("My card"), id("Ours"), id("Our card"))
    }

    private suspend fun standing(s: Rig, standing: VaultStanding) {
        s.r.keys.put(s.r.shared, s.r.sharedKey, VaultAccess.ROLE_WRITER, standing)
        s.c.syncQuietly()
    }

    /** The shared vault's login and card are offered, released and matched, and the person's own are too. */
    private fun assertSharedFilledFrom(s: Rig, what: String) {
        val c = s.c
        assertTrue(c.fillLogins(listOf("ours.test")).any { it.itemId == s.ours }, "$what: the shared login is offered")
        assertTrue(c.fillCards().any { it.itemId == s.ourCard }, "$what: the shared card is offered")
        assertEquals("pw-Ours", c.fillCredential(s.ours)?.password, "$what: the shared login is released to a fill")
        assertTrue(c.fillMatches(s.ours, listOf("https://ours.test/login")), "$what: the shared login matches its address")
        assertEquals("5555555555554444", c.fillCardField(s.ourCard, "number"), "$what: the shared card is released to a fill")
        assertOwnFilledFrom(s, what)
    }

    private fun assertOwnFilledFrom(s: Rig, what: String) {
        val c = s.c
        assertTrue(c.fillLogins(listOf("mine.test")).any { it.itemId == s.mine }, "$what: the person's own login is offered")
        assertTrue(c.fillCards().any { it.itemId == s.myCard }, "$what: the person's own card is offered")
        assertEquals("pw-Mine", c.fillCredential(s.mine)?.password, "$what: the person's own login is released to a fill")
        assertTrue(c.fillMatches(s.mine, listOf("https://mine.test/login")), "$what: the person's own login matches its address")
    }

    private fun assertSharedNotFilledFrom(s: Rig, what: String) {
        val c = s.c
        assertTrue(c.fillLogins(listOf("ours.test")).none { it.itemId == s.ours }, "$what: the shared login is not offered")
        assertTrue(c.fillLogins(emptyList()).none { it.itemId == s.ours }, "$what: nor among every login")
        assertTrue(c.fillCards().none { it.itemId == s.ourCard }, "$what: the shared card is not offered")
        assertNull(c.fillCredential(s.ours), "$what: the shared login is not released to a fill")
        assertNull(c.fillCredentialUnrecorded(s.ours), "$what: nor unrecorded")
        assertFalse(c.fillMatches(s.ours, listOf("https://ours.test/login")), "$what: the shared login matches nothing")
        assertNull(c.fillCardField(s.ourCard, "number"), "$what: the shared card is not released to a fill")
        assertNull(c.fillCardFieldUnrecorded(s.ourCard, "number"), "$what: nor unrecorded")
        assertFalse(c.recordFillPicked(s.ours), "$what: a pick of the shared login is not recorded")
        assertFalse(c.recordFillPicked(s.ourCard), "$what: a pick of the shared card is not recorded")
        assertFalse(c.recordFillPickedAt(s.ours, s.r.now), "$what: nor a pick reported later")
        assertTrue(c.credentialIdentities().none { it.itemId == s.ours }, "$what: the shared login is no credential identity")
    }

    @Test
    fun aWithheldVaultWhoseKeyIsHeld_isNotFilledFrom_andNoUseOfItsItemsIsRecorded() = runBlocking<Unit> {
        val s = rig()
        standing(s, VaultStanding.WITHHELD)
        assertNotNull(s.r.keys.withKey(s.r.shared) { true }, "the withheld vault's key is held")
        val before = s.host.uses.size
        assertSharedNotFilledFrom(s, "withheld")
        assertTrue(s.host.uses.drop(before).none { it == s.ours || it == s.ourCard }, "no use of the withheld vault's items is recorded: ${s.host.uses}")
        assertOwnFilledFrom(s, "withheld")
    }

    @Test
    fun aWithheldVaultsItems_stillList_open_andCopyOut() = runBlocking<Unit> {
        val s = rig()
        standing(s, VaultStanding.WITHHELD)
        val c = s.c
        assertTrue(c.state.items.any { it.itemId == s.ours } && c.state.items.any { it.itemId == s.ourCard }, "its items are listed")
        assertEquals("Ours", assertNotNull(c.itemDetail(s.ours), "its login opens").name)
        assertNotNull(c.itemDetail(s.ourCard), "its card opens")
        assertEquals("pw-Ours", c.revealSecret(s.ours, SecretField.PASSWORD), "the person reveals or copies its password")
        assertEquals("5555555555554444", c.revealSecret(s.ourCard, SecretField.CARD_NUMBER), "and its card number")
        assertEquals(ActionResult.Ok, c.moveOrCopyItem(s.ours, s.r.personal, move = false), "a copy goes into the person's own vault")
        assertEquals(2, c.state.items.count { it.name == "Ours" }, "the copy is listed beside the item")
        assertTrue(c.state.items.any { it.itemId == s.ours }, "the item stays in the withheld vault")
    }

    @Test
    fun theOwnAndAVerifiedSharedVault_areFilledFrom_aFrozenAndAFailedOneAreNot_andOneVerifiedAgainIsFilledFromAgain() = runBlocking<Unit> {
        val s = rig()
        assertSharedFilledFrom(s, "verified")
        assertTrue(s.ours in s.host.uses && s.mine in s.host.uses, "a fill records a use: ${s.host.uses}")
        for (st in listOf(VaultStanding.FROZEN, VaultStanding.FAILED)) {
            standing(s, st)
            assertSharedNotFilledFrom(s, "$st")
            assertOwnFilledFrom(s, "$st")
        }
        standing(s, VaultStanding.WITHHELD)
        standing(s, VaultStanding.VERIFIED)
        assertSharedFilledFrom(s, "verified again")
    }
}
