package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A move out of a vault that is not finished is said once on that vault's own page: the offer at the top says it, with
 * "finish the move" and "later", and the page leaves it out while the offer stands; once the offer is put off, the page
 * says it itself. (It was said twice there, once by each.)
 */
class UnfinishedMoveOnceTest {
    @Test
    fun theVaultsPageLeavesTheLineToTheOfferAboveUntilItIsPutOff() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        val family = assertNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL]).vaults.first { it.name == "Family" }
        family.moveUnfinishedInto = "Work"
        family.moveDeleteWaiting = true
        api.script.changed()
        m.onSnapshot(api.snapshot)

        var account = assertNotNull(api.snapshot.account)
        var row = account.vaults.first { it.name == "Family" }
        assertNotNull(row.unfinishedMove, "the vault has a move that is not finished")
        val offer = account.unfinishedMoves.single()
        assertEquals(offer.line.key, assertNotNull(row.unfinishedMove).key, "the offer and the page would say the same line")
        assertTrue(unfinishedMoveOfferedAbove(account, row), "the offer says it: the page leaves it out")
        assertFalse(unfinishedMoveOfferedAbove(account, account.vaults.first { it.name == "Work" }))

        m.act { vaults.unfinishedMoveLater(offer) }
        account = assertNotNull(api.snapshot.account)
        row = account.vaults.first { it.name == "Family" }
        assertNotNull(row.unfinishedMove)
        assertFalse(unfinishedMoveOfferedAbove(account, row), "put off: the page says it itself")

        val src = File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultScreens.kt").readText()
        val page = src.substringAfter("internal fun SharedVaultSettings(").substringBefore("\n}\n")
        assertTrue("VaultStateLines(v, moveOfferedAbove = unfinishedMoveOfferedAbove(account, v))" in page)
        assertTrue("if (!moveOfferedAbove) v.unfinishedMove?.let { Say(UiText.of(it)" in src)
    }
}
