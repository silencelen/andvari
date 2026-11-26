package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.MoveEverythingScreen
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A move of everything out of a vault that this computer started and did not finish (design §3.13): the first screen
 * after an unlock offers to finish it, with "Not now", which puts it off until the next unlock. Walked on the fake.
 */
class UnfinishedMoveOfferTest {
    @Test
    fun theFirstScreenOffersToFinishAMoveLeftUnfinishedAndNotNowPutsItOff() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        val family = assertNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL]).vaults.first { it.name == "Family" }
        family.moveUnfinishedInto = "Work"
        family.moveDeleteWaiting = true
        api.script.changed()
        m.onSnapshot(api.snapshot)
        val offer = assertNotNull(api.snapshot.account).unfinishedMoves.single()
        assertEquals(CopyKey.MOVE_DELETE_WAITING, offer.line.key)
        draw(m)
        // Finish: the move's screen opens again on the old vault.
        m.run({ vaults.openMoveEverything(offer.vault) })
        val open = assertNotNull(api.snapshot.account)
        assertEquals("Family", assertNotNull<MoveEverythingScreen>(open.moving, "the move is open again").let { offer.vault.name })
        assertTrue(open.unfinishedMoves.isEmpty(), "while it is open it is not offered beside it")
        m.quietly { m.api.vaults.closeMoveEverything() }
        // Not now: not offered again until the next unlock.
        val again = assertNotNull(api.snapshot.account).unfinishedMoves.single()
        m.act { vaults.unfinishedMoveLater(again) }
        assertTrue(assertNotNull(api.snapshot.account).unfinishedMoves.isEmpty())
        val shell = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/AccountScreens.kt").readText()
        assertTrue(shell.contains("for (move in account.unfinishedMoves) UnfinishedMoveOffer(model, s, move)"))
        val card = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultScreens.kt").readText().substringAfter("internal fun UnfinishedMoveOffer(").substringBefore("\n}\n")
        assertTrue(card.contains("Say(UiText.of(move.line)"))
        assertTrue(card.contains("vaults.openMoveEverything(move.vault)") && card.contains("vaults.unfinishedMoveLater(move)"))
    }

    /**
     * In the window, walked with the keyboard: "Finish" pressed on the vault's first page goes to the Sharing page, where
     * the move's screen is drawn in the offer's place (its Close is the page's first control after Back). Before, the offer
     * vanished and nothing took its place until the person opened Sharing.
     */
    @OptIn(androidx.compose.ui.InternalComposeUiApi::class)
    @Test
    fun finishOnTheVaultsFirstPageLeadsToThePageWhereTheMovesScreenIsDrawn() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        val family = assertNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL]).vaults.first { it.name == "Family" }
        family.moveUnfinishedInto = "Work"
        api.script.changed()
        m.onSnapshot(api.snapshot)
        assertEquals(1, assertNotNull(api.snapshot.account).unfinishedMoves.size)
        val log = ArrayList<String>()
        var t = 0L
        val scene = ImageComposeScene(900, 6000, Density(1f)) {
            CompositionLocalProvider(LocalFocusLog provides log) {
                MaterialTheme {
                    Surface {
                        val s = m.snapshots.collectAsState().value
                        s.account?.let { AccountShell(m, s, it) }
                    }
                }
            }
        }
        fun frames() = repeat(2) {
            t += 50_000_000L
            scene.render(t)
        }
        fun press(k: Key) {
            scene.sendKeyEvent(KeyEvent(k, KeyEventType.KeyDown))
            scene.sendKeyEvent(KeyEvent(k, KeyEventType.KeyUp))
            frames()
        }
        val finish = UiText.ph(Placeholder.MOVE_FINISH).shown()
        val close = UiText.ph(Placeholder.CLOSE).shown()
        val back = UiText.ph(Placeholder.BACK).shown()
        try {
            frames()
            var tabs = 0
            while (log.lastOrNull() != finish && tabs < 80) {
                press(Key.Tab)
                tabs++
            }
            assertEquals(finish, log.lastOrNull(), "the offer's Finish is reached on the vault's first page: $log")
            val before = log.size
            press(Key.Enter)
            assertNotNull(assertNotNull(api.snapshot.account).moving, "the move is open again")
            repeat(80) { press(Key.Tab) }
            val after = log.drop(before)
            // The Sharing page (its own page: its Back first), whose first control is the move's screen's way out.
            assertEquals(listOf(back, close), after.take(2), "the move's screen is drawn where the person now is: $after")
            assertTrue(finish !in after, "the offer is gone while the move is open")
        } finally {
            scene.close()
        }
    }

    private fun draw(m: TrustModel) {
        val s = m.api.snapshot
        val move = assertNotNull(s.account).unfinishedMoves.single()
        val scene = ImageComposeScene(480, 400, Density(1f)) { MaterialTheme { Surface { UnfinishedMoveOffer(m, s, move) {} } } }
        try {
            scene.render()
        } finally {
            scene.close()
        }
    }
}
