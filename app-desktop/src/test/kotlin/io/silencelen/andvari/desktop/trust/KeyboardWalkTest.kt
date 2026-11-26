package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.InternalComposeUiApi
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.model.wire.AccountRole
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The console, the setup screens and "Move everything" walked with the keyboard alone: Tab from nothing focused, Enter
 * on a focused button. Each control the focus reaches shows its focus mark ([focusMark], which also writes the walk
 * here through [LocalFocusLog]); the first control reached is never a destructive one. The module has no Compose test
 * runtime, so the walk runs in a headless scene: the dialogs (each action's step) are a window of their own there and
 * are pinned by source instead.
 */
class KeyboardWalkTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun src(name: String) = File(dir + name).readText()
    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")
    private fun at(scene: FakeScene) = FakeScenes.desktopAt(scene).let { api -> api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }) }

    private fun ph(p: Placeholder, vararg args: String) = UiText.ph(p, *args).shown()

    @Test
    fun theConsoleIsWalkedByTabAndItsFirstControlIsReadAgainNeverADestructiveOne() {
        val (api, m) = at(FakeScene.OPERATOR_CONSOLE)
        val console = assertNotNull(api.operatorApi.console)
        val member = console.accounts.first { it.role != AccountRole.OPERATOR }
        val email = plainName(member.email)
        val manage = ph(Placeholder.OP_MANAGE, email)
        val walk = KeyWalk { Column { OperatorPage(m, api.snapshot) } }
        try {
            walk.tabs(3)
            assertEquals(ph(Placeholder.OP_READ_AGAIN), walk.log.first(), walk.log.toString())
            // On to the member's row, and open it with Enter: its panel's first control is the quota, not disable.
            walk.tabUntil(manage, 40)
            println("console walk to the row: ${walk.log}")
            walk.enter()
            walk.log.clear()
            walk.tabs(60)
        } finally {
            walk.close()
        }
        println("console walk after Enter on the row: ${walk.log}")
        val quota = walk.log.indexOf(ph(Placeholder.OP_QUOTA, email))
        val disable = walk.log.indexOf(ph(Placeholder.OP_DISABLE, email))
        assertTrue(quota >= 0 && disable >= 0, walk.log.toString())
        assertTrue(quota < disable, "the panel's first control is not the destructive one: ${walk.log}")
        // The order in the source: what reads or limits first, disabling and deleting last, close after them.
        val panel = body(src("OperatorScreens.kt"), "private fun AccountPanel(")
        assertTrue(panel.indexOf("Placeholder.OP_QUOTA") < panel.indexOf("Placeholder.OP_DISABLE"))
        assertTrue(panel.indexOf("Placeholder.OP_DISABLE") < panel.indexOf("Placeholder.OP_DELETE") && panel.indexOf("Placeholder.OP_DELETE") < panel.indexOf("Placeholder.CLOSE"))
        // The server's card: removing operator recovery is the last change offered.
        val card = body(src("OperatorScreens.kt"), "private fun CardSection(")
        assertTrue(card.indexOf("Placeholder.OP_CARD_RENAME, server") < card.indexOf("Placeholder.OP_RECOVERY_REMOVE, server"))
    }

    /**
     * The walk is the focus as the focus system moves it, however quickly the next key comes: a control the focus passed
     * through between two frames is in it, in order. Before, the record (and the mark) waited for the control's focus
     * event to be delivered and a frame to be composed with it, so a Tab that came first left the control out; that is
     * how the console's first panel control went missing from one walk on a loaded machine.
     */
    @Test
    fun aControlTheFocusPassesThroughBetweenTwoFramesIsInTheWalk() {
        val words = listOf("one", "two", "three", "four")
        val walk = KeyWalk { Column { for (w in words) Second(UiText.Plain(w)) {} } }
        try {
            walk.quickTabs(3)
            assertEquals(words.take(3), walk.log.toList())
            walk.quickTabs(1)
            assertEquals(words, walk.log.toList())
        } finally {
            walk.close()
        }
    }

    @Test
    fun everyStepIsADialogWhoseWayOutComesFirstAndCarriesTheMark() {
        // AlertDialog lays out its dismiss button before its confirm, so the focus reaches Cancel first after the fields.
        val frame = body(src("OperatorScreens.kt"), "private fun StepFrame(")
        assertTrue(frame.indexOf("dismissButton = { DialogButton(UiText.of(CopyKey.CANCEL), onClick = onCancel) }") in 0 until frame.indexOf("confirmButton = { DialogButton(confirm"))
        assertTrue(frame.contains("onDismissRequest = onCancel"), "Escape is the way out")
        val setup = body(src("ServerSetupScreens.kt"), "private fun SetupPasswordStep(")
        assertTrue(setup.contains("dismissButton = { DialogButton(UiText.of(CopyKey.CANCEL), onClick = onCancel) }"))
    }

    @Test
    fun theSetupScreensAreWalkedByTabAndReachTheirOneActionFirst() {
        for ((scene, words) in listOf(FakeScene.SERVER_SETUP_NOT_UPLOADED to ph(Placeholder.SETUP_RETRY), FakeScene.SERVER_SETUP_FINISHED to ph(Placeholder.SETUP_TO_KIT))) {
            val (api, m) = at(scene)
            val screen = assertIs<EntryScreen.ServerSetup>(api.snapshot.entry)
            val walk = KeyWalk { ServerSetupScreen(m, api.snapshot, screen) }
            try {
                walk.tabs(3)
            } finally {
                walk.close()
            }
            assertEquals(words, walk.log.first(), "$scene: ${walk.log}")
        }
    }

    @Test
    fun moveEverythingIsWalkedByTabAndItsWayOutComesBeforeTheMove() {
        val (api, m) = at(FakeScene.MOVE_EVERYTHING)
        val account = assertNotNull(api.snapshot.account)
        assertNotNull(account.moving)
        val walk = KeyWalk { Column { SharedVaultsSection(m, api.snapshot, account) } }
        try {
            walk.tabs(40)
        } finally {
            walk.close()
        }
        // The move's own button stays off until a name is typed (no stop here), so its first control is the way out;
        // the vaults' rows come after it.
        assertEquals(ph(Placeholder.CLOSE), walk.log.first(), walk.log.toString())
        val view = body(src("VaultScreens.kt"), "private fun MoveEverythingView(")
        val buttons = view.substringAfter("WayOutThenMain(")
        assertTrue(buttons.indexOf("Placeholder.CLOSE") in 0 until buttons.indexOf("CopyKey.MOVE_EVERYTHING"), "the way out before the move")
    }

    /** A headless scene walked with the keyboard; [log] holds the words of each marked control the focus reached. */
    @OptIn(InternalComposeUiApi::class)
    private class KeyWalk(content: @Composable () -> Unit) {
        val log = ArrayList<String>()
        private var t = 0L
        private val scene = ImageComposeScene(900, 6000, Density(1f)) {
            CompositionLocalProvider(LocalFocusLog provides log) { MaterialTheme { Surface { content() } } }
        }

        init {
            scene.render(t)
        }

        /** One key, then two frames, so what it opened is composed and placed before the next key. */
        private fun press(key: Key) {
            send(key)
            t += 50_000_000L
            scene.render(t)
            t += 50_000_000L
            scene.render(t)
        }

        private fun send(k: Key) {
            scene.sendKeyEvent(KeyEvent(k, KeyEventType.KeyDown))
            scene.sendKeyEvent(KeyEvent(k, KeyEventType.KeyUp))
        }

        fun tabs(n: Int) = repeat(n) { press(Key.Tab) }

        /** [n] Tabs with no frame between them, as quick hands give them; then one frame. */
        fun quickTabs(n: Int) {
            repeat(n) { send(Key.Tab) }
            t += 50_000_000L
            scene.render(t)
        }

        fun tabUntil(words: String, most: Int) {
            repeat(most) {
                if (log.lastOrNull() == words) return
                press(Key.Tab)
            }
            assertEquals(words, log.lastOrNull(), log.toString())
        }

        fun enter() = press(Key.Enter)

        fun close() = scene.close()
    }
}
