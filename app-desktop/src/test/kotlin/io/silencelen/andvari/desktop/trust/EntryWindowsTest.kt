package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.InternalComposeUiApi
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The trust and recovery flows, the setup screens and the other entry screens in the current desktop app's style: each
 * window that stands alone opens under the brand head with its own title (the current app's recovery window); what is
 * written down or read out sits in its surface card; a gate's way out is a text button the focus reaches first; every
 * control shows a focus mark. Every entry screen of the fake is drawn, so none throws in its new shape.
 */
class EntryWindowsTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun src(name: String) = File(dir + name).readText()
    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")

    private fun at(scene: FakeScene) = FakeScenes.desktopAt(scene).let { api -> api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }) }

    /** Every composable the entry dispatch names, with the file it is in. */
    private val entryScreens = listOf(
        "EntryScreens.kt" to listOf("FirstRunScreen", "InviteEntryScreen", "OwnServerScreen", "TrustGateScreen", "ServerChangedScreen", "AddressMismatchScreen", "ServerScreen", "SignInChoiceScreen", "ForgotScreen"),
        "AccountEntryScreens.kt" to listOf("JoinInviteScreen", "NotTakingAccountsScreen", "SignUpEmailScreen", "SignUpCodeScreen", "CreateAccountScreen", "RecoveryWarningScreen", "SignInServerScreen", "SignInScreen", "LinkRequiredScreen"),
        "LinkAndRecoveryScreens.kt" to listOf(
            "LinkDeviceEntryScreen", "LinkDeviceWaitingScreen", "LinkDeviceCodeScreen", "LinkDevicePasswordScreen", "LinkDeviceEndedScreen",
            "KitEntryScreen", "KitRecoverScreen", "ReplacePasswordScreen", "AskOperatorScreen", "OperatorHelpScreen", "CheckAccountScreen",
        ),
        "ServerSetupScreens.kt" to listOf("ServerSetupScreen"),
    )

    @Test
    fun everyWindowThatStandsAloneOpensUnderTheBrandHead() {
        for ((file, names) in entryScreens) for (name in names) {
            val b = body(src(file), "internal fun $name(")
            assertTrue(b.contains("WindowHead(") || b.contains("BrandHead()") || b.contains("Sigil()"), "$name has no brand head")
            assertTrue(!Regex("(?<![A-Za-z])Title\\(").containsMatchIn(b), "$name: the title is the head's, not a heading under it")
        }
        // The kit's steps each open under it too (the kit is a window of its own before the vault opens).
        val kit = src("KitScreens.kt")
        for (step in listOf("private fun KitNotMade(", "private fun KitReveal(", "private fun KitConfirm(")) assertTrue(body(kit, step).contains("WindowHead("), step)
        // The head is the current app's: its rune, the window's title large and centred, quiet lines under it.
        val head = body(src("TrustUi.kt"), "internal fun WindowHead(")
        assertTrue(head.contains("BrandRune()") && head.contains("titleLarge") && head.contains("TextAlign.Center") && head.contains("QuietInstance(it)"))
    }

    @Test
    fun whatIsWrittenDownOrReadOutSitsInTheCurrentAppsSurfaceCard() {
        val link = src("LinkAndRecoveryScreens.kt")
        assertTrue(body(link, "internal fun LinkDeviceCodeScreen(").contains("CodeCard {"))
        assertTrue(body(link, "internal fun OperatorHelpScreen(").contains("CodeCard {"))
        assertTrue(body(link, "internal fun CheckAccountScreen(").contains("CodeCard {"))
        assertTrue(body(src("KitScreens.kt"), "private fun KitReveal(").contains("CodeCard {"))
        assertTrue(body(src("ServerSetupScreens.kt"), "internal fun ServerSetupScreen(").contains("CodeCard { SetupDetails(it) }"))
        assertTrue(body(src("TrustUi.kt"), "internal fun CodeCard(").contains("colorScheme.surfaceVariant"))
        // The waits are the current app's: a small spinner beside its line, never the large default one.
        for ((file, name) in listOf("LinkAndRecoveryScreens.kt" to "internal fun LinkDeviceWaitingScreen(", "ServerSetupScreens.kt" to "internal fun ServerSetupScreen(", "KitScreens.kt" to "internal fun KitScreenView(")) {
            val b = body(src(file), name)
            assertTrue(b.contains("OpeningSpinner()") && !b.contains("CircularProgressIndicator()"), name)
        }
    }

    @Test
    fun aGatesWayOutComesFirstAsATextButtonAndTheFocusReachesItFirst() {
        val entry = src("EntryScreens.kt")
        val gate = body(entry, "internal fun TrustGateScreen(")
        assertTrue(gate.indexOf("UiText.of(CopyKey.CANCEL)") in 0 until gate.indexOf("trustGateConfirmLabel(screen.prompt)"), gate)
        assertTrue(gate.contains("WayOutThenMain("))
        assertTrue(body(entry, "internal fun InstanceCard(").contains("WayOutThenMain("), "the kind change's gate too")
        val warning = body(src("AccountEntryScreens.kt"), "internal fun RecoveryWarningScreen(")
        assertTrue(warning.indexOf("w.keepPrivate") < warning.indexOf("w.turnOn") && warning.contains("WayOutThenMain("))
        val row = body(src("TrustUi.kt"), "internal fun WayOutThenMain(")
        assertTrue(row.indexOf("Quieter(wayOut") < row.indexOf("Main(main"))

        // Drawn, and walked with Tab: the first control the focus reaches is Cancel, then the confirm.
        val (api, m) = at(FakeScene.GATE_TYPED_ADDRESS)
        val screen = assertIs<EntryScreen.TrustGate>(api.snapshot.entry)
        val walk = walk(6) { TrustGateScreen(m, api.snapshot, screen) }
        assertEquals(UiText.of(CopyKey.CANCEL).shown(), walk.first(), walk.toString())
        assertEquals(trustGateConfirmLabel(screen.prompt).shown(), walk[1], walk.toString())
    }

    @Test
    fun everyControlOfThePathCarriesTheFocusMark() {
        val ui = src("TrustUi.kt")
        for (f in listOf("internal fun Main(", "internal fun Second(", "internal fun Quieter(", "internal fun DialogButton(", "internal fun Tick(", "internal fun Choice(", "internal fun PageHeader(")) {
            val b = body(ui, f)
            assertTrue(b.contains("focusMark(") && (b.contains("interactionSource = source") || b.contains("source, LocalIndication.current")), f)
        }
        assertTrue(body(src("EntryScreens.kt"), "private fun EqualChoice(").contains("focusMark("))
        val mark = body(ui, "internal fun focusMark(")
        // The mark follows the focus as the focus system reports it, never an effect a quick Tab can overtake.
        assertTrue(mark.contains("onFocusChanged") && mark.contains("border(FOCUS_MARK_WIDTH"))
        assertFalse(mark.contains("collectIsFocusedAsState") || mark.contains("LaunchedEffect"), mark)
        // The dialogs' buttons are the marked ones too.
        assertTrue(body(src("EntryScreens.kt"), "private fun ForgetQuestion(").contains("DialogButton(UiText.of(CopyKey.CANCEL)"))
        assertTrue(body(src("ServerSetupScreens.kt"), "private fun SetupPasswordStep(").contains("DialogButton(UiText.of(CopyKey.CANCEL)"))
    }

    @Test
    fun everyEntryScreenOfTheFakeDrawsInItsNewShape() {
        var drawn = 0
        for (scene in FakeScene.entries) {
            val (api, m) = at(scene)
            val s = api.snapshot
            val entry = s.entry
            if (s.phase != AppPhase.ENTRY || entry == null) continue
            val image = ImageComposeScene(480, 1400, Density(1f)) { MaterialTheme { Surface { EntryScreens(m, s, entry) } } }
            try {
                image.render()
            } finally {
                image.close()
            }
            drawn++
        }
        assertTrue(drawn >= 40, "drawn: $drawn")
    }

    /** The words of each marked control the focus reaches, pressing Tab [presses] times from nothing focused. */
    @OptIn(InternalComposeUiApi::class)
    private fun walk(presses: Int, content: @androidx.compose.runtime.Composable () -> Unit): List<String> {
        val log = ArrayList<String>()
        val scene = ImageComposeScene(480, 1400, Density(1f)) {
            CompositionLocalProvider(LocalFocusLog provides log) { MaterialTheme { Surface { content() } } }
        }
        try {
            var t = 0L
            scene.render(t)
            repeat(presses) {
                scene.sendKeyEvent(KeyEvent(Key.Tab, KeyEventType.KeyDown))
                scene.sendKeyEvent(KeyEvent(Key.Tab, KeyEventType.KeyUp))
                t += 50_000_000L
                scene.render(t)
            }
        } finally {
            scene.close()
        }
        return log
    }
}
