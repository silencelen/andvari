package io.silencelen.andvari.desktop.trust

import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.session.WireTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The rule of 2026-11-17: a lock takes a recovery kit shown with this computer's refusal, and the screen the person comes
 * back to says so until they dismiss it ([io.silencelen.andvari.core.app.AppSnapshot.kitWiped]); a start of the app
 * after it was closed with such a kit on show says the same. Walked on the shared code's real engine over this
 * computer's own stores (the fake never sets the notice), with no server: every call to one fails here.
 */
class KitWipedTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun body(file: String, head: String) = File(dir + file).readText().substringAfter(head).substringBefore("\n}\n")

    /** The shared code's mark at rest that a kit of a committed change was on show (nothing of the kit is in it). */
    private val markKey = "ovh.kit.notkept.onshow"

    private fun home(): DesktopHome =
        DesktopHome(java.nio.file.Files.createTempDirectory("andvari-kitwiped").toFile().also { it.deleteOnExit() }, NoKeyStore, log = {}, keyStorePause = {})

    /** A start of the app over [home]: the engine, as [TrustSeam] builds it, with a transport that reaches no server. */
    private fun started(home: DesktopHome): TrustModel {
        val state = JsonDeviceState(home.stateFile())
        val api = EngineDesktopAppApi(
            AppEngine(
                platform = TrustSeam.desktopPlatform(),
                deviceName = "test",
                transport = WireTransport { origin, _ -> error("no server in this test: $origin") },
                state = state,
                secure = JsonDeviceState(home.secureFile),
                requestStore = JsonDeviceState(home.requestFile),
                crypto = createCryptoProvider(),
                clock = { System.currentTimeMillis() },
                baked = null,
                storeBuild = false,
                stores = null,
                main = Dispatchers.Unconfined,
                work = Dispatchers.Unconfined,
                cacheFiles = home.cacheFiles,
                contentStores = home.content.stores,
                keepsAtRest = home::keepsAtRest,
            ),
        )
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.start()
        m.onSnapshot(api.snapshot)
        return m
    }

    private fun drawWhole(m: TrustModel) {
        val scene = ImageComposeScene(480, 900, Density(1f)) { androidx.compose.material3.MaterialTheme { TrustApp(m, null, "log") } }
        try {
            scene.render()
        } finally {
            scene.close()
        }
    }

    @Test
    fun aStartAfterTheAppWasClosedWithSuchAKitOnShowSaysItIsGoneUntilTheNoticeIsDismissed() {
        val home = home()
        // The app was closed with such a kit on show, after a recovery: the shared code left its mark at rest.
        JsonDeviceState(home.stateFile()).set(markKey, "recovery|ada@example.com")
        val m = started(home)
        val s = m.api.snapshot
        assertEquals(AppPhase.ENTRY, s.phase)
        val notice = assertNotNull(s.kitWiped, "said at the start")
        assertEquals(CopyKey.KIT_WIPED_AFTER_RECOVERY, notice.line)
        assertNull(notice.whyHere)
        assertEquals(
            listOf(UiText.of(CopyKey.KIT_WIPED_AFTER_RECOVERY).shown(), "ada@example.com"),
            kitWipedLines(notice).map { it.shown() },
        )
        drawWhole(m)
        // A lock, or anything the person does on the first screen, does not take it: only the dismiss does.
        m.api.lock()
        m.lockNow()
        m.tick()
        assertSame(notice, m.api.snapshot.kitWiped)
        // Closed again without a dismiss: the next start says it again.
        m.api.close()
        val again = started(home)
        val second = assertNotNull(again.api.snapshot.kitWiped, "not used up by a start")
        assertEquals(CopyKey.KIT_WIPED_AFTER_RECOVERY, second.line)
        // The bar's dismiss: gone, and the next start says nothing.
        again.quietly { again.api.dismissKitWiped(second) }
        assertNull(again.api.snapshot.kitWiped)
        again.api.close()
        assertNull(started(home).api.snapshot.kitWiped, "dismissed: not said again")
    }

    /** Where something stood in the way on this computer, the notice never says "on any device" and draws what it was. */
    @Test
    fun theNoticeDrawsWhatStandsInTheWayHereWhereTheSharedCodeNamesIt() {
        val home = home()
        JsonDeviceState(home.stateFile()).set(markKey, "registration|${CopyKey.KIT_REGISTERED_IDENTITY_FAULT.name}|bo@example.com")
        val m = started(home)
        val notice = assertNotNull(m.api.snapshot.kitWiped)
        assertEquals(CopyKey.KIT_WIPED_AFTER_REGISTRATION_NOT_HERE, notice.line)
        // The shared code's reason line for the kit's own line (never the kit's line, which says to save the kit), and no
        // way out: a fault of the account's identity has none here.
        assertEquals(CopyKey.KIT_NOT_HERE_WHY_IDENTITY_FAULT, notice.whyHere)
        assertNull(notice.wayOut)
        assertNull(kitWipedWayOut(m.api.snapshot))
        assertEquals(
            listOf(UiText.of(notice.line).shown(), UiText.of(CopyKey.KIT_NOT_HERE_WHY_IDENTITY_FAULT).shown(), "bo@example.com"),
            kitWipedLines(notice).map { it.shown() },
        )
        drawWhole(m)
    }

    /**
     * The six reason lines under the notice, each from the shared code (by key), drawn under the notice's own line and
     * before the address, with the shared code's way out for it: over the real engine, one start for each kit line the
     * mark at rest can carry. No account is kept here, so no way out is offered under any of them.
     */
    @Test
    fun theNoticeDrawsEachOfTheSixReasonLinesWithTheSharedCodesWayOut() {
        val cases = listOf(
            Triple(CopyKey.KIT_RECOVERED_NOT_KEPT, CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT, io.silencelen.andvari.core.app.KeptWayOut.SIGN_OUT_KEPT_ACCOUNT),
            Triple(CopyKey.RECOVERY_COMMITTED_OPERATOR_ACCOUNT_HELD, CopyKey.KIT_NOT_HERE_WHY_OPERATOR_HELD, io.silencelen.andvari.core.app.KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT),
            Triple(CopyKey.KIT_REGISTERED_IDENTITY_FAULT, CopyKey.KIT_NOT_HERE_WHY_IDENTITY_FAULT, null),
            Triple(CopyKey.RECOVERY_COMMITTED_SERVER_KEYS_NOT_KNOWN_HERE, CopyKey.KIT_NOT_HERE_WHY_SERVER_KEYS, io.silencelen.andvari.core.app.KeptWayOut.REMOVE_THIS_COPY),
            Triple(CopyKey.RECOVERY_COMMITTED_KEPT_COPY_DAMAGED, CopyKey.KIT_NOT_HERE_WHY_COPY_DAMAGED, io.silencelen.andvari.core.app.KeptWayOut.REMOVE_THIS_COPY),
            Triple(CopyKey.KIT_NOT_KEPT_HERE, CopyKey.KIT_NOT_HERE_WHY_NOT_OPENED, null),
        )
        assertEquals(6, cases.map { it.second }.distinct().size)
        for ((kitLine, why, way) in cases) {
            val home = home()
            JsonDeviceState(home.stateFile()).set(markKey, "recovery|${kitLine.name}|cy@example.com")
            val m = started(home)
            val notice = assertNotNull(m.api.snapshot.kitWiped, "$kitLine")
            assertEquals(why, notice.whyHere, "$kitLine")
            assertEquals(way, notice.wayOut, "$kitLine")
            assertEquals(
                listOf(UiText.of(notice.line).shown(), UiText.of(why).shown(), "cy@example.com"),
                kitWipedLines(notice).map { it.shown() }, "$kitLine",
            )
            assertNull(kitWipedWayOut(m.api.snapshot), "$kitLine: no account is kept here to act on")
            drawWhole(m)
            m.api.close()
        }
    }

    /**
     * The notice is drawn above whatever is on show, in every phase (the fake cannot set it, and the real engine cannot
     * reach the lock screen or an open vault without a server, so this part is read from the code): outside the switch
     * over the phase, first in the column, with the dismiss as its only way out, and in the app's one window, which the
     * Settings switch hides from screen capture.
     */
    @Test
    fun theNoticeIsDrawnAboveEveryPhaseInTheOneWindowAndGoesOnlyByItsDismiss() {
        val app = body("TrustApp.kt", "fun TrustApp(")
        val column = app.substringAfter("Column(Modifier.fillMaxSize()) {")
        assertTrue(column.trimStart().lines().first { !it.trim().startsWith("//") }.trim() == "KitWipedBar(model, s)", "first, above everything")
        assertTrue(column.indexOf("KitWipedBar(model, s)") < column.indexOf("when (s.phase)"), "outside the phases")
        val bar = body("TrustApp.kt", "private fun KitWipedBar(")
        assertTrue(bar.contains("val notice = s.kitWiped ?: return"))
        assertTrue(bar.contains("model.api.dismissKitWiped(notice)"))
        assertEquals(1, Regex("""dismissKitWiped""").findAll(File(dir).walkTopDown().filter { it.isFile }.joinToString("\n") { it.readText() }).count(), "the bar's dismiss is the only call")
        for (opens in listOf("Dialog(", "Popup(", "Window(")) {
            assertFalse(bar.contains(opens), "drawn in the app's window, not a surface of its own: $opens")
            assertFalse(body("KitScreens.kt", "internal fun KitScreenView(").contains(opens))
        }
        val main = File("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt").readText()
        assertTrue(main.contains("TrustApp(model, cryptoUnavailable, DesktopDiagnostics.logFile.absolutePath)"))
        assertTrue(main.substringAfter("private fun ApplicationScope.AppWindow(").contains("GuardedWindow(\n        capture,"))
    }
}
