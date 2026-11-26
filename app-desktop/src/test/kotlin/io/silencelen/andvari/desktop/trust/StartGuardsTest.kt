package io.silencelen.andvari.desktop.trust

import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A hostile server or a damaged file cannot close the app. */
@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
class StartGuardsTest {
    private val tmp: File = Files.createTempDirectory("andvari-l7-guards").toFile()

    @AfterTest
    fun cleanUp() {
        tmp.deleteRecursively()
    }

    /** A two-step link past ~2,300 bytes threw `WriterException: Data too big` out of the screen. */
    @Test
    fun aLinkTooLongToDrawNeverThrows() {
        val long = "otpauth://totp/andvari:me?secret=" + "A".repeat(3000)
        assertFailsWith<com.google.zxing.WriterException>("the raw encoder throws, as it did on the screen") { qrImage(long) }
        assertNull(qrImageOrNull(long), "the screen's form says so instead")
        assertNull(qrMatrixOrNull(long))
        assertNotNull(qrImageOrNull("otpauth://totp/andvari:me?secret=ABC"), "an ordinary link still draws")
    }

    @Test
    fun aFailedScreenIsLoggedThroughTheRedactingLogLocksAndBecomesTheCard() {
        val logged = ArrayList<String>()
        val f = ScreenFailure(log = { where, t -> logged += "$where/${t.javaClass.simpleName}" })
        var locked = 0
        f.onFailure = { locked++ }
        assertFalse(f.failed.value)
        f.handler().onException(IllegalStateException("a secret in a message"))
        assertTrue(f.failed.value, "the window becomes the error card")
        assertEquals(1, locked, "the vault is locked first")
        assertEquals(listOf("a screen failed/IllegalStateException"), logged, "only through the log it is given")
    }

    @Test
    fun aFailingLockDoesNotStopTheCard() {
        val logged = ArrayList<String>()
        val f = ScreenFailure(log = { where, _ -> logged += where })
        f.onFailure = { error("lock failed") }
        f.caught("start", RuntimeException())
        assertTrue(f.failed.value)
        assertEquals(listOf("start", "while handling a failure"), logged)
    }

    private fun plantKeep(root: File, on: Boolean) {
        File(root, "v2").mkdirs()
        File(root, "v2/desktop-prefs.json").writeText("""{"keepSignIn":$on}""")
    }

    /** A truncated device-state.json closed the app at every start. */
    @Test
    fun aStateFileThatDoesNotParseIsNamedAndSetAsideOnlyOnTheAnswer() {
        val root = File(tmp, "home")
        File(root, "v2").mkdirs()
        File(root, "v2/device-state.json").writeText("{\"pin:https://a.example\":\"abc")
        val home = DesktopHome(root)
        val damaged = StateFiles.damaged(home)
        assertEquals(listOf(File(home.dir, "device-state.json")), damaged)
        assertTrue(damaged.single().exists(), "nothing is moved before the person answers")

        assertTrue(StateFiles.setAside(damaged))
        assertFalse(File(home.dir, "device-state.json").exists())
        val aside = home.dir.listFiles()!!.single { it.name.startsWith("device-state.json.unreadable-") }
        assertEquals("{\"pin:https://a.example\":\"abc", aside.readText(), "kept, never deleted")
        assertTrue(StateFiles.damaged(DesktopHome(root)).isEmpty(), "the next start is fresh: no loop")
    }

    @Test
    fun theKeptSessionIsCheckedOnlyWhileTheSignInIsKept() {
        val root = File(tmp, "home")
        plantKeep(root, true)
        File(root, "v2/secure-state.json").writeText("")
        assertEquals(listOf(File(root, "v2/secure-state.json").absoluteFile), StateFiles.damaged(DesktopHome(root)).map { it.absoluteFile })

        val off = File(tmp, "off")
        plantKeep(off, false)
        File(off, "v2/secure-state.json").writeText("")
        assertTrue(StateFiles.damaged(DesktopHome(off)).isEmpty(), "not read while off (and removed unread)")
    }

    @Test
    fun aGoodOrAbsentFileIsNotDamaged() {
        assertTrue(StateFiles.readsAsMap(File(tmp, "absent.json")))
        File(tmp, "ok.json").writeText("""{"a":"b"}""")
        assertTrue(StateFiles.readsAsMap(File(tmp, "ok.json")))
        File(tmp, "list.json").writeText("""["a"]""")
        assertFalse(StateFiles.readsAsMap(File(tmp, "list.json")), "not the engine's map")
        File(tmp, "dir.json").mkdirs()
        assertFalse(StateFiles.readsAsMap(File(tmp, "dir.json")), "cannot be read: damaged, never empty")
    }
}
