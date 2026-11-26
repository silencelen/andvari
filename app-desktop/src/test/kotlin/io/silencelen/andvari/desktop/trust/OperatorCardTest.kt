package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The server's identity card renamed, moved (the address checked first), its recovery key set and removed. */
class OperatorCardTest {
    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })
    private val pw = FakeScenes.PASSWORD

    private fun console(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE)
        val m = TrustModel(api, scope, { 0L }, SignInKeeping.Never, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun card(m: TrustModel, key: String): OperatorModel.Answer? = m.operator.answerAt(OperatorModel.Area.CARD, key)

    private fun ph(a: OperatorModel.Answer?): Placeholder = assertIs<UiText.Ph>(assertNotNull(a).text).placeholder

    @Test
    fun everyCardChangeTakesTheRightPasswordAndAWrongOneSendsNothingThatChanges() {
        val (api, m) = console()
        val op = m.operator
        val server = assertNotNull(api.script.server(FakeScenes.FAMILY_ORIGIN))
        val before = server.name

        op.rename("The Family", "not the password")
        assertEquals(Placeholder.OP_WRONG_PASSWORD, ph(card(m, OperatorModel.CARD_RENAME)))
        assertEquals(before, server.name)
        op.rename("  The Family  ", pw)
        assertEquals(OperatorResult.DONE, card(m, OperatorModel.CARD_RENAME)?.result)
        assertEquals("The Family", server.name)

        val fp = "ab".repeat(32)
        op.changeRecoveryKey(fp, "", "not the password")
        assertEquals(Placeholder.OP_WRONG_PASSWORD, ph(card(m, OperatorModel.CARD_RECOVERY)))
        op.changeRecoveryKey(fp.uppercase(), "", pw)
        assertEquals(OperatorResult.DONE, card(m, OperatorModel.CARD_RECOVERY)?.result)
        op.changeRecoveryKey(fp, "rotation:signed", pw)
        assertEquals(OperatorResult.DONE, card(m, OperatorModel.CARD_RECOVERY)?.result)
        op.changeRecoveryKey(fp, "not a statement", pw)
        assertEquals(Placeholder.OP_ROTATION_REFUSED_EITHER, ph(card(m, OperatorModel.CARD_RECOVERY)))

        op.removeRecoveryKey("not the password")
        assertEquals(Placeholder.OP_WRONG_PASSWORD, ph(card(m, OperatorModel.CARD_RECOVERY)))
        op.removeRecoveryKey(pw)
        assertEquals(OperatorResult.DONE, card(m, OperatorModel.CARD_RECOVERY)?.result)
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun theAddressGrammarAndTheFingerprintAreCheckedBeforeAnythingIsSigned() {
        val (api, m) = console()
        val op = m.operator
        api.script.holdNext()
        for (bad in listOf("vault.example.org", "https://vault.example.org/path", "ftp://vault.example.org", "https://user@vault.example.org")) {
            assertNull(op.move(bad, pw), bad)
            val said = assertNotNull(card(m, OperatorModel.CARD_MOVE)).text
            assertEquals(CopyKey.ADDRESS_NEEDS_HTTPS_DOMAIN.english, said.shown(), "the grammar's own sentence")
        }
        assertNull(op.changeRecoveryKey("abc", "", pw))
        assertEquals(Placeholder.OP_FINGERPRINT_SHAPE, ph(card(m, OperatorModel.CARD_RECOVERY)))
        assertNull(op.rename("   ", pw))
        assertEquals(Placeholder.OP_CARD_NAME_EMPTY, ph(card(m, OperatorModel.CARD_RENAME)))
        assertFalse(api.script.holding, "nothing was sent")

        // A good address goes on (the armed hold takes it), with a trailing slash dropped.
        assertNotNull(op.move("https://vault.newplace.example/", pw))
        assertTrue(api.script.holding)
        api.script.releaseHold()
        assertEquals(OperatorResult.DONE, card(m, OperatorModel.CARD_MOVE)?.result)
        assertNotNull(api.script.server("https://vault.newplace.example"))
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun thePasswordLineNamesTheAccountTheServerAndItsAddressAndHandoverStaysWithTheTool() {
        val (api, _) = console()
        val line = assertNotNull(masterPasswordFor(api.snapshot)).shown()
        val instance = assertNotNull(api.snapshot.instance).label
        assertTrue(line.contains(assertNotNull(api.snapshot.account).email))
        assertTrue(line.contains(instance.name))
        assertTrue(line.contains(instance.origin))
        val section = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
            .substringAfter("private fun CardSection(").substringBefore("\n}\n")
        // The card's actions take the password in their own step, whose field is the named one.
        assertFalse(section.contains("MasterPasswordField("), "no password field on the page")
        assertTrue(section.contains("op.chooseForServer(OperatorModel.Action.RENAME)"))
        val step = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
            .substringAfter("private fun PasswordStepDialog(").substringBefore("\n}\n")
        assertTrue(step.contains("MasterPasswordField(s, password"))
        assertTrue(section.contains("Placeholder.OP_HANDOVER_CLI"))
        assertTrue(Placeholder.OP_HANDOVER_CLI.gloss.contains("command-line tool"))
        // Every password field of the console is the named one.
        val screens = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
        assertFalse(screens.contains("SecretField("), "no unnamed password field")
    }
}
