package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.RegistrationVia
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.ServerSetupStep
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

/**
 * What the app interface offers the desktop, bound on the screens and driven
 * against the fake: a server set up from a setup link typed as its address, the sign-up it leads to, the setup screen
 * in its states with the kit held behind it, the retry and "Finish" each with the master password in a step of its
 * own, the console's new lines, and the first screen's notice for a deletion whose outcome is unknown.
 */
class AppInterfaceOffersTest {
    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })
    private val pw = FakeScenes.PASSWORD

    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        val m = TrustModel(api, scope, { 0L }, SignInKeeping.Never, { 0L }, faultLog = {})
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun src(f: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$f").readText()

    private inline fun <reified T : EntryScreen> on(api: FakeDesktopAppApi): T = assertIs<T>(api.snapshot.entry, "on ${T::class.simpleName}")

    @Test
    fun aSetupLinkTypedAsTheServersAddressLeadsToTheSignUpThenTheSetupThenTheKit() {
        val (api, m) = at(FakeScene.FIRST_RUN)
        m.act { entry.openOwnServer(on(api)) }
        val own = on<EntryScreen.OwnServer>(api)
        assertTrue(own.takesSetupLinks, "the desktop takes a setup link here")
        assertTrue("line = if (screen.takesSetupLinks) UiText.ph(Placeholder.OWN_SERVER_TAKES_SETUP_LINK) else null" in src("EntryScreens.kt"))
        val server = api.script.addServer("https://vault.setup.example", "Setup", ServerKind.PRIVATE_SERVER)
        m.run({ entry.submitServerAddress(own, api.script.setupLink(server)) })
        val form = on<EntryScreen.CreateAccount>(api)
        assertEquals(RegistrationVia.SETUP_LINK, form.via)
        assertTrue("if (screen.via == io.silencelen.andvari.core.app.RegistrationVia.SETUP_LINK) Say(Placeholder.CREATE_AS_OPERATOR" in src("AccountEntryScreens.kt"))
        m.run({ entry.createAccount(form, NewAccountInput("operator@setup.example", "Operator", pw, false)) })
        val setup = on<EntryScreen.ServerSetup>(api)
        assertEquals(ServerSetupStep.FINISHED, setup.step)
        assertNotNull(setup.details, "what Instance details shows")
        // The kit is held behind the setup screen until the person goes on.
        m.act { entry.finishServerSetup(setup) }
        on<EntryScreen.Kit>(api)
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun aSetupNotUploadedHoldsTheKitAndItsRetryTakesThePasswordInAStepOfItsOwn() {
        val (api, m) = at(FakeScene.SERVER_SETUP_NOT_UPLOADED)
        val setup = on<EntryScreen.ServerSetup>(api)
        assertEquals(ServerSetupStep.NOT_UPLOADED, setup.step)
        var answered: ServerResult? = null
        m.runSaying({ entry.retryServerSetup(setup, "not the password") }, ::setupRetryWords) { answered = it }
        assertEquals(ServerResult.WRONG_PASSWORD, answered)
        assertEquals(Placeholder.OP_WRONG_PASSWORD, assertIs<UiText.Ph>(assertNotNull(m.saidOn(api.snapshot)).text).placeholder)
        assertEquals(ServerSetupStep.NOT_UPLOADED, on<EntryScreen.ServerSetup>(api).step, "nothing uploaded, no kit")
        m.runSaying({ entry.retryServerSetup(on(api), pw) }, ::setupRetryWords) { answered = it }
        assertEquals(ServerResult.DONE, answered)
        assertEquals(ServerSetupStep.FINISHED, on<EntryScreen.ServerSetup>(api).step)
        // The screen: the retry opens its own step (a dialog), whose field is under nothing that can move.
        val screens = src("ServerSetupScreens.kt")
        assertTrue("Main(UiText.ph(Placeholder.SETUP_RETRY), enabled = !s.busy, busy = s.busy) { retrying = true }" in screens)
        assertTrue("if (r != ServerResult.WRONG_PASSWORD) closed()" in screens)
        assertTrue("is EntryScreen.ServerSetup -> ServerSetupScreen(model, s, screen)" in src("EntryScreens.kt"))
    }

    @Test
    fun finishIsOfferedInTheVaultWhileTheServerHasNoCardAndTakesThePasswordInItsOwnStep() {
        val (api, m) = at(FakeScene.OPERATOR_SETUP_UNFINISHED)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        val prompt = assertNotNull(api.snapshot.account?.prompts?.filterIsInstance<AccountPrompt.FinishServerSetup>()?.firstOrNull(), "Finish is offered")
        assertEquals(CopyKey.FINISH_SERVER_SETUP, prompt.label)
        var r: OperatorResult? = null
        assertNotNull(m.operator.finishServerSetup("not the password") { r = it })
        assertEquals(OperatorResult.WRONG_PASSWORD, r)
        assertEquals(Placeholder.OP_WRONG_PASSWORD, assertIs<UiText.Ph>(assertNotNull(m.saidOn(api.snapshot)).text).placeholder)
        assertNotNull(m.operator.finishServerSetup(pw) { r = it })
        assertEquals(OperatorResult.DONE, r)
        m.onSnapshot(api.snapshot)
        assertTrue(api.snapshot.account?.prompts.orEmpty().none { it is AccountPrompt.FinishServerSetup }, "once the card is pinned, Finish goes")
        assertTrue("is AccountPrompt.FinishServerSetup -> FinishServerSetupPrompt(model, s, p)" in src("PeopleScreens.kt"))
        assertTrue("model.operator.finishServerSetup(pw)" in src("ServerSetupScreens.kt"))
        // Once it is gone, nothing more is sent.
        assertNull(m.operator.finishServerSetup(pw) {})
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun theConsoleSaysRowsItWillNotShowACardStoredNotShownAndARefusalOfThisComputersOwn() {
        // Rows the server sent that this computer will not show: the shared code's own line, above the lists.
        val header = src("OperatorScreens.kt").substringAfter("private fun ConsoleHeader(").substringBefore("\n}\n")
        assertTrue("c.serverSentBadRowsLine?.let { Say(keyLine(it)" in header)
        val badRows = keyLine(CopyKey.OPERATOR_SERVER_SENT_BAD_ROWS)
        assertEquals(UiText.of(CopyKey.OPERATOR_SERVER_SENT_BAD_ROWS).shown(), badRows.shown(), "the shared code's line")
        assertEquals(CopyKey.OPERATOR_SERVER_SENT_BAD_ROWS.awaitingOwner, badRows.isPlaceholder, "said as awaiting exactly while it awaits its words")
        // A card the server stored and does not show: said as that, never as done, and no other card change offered.
        assertFalse(OperatorResult.CARD_STORED_NOT_SHOWN.done)
        assertNotNull(operatorWords(OperatorResult.CARD_STORED_NOT_SHOWN, 0), "said, never silent as a DONE is")
        assertFalse(cardChangeOffered(storedNotShown = true))
        assertTrue(cardChangeOffered(storedNotShown = false))
        val card = src("OperatorScreens.kt").substringAfter("private fun CardSection(").substringBefore("\n}\n")
        assertTrue(card.indexOf("if (!cardChangeOffered(c.cardStoredNotShown))") < card.indexOf("Placeholder.OP_CARD_CHANGE"), "before any card change is offered")
        // A change this computer did not send: its own sentence, never "the server refused".
        val here = operatorWords(OperatorResult.CARD_REFUSED_HERE, 0)
        assertFalse((here as? UiText.Ph)?.placeholder == Placeholder.OP_CARD_REFUSED_EITHER, "not the line for a refusal that may be the server's")
        assertNotNull(here)
    }

    @Test
    fun thePinnedRecoveryKeyAndTheServersIdAreShownFromThePin() {
        val values = pinnedCardValues("ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12", "inst-0123", public = false)
        assertEquals(listOf(Placeholder.OP_STEP_INSTANCE_ID, Placeholder.OP_STEP_RECOVERY_FP), values.map { (it.label as UiText.Ph).placeholder })
        assertEquals("inst-0123", values[0].value.shown())
        assertEquals("ab12 cd34 ef56", values[1].value.shown().take(14), "grouped by four, as the operator key is")
        // A public server names no recovery key: only its id.
        assertEquals(1, pinnedCardValues(null, "inst-0123", public = true).size)
        // What the pin does not hold is said, never left out or guessed.
        val none = pinnedCardValues(null, null, public = false)
        assertEquals(listOf(Placeholder.OP_PIN_HOLDS_NONE, Placeholder.OP_CARD_NAMES_NO_RECOVERY_KEY), none.map { (it.value as UiText.Ph).placeholder })
        // The words that stood in for them are gone.
        assertTrue(Placeholder.entries.none { it.name == "OP_INSTANCE_ID_NOT_GIVEN" || it.name == "OP_CARD_RECOVERY_NOT_GIVEN" })
    }

    @Test
    fun theFirstScreenSaysADeletionWhoseOutcomeIsUnknownAndTheDesktopsOwnFlagIsGone() {
        val (api, m) = at(FakeScene.LOCKED)
        m.run({ unlock(assertNotNull(snapshot.locked), pw) })
        m.onSnapshot(api.snapshot)
        m.run({ settings.openDeletion() })
        m.onSnapshot(api.snapshot)
        val screen = assertNotNull(api.snapshot.account?.deletion)
        api.script.deletionAnswerLost = true
        api.script.deletionHappenedAnyway = true
        m.deleteAccount(screen, FakeScenes.EMAIL, pw, null)
        m.checkDeletion(assertNotNull(api.snapshot.account?.deletion))
        m.onSnapshot(api.snapshot)
        assertTrue(assertNotNull(api.snapshot.locked).deletionOutcomeUnknown)
        m.signInAgain()
        m.onSnapshot(api.snapshot)
        val first = on<EntryScreen.FirstRun>(api)
        assertNotNull(first.deletionOutcomeUnknown, "core's notice on the first screen")
        m.act { entry.dismissNotice(first) }
        assertNull(on<EntryScreen.FirstRun>(api).deletionOutcomeUnknown, "dismissed")
        assertTrue(TrustModel::class.java.methods.none { it.name == "getDeletionCantTell" }, "the desktop's own flag is gone")
    }

    @Test
    fun moveEverythingSaysBeforeTheStartThatAFreshVaultIsMade() {
        val vault = src("VaultScreens.kt")
        assertTrue("screen.startsFresh?.let { lines += keyLine(it) }" in vault.substringAfter("internal fun moveBeforeLines(").substringBefore("\n}\n"))
        // A fresh vault takes a name, even after a stop.
        assertTrue("val carriesOn = screen.stopped != null && screen.startsFresh == null" in vault)
    }

    @Test
    fun theDesktopHasNoNetworkHookSoTheSharedCodeIsNotToldOfANetworkBack() {
        // The JVM gives no notice of a network change, and the desktop has no hook of its own: nothing calls it.
        val all = File("src/main/kotlin").walkTopDown().filter { it.name.endsWith(".kt") }.joinToString("\n") { it.readText() }
        assertFalse("networkReturned()" in all)
    }
}
