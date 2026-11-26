package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.WhoCanRecover
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Settings › Recovery is bound to the real engine, so
 * every state the screen can show is walked against the API's states: the opening's UNREACHABLE, the three offers
 * (the choice, turning off, nothing), the warning with and without the takeover lines, live requests, and the two
 * prompts that now really appear (`KeepOperatorRecovery`, `RecoveryKeyChanged`) with each of their answers.
 */
class RecoverySettingsStatesTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        if (api.snapshot.phase == AppPhase.LOCKED) m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun FakeAppApi.account() = assertNotNull(snapshot.account)

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun anOpeningThatGetsNoAnswerSaysSoAndKeepsTheButton() {
        val (api, m) = at(FakeScene.VAULTS)
        api.script.failNext(Trouble.UNREACHABLE)
        m.run({ recovery.openRecovery() })
        val said = assertNotNull(m.saidOn(api.snapshot), "the answer is said above the page")
        assertEquals(PlainResult.UNREACHABLE, said.result)
        assertNull(api.account().recovery, "no screen: the button stays to try again")
        val section = src("RecoverySettingsScreens.kt").substringAfter("internal fun RecoverySection(").substringBefore("\n}\n")
        assertTrue(section.contains("if (screen == null) {") && section.contains("model.run({ recovery.openRecovery() })"))
        // The page that holds Settings says what an intent answered (SaidHere), above the sections.
        val page = src("AccountScreens.kt")
        assertTrue(page.substringAfter("private fun AccountLines(").substringBefore("\n}\n").contains("SaidHere(model, s)"))
        val settings = page.substringAfter("SignedInPage.SETTINGS -> PageScaffold(").substringBefore("\n        }\n")
        assertTrue(settings.indexOf("header()") in 0 until settings.indexOf("AccountSettingsPage(model, s, account)"))
        // Once the server answers, the screen opens.
        m.run({ recovery.openRecovery() })
        assertNotNull(api.account().recovery)
    }

    @Test
    fun thePublicInstanceOffersNothingButTheKit() {
        val (api, m) = at(FakeScene.VAULTS)
        m.run({ recovery.openRecovery() })
        val screen = assertNotNull(api.account().recovery)
        assertNull(screen.question, "no choice on the public instance")
        assertEquals(WhoCanRecover.ONLY_ME, screen.whoCanRecover)
        assertEquals(RecoveryOffer.NOTHING, recoveryOffer(screen))
        assertEquals(CopyKey.RECOVERY_ONLY_ME.english, (whoCanRecoverLine(screen) as UiText.Plain).text)
        assertTrue(takeoverLines(screen.question?.takeoverTitle).isEmpty())
    }

    @Test
    fun operatorRecoveryOnOffersTurnOffAndLiveRequestsOfferCancel() {
        val (api, m) = at(FakeScene.RECOVERY)
        var screen = assertNotNull(api.account().recovery)
        assertEquals(WhoCanRecover.ME_OR_OPERATOR, screen.whoCanRecover)
        assertEquals(RecoveryOffer.TURN_OFF, recoveryOffer(screen))
        assertTrue(screen.requests.isEmpty())
        assertNotNull(api.script.someoneAsksOperator(AppPlatform.ANDROID))
        screen = assertNotNull(api.account().recovery)
        val request = screen.requests.single()
        assertEquals(Placeholder.RECOVERY_REQUEST_ROW, assertIs<UiText.Ph>(requestLine(request)).placeholder)
        m.run({ recovery.cancelRecoveryRequest(request) })
        assertTrue(assertNotNull(api.account().recovery).requests.isEmpty(), "said: ${m.said.value?.text?.shown()}")
        // Turned off with the password: the choice comes back.
        m.run({ recovery.turnOffOperatorRecovery(assertNotNull(api.account().recovery), FakeScenes.PASSWORD) })
        screen = assertNotNull(api.account().recovery)
        assertEquals(WhoCanRecover.ONLY_ME, screen.whoCanRecover)
        assertEquals(RecoveryOffer.CHOICE, recoveryOffer(screen))
        m.act { recovery.reviewOperatorRecovery(screen) }
        assertEquals(RecoveryOffer.WARNING, recoveryOffer(assertNotNull(api.account().recovery)))
        m.act { recovery.keepRecoveryPrivate(assertNotNull(assertNotNull(api.account().recovery).warning)) }
        assertEquals(RecoveryOffer.CHOICE, recoveryOffer(assertNotNull(api.account().recovery)), "keep it private changes nothing")
    }

    @Test
    fun anUnsignedKeyChangeShowsTheTakeoverLinesWithTheChoiceAndOnTheWarning() {
        val (api, m) = at(FakeScene.RECOVERY_WARNING_IN_SETTINGS)
        val warning = assertNotNull(assertNotNull(api.account().recovery).warning)
        val lines = takeoverLines(warning.takeoverTitle)
        assertEquals(2, lines.size, "the title and the body")
        assertEquals(CopyKey.RECOVERY_KEY_CHANGED_BODY.english, (lines[1] as UiText.Plain).text)
        m.act { recovery.keepRecoveryPrivate(warning) }
        val screen = assertNotNull(api.account().recovery)
        assertEquals(RecoveryOffer.CHOICE, recoveryOffer(screen))
        assertEquals(2, takeoverLines(assertNotNull(screen.question).takeoverTitle).size, "with the choice too (FS-R2)")
        val section = src("RecoverySettingsScreens.kt")
        assertTrue(section.contains("for (line in takeoverLines(screen.question?.takeoverTitle))"))
        assertTrue(section.contains("for (line in takeoverLines(warning.takeoverTitle))"))
    }

    @Test
    fun theRecoveryKeyChangedPromptTurnsOffKeepsOrWaits() {
        // Later: nothing changes.
        run {
            val (api, m) = at(FakeScene.PROMPT_RECOVERY_KEY_CHANGED)
            val p = assertNotNull(api.account().prompts.filterIsInstance<AccountPrompt.RecoveryKeyChanged>().firstOrNull())
            assertEquals(UiText.of(p.title).shown(), promptLine(p).shown())
            m.act { recovery.recoveryKeyChangedLater(p) }
            assertTrue(api.account().prompts.none { it is AccountPrompt.RecoveryKeyChanged })
        }
        // Turn off, the default; a wrong password first.
        run {
            val (api, m) = at(FakeScene.PROMPT_RECOVERY_KEY_CHANGED)
            val p = assertNotNull(api.account().prompts.filterIsInstance<AccountPrompt.RecoveryKeyChanged>().firstOrNull())
            m.run({ recovery.answerRecoveryKeyChanged(p, false, "wrong") })
            assertEquals(RecoveryChangeResult.WRONG_PASSWORD, m.saidOn(api.snapshot)?.result)
            m.run({ recovery.answerRecoveryKeyChanged(p, false, FakeScenes.PASSWORD) })
            assertTrue(api.account().prompts.none { it is AccountPrompt.RecoveryKeyChanged }, "said: ${m.said.value?.text?.shown()}")
            m.run({ recovery.openRecovery() })
            assertEquals(WhoCanRecover.ONLY_ME, assertNotNull(api.account().recovery).whoCanRecover)
        }
        // Keep, with the new key.
        run {
            val (api, m) = at(FakeScene.PROMPT_RECOVERY_KEY_CHANGED)
            val p = assertNotNull(api.account().prompts.filterIsInstance<AccountPrompt.RecoveryKeyChanged>().firstOrNull())
            m.run({ recovery.answerRecoveryKeyChanged(p, true, FakeScenes.PASSWORD) })
            assertTrue(api.account().prompts.none { it is AccountPrompt.RecoveryKeyChanged }, "said: ${m.said.value?.text?.shown()}")
            m.run({ recovery.openRecovery() })
            assertEquals(WhoCanRecover.ME_OR_OPERATOR, assertNotNull(api.account().recovery).whoCanRecover)
        }
        val view = src("PeopleScreens.kt").substringAfter("is AccountPrompt.RecoveryKeyChanged -> {").substringBefore("is AccountPrompt.KeepOperatorRecovery -> {")
        assertTrue(view.contains("Say(p.body)"))
        assertTrue(view.contains("recovery.answerRecoveryKeyChanged(p, false, pw)") && view.contains("recovery.answerRecoveryKeyChanged(p, true, pw)"))
        assertTrue(view.contains("recovery.recoveryKeyChangedLater(p)"))
    }

    @Test
    fun theKeepOperatorRecoveryPromptKeepsOrTurnsOffWithThePassword() {
        run {
            val (api, m) = at(FakeScene.PROMPT_KEEP_OPERATOR_RECOVERY)
            val p = assertNotNull(api.account().prompts.filterIsInstance<AccountPrompt.KeepOperatorRecovery>().firstOrNull())
            assertEquals(UiText.of(p.question).shown(), promptLine(p).shown())
            m.run({ recovery.answerKeepOperatorRecovery(p, true, "wrong") })
            assertEquals(RecoveryChangeResult.WRONG_PASSWORD, m.saidOn(api.snapshot)?.result)
            m.run({ recovery.answerKeepOperatorRecovery(p, true, FakeScenes.PASSWORD) })
            assertTrue(api.account().prompts.none { it is AccountPrompt.KeepOperatorRecovery }, "said: ${m.said.value?.text?.shown()}")
            m.run({ recovery.openRecovery() })
            assertEquals(WhoCanRecover.ME_OR_OPERATOR, assertNotNull(api.account().recovery).whoCanRecover)
        }
        run {
            val (api, m) = at(FakeScene.PROMPT_KEEP_OPERATOR_RECOVERY)
            val p = assertNotNull(api.account().prompts.filterIsInstance<AccountPrompt.KeepOperatorRecovery>().firstOrNull())
            m.run({ recovery.answerKeepOperatorRecovery(p, false, FakeScenes.PASSWORD) })
            assertTrue(api.account().prompts.none { it is AccountPrompt.KeepOperatorRecovery })
            m.run({ recovery.openRecovery() })
            assertEquals(WhoCanRecover.ONLY_ME, assertNotNull(api.account().recovery).whoCanRecover)
        }
        val view = src("PeopleScreens.kt").substringAfter("is AccountPrompt.KeepOperatorRecovery -> {").substringBefore("is AccountPrompt.ConnectionNotMade -> {")
        assertTrue(view.contains("recovery.answerKeepOperatorRecovery(p, true, pw)") && view.contains("recovery.answerKeepOperatorRecovery(p, false, pw)"))
        assertTrue(view.indexOf("CopyKey.KEEP_OPERATOR_NOT_NOW") < view.indexOf("CopyKey.KEEP_OPERATOR_KEEP"), "Not now first, as the default")
    }
}
