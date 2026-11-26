package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.ComparisonResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * A person who answers "a contact's key changed" with Compare codes gets the comparison (design §6.9, §6.11): it opens
 * as a screen of its own over whichever page the prompt stood on (the prompt stands on every page, and the comparison
 * used to show only inside Sharing's People card, below the vaults, and on the vault's home page or in Settings not at
 * all). Each answer does what the design says: a wrong code is no verdict and replaces nothing, the other person's code
 * replaces the key, and leaving decides nothing.
 */
class ComparisonOpensTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    /** Ada made a link; Dana, a contact already, answers it under another key. */
    private fun danaAnswersUnderANewKey(): Triple<FakeAppApi, TrustModel, String> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        val dana = assertNotNull(api.script.unnamedDeviceAddsContact("Dana"))
        m.run({ links.createConnectLink(emptyList(), 60) })
        val link = assertNotNull(assertNotNull(api.snapshot.account).links).links.single()
        assertTrue(api.script.contactAnswersUnderNewKey(link, dana))
        m.onSnapshot(api.snapshot)
        return Triple(api, m, dana.userId)
    }

    private fun keyPrompt(api: FakeAppApi): AccountPrompt.KeyChanged? =
        assertNotNull(api.snapshot.account).prompts.filterIsInstance<AccountPrompt.KeyChanged>().singleOrNull()

    private fun comparing(api: FakeAppApi): CompareScreen? = assertNotNull(api.snapshot.account).comparing

    @Test
    fun theComparisonIsAScreenOfItsOwnOverEveryPage() {
        val shell = src("AccountScreens.kt").substringAfter("internal fun AccountShell(").substringBefore("\n}\n")
        val opens = shell.indexOf("account.comparing?.let { return ComparePage(model, s, it) }")
        assertTrue(opens > 0, "the shell opens the comparison as its own screen")
        assertTrue(opens > shell.indexOf("var page by rememberSaveable"), "after the page is remembered, so Back returns to it")
        assertTrue(opens < shell.indexOf("when (page)"), "before any page is drawn: the vault's home, Sharing and Settings alike")
        // Nowhere else: People no longer draws it inside its card.
        val people = src("PeopleScreens.kt")
        assertFalse("CompareView(model, s, it)" in people.substringAfter("internal fun PeopleSection(").substringBefore("\n}\n"))
        val page = people.substringAfter("internal fun ComparePage(").substringBefore("\n}\n")
        assertTrue("PageScaffold(UiText.of(CopyKey.COMPARE_CODES), onBack = { model.act { contacts.closeCompare() } })" in page)
        assertTrue("ActiveBackHandler(model, enabled = !s.busy) { model.act { contacts.closeCompare() } }" in page)
        assertTrue("SaidHere(model, s)" in page && "CompareView(model, s, c)" in page, "what an entry answered is said on the page")
    }

    @Test
    fun fromThePromptToTheComparisonAndBackThenTheMatchReplacesTheKey() {
        val (api, m, userId) = danaAnswersUnderANewKey()
        val prompt = assertNotNull(keyPrompt(api))
        assertNull(comparing(api))

        // Compare codes: the comparison with this device's own six digits, saying a match replaces the key.
        m.run({ contacts.openCompareForNewKey(prompt) })
        var ready = assertIs<CompareScreen.Ready>(comparing(api))
        assertEquals("Dana", ready.label)
        assertTrue(ready.replacesKey)
        assertEquals(6, ready.code.length)

        // A wrong code is no verdict: it is said, the comparison stays, and the key is not replaced.
        val theirs = assertNotNull(api.script.codeTheyReadOut(userId))
        val wrong = (0..999_999).asSequence().map { it.toString().padStart(6, '0') }.first { it != ready.code && it != theirs }
        m.runSaying({ contacts.submitComparison(ready, wrong) }, { r -> comparisonWords(m, ready, wrong, r) })
        assertEquals(CopyKey.CODES_DO_NOT_MATCH.english, m.saidOn(api.snapshot)?.text?.shown())
        assertSame(ready, comparing(api), "the same comparison, to type again")
        assertSame(prompt, keyPrompt(api))

        // Back: the comparison closes, nothing was decided, and the prompt is where it was.
        m.act { contacts.closeCompare() }
        assertNull(comparing(api))
        assertSame(prompt, keyPrompt(api))

        // Again, with the code Dana reads out: the key is replaced, the prompt is gone, and the screen says the codes match.
        m.run({ contacts.openCompareForNewKey(prompt) })
        ready = assertIs(comparing(api))
        m.runSaying({ contacts.submitComparison(ready, theirs) }, { r -> comparisonWords(m, ready, theirs, r) })
        assertIs<CompareScreen.Matched>(comparing(api), "said: ${m.said.value?.text?.shown()}")
        assertNull(m.saidOn(api.snapshot), "a match says nothing above the screen: the screen says it")
        assertNull(keyPrompt(api), "the new key is the one pinned now")
        m.act { contacts.closeCompare() }
        assertNull(comparing(api))
    }

    @Test
    fun ownCodeTypedBackReachesTheSharedCodeAndItsMismatchSaysSo() {
        val (api, m, _) = danaAnswersUnderANewKey()
        m.run({ contacts.openCompareForNewKey(assertNotNull(keyPrompt(api))) })
        val ready = assertIs<CompareScreen.Ready>(comparing(api))
        // The screen refuses nothing itself: for one link in a million both codes are equal, and then this is the right entry.
        m.runSaying({ contacts.submitComparison(ready, ready.code) }, { r -> comparisonWords(m, ready, ready.code, r) })
        val said = assertIs<UiText.Ph>(m.saidOn(api.snapshot)?.text)
        assertEquals(Placeholder.COMPARE_OWN_CODE_REFUSED, said.placeholder)
        assertSame(ready, comparing(api))
        // Any other answer is worded as everywhere else: the design's sentence for a mismatch, nothing for a match.
        assertEquals(CopyKey.CODES_DO_NOT_MATCH.english, comparisonWords(m, ready, "000000".takeIf { it != ready.code } ?: "000001", ComparisonResult.MISMATCH)?.shown())
        assertNull(comparisonWords(m, ready, ready.code, ComparisonResult.DONE))
        assertFalse("model.say(UiText.ph(Placeholder.COMPARE_OWN_CODE_REFUSED))" in src("PeopleScreens.kt"), "no refusal before the shared code")
    }

    @Test
    fun aMatchSaysTheCodesMatchAndAMatchNotSavedSaysItsOwnSentence() {
        // The approved line for a match is not the one for a match the account could not record.
        assertNotEquals(Approved.COMPARE_MATCHED_NOT_SAVED, Placeholder.COMPARE_MATCHED.words)
        assertEquals(Approved.COMPARE_MATCHED_NOT_SAVED, UiText.forResult(ComparisonResult.NOT_SAVED, 0)?.shown())

        val (api, m, userId) = danaAnswersUnderANewKey()
        m.run({ contacts.openCompareForNewKey(assertNotNull(keyPrompt(api))) })
        val ready = assertIs<CompareScreen.Ready>(comparing(api))
        val theirs = assertNotNull(api.script.codeTheyReadOut(userId))
        api.script.comparisonNotSaved = true
        m.runSaying({ contacts.submitComparison(ready, theirs) }, { r -> comparisonWords(m, ready, theirs, r) })
        assertEquals(Approved.COMPARE_MATCHED_NOT_SAVED, m.saidOn(api.snapshot)?.text?.shown())
        assertSame(ready, comparing(api), "typing the same digits again retries")
        assertNotNull(keyPrompt(api), "nothing is replaced until the account has it")
        m.runSaying({ contacts.submitComparison(ready, theirs) }, { r -> comparisonWords(m, ready, theirs, r) })
        assertIs<CompareScreen.Matched>(comparing(api))
        assertNull(keyPrompt(api))
    }
}
