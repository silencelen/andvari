package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The states the shared code gained: the sign-up's
 * first step refusing for a kept account, the lock screen's "cannot tell yet" line, the people list's body when the
 * operator's part is unknown, and a registration a lock overtakes.
 */
class SharedCodeNewStatesTest {
    private val scope = CoroutineScope(Dispatchers.Unconfined)

    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, scope, BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private inline fun <reified S : EntryScreen> FakeAppApi.on(): S = assertIs<S>(snapshot.entry)

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun theSignUpsFirstStepRefusesForAKeptAccountWithTheCreateAccountRefusal() {
        val (api, m) = at(FakeScene.VAULTS)
        api.script.sessionEndedByServer()
        api.signInAgain(assertNotNull(api.snapshot.locked))
        val kept = assertNotNull(api.snapshot.keptSignedOut)
        assertEquals(ServerResult.DONE, runBlocking { api.entry.createAccountOnAndvari(api.on()) })

        m.run({ entry.startSignUp(api.on(), "new@example.com", true) })
        val said = assertNotNull(m.saidOn(api.snapshot), "said on the sign-up's email step")
        assertEquals(SignUpStartResult.ANOTHER_ACCOUNT_KEPT, said.result)
        val ph = assertIs<UiText.Ph>(said.text)
        assertEquals(Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST, ph.placeholder, "the same refusal as Create account")
        assertEquals(listOf(kept.email.orEmpty(), kept.instance.name, kept.instance.origin), ph.args)
        assertTrue(offersKeptSignOut(api.snapshot, said.result), "with the same sign-out offer under it")
        assertEquals(keptAccountWords(CreateAccountResult.ANOTHER_ACCOUNT_KEPT, kept)!!.shown(), keptAccountWords(SignUpStartResult.ANOTHER_ACCOUNT_KEPT, kept)!!.shown())
        assertIs<EntryScreen.SignUpEmail>(api.snapshot.entry, "the person stays on the email step")
    }

    @Test
    fun theLockScreenSaysTheSharedCodesCannotTellYetLine() {
        assertEquals(Placeholder.LOCK_DELETION_OUTCOME_UNKNOWN, assertIs<UiText.Ph>(lockDeletionLine(coreSaysUnknown = true, appCannotTell = false)).placeholder)
        assertEquals(Placeholder.LOCK_DELETION_OUTCOME_UNKNOWN, assertIs<UiText.Ph>(lockDeletionLine(coreSaysUnknown = true, appCannotTell = true)).placeholder)
        assertEquals(Placeholder.DELETION_CANNOT_TELL, assertIs<UiText.Ph>(lockDeletionLine(coreSaysUnknown = false, appCannotTell = true)).placeholder)
        assertNull(lockDeletionLine(coreSaysUnknown = false, appCannotTell = false))
        assertFalse(Placeholder.LOCK_DELETION_OUTCOME_UNKNOWN.gloss.contains("was deleted;"), "never says deleted")
        assertTrue(src("AccountScreens.kt").contains("lockDeletionLine(locked.deletionOutcomeUnknown, model.deletionCannotTell(s))?.let { Say(it,"))
        // The fake's lock screen has no unknown deletion: no line.
        val (api, m) = at(FakeScene.LOCKED)
        val locked = assertNotNull(api.snapshot.locked)
        assertFalse(locked.deletionOutcomeUnknown)
        assertNull(lockDeletionLine(locked.deletionOutcomeUnknown, m.deletionCannotTell(api.snapshot)))
    }

    @Test
    fun thePeopleListsBodyCanBeTheOperatorUnknownLine() {
        // Named by its key; whatever its words are, it says the operator may hold the key if operator recovery was chosen.
        val body = UiText.of(CopyKey.PEOPLE_BODY_OPERATOR_UNKNOWN)
        assertFalse(CopyKey.PEOPLE_BODY_OPERATOR_UNKNOWN.reserved, "the shared code has a line for it")
        assertTrue(body.shown().contains("or the operator, if you chose operator recovery"), body.shown())
        // Both places the list's body shows read it from the shared code's PeopleList.body, whichever key it is.
        val people = src("PeopleScreens.kt")
        assertEquals(2, Regex("""Say\(p\.body\)""").findAll(people).count())
        assertFalse(people.contains("CopyKey.PEOPLE_BODY"), "the screen never picks the body itself")
    }

    /**
     * Item 4: the shared code's new sentences reach the vault page through the channels it already shows, word for word:
     * what a lock cut short (the content's notice at the next unlock), the personal vault a server answer tried to take
     * away or re-key (a vault notice, as a warning), and a trash list that could not be read whole (openTrash's failure).
     */
    @Test
    fun theSharedCodesNewSentencesShowWhereTheContentPutsThem() {
        val items = src("VaultItemsScreens.kt")
        val notice = items.substringAfter("internal fun VaultNotice(").substringBefore("\n}\n")
        assertTrue(notice.contains("noticeLines(state)") && notice.contains("c.dismissNotice()"))
        assertTrue(items.substringAfter("internal fun noticeLines(").contains("return listOf(UiText.Plain(notice))"))
        assertTrue(items.contains("state.vaultNotices.forEach { n ->\n        Say(UiText.Plain(n.text), color = if (n.warning) MaterialTheme.colorScheme.error else Color.Unspecified)"))
        // The trash is opened from the vault's top bar (the current app's structure); what it answers is said above the page.
        assertTrue(src("VaultHome.kt").contains("trash = { scope.launchOvertakable { said(actionAnswer(c.openTrash())) } }"))
        assertTrue(items.contains("(barAnswer ?: transfer.answer)?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }"))
        // VaultNotice shows above every vault screen.
        assertTrue(Regex("""VaultNotice\(c, state\)""").containsMatchIn(items), "VaultNotice is called")
    }

    /**
     * A registration a lock overtakes: the engine answers STALE and keeps the new account LOCKED; the next
     * unlock goes to the recovery kit. The fake does not model the STALE registration itself, so the
     * walk is: the registration reaches its kit, a lock lands while the kit holds the account's keys, the app's rule
     * reads a STALE asked on the registration form as the lock it is, and the next unlock goes to a kit, never the vault.
     */
    @Test
    fun aRegistrationALockOvertakesLeavesTheAppLockedAndTheNextUnlockGoesToTheKit() {
        val (api, m) = at(FakeScene.CREATE_ACCOUNT)
        val form = api.on<EntryScreen.CreateAccount>()
        val asked = m.placeOf(api.snapshot)
        assertEquals(AppPhase.ENTRY, asked.phase)
        m.run({ entry.createAccount(form, NewAccountInput(FakeScenes.EMAIL, "Alice", FakeScenes.PASSWORD, true)) })
        assertIs<EntryScreen.Kit>(api.snapshot.entry, "the registration reached its kit")

        m.act { lock() }
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the new account is kept, locked")
        // The engine's answer to the overtaken registration: STALE, asked on the form, now at the lock screen.
        assertTrue(m.overtakenByLock(asked, CreateAccountResult.STALE, api.snapshot), "said as the lock, never as a failure")
        assertFalse(m.overtakenByLock(asked, CreateAccountResult.WEAK_PASSWORD, api.snapshot))

        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase, "the vault stays shut")
        val kit = assertIs<EntryScreen.Kit>(api.snapshot.entry, "the next unlock goes to the recovery kit")
        assertEquals(KitReason.NEVER_SAVED, kit.kit.reason)
    }
}
