package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.content.ContentCopy
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
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Under a server's policy that forbids a copy on devices (decided on 2026-11-17: try once to send what waits, then wipe,
 * and say afterwards how many could not be sent), over the shared code's fake, which plays the engine's run: while the
 * copy is being removed the screen says so where a stopped server's line would be, keeps Save offered, and a change made
 * then is refused with that line while what was typed stays; afterwards the notice says the shared code's lines in its
 * order, above every phase, for its own account only, until the person dismisses it. Nothing of it is worded or decided
 * here.
 */
class PolicyWipeOnPhoneTest {
    private fun main(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    private fun phone(): Pair<FakeAppApi, TrustModel> {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = TrustModel(fake, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(fake.snapshot)
        assertEquals(AppPhase.UNLOCKED, fake.snapshot.phase)
        return fake to m
    }

    private fun login(name: String) = LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false)

    /** The walk: the policy arrives, the copy is being removed, a change is refused, the notice, a lock, its dismissal. */
    @Test
    fun fromThePolicysArrivalToTheDismissedNotice() {
        val (fake, m) = phone()
        val c = assertNotNull(m.content.value)
        assertNull(c.states.value.removingLine)

        // The run begins: the content says the copy is being removed.
        assertNotNull(fake.fakeContent).removingForPolicy()
        val removing = c.states.value
        val line = assertNotNull(removing.removingLine)
        assertEquals(ContentCopy.REMOVING_LINE, line)
        // Drawn where a stopped server's line would be, and it is not that line.
        assertEquals(UiText.Plain(line).shown(), assertNotNull(syncLine(removing)).shown())
        assertNotEquals(UiText.ph(Placeholder.SYNC_STOPPED).shown(), syncLine(removing)!!.shown())
        // Save and the other writes stay offered (the floating Add button and Save stand on this).
        assertTrue(canSave(removing), "not a stopped server: Save stays")
        // No vault is offered for a new item meanwhile; the editor says the removal's line instead of hiding "New".
        assertEquals(emptyList(), c.vaultsForNewItems())
        // A change made at that moment is not made, and says so in the shared code's line for it (the editor keeps what
        // was typed and shows that answer).
        assertEquals(ActionResult.Failed(ContentCopy.COPY_BEING_REMOVED), runBlocking { c.saveLogin(null, login("Bank"), null) })
        assertTrue(c.states.value.items.none { it.name == "Bank" })
        // A change to a shared vault meanwhile says the same line, never a general failure.
        m.run({ vaults.createVault("Family") })
        m.onSnapshot(fake.snapshot)
        val said = assertNotNull(m.saidOn(fake.snapshot))
        assertEquals(VaultActionResult.REMOVING_COPY, said.result)
        assertEquals(UiText.of(CopyKey.SAVE_COPY_BEING_REMOVED).shown(), said.text.shown())

        // The run ends, the copy is gone: the notice, with the shared code's lines in its order.
        fake.fakeContent!!.removingForPolicy(false)
        assertNull(syncLine(c.states.value)?.takeIf { it.shown() == UiText.Plain(line).shown() }, "the removal's line goes with the removal")
        // Logins the phone caught are not part of the copy: they stay, and the notice does not count them.
        fake.script.policyCopyRemoved(notSent = 2, unsure = 1, unfinishedMoves = 1, serverName = "Home")
        m.onSnapshot(fake.snapshot)
        val notice = assertNotNull(fake.snapshot.policyWipe)
        assertEquals(
            listOf(CopyKey.POLICY_COPY_REMOVED_LOST, CopyKey.POLICY_COPY_REMOVED_UNSURE_ONE, CopyKey.POLICY_COPY_REMOVED_MOVE_UNFINISHED_ONE),
            notice.lines.map { it.key },
        )
        assertEquals(
            notice.lines.map { UiText.of(it).shown() },
            policyWipeLines(notice).map { it.shown() },
            "every line as the shared code hands it, in its order, the half-done moves last",
        )
        assertEquals(listOf("2", "Home", "1"), notice.lines[0].values)

        // Kept across a lock and an unlock: nothing but its dismissal takes it away.
        m.act { lock() }
        m.onSnapshot(fake.snapshot)
        assertSame(notice, fake.snapshot.policyWipe, "on the lock screen too")
        assertEquals(VaultUnlockResult.DONE, runBlocking { fake.unlock(assertNotNull(fake.snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(fake.snapshot)
        assertSame(notice, fake.snapshot.policyWipe, "after the unlock too")
        m.dismissPolicyWipe(notice)
        assertNull(fake.snapshot.policyWipe, "dismissed: not said again")
    }

    /** A known number is never hidden behind "cannot tell": the app draws the shared code's first line as it is. */
    @Test
    fun aKnownNumberIsNeverHidden() {
        val (fake, m) = phone()
        fake.script.policyCopyRemoved(notSent = 3, cannotTell = true, unopened = false)
        m.onSnapshot(fake.snapshot)
        val notice = assertNotNull(fake.snapshot.policyWipe)
        assertEquals(CopyKey.POLICY_COPY_REMOVED_AT_LEAST_LOST, notice.lines.first().key)
        assertEquals("3", notice.lines.first().values[0])
        assertEquals(notice.lines.map { UiText.of(it).shown() }, policyWipeLines(notice).map { it.shown() })
        // With nothing known lost and some sent with no answer: the line for those that may or may not have arrived.
        val (fake2, m2) = phone()
        fake2.script.policyCopyRemoved(notSent = 0, unsure = 4)
        m2.onSnapshot(fake2.snapshot)
        val unsure = assertNotNull(fake2.snapshot.policyWipe)
        assertEquals(listOf(CopyKey.POLICY_COPY_REMOVED_NONE_KNOWN_LOST, CopyKey.POLICY_COPY_REMOVED_UNSURE), unsure.lines.map { it.key })
        assertEquals(unsure.lines.map { UiText.of(it).shown() }, policyWipeLines(unsure).map { it.shown() })
    }

    /** Another account's notice is never drawn inside this one; where no session is kept, it is. */
    @Test
    fun theNoticeIsShownForItsOwnAccountOnly() {
        val (fake, m) = phone()
        fake.script.policyCopyRemoved(notSent = 4, userId = "someone-else")
        m.onSnapshot(fake.snapshot)
        assertNull(fake.snapshot.policyWipe, "another account's notice is not read inside this one")
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, runBlocking { fake.signOutConfirmed(assertNotNull(fake.signOutCheck())) })
        m.onSnapshot(fake.snapshot)
        assertEquals(4, assertNotNull(fake.snapshot.policyWipe, "no session kept: shown").notSent)
    }

    /**
     * Drawn above whatever screen is on show, in every phase, from the snapshot only: the app keeps no notice of its own
     * (so none is carried across accounts), and its one dismissal is the person's.
     */
    @Test
    fun theNoticeIsDrawnFromTheSnapshotAboveEveryPhaseAndOnlyThePersonDismissesIt() {
        val root = main("trust/TrustApp.kt").substringAfter("fun TrustApp(").substringBefore("\n}\n")
        val at = root.indexOf("s.policyWipe?.let { PolicyWipeNoticeView(model, it) }")
        assertTrue(at > 0 && at < root.indexOf("when (s.phase)"), "above the phase's screen, whichever it is")
        val view = main("trust/TrustApp.kt").substringAfter("internal fun PolicyWipeNoticeView(").substringBefore("\n}\n")
        assertTrue("policyWipeLines(notice)" in view && "model.dismissPolicyWipe(notice)" in view)
        val sources = File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        fun usersOf(token: String) = sources.filter { f -> f.readLines().any { token in it.substringBefore("//") } }.map { it.name }.toSet()
        assertEquals(setOf("TrustModel.kt"), usersOf("api.dismissPolicyWipe("), "one call, from the person's dismiss")
        assertEquals(setOf("TrustApp.kt"), usersOf("PolicyWipeNoticeView("))
        for (f in sources) {
            assertFalse(Regex("(val|var) \\w+\\s*[:=][^\\n]*PolicyWipeNotice\\b").containsMatchIn(f.readText()), "no notice kept: ${f.name}")
        }
    }

    /**
     * The editor while the copy is being removed: "New" stays and says the removal's line where no vault is offered; what
     * was typed is the editor's own, kept for the opening (not the content instance), so it stays on the screen when a
     * save is refused and when the shared code composes the vault again after the wipe; Save goes to the content on show.
     */
    @Test
    fun theEditorKeepsWhatWasTypedAndSaysTheRemovalsLineWhereNoVaultIsOffered() {
        val screens = main("trust/VaultItemsScreens.kt")
        val editor = screens.substringAfter("private fun ItemEditor(").substringBefore("\n}\n")
        assertTrue("if (itemId == null && choices.isEmpty()) state.removingLine?.let { Say(UiText.Plain(it)" in editor)
        assertTrue("remember(c, key, state.removingLine)" in editor, "the vaults offered are read again as the removal begins and ends")
        assertEquals(0, Regex("remember\\(c, key\\)").findAll(editor).count(), "nothing typed is keyed by the content instance")
        assertTrue(Regex("var name by remember\\(opening, key\\)").containsMatchIn(editor))
        // A refused save leaves the editor open with its answer; only Ok closes it.
        assertTrue("is ActionResult.Ok -> onDone()" in editor && "is ActionResult.Failed -> answer = r.message" in editor)
        val section = screens.substringAfter("internal fun VaultItemsSection(").substringBefore("\n}\n")
        assertTrue("var editing by remember(opening)" in section && "var open by remember(opening)" in section)
        assertTrue("floatingActionButton = { if (onList && canSave(state))" in section, "the Add button stands on canSave alone")
    }
}
