package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Walks over the shared code's stand-in, driven through this app's model as the screens drive it:
 *
 * - a move's note (a half-made vault of an earlier try kept as a vault of its own): its lines in order with the member
 *   right after the line that names them, kept across a lock and a restart of the app (the stand-in's restart is trusted
 *   for a move's notes, side by side with the engine's), gone at its dismissal and not back;
 * - a device link whose password step is answered with a refused proof (a former password that still opens this phone's
 *   copy): the shared code's own line, never "wrong password", and the link stays open on its password step.
 */
class StandInWalksOwedTest {
    private val pw = FakeScenes.PASSWORD

    private fun model(api: AppApi): TrustModel =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }).also {
            it.start()
            it.onSnapshot(api.snapshot)
        }

    private fun <R : IntentResult> TrustModel.done(intent: suspend AppApi.() -> R): R {
        var result: R? = null
        runBlocking { run(intent) { result = it }.join() }
        onSnapshot(api.snapshot)
        return assertNotNull(result, "the intent ended without a result: ${wentWrong.value?.text}")
    }

    private fun TrustModel.unlockNow() = assertEquals(VaultUnlockResult.DONE, done { unlock(assertNotNull(snapshot.locked), pw) })

    private fun shown(lines: List<UiText>) = lines.map { it.shown() }

    @Test
    fun aMovesNoteIsDrawnWithItsMemberKeptAcrossALockAndARestartAndGoesAtItsDismissal() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = model(fake)
        assertEquals(VaultActionResult.DONE, m.done { vaults.openMembers(snapshot.account!!.vaults.first { it.name == "Family" }) })
        val member = fake.snapshot.account!!.members!!.members.first { it.who is PersonName.Contact }
        assertEquals(VaultActionResult.DONE, m.done { vaults.openMoveEverythingRemoving(member) })
        fake.script.nextMoveKeepsHalfMade = 1
        assertEquals(VaultActionResult.DONE, m.done { vaults.moveEverything(assertNotNull(snapshot.account!!.moving), "Family 2") })

        val note = fake.snapshot.account!!.moveNotes.single()
        val lines = shown(moveNoteLines(note))
        val holds = note.lines.indexOfFirst { it.key == CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS }
        assertTrue(holds >= 0, "the note names the member who still holds the kept vault: ${note.lines.map { it.key }}")
        assertEquals(note.lines.size + 1, lines.size, "each line as handed, and the member once")
        assertEquals(UiText.of(note.lines[holds]).shown(), lines[holds])
        assertEquals(personLine(assertNotNull(note.member)).shown(), lines[holds + 1], "the member right after the line that names them")

        // Kept across a lock, and across a restart of the app.
        m.act { lock() }
        m.onSnapshot(fake.snapshot)
        m.unlockNow()
        assertEquals(lines, shown(moveNoteLines(fake.snapshot.account!!.moveNotes.single())), "kept across a lock")
        fake.script.restart()
        val again = model(fake)
        assertEquals(AppPhase.LOCKED, fake.snapshot.phase)
        again.unlockNow()
        val kept = fake.snapshot.account!!.moveNotes.single()
        assertEquals(lines, shown(moveNoteLines(kept)), "kept across a restart")

        // The dismissal, the only thing that takes it away; not back after a lock.
        again.dismissMoveNote(kept)
        again.onSnapshot(fake.snapshot)
        assertEquals(emptyList(), fake.snapshot.account!!.moveNotes)
        again.act { lock() }
        again.onSnapshot(fake.snapshot)
        again.unlockNow()
        assertEquals(emptyList(), fake.snapshot.account!!.moveNotes, "not back")
    }

    /**
     * A move that meets a frozen half-made vault of an earlier try: the note's line that the member the move removes still
     * holds that vault is followed by that member, as beside the line for a half-made vault that was kept.
     */
    @Test
    fun aFrozenHalfMadeVaultsNoteNamesTheMemberWhoStillHoldsIt() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = model(fake)
        assertEquals(VaultActionResult.DONE, m.done { vaults.openMembers(snapshot.account!!.vaults.first { it.name == "Family" }) })
        val member = fake.snapshot.account!!.members!!.members.first { it.who is PersonName.Contact }
        assertEquals(VaultActionResult.DONE, m.done { vaults.openMoveEverythingRemoving(member) })
        fake.script.nextMoveHalfMadeFrozen = true
        assertEquals(VaultActionResult.DONE, m.done { vaults.moveEverything(assertNotNull(snapshot.account!!.moving), "Family 2") })

        val note = fake.snapshot.account!!.moveNotes.single()
        val holds = note.lines.indexOfFirst { it.key == CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS }
        assertTrue(holds >= 0, "the note says the member still holds the frozen vault: ${note.lines.map { it.key }}")
        val held = assertNotNull(note.member, "the note names the member")
        val lines = moveNoteLines(note)
        WalkPrint.draws("the frozen half-made vault's note", lines)
        assertEquals(note.lines.size + 1, lines.size, "each line as handed, and the member once")
        assertEquals(UiText.of(note.lines[holds]).shown(), lines[holds].shown())
        assertEquals(personLine(held).shown(), lines[holds + 1].shown(), "the member right after the line that names them")
    }

    /**
     * A device link that ends where this phone cannot tell an account made again from a substitution (the stand-in plays
     * it at the approval): the shared code's line, which points to the sign-in with the master password; the ended screen
     * offers that sign-in beside another link, and its tap reaches it; no offer to forget anything anywhere on the way.
     */
    @Test
    fun aDeviceLinkThePhoneCannotTellOffersThePasswordSignInItsLinePointsTo() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LINK_DEVICE_CODE)
        val m = model(fake)
        fake.script.earlierAccountKnown = true
        fake.script.linkIdentityCannotTell = true
        fake.script.otherDeviceApproves()
        m.onSnapshot(fake.snapshot)
        val ended = assertIs<EntryScreen.LinkDeviceEnded>(fake.snapshot.entry)
        assertEquals(io.silencelen.andvari.core.app.LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL, ended.outcome)
        val line = OutcomeWords.linkDeviceEnd(ended.outcome, m.api.retryAfterSeconds())
        WalkPrint.draws("the link's cannot-tell end, over the stand-in", listOf(line, UiText.of(CopyKey.SIGN_IN_LINK_DEVICE), UiText.of(CopyKey.SIGN_IN_PASSWORD)))
        assertEquals(UiText.of(CopyKey.DEVICE_LINK_IDENTITY_CANNOT_TELL).shown(), line.shown(), "the shared code's line, as handed")
        assertTrue(linkEndOffersPasswordSignIn(ended.outcome), "the password sign-in is offered beside another link")
        assertEquals(null, fake.snapshot.earlierAccount, "no offer to forget")
        assertEquals(null, wayOutFor(ended.outcome))

        m.openPasswordSignInAfterLink(ended)
        m.onSnapshot(fake.snapshot)
        assertIs<EntryScreen.SignInServer>(fake.snapshot.entry, "the password sign-in")
        assertEquals(null, fake.snapshot.earlierAccount)
        assertEquals(null, m.saidOn(fake.snapshot))
        // Another link stays the other way, and is not this end's only offer.
        assertTrue(!linkEndOffersPasswordSignIn(io.silencelen.andvari.core.app.LinkDeviceEnd.TOO_MANY), "only where the line points to it")
    }

    @Test
    fun aRefusedProofAtADeviceLinkIsSaidAsItselfAndTheLinkStaysOpen() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = model(fake)
        // A password change this phone's copy could not follow: the previous password still opens the copy here.
        fake.script.deviceCannotFollowPassword = true
        val next = "a brand new master password 7"
        assertEquals(PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE, m.done { settings.changeMasterPassword(pw, next) })
        // The server signs this phone out; "Sign in again" keeps the account here; a device link for the same account.
        fake.script.sessionEndedByServer()
        m.onSnapshot(fake.snapshot)
        m.act { signInAgain(assertNotNull(snapshot.locked)) }
        m.onSnapshot(fake.snapshot)
        runBlocking {
            fake.entry.openSignIn(assertIs<EntryScreen.FirstRun>(fake.snapshot.entry))
            fake.entry.openLinkDevice(assertIs<EntryScreen.SignInChoice>(fake.snapshot.entry))
            val account = fake.script.publicInstance.accounts.values.first { it.email == FakeScenes.EMAIL }
            fake.entry.submitDeviceLink(assertIs<EntryScreen.LinkDeviceEntry>(fake.snapshot.entry), fake.script.deviceLinkFrom(account, "MacBook"), PayloadSource.SCANNED)
        }
        fake.script.otherDeviceAnswers()
        fake.script.otherDeviceApproves()
        m.onSnapshot(fake.snapshot)
        val screen = assertIs<EntryScreen.LinkDevicePassword>(fake.snapshot.entry)
        WalkPrint.draws("e1 the password step", listOf(screen.prompt.title?.let { UiText.of(it) }, UiText.ph(Placeholder.PASSWORD_FIELD)))

        // The former password: a refused proof, said in the shared code's own words; never "wrong password".
        val r = m.done { entry.submitLinkPassword(screen, pw) }
        assertEquals(LinkPasswordResult.PROOF_REFUSED, r)
        val said = assertNotNull(UiText.forResult(r, 0)).shown()
        assertEquals(UiText.of(CopyKey.LINK_PROOF_REFUSED_TYPE_CURRENT).shown(), said)
        assertNotEquals(UiText.forResult(LinkPasswordResult.WRONG, 0)?.shown(), said)
        val here = assertNotNull(m.saidOn(fake.snapshot), "said where the person is, on the password step")
        assertEquals(r, here.result)
        assertEquals(said, here.text.shown(), "as the screen draws it")
        WalkPrint.draws("e2 the former password, refused", listOf(here.text, UiText.ph(Placeholder.PASSWORD_FIELD)))
        // Said as itself: no way out drawn under it in place of the password step, and no offer.
        assertEquals(null, wayOutFor(here.result))
        assertEquals(null, fake.snapshot.earlierAccount)
        // The link stays open, on its password step: the same screen object.
        assertTrue(screen === fake.snapshot.entry, "the password step stays")

        // e3. The current password links.
        val linked = m.done { entry.submitLinkPassword(assertIs(snapshot.entry), next) }
        WalkPrint.note("e3 the current password", "$linked ${fake.snapshot.phase}")
        assertEquals(LinkPasswordResult.DONE, linked)
        assertEquals(AppPhase.UNLOCKED, fake.snapshot.phase)
        assertEquals(null, m.saidOn(fake.snapshot))
    }
}
