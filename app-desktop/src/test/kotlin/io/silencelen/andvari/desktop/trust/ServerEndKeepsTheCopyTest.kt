package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * "Keep me signed in" and everything it deletes change only by the
 * person's own act (a completed sign-out, "Forget this server", a completed account deletion, unticking the switch).
 * No change of screen and no server's answer switches it off or deletes a file. Each path below ends with the kept
 * sign-in (and its key-store item), the vault's copy and what waits to be sent still on disk, and the switch on.
 */
class ServerEndKeepsTheCopyTest {
    private class Kept(val api: FakeDesktopAppApi, val m: TrustModel, val home: DesktopHome, val root: File, val store: TestKeyStore)

    /** Ada unlocked with the switch on, and on disk: the wrapped sign-in, the vault's copy, and a change waiting (the content's record). */
    private fun kept(): Kept {
        val root = Files.createTempDirectory("andvari-d1").toFile().also { it.deleteOnExit() }
        val store = TestKeyStore()
        val home = DesktopHome(root, store, log = {})
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, HomeSignInKeeping(home))
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        m.setKeepSignIn(true)
        home.secureFile.replace("""{"session":"kept"}""")
        File(home.cacheDir, "vault-abc.db").apply { parentFile.mkdirs(); writeText("rows") }
        assertTrue(home.content.storage.record("kept-waiting").write(byteArrayOf(7)))
        val k = Kept(api, m, home, root, store)
        assertStillKept(k, "at the start")
        return k
    }

    private fun assertStillKept(k: Kept, where: String) {
        k.m.onSnapshot(k.api.snapshot)
        assertTrue(k.m.keepSignIn.value, "$where: the switch is still on")
        assertEquals(Keep.ON, k.home.prefs.keep(), "$where: and its settings say so")
        assertTrue(File(k.root, "v2/secure-state.json").exists(), "$where: the kept sign-in")
        assertEquals(1, k.store.keys.size, "$where: its key-store item")
        assertTrue(File(k.root, "v2/vault-cache/vault-abc.db").exists(), "$where: the vault's copy")
        assertTrue(File(k.root, "v2/content/kept-waiting").exists(), "$where: what waits to be sent")
    }

    /** The path that showed it: the server ends the session, then "Sign in again" opens the journey. */
    @Test
    fun signInAgainOnASessionTheServerEndedKeepsTheCopy() {
        val k = kept()
        k.api.script.sessionEndedByServer()
        assertStillKept(k, "the server ended the session (a refused refresh, a revoked device)")
        assertEquals(AppPhase.LOCKED, k.api.snapshot.phase)
        k.m.signInAgain()
        assertEquals(AppPhase.ENTRY, k.api.snapshot.phase)
        assertNotNull(k.api.snapshot.keptSignedOut)
        assertStillKept(k, "after 'Sign in again'")
    }

    @Test
    fun everyWayAroundTheJourneyKeepsTheCopyAndSigningInAgainTakesItBack() {
        val k = kept()
        k.m.lockNow()
        assertStillKept(k, "locked")
        k.api.script.sessionEndedByServer()
        k.m.signInAgain()
        // Around the journey: back, start over, another account refused.
        k.m.act { entry.openSignIn(assertIs(snapshot.entry)) }
        assertStillKept(k, "sign-in choices")
        k.m.act { entry.back() }
        assertStillKept(k, "back")
        k.m.act { entry.startOver() }
        assertIs<EntryScreen.FirstRun>(k.api.snapshot.entry)
        assertStillKept(k, "start over, at the first screen")
        val bea = k.api.script.publicInstance.addAccount("bea@example.com", FakeScenes.PASSWORD)
        k.m.act { entry.openSignIn(assertIs(snapshot.entry)) }
        k.m.act { entry.openPasswordSignIn(assertIs(snapshot.entry)) }
        k.m.run({ entry.choosePublicInstance(assertIs(snapshot.entry)) })
        k.m.run({ entry.submitSignIn(assertIs(snapshot.entry), bea.email, FakeScenes.PASSWORD) })
        assertEquals(SignInAnswer.ANOTHER_ACCOUNT_KEPT, k.m.saidOn(k.api.snapshot)?.result)
        assertStillKept(k, "another account refused")

        // The same account signs in again: the copy is taken back, the switch still on.
        k.m.run({ entry.submitSignIn(assertIs(snapshot.entry), FakeScenes.EMAIL, FakeScenes.PASSWORD) })
        assertFalse(k.api.snapshot.phase == AppPhase.ENTRY && k.api.snapshot.entry is EntryScreen.SignIn, "signed in")
        assertStillKept(k, "signed in again")
    }

    @Test
    fun noServerAnswerSwitchesItOff() {
        val k = kept()
        val server = assertNotNull(k.api.script.server(assertNotNull(k.api.snapshot.instance).label.origin))
        server.tooNewForThisBuild = true
        k.m.run({ vaults.createVault("Trips") })
        assertTrue(assertNotNull(k.api.snapshot.instance).updateRequired)
        assertStillKept(k, "update required")
        server.tooNewForThisBuild = false

        k.api.script.cardNotVerified()
        assertStillKept(k, "a newer card that does not verify")
        k.api.script.cardWithheld()
        assertStillKept(k, "an older card served")
        k.api.script.cardOk()

        // The desktop is not a store build: it follows a move the operator signed.
        k.api.script.storeBuild = false
        k.api.script.cardMoved("https://moved.example")
        val moved = assertIs<InstanceCardState.Moved>(assertNotNull(k.api.snapshot.instance).card)
        k.m.run({ instance.followMove(moved) })
        assertStillKept(k, "a followed move")

        k.api.script.cardForked()
        assertStillKept(k, "a card that stops verifying (a fork)")
        k.m.lockNow()
        k.api.script.sessionEndedByServer()
        assertStillKept(k, "a session ended under a fork")
    }

    @Test
    fun aMoveThatCannotFinishKeepsTheCopy() {
        val k = kept()
        k.api.script.namespaceMoveFails = true
        k.api.script.storeBuild = false
        k.api.script.cardMoved("https://moved.example")
        val moved = assertIs<InstanceCardState.Moved>(assertNotNull(k.api.snapshot.instance).card)
        k.m.run({ instance.followMove(moved) })
        assertStillKept(k, "a move left unfinished")
    }

    /** The person's own ends do switch it off, and only when no account is kept any more. */
    @Test
    fun aCompletedSignOutIsThePersonsOwnEndAndDeletesWhatWasKept() {
        val k = kept()
        k.m.signOut()
        k.m.onSnapshot(k.api.snapshot)
        assertEquals(AppPhase.ENTRY, k.api.snapshot.phase)
        assertFalse(k.m.keepSignIn.value)
        assertFalse(File(k.root, "v2/secure-state.json").exists())
        assertTrue(k.store.keys.isEmpty())
        assertFalse(File(k.root, "v2/vault-cache/vault-abc.db").exists())
        assertFalse(File(k.root, "v2/content/kept-waiting").exists())
    }

    @Test
    fun signingOutTheKeptAccountFromTheJourneyIsThePersonsOwnEnd() {
        val k = kept()
        k.api.script.sessionEndedByServer()
        k.m.signInAgain()
        assertStillKept(k, "after 'Sign in again'")
        // A plain sign-out is refused over a copy that cannot be counted, and keeps everything.
        k.m.signOut()
        k.m.onSnapshot(k.api.snapshot)
        assertStillKept(k, "after a sign-out without the second confirmation")
        // The second confirmation alone signs out (the rule of 2026-11-17).
        val ask = SignOutAsk(k.m, SignOutAct.SignOut) {}
        assertTrue(assertNotNull(ask.check).needsConfirmation)
        ask.proceed()
        ask.confirmLoss()
        k.m.onSnapshot(k.api.snapshot)
        assertFalse(k.m.keepSignIn.value, "signed out on purpose")
        assertFalse(File(k.root, "v2/secure-state.json").exists())
    }

    @Test
    fun forgettingThisServerIsThePersonsOwnEnd() {
        val k = kept()
        k.m.forgetServer(assertNotNull(k.api.snapshot.instance))
        k.m.onSnapshot(k.api.snapshot)
        assertEquals(AppPhase.ENTRY, k.api.snapshot.phase)
        assertFalse(k.m.keepSignIn.value)
        assertFalse(File(k.root, "v2/vault-cache/vault-abc.db").exists())
    }

    /** The switch no longer follows the phase at all: only the person's ends and its own tick move it. */
    @Test
    fun theModelNoLongerSwitchesOffOnAPhaseChange() {
        val model = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/TrustModel.kt").readText()
        val follows = model.substringAfter("private fun keepFollows(").substringBefore("\n    }\n")
        assertFalse(follows.contains("AppPhase.ENTRY"), "no switch-off on reaching the first screen")
        val callers = Regex("""switchOff\(\)""").findAll(model).count()
        // Another account open no longer switches it off (SecondLookTest).
        assertEquals(4, callers, "the definition, setKeepSignIn, personEnded, the policy")
    }
}
