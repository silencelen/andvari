package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.SignupPolicy
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CompletableDeferred
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
 * A server's policy that keeps the account's keys at the server (it forbids keeping data on devices), over the shared
 * code's REAL engine on this computer's stores and the shared code's test server: what the lock screen says once such a
 * policy is recorded (also after a restart), what an unlock says while the server cannot be reached (decided on
 * 19 November: no unlock and no removal then), how that reads beside a wrong password, and the unlock the server answers.
 */
class KeysAtServerRealEngineTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private fun body(file: String, head: String) =
        File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$file").readText().substringAfter(head).substringBefore("\n}\n")

    /**
     * The test server with a policy that allows the copy until [forbid]. [down]: no answer to anything; [policyGate]: the
     * next policy read waits for it (a late answer).
     */
    private class Server(private val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        var down = false
        var forbid = false
        var policyGate: CompletableDeferred<Unit>? = null
        /** Where not null, the server answers the read of the account's keys with this refusal. */
        var keysRefusal: WireResult.Refused? = null
        val calls = ArrayList<WireRoute>()

        private fun policy(forbids: Boolean): String = WireJson.json.encodeToString(
            ClientPolicy.serializer(),
            ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, !forbids, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false),
        )

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            calls += route
            if (down) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            if (route == WireRoute.ACCOUNT_KEYS) keysRefusal?.let { return it }
            if (route == WireRoute.CLIENT_POLICY) {
                policyGate?.let { g -> policyGate = null; g.await() }
                return WireResult.Ok(decode(policy(forbid)), 200)
            }
            return instance.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    private inline fun <reified T : EntryScreen> DesktopAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun signUp(a: DesktopAppApi) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    /** One process of the desktop over [dir]'s stores: its home, the real engine, and the window's model. */
    private class Run(dir: File, instance: FakeInstance, server: Server, crypto: io.silencelen.andvari.core.crypto.CryptoProvider) {
        val home = DesktopHome(dir, NoKeyStore, log = {}, keyStorePause = {})
        val transport = BearerTransport(mapOf(instance.origin to server))
        val api = EngineDesktopAppApi(
            AppEngine(
                platform = TrustSeam.desktopPlatform(), deviceName = "test", transport = transport,
                state = JsonDeviceState(home.stateFile()), secure = JsonDeviceState(home.secureFile), requestStore = JsonDeviceState(home.requestFile),
                crypto = crypto, clock = { instance.now }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = home.cacheFiles, contentStores = home.content.stores, keepsAtRest = home::keepsAtRest,
            ),
        )
        val faults = ArrayList<String>()
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, HomeSignInKeeping(home), faultLog = { faults += it })

        init {
            home.consentWithdrawn = api::atRestConsentChanged
            m.start()
            m.onSnapshot(api.snapshot)
        }

        /** The person types [password] on the lock screen and presses Unlock: what the screen then says. */
        suspend fun unlockOnScreen(password: String): TrustModel.Said? {
            m.run({ unlock(assertNotNull(api.snapshot.locked), password) }).join()
            m.onSnapshot(api.snapshot)
            return m.said.value
        }
    }

    /** Signed up with "Keep me signed in", opened again under the allowing policy; then a forbidding policy is recorded while locked (a late answer). */
    private suspend fun recordedWhileLocked(r: Run, server: Server) {
        signUp(r.api)
        r.m.onSnapshot(r.api.snapshot)
        r.m.setKeepSignIn(true)
        r.m.answerNoKeyStore(true)
        r.api.lock()
        r.m.onSnapshot(r.api.snapshot)
        assertEquals(VaultUnlockResult.DONE, r.api.unlock(assertNotNull(r.api.snapshot.locked), strong))
        r.m.onSnapshot(r.api.snapshot)
        assertTrue(r.home.vaultFileOnDisk(), "the copy is at rest")
        assertNull(r.api.snapshot.locked)
        r.api.lock()
        r.m.onSnapshot(r.api.snapshot)
        assertNull(assertNotNull(r.api.snapshot.locked).keysAtServerLine, "the allowing policy keeps the keys here")
        // The next opening reads the policy again; its answer comes only after the lock, and it forbids.
        val gate = CompletableDeferred<Unit>()
        server.policyGate = gate
        assertEquals(VaultUnlockResult.DONE, r.api.unlock(assertNotNull(r.api.snapshot.locked), strong))
        r.m.onSnapshot(r.api.snapshot)
        r.api.lock()
        r.m.onSnapshot(r.api.snapshot)
        server.forbid = true
        gate.complete(Unit)
        r.m.onSnapshot(r.api.snapshot)
    }

    private fun Run.keysLine(): UiText? = api.snapshot.locked?.keysAtServerLine?.let { UiText.of(it) }

    @Test
    fun theLockScreenSaysTheKeysAreAtTheServerAndAnUnlockWithoutItOpensAndRemovesNothing() = runBlocking<Unit> {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val dir = java.nio.file.Files.createTempDirectory("andvari-keysatserver").toFile()
        var first: Run? = null
        var second: Run? = null
        try {
            val r = Run(dir, instance, server, crypto).also { first = it }
            recordedWhileLocked(r, server)

            // Locked, the policy recorded: the shared code hands the lock screen its line; the copy and the switch stay.
            assertEquals(AppPhase.LOCKED, r.api.snapshot.phase)
            assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER, r.api.snapshot.locked?.keysAtServerLine?.key)
            assertTrue(r.home.vaultFileOnDisk(), "nothing removed at the record")
            assertTrue(r.m.keepSignIn.value)
            assertNull(r.api.snapshot.policyWipe)
            r.api.close()
            first = null

            // A restart: the same lock screen and the same line.
            val r2 = Run(dir, instance, server, crypto).also { second = it }
            assertEquals(AppPhase.LOCKED, r2.api.snapshot.phase)
            assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER, r2.api.snapshot.locked?.keysAtServerLine?.key)
            assertEquals(UiText.of(CopyKey.UNLOCK_KEYS_AT_SERVER).shown(), r2.keysLine()?.shown())

            // The server cannot be reached: the right password opens nothing and removes nothing. The shared code hands its
            // own sentence for it, and the person reads that sentence as handed, under the lock screen's line: never the
            // line without wording, never the general line that the server did not answer.
            server.down = true
            val noAnswer = assertNotNull(r2.unlockOnScreen(strong))
            assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, noAnswer.result)
            assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER_UNREACHABLE, VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE.sentence)
            assertEquals(UiText.of(CopyKey.UNLOCK_KEYS_AT_SERVER_UNREACHABLE).shown(), noAnswer.text.shown(), "the server's silence, said as the shared code says it")
            assertFalse((noAnswer.text as? UiText.Ph)?.placeholder in setOf(Placeholder.TROUBLE, Placeholder.TROUBLE_UNREACHABLE, Placeholder.REFUSAL))
            println("WALK|engine 1 unreachable, right password|${noAnswer.text.shown()}")
            assertEquals(AppPhase.LOCKED, r2.api.snapshot.phase)
            assertTrue(r2.home.vaultFileOnDisk(), "nothing removed")
            assertNull(r2.api.snapshot.policyWipe)
            assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER, r2.api.snapshot.locked?.keysAtServerLine?.key, "the line stays")
            // A wrong password while it cannot be reached reads exactly the same: nothing here can check it.
            val wrongNoAnswer = assertNotNull(r2.unlockOnScreen("not the password"))
            assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, wrongNoAnswer.result)
            println("WALK|engine 1 unreachable, wrong password|${wrongNoAnswer.text.shown()}")
            assertEquals(noAnswer.text.shown(), wrongNoAnswer.text.shown())

            // With the server: a wrong password is said as the shared code's other outcome, so the two can be told apart.
            server.down = false
            server.calls.clear()
            val wrong = assertNotNull(r2.unlockOnScreen("not the password"))
            assertEquals(VaultUnlockResult.WRONG_PASSWORD, wrong.result)
            assertTrue(WireRoute.ACCOUNT_KEYS in server.calls, "the keys were asked of the server")
            assertFalse(wrong.text.shown() == noAnswer.text.shown())
            assertEquals(AppPhase.LOCKED, r2.api.snapshot.phase)
            assertTrue(r2.home.vaultFileOnDisk())

            // The unlock the server answers: it opens, and the shared code's run removes the copy and says so.
            // No outcome of the unlock is said; the line said is the switch's, which follows the policy once the copy went.
            val opened = r2.unlockOnScreen(strong)
            assertNull(opened?.result, "nothing of the unlock said in place")
            assertEquals(Placeholder.KEEP_FORBIDDEN, assertIs<UiText.Ph>(assertNotNull(opened).text).placeholder)
            assertEquals(AppPhase.UNLOCKED, r2.api.snapshot.phase)
            assertNotNull(r2.api.snapshot.policyWipe, "the notice of the removal")
            assertFalse(r2.home.vaultFileOnDisk(), "the copy went")
            assertFalse(r2.m.keepSignIn.value, "the switch follows the policy once the copy is gone")
            // Locked again in this run: the line is there again.
            r2.api.lock()
            r2.m.onSnapshot(r2.api.snapshot)
            assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER, r2.api.snapshot.locked?.keysAtServerLine?.key)
            assertEquals(emptyList(), r2.faults)
        } finally {
            first?.api?.close()
            second?.api?.close()
            dir.deleteRecursively()
        }
    }

    /**
     * The server ends the session while the keys are at the server: the lock screen hands both the server's end and the
     * keys' line, and no password opens anything any more (the shared code answers that end, sign in again).
     */
    @Test
    fun aSessionTheServerEndedWhileTheKeysAreAtTheServerOpensNothing() = runBlocking<Unit> {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val dir = java.nio.file.Files.createTempDirectory("andvari-keysatserver-ended").toFile()
        var run: Run? = null
        try {
            val r = Run(dir, instance, server, crypto).also { run = it }
            recordedWhileLocked(r, server)
            assertNotNull(r.api.snapshot.locked?.keysAtServerLine)
            // The server ends the session: the bearer is refused, and so is the one refresh after it.
            r.transport.expired += r.transport.sent.mapNotNull { it.bearer }
            r.transport.refreshAnswer = { WireResult.Refused(401, WireError("invalid_token", "invalid_token")) }
            // The unlock that meets the end: the session ended while its read was out, and the shared code says that end at
            // this very unlock, in its own sentence (it was asked on the lock screen: no lock overtook it). Said as handed.
            val said = assertNotNull(r.unlockOnScreen(strong))
            assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, said.result)
            assertEquals(UiText.of(CopyKey.UNLOCK_KEYS_AT_SERVER_ENDED).shown(), said.text.shown())
            println("WALK|engine 2 the unlock that learns the end|${said.text.shown()}")
            val locked = assertNotNull(r.api.snapshot.locked)
            assertTrue(locked.signedOutByServer, "the server's end")
            assertFalse(locked.sessionNotConfirmed)
            assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER, locked.keysAtServerLine?.key)
            // The card for the server's end is drawn beside it. No password opens anything here, so it never says that the
            // copy opens read-only: the shared code's line for this end, as handed, in place of the desktop's own.
            assertEquals(CopyKey.SIGNED_OUT_KEYS_AT_SERVER, locked.endLine)
            assertEquals(UiText.of(CopyKey.SIGNED_OUT_KEYS_AT_SERVER).shown(), serverEndText(r.api.snapshot).shown())
            assertTrue(Placeholder.entries.none { it.name == "SIGNED_OUT_KEYS_AT_SERVER" }, "the desktop's own line for this end is gone")
            println("WALK|engine 2 the lock screen's card|${serverEndText(r.api.snapshot).shown()}")
            assertTrue(body("AccountScreens.kt", "internal fun SignedOutByServerCard(").contains("Say(serverEndText(s),"), "the card says it")
            // Everywhere else the card is as it was: the same lock screen without the keys' line still says the read-only copy.
            assertEquals(
                Placeholder.SIGNED_OUT_BY_SERVER,
                assertIs<UiText.Ph>(serverEndText(rebuilt(r.api.snapshot, "locked" to rebuilt(locked, "keysAtServerLine" to null)))).placeholder,
            )
            // Again: nothing is asked, nothing opens; the shared code says the same end in the same sentence, as handed.
            server.calls.clear()
            val again = assertNotNull(r.unlockOnScreen(strong))
            assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, again.result)
            assertEquals(UiText.of(CopyKey.UNLOCK_KEYS_AT_SERVER_ENDED).shown(), again.text.shown())
            println("WALK|engine 2 the next unlock|${again.text.shown()}")
            assertFalse(WireRoute.ACCOUNT_KEYS in server.calls)
            assertEquals(AppPhase.LOCKED, r.api.snapshot.phase)
            assertTrue(r.home.vaultFileOnDisk(), "nothing removed")
        } finally {
            run?.api?.close()
            dir.deleteRecursively()
        }
    }

    /**
     * The server answers the read of the keys and refuses it: as too many requests (with a wait), and as forbidden. Nothing
     * opens and nothing is removed, the lock screen stays with its line, and what is said has words. What the desktop says
     * is printed (`WALK|engine 3...`): it is the shared code's answer as it reaches the desktop today.
     */
    @Test
    fun anUnlockWhoseKeysTheServerRefusedOpensAndRemovesNothingAndIsSaidWithWords() = runBlocking<Unit> {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val dir = java.nio.file.Files.createTempDirectory("andvari-keysatserver-refused").toFile()
        var run: Run? = null
        try {
            val r = Run(dir, instance, server, crypto).also { run = it }
            recordedWhileLocked(r, server)
            val refusals = listOf(
                "429 with a wait of 120 seconds" to WireResult.Refused(429, WireError("rate_limited", "rate_limited"), 120),
                "403" to WireResult.Refused(403, WireError("forbidden", "forbidden")),
            )
            for ((name, refusal) in refusals) {
                server.keysRefusal = refusal
                server.calls.clear()
                val said = assertNotNull(r.unlockOnScreen(strong), name)
                println("WALK|engine 3 the keys' read refused, $name|${said.result}|${said.text.shown()}")
                assertTrue(WireRoute.ACCOUNT_KEYS in server.calls, "$name: the keys were asked of the server")
                assertFalse(said.result?.done == true, name)
                assertFalse((said.text as? UiText.Ph)?.placeholder in setOf(Placeholder.TROUBLE, Placeholder.REFUSAL), "$name: said with words")
                assertEquals(AppPhase.LOCKED, r.api.snapshot.phase, name)
                assertTrue(r.home.vaultFileOnDisk(), "$name: nothing removed")
                assertNull(r.api.snapshot.policyWipe, name)
                assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER, r.api.snapshot.locked?.keysAtServerLine?.key, "$name: the line stays")
            }
            // With the refusal gone, the same password opens.
            server.keysRefusal = null
            r.unlockOnScreen(strong)
            assertEquals(AppPhase.UNLOCKED, r.api.snapshot.phase)
            assertEquals(emptyList(), r.faults)
        } finally {
            run?.api?.close()
            dir.deleteRecursively()
        }
    }

    /** The lock screen draws the shared code's line as handed, above the server's end and the password field. */
    @Test
    fun theLockScreenDrawsTheKeysLineAsHanded() {
        val lock = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/AccountScreens.kt").readText()
            .substringAfter("internal fun LockScreen(").substringBefore("\n}\n")
        val drawn = lock.indexOf("locked.keysAtServerLine?.let { Say(it) }")
        assertTrue(drawn >= 0, "the keys' line is drawn")
        assertTrue(drawn < lock.indexOf("SignedOutByServerCard(") && drawn < lock.indexOf("SecretField("), "above the server's end and the field")
        assertEquals(1, Regex("keysAtServerLine").findAll(lock).count(), "drawn once, nothing added to it")
    }
}
