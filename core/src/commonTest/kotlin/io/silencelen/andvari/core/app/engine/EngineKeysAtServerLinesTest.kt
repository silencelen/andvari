package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
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
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Under a server's policy that keeps the account's keys at the server, what the lock screen and an unlock say where the
 * server does not hand the keys over: the session's end (on the lock screen, at the unlock that learns it, at every
 * unlock after it), silence, and a refusal of the read. In none of them does anything open or is anything removed (the
 * owner's condition, decided on 18 and 19 November). Over the real engine, the test transport that refreshes a session
 * and a server that answers as told.
 */
class EngineKeysAtServerLinesTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Files : VaultCacheFiles {
        val deleted = ArrayList<String>()
        val caches = HashMap<String, VaultCache>()
        override fun open(fileName: String, userId: String): VaultCache =
            caches.getOrPut(fileName) { object : VaultCache by InMemoryVaultCache() { override val durable: Boolean get() = true } }
        override fun delete(fileName: String): Boolean {
            deleted += fileName
            caches.remove(fileName)
            return true
        }
    }

    /** [instance]; its policy forbids the copy while [forbid]; [down]: no answer at all; [keysRefusal]: the read of the keys is refused so. */
    private class Server(val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        var forbid = false
        var down = false
        var keysRefusal: WireResult.Refused? = null

        fun policy(forbids: Boolean): String = WireJson.json.encodeToString(
            ClientPolicy.serializer(),
            ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, !forbids, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false),
        )

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (down) {
                instance.calls += route
                return WireResult.NoAnswer(NoAnswerKind.TRANSPORT, neverLeft = true)
            }
            return when (route) {
                WireRoute.CLIENT_POLICY -> WireResult.Ok(decode(policy(forbid)), 200)
                WireRoute.ACCOUNT_KEYS -> {
                    val refused = keysRefusal
                    if (refused != null) {
                        instance.calls += route
                        refused
                    } else {
                        instance.call(route, pathParams, query, bodyJson, authenticated, decode)
                    }
                }
                WireRoute.SYNC -> {
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val r = SyncResponse(1, true, vaults, emptyList(), emptyList(), emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
    }

    private class Env(
        val instance: FakeInstance, val server: Server, val transport: BearerTransport, val files: Files,
        val state: MemoryDeviceState, val secure: MemoryDeviceState, val app: EngineAppApi,
    )

    private fun env(from: Env? = null): Env {
        val instance = from?.instance ?: FakeInstance(crypto)
        val server = from?.server ?: Server(instance)
        val transport = from?.transport ?: BearerTransport(mapOf(instance.origin to server))
        val files = from?.files ?: Files()
        val state = from?.state ?: MemoryDeviceState()
        val secure = from?.secure ?: MemoryDeviceState()
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", transport, state, secure, crypto,
                { instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files, keepsAtRest = { true }),
        ).also { it.start() }
        return Env(instance, server, transport, files, state, secure, app)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun open(a: EngineAppApi) {
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

    private suspend fun EngineAppApi.unlockWith(password: String = strong) = unlock(snapshot.locked!!, password)

    /** Every record on the device, both stores. */
    private fun Env.everything(): Map<String, String> =
        secure.keys().associate { "secure:$it" to secure.get(it)!! } + state.keys().associate { "state:$it" to state.get(it)!! }

    /** Signed up, the copy at rest, then the server forbids it: the run removes the copy; the account's keys are at the server. Locked at the end. */
    private suspend fun Env.keysAtServer() {
        open(app)
        app.lock()
        assertEquals(VaultUnlockResult.DONE, app.unlockWith())
        server.forbid = true
        app.lock()
        assertEquals(VaultUnlockResult.DONE, app.unlockWith())
        app.policyWipe.running?.join()
        assertNotNull(app.snapshot.policyWipe, "the copy was removed")
        app.lock()
        assertNotNull(app.snapshot.locked?.keysAtServerLine, "the keys are at the server")
    }

    /** Nothing is open: the lock screen stays, and no vault or content exists. */
    private fun Env.nothingOpen() {
        assertEquals(AppPhase.LOCKED, app.snapshot.phase)
        assertNull(app.vault)
        assertNull(app.content)
    }

    /**
     * The server ends the session while the keys are at the server. The unlock at which that end is learned (the read of
     * the keys meets an expired token whose refresh is refused) says that end, as does every unlock after it, which asks
     * nothing; the lock screen says the end with a line that claims no copy. Nothing opens; nothing is removed.
     */
    @Test fun aSessionTheServerEndedIsSaidAsThatEndOnTheLockScreenAndAtEveryUnlock() = runBlocking<Unit> {
        val e = env()
        e.keysAtServer()
        val before = assertNotNull(e.app.snapshot.locked)
        assertFalse(before.signedOutByServer)
        assertNull(before.endLine, "no end yet")
        assertNull(before.endLineBesideSignOut)

        e.transport.expired += e.transport.sent.mapNotNull { it.bearer }
        e.transport.refreshAnswer = { WireResult.Refused(401, WireError("refresh_reuse", "x")) }
        val records = e.everything().keys
        val deleted = e.files.deleted.toList()
        e.instance.calls.clear()

        val first = e.app.unlockWith()
        println("the unlock that learned the server's end: $first")
        assertTrue(WireRoute.ACCOUNT_KEYS in e.instance.calls || e.transport.sent.any { it.route == WireRoute.ACCOUNT_KEYS }, "the keys were asked for")
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, first, "the end is said as that end, never as an older state")
        assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER_ENDED, first.sentence)
        e.nothingOpen()
        val locked = assertNotNull(e.app.snapshot.locked)
        assertTrue(locked.signedOutByServer)
        assertFalse(locked.sessionNotConfirmed)
        assertEquals(CopyKey.SIGNED_OUT_KEYS_AT_SERVER, locked.endLine)
        assertEquals(CopyKey.SIGNED_OUT_KEYS_AT_SERVER_SIGN_OUT_FIRST, locked.endLineBesideSignOut)
        assertNotNull(locked.keysAtServerLine)
        assertFalse(locked.quickUnlock)

        e.instance.calls.clear()
        val sentBefore = e.transport.sent.size
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, e.app.unlockWith(), "every later unlock")
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, e.app.unlockWith("not the password at all 1"), "a wrong password reads the same: nothing can check it")
        assertEquals(sentBefore, e.transport.sent.size, "no token: nothing is asked")
        e.nothingOpen()

        // A restart over the same stores: the same lock screen and the same answer.
        val again = env(e)
        assertEquals(CopyKey.SIGNED_OUT_KEYS_AT_SERVER, again.app.snapshot.locked?.endLine)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, again.app.unlockWith())
        again.nothingOpen()
        assertEquals(deleted, e.files.deleted, "nothing removed")
        assertEquals(records, e.everything().keys, "every record stays")
    }

    /**
     * The server does not answer: the unlock says so in its own sentence, for the right and a wrong password alike;
     * nothing opens and every record stays exactly as it was. Without such a policy the copy here opens offline, as before.
     */
    @Test fun anUnlockTheServerDidNotAnswerHasItsOwnSentenceAndOpensAndRemovesNothing() = runBlocking<Unit> {
        val e = env()
        e.keysAtServer()
        e.server.down = true
        val records = e.everything()
        val deleted = e.files.deleted.toList()
        val right = e.app.unlockWith()
        val wrong = e.app.unlockWith("not the password at all 1")
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, right)
        assertEquals(right, wrong, "the password could not be checked")
        assertNull(right.trouble, "its own reason, said by its sentence")
        assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER_UNREACHABLE, right.sentence)
        e.nothingOpen()
        assertNull(e.app.snapshot.locked?.endLine, "the session did not end")
        assertEquals(records, e.everything(), "nothing removed or changed")
        assertEquals(deleted, e.files.deleted)

        // Without such a policy: the copy kept here opens offline, as it did.
        val plain = env()
        open(plain.app)
        plain.app.lock()
        plain.server.down = true
        assertNull(plain.app.snapshot.locked?.keysAtServerLine)
        assertEquals(VaultUnlockResult.DONE, plain.app.unlockWith())
    }

    /**
     * The server answers the read of the keys with a refusal: "too many requests" with a wait, or "forbidden". Nothing
     * opens and every record stays. What the session keeper hands the layer for both today is the same as for silence
     * (the layer cannot tell them apart, and says the sentence for silence); once it hands the refusal, the layer says
     * the wait or the refusal ([EngineAppApi.keysAtServerAnswer]). Never DONE, never the plain unworded troubles.
     */
    @Test fun aRefusalAtTheKeysReadOpensAndRemovesNothing() = runBlocking<Unit> {
        val e = env()
        e.keysAtServer()
        val records = e.everything()
        val deleted = e.files.deleted.toList()

        e.server.keysRefusal = WireResult.Refused(429, WireError("rate_limited", "x"), retryAfterSeconds = 120)
        val waited = e.app.unlockWith()
        println("the unlock whose read of the keys was answered 429: $waited")
        assertTrue(waited == VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE || waited == VaultUnlockResult.RATE_LIMITED, "$waited")
        e.nothingOpen()

        e.server.keysRefusal = WireResult.Refused(403, WireError("forbidden", "x"))
        val refused = e.app.unlockWith()
        println("the unlock whose read of the keys was answered 403: $refused")
        assertTrue(refused == VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE || refused == VaultUnlockResult.KEYS_AT_SERVER_REFUSED, "$refused")
        assertNotNull(refused.sentence)
        e.nothingOpen()

        assertEquals(records, e.everything(), "nothing removed or changed")
        assertEquals(deleted, e.files.deleted)
        // With the server's answer back, the same password opens.
        e.server.keysRefusal = null
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
    }

    /** The layer's reading of what the keeper hands where the keys were not handed over: each refusal as what it is. */
    @Test fun eachAnswerAtTheKeysReadIsSaidAsWhatItIs() = runBlocking<Unit> {
        val e = env()
        e.keysAtServer()
        val a = e.app
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, a.keysAtServerAnswer(true, null, null))
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, a.keysAtServerAnswer(true, 429, 60), "an end is the end, whatever came with it")
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, a.keysAtServerAnswer(false, null, null))
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, a.keysAtServerAnswer(false, 503, null))
        assertEquals(0, a.retryAfterSeconds())
        assertEquals(VaultUnlockResult.RATE_LIMITED, a.keysAtServerAnswer(false, 429, 120))
        assertEquals(120, a.retryAfterSeconds(), "the wait is said")
        assertEquals(VaultUnlockResult.UPDATE_REQUIRED, a.keysAtServerAnswer(false, 426, null))
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_REFUSED, a.keysAtServerAnswer(false, 403, null))
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_REFUSED, a.keysAtServerAnswer(false, 404, null))
        for (r in listOf(VaultUnlockResult.KEYS_AT_SERVER_ENDED, VaultUnlockResult.KEYS_AT_SERVER_REFUSED, VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE)) {
            assertNotNull(r.sentence, "$r has its own sentence")
            assertFalse(r.done)
        }
        assertNotEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE.sentence, VaultUnlockResult.KEYS_AT_SERVER_REFUSED.sentence, "a refusal is never said as silence")
        // A lookup of the outcome for a trouble still finds the plain one.
        assertEquals(VaultUnlockResult.UNREACHABLE, VaultUnlockResult.entries.first { it.trouble == Trouble.UNREACHABLE })
    }
}
