package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.PolicyWipeMarks
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.SignupPolicy
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Under a server's policy that forbids keeping data on the device, the account's wrapped keys at rest go, as on the
 * released line, and an unlock asks the server for them, as a sign-in proves the password: the session's tokens stay,
 * so the account stays signed in; without the server there is no unlock, and nothing is removed then. Over the real
 * engine and a server that answers as told.
 */
class EnginePolicyKeysTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Files : VaultCacheFiles {
        val opened = ArrayList<String>()
        val deleted = ArrayList<String>()
        val caches = HashMap<String, VaultCache>()
        override fun open(fileName: String, userId: String): VaultCache {
            opened += fileName
            return caches.getOrPut(fileName) { object : VaultCache by InMemoryVaultCache() { override val durable: Boolean get() = true } }
        }
        override fun delete(fileName: String): Boolean {
            deleted += fileName
            caches.remove(fileName)
            return true
        }
    }

    /** [instance] with an honest item plane; its policy forbids the copy while [forbid]; [down]: no answer at all to anything. */
    private class Server(val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        var forbid = false
        var down = false
        var rev = 1L
        val taken = LinkedHashSet<String>()

        /** When set, a password change waits here before the server takes it (its answer arrives once completed). */
        var holdPasswordChange: kotlinx.coroutines.CompletableDeferred<Unit>? = null

        fun policy(forbids: Boolean): String = WireJson.json.encodeToString(
            ClientPolicy.serializer(),
            ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, !forbids, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false),
        )

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (down) {
                instance.calls += route
                return WireResult.NoAnswer(NoAnswerKind.TRANSPORT, neverLeft = true)
            }
            if (route == WireRoute.PASSWORD_CHANGE) holdPasswordChange?.let { h -> holdPasswordChange = null; h.await() }
            return when (route) {
                WireRoute.CLIENT_POLICY -> WireResult.Ok(decode(policy(forbid)), 200)
                WireRoute.SYNC -> {
                    val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), emptyList(), emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> {
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                    val results = b.mutations.map { m ->
                        if (taken.add(m.mutationId)) rev++
                        MutationResult(m.mutationId, MutationStatus.APPLIED, rev)
                    }
                    WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
    }

    /** The secure store as the engine sees it: the next write of the key [refuse] names is refused, as a failing store does. */
    private class Refusing(val inner: MemoryDeviceState) : io.silencelen.andvari.core.client.DeviceState by inner {
        var refuse: String? = null
        override fun set(key: String, value: String?) {
            if (key == refuse) {
                refuse = null
                throw IllegalStateException("the store refused this write")
            }
            inner.set(key, value)
        }
    }

    private class Env(
        val instance: FakeInstance, val server: Server, val files: Files, val state: MemoryDeviceState, val secure: MemoryDeviceState, val app: EngineAppApi,
        val refusing: Refusing,
    )

    /** A process over [from]'s server, files and stores (a restart), or a first one. */
    private fun env(from: Env? = null): Env {
        val instance = from?.instance ?: FakeInstance(crypto)
        val server = from?.server ?: Server(instance)
        val files = from?.files ?: Files()
        val state = from?.state ?: MemoryDeviceState()
        val secure = from?.secure ?: MemoryDeviceState()
        val refusing = Refusing(secure)
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(instance.origin to server)), state, refusing, crypto,
                { instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files, keepsAtRest = { true }),
        ).also { it.start() }
        return Env(instance, server, files, state, secure, app, refusing)
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

    private fun Env.account() = instance.accounts.values.last()
    private fun Env.userId() = account().userId

    /** The kept session record, as it is at rest. */
    private fun Env.sessionAtRest(): String = assertNotNull(secure.get(SessionKeeper.KEY))

    /** Every record on the device, both stores, as "store:key" → value. */
    private fun Env.everything(): Map<String, String> =
        secure.keys().associate { "secure:$it" to secure.get(it)!! } + state.keys().associate { "state:$it" to state.get(it)!! }

    /** Signed up under a policy that allows the copy, opened again (the copy at rest), then the server forbids it: the run wipes the copy at that opening. Locked at the end. */
    private suspend fun Env.wiped() {
        open(app)
        app.lock()
        assertEquals(VaultUnlockResult.DONE, app.unlockWith())
        assertTrue(assertNotNull(app.vault).keptAtRest, "the copy is at rest")
        server.forbid = true
        app.lock()
        assertEquals(VaultUnlockResult.DONE, app.unlockWith(), "the kept wrap still opened this one, read before the policy")
        app.policyWipe.running?.join()
        assertNotNull(app.snapshot.policyWipe, "the copy was removed")
        assertTrue(files.deleted.isNotEmpty())
        app.lock()
    }

    /**
     * After the wipe, every record left on the device for the account, one by one, and none of them, with the master
     * password and even the salt the server holds (which the device does not keep either), opens the account's key.
     */
    @Test fun afterTheWipeNothingOnTheDeviceOpensTheAccountsKeysWithThePasswordAlone() = runBlocking<Unit> {
        val e = env()
        e.wiped()
        val a = e.account()
        val all = e.everything()
        // No text of the account's wrapped keys is kept anywhere.
        for ((k, v) in all) {
            assertFalse(a.wrappedUvk in v, "$k keeps the wrapped account key")
            assertFalse(a.encryptedIdentitySeed in v, "$k keeps the sealed identity seed")
            assertFalse(a.personalWrap!!.wrappedVk in v, "$k keeps the personal vault's wrap")
        }
        // The session record: the tokens, the ids and the public identity, and none of the wrapped keys.
        val s = WireJson.json.parseToJsonElement(e.sessionAtRest()).toString()
        assertTrue("\"keysAtServer\":true" in s, s)
        assertTrue("\"wrappedUvk\":\"\"" in s && "\"encryptedIdentitySeed\":\"\"" in s && "\"kdfSalt\":\"\"" in s, s)
        assertTrue(a.identityPub in s, "the public identity stays")
        // What a thief of the device would try: the password at the server's own salt and cost, against every piece of
        // every record on the device. Nothing opens as the account's key.
        val keys = assertNotNull(PasswordKeys.derive(crypto, strong.toCharArray(), Bytes.fromB64(a.kdfSalt), a.kdfParams, served = true))
        val pieces = all.values.flatMap { v -> Regex("[A-Za-z0-9+/_-]{40,}={0,2}").findAll(v).map { it.value }.toList() }
        assertTrue(pieces.isNotEmpty())
        for (p in pieces) {
            val opened = runCatching { Envelope.openB64(crypto, keys.wrapKey, p, Ad.uvk(a.userId)) }.getOrNull()
            assertNull(opened, "a record on the device opened to the account's key")
        }
        keys.wipe()
        // The records left on the device, one by one: the session-grade store holds the session record alone.
        println("records left after the wipe: ${all.keys.sorted()}")
        assertEquals(setOf(SessionKeeper.KEY), e.secure.keys(), "all: ${all.keys.sorted()}")
        assertNotNull(e.state.get("ovh.identity|${a.userId}"), "the public record of the account's identity stays")
        // And a restart over the same stores with no server opens nothing.
        e.server.down = true
        val again = env(e)
        assertEquals(AppPhase.LOCKED, again.app.snapshot.phase)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, again.app.unlockWith())
        assertEquals(AppPhase.LOCKED, again.app.snapshot.phase)
        assertNull(again.app.vault)
    }

    /** With the server, an unlock reads the keys it holds and opens the account; nothing of them is kept at rest after. */
    @Test fun anUnlockAsksTheServerAndOpens() = runBlocking<Unit> {
        val e = env()
        e.wiped()
        assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER, e.app.snapshot.locked?.keysAtServerLine?.key)
        assertFalse(assertNotNull(e.app.snapshot.locked).quickUnlock)
        e.instance.calls.clear()
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        assertEquals(AppPhase.UNLOCKED, e.app.snapshot.phase)
        assertTrue(WireRoute.ACCOUNT_KEYS in e.instance.calls, "the keys were read from the server")
        assertNotNull(e.app.content, "the account goes on from the server, in memory")
        assertTrue("\"keysAtServer\":true" in e.sessionAtRest(), "nothing of the served keys is kept at rest")
        assertFalse(e.account().wrappedUvk in e.sessionAtRest())
        e.app.lock()
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith(), "and again after a lock")
    }

    /**
     * Without the server there is no unlock, and nothing is removed: a forbidding policy recorded while the device is
     * locked, with two changes waiting in the copy, and the server out of reach at the next unlock. Once it answers,
     * the unlock opens, and the one try sends both before the copy goes.
     */
    @Test fun withoutTheServerThereIsNoUnlockAndNothingIsWipedOrLost() = runBlocking<Unit> {
        val e = env()
        open(e.app)
        e.app.lock()
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        val c = assertNotNull(e.app.content)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        e.server.down = true
        for (i in 1..2) assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Site$i", "me", "pw-$i", listOf("https://site$i.test"), "", "", false), null))
        e.app.lock()
        val cache = assertNotNull(e.files.caches[e.files.opened.last()])
        assertEquals(2, cache.pending().size)
        // The policy is recorded while locked (as a late answer of a read is).
        e.app.policies.record(e.instance.origin, WireJson.json.decodeFromString(ClientPolicy.serializer(), e.server.policy(true)), e.instance.now)
        assertTrue("\"keysAtServer\":true" in e.sessionAtRest(), "the wrapped keys went at the record")
        assertNotNull(PolicyWipeMarks(e.state).mark(e.instance.origin, e.userId()), "the wipe is owed")

        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, e.app.unlockWith())
        assertEquals(AppPhase.LOCKED, e.app.snapshot.phase)
        assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER, e.app.snapshot.locked?.keysAtServerLine?.key)
        assertEquals(emptyList(), e.files.deleted, "nothing wiped")
        assertEquals(2, cache.pending().size, "nothing lost")
        assertNull(e.app.snapshot.policyWipe)

        e.server.down = false
        e.server.forbid = true
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        e.app.policyWipe.running?.join()
        assertEquals(2, e.server.taken.size, "both were sent before the copy went")
        assertEquals(0, assertNotNull(e.app.snapshot.policyWipe).notSent)
    }

    /**
     * Both things the record of a forbidding policy does at rest are done at that moment, on the recording thread: the
     * mark that a wipe is owed and the removal of the account's wrapped keys. Also when the process's part ends before
     * anything launched could run: a new process finds both at rest, cannot unlock without the server, and with it
     * sends what waited once before the copy goes.
     */
    @Test fun theOwedMarkAndTheKeysRemovalAreAtRestFromTheRecordEvenWhenTheProcessEndsBeforeTheHop() = runBlocking<Unit> {
        val e = env()
        open(e.app)
        e.app.lock()
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        val c = assertNotNull(e.app.content)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        e.server.down = true
        for (i in 1..2) assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Site$i", "me", "pw-$i", listOf("https://site$i.test"), "", "", false), null))
        e.app.lock()
        assertTrue(e.account().wrappedUvk in e.sessionAtRest(), "before the record, the wrap is kept")
        val client = e.app.clientFor(e.instance.origin)
        // The process's part ends: nothing launched on its scope runs any more.
        e.app.close()
        e.server.down = false
        e.server.forbid = true
        e.app.policies.fetch(client, e.instance.now)
        assertNotNull(PolicyWipeMarks(e.state).mark(e.instance.origin, e.userId()), "the mark is at rest")
        assertTrue("\"keysAtServer\":true" in e.sessionAtRest(), "the wrapped keys went at the record")
        assertFalse(e.account().wrappedUvk in e.sessionAtRest())

        e.server.down = true
        val again = env(e)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, again.app.unlockWith(), "no unlock without the server")
        assertEquals(emptyList(), e.files.deleted, "nothing wiped")
        e.server.down = false
        assertEquals(VaultUnlockResult.DONE, again.app.unlockWith())
        again.app.policyWipe.running?.join()
        assertEquals(2, e.server.taken.size, "both were sent once before the copy went")
        assertEquals(0, assertNotNull(again.app.snapshot.policyWipe).notSent)
        assertTrue(e.files.deleted.isNotEmpty(), "then the copy went")
        again.app.close()
    }

    /**
     * A wrong password: the keys are read (one `GET /account/keys`, with the session's bearer), and nothing derived from
     * the password is sent; it is answered as wrong. A session its server ended has no token to ask with: no unlock.
     */
    @Test fun aWrongPasswordSendsNothingDerivedAndAnEndedSessionCannotAsk() = runBlocking<Unit> {
        val e = env()
        e.wiped()
        e.instance.calls.clear()
        e.instance.bodies.clear()
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, e.app.unlockWith("not the password at all 1"))
        assertEquals(listOf(WireRoute.ACCOUNT_KEYS), e.instance.calls, "one read of the keys per try, nothing else")
        assertEquals(listOf(""), e.instance.bodies, "nothing was sent with it")
        assertEquals(AppPhase.LOCKED, e.app.snapshot.phase)

        e.app.keeper.endedByServer(e.instance.origin)
        e.instance.calls.clear()
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, e.app.unlockWith())
        assertEquals(emptyList(), e.instance.calls, "no token: nothing is asked")
        assertNotNull(e.app.snapshot.locked?.keysAtServerLine)
    }

    /**
     * The shared code answers whether a wipe is owed for an account at a server (so that an app deletes nothing of the
     * copy by itself), and asking changes nothing: owed from the forbidding record until the wipe is made, and not owed
     * once the policy allows the copy again.
     */
    @Test fun whetherAWipeIsOwedIsAnsweredAndAskingChangesNothing() = runBlocking<Unit> {
        val e = env()
        open(e.app)
        e.app.lock()
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        e.app.lock()
        val o = e.instance.origin
        val u = e.userId()
        assertFalse(e.app.policyWipeOwed(o, u))
        e.app.policies.record(o, WireJson.json.decodeFromString(ClientPolicy.serializer(), e.server.policy(true)), e.instance.now)
        val before = e.state.keys().associateWith { e.state.get(it) }
        repeat(3) { assertTrue(e.app.policyWipeOwed(o, u)) }
        assertEquals(before, e.state.keys().associateWith { e.state.get(it) }, "asking changes nothing")
        assertEquals(emptyList(), e.files.deleted)
        assertFalse(e.app.policyWipeOwed(o, "11111111-2222-4333-8444-555555555555"), "only that account's")
        // Lifted before the wipe: nothing is owed any more.
        e.app.policies.record(o, WireJson.json.decodeFromString(ClientPolicy.serializer(), e.server.policy(false)), e.instance.now)
        assertFalse(e.app.policyWipeOwed(o, u))
        // Forbidden again, and the wipe made at the next opening: nothing is owed after it.
        e.app.policies.record(o, WireJson.json.decodeFromString(ClientPolicy.serializer(), e.server.policy(true)), e.instance.now)
        assertTrue(e.app.policyWipeOwed(o, u))
        e.server.forbid = true
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        e.app.policyWipe.running?.join()
        assertNotNull(e.app.snapshot.policyWipe)
        assertFalse(e.app.policyWipeOwed(o, u))
    }

    /** A policy that allows the copy again brings the kept wrap back at the next unlock (which still asks the server). */
    @Test fun aPolicyThatAllowsAgainBringsTheKeptWrapBackAtTheNextUnlock() = runBlocking<Unit> {
        val e = env()
        e.wiped()
        e.server.forbid = false
        e.app.policies.record(e.instance.origin, WireJson.json.decodeFromString(ClientPolicy.serializer(), e.server.policy(false)), e.instance.now)
        assertTrue("\"keysAtServer\":true" in e.sessionAtRest(), "nothing comes back before an unlock")
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        assertTrue(e.account().wrappedUvk in e.sessionAtRest(), "the wrap is kept again")
        assertNull(e.app.snapshot.locked?.keysAtServerLine)
        e.app.lock()
        // Now the device's own wrap opens without the server again.
        e.server.down = true
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
    }

    /**
     * The mark that a wipe is owed survives a failure of the keys' removal: the secure store refuses the session record's
     * write at the record of a forbidding policy, with two changes waiting. The failure is not swallowed, the mark is at
     * rest and the wipe is said to be owed; a restart removes the keys the refused write left, and the first unlock the
     * server answers sends both changes once and counts them before the copy goes.
     */
    @Test fun aRefusedWriteWhenTheKeysLeaveDoesNotLoseTheMarkThatAWipeIsOwed() = runBlocking<Unit> {
        val e = env()
        open(e.app)
        e.app.lock()
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        val c = assertNotNull(e.app.content)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        e.server.down = true
        for (i in 1..2) assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Site$i", "me", "pw-$i", listOf("https://site$i.test"), "", "", false), null))
        e.app.lock()
        assertEquals(2, assertNotNull(e.files.caches[e.files.opened.last()]).pending().size)
        val o = e.instance.origin
        val u = e.userId()

        e.refusing.refuse = SessionKeeper.KEY
        val thrown = runCatching { e.app.policies.record(o, WireJson.json.decodeFromString(ClientPolicy.serializer(), e.server.policy(true)), e.instance.now) }.exceptionOrNull()
        assertIs<IllegalStateException>(thrown, "the store's refusal is not swallowed")
        assertNull(e.refusing.refuse, "the session record's write was the one refused")
        assertNotNull(PolicyWipeMarks(e.state).mark(o, u), "the mark is at rest")
        assertTrue(e.app.policyWipeOwed(o, u), "a wipe is owed")
        e.app.close()

        val again = env(e)
        assertTrue("\"keysAtServer\":true" in e.sessionAtRest(), "the keys the refused write left went at the restart")
        assertTrue(again.app.policyWipeOwed(o, u), "still owed after a restart")
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, again.app.unlockWith(), "no unlock without the server")
        assertEquals(emptyList(), e.files.deleted, "nothing wiped")
        e.server.down = false
        e.server.forbid = true
        assertEquals(VaultUnlockResult.DONE, again.app.unlockWith())
        again.app.policyWipe.running?.join()
        assertEquals(2, e.server.taken.size, "both were sent once before the copy went")
        assertEquals(0, assertNotNull(again.app.snapshot.policyWipe, "the notice counts them").notSent)
        assertTrue(e.files.deleted.isNotEmpty(), "then the copy went")
        assertFalse(again.app.policyWipeOwed(o, u))
        again.app.close()
    }

    /**
     * A password change whose answer arrives after a lock, under a policy that forbids keeping data: the server's new
     * wrapped key and its salt are not written at rest into a record that keeps its keys at the server, nor anything of
     * the old ones; the new password at the new salt opens nothing on the device, and without the server there is no
     * unlock.
     */
    @Test fun aPasswordChangeAnsweredAfterALockKeepsNoWrapAtRest() = runBlocking<Unit> {
        val e = env()
        e.wiped()
        val old = e.account().let { Triple(it.wrappedUvk, it.kdfSalt, it.encryptedIdentitySeed) }
        val oldPersonal = e.account().personalWrap!!.wrappedVk
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith(), "the unlock asks the server")
        val newer = "a whole New master password 7 here"
        val hold = kotlinx.coroutines.CompletableDeferred<Unit>()
        e.server.holdPasswordChange = hold
        val change = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { e.app.settings.changeMasterPassword(strong, newer) }
        assertFalse(change.isCompleted, "the change waits for its answer")
        e.app.lock()
        hold.complete(Unit)
        assertEquals(io.silencelen.andvari.core.app.PasswordChangeResult.DONE, change.await())
        val a = e.account()
        assertTrue(a.wrappedUvk != old.first && a.kdfSalt != old.second, "the server holds the new wrap")

        // Every key and value of both stores: no wrapped key of the account, old or new, no salt for either, no sealed seed.
        for ((name, store) in listOf("secure" to e.secure, "state" to e.state)) {
            for (k in assertNotNull(store.keys())) {
                val v = assertNotNull(store.get(k))
                println("at rest after the change: $name:$k")
                for ((what, text) in listOf(
                    "the new wrapped key" to a.wrappedUvk, "the new salt" to a.kdfSalt, "the old wrapped key" to old.first,
                    "the old salt" to old.second, "the sealed identity seed" to a.encryptedIdentitySeed, "the old sealed seed" to old.third,
                    "the personal vault's wrap" to a.personalWrap!!.wrappedVk, "the old personal wrap" to oldPersonal,
                )) assertFalse(text in v, "$name:$k keeps $what")
            }
        }
        assertTrue("\"keysAtServer\":true" in e.sessionAtRest())
        // The new password at the new salt opens no piece of anything on the device as the account's key.
        val keys = assertNotNull(PasswordKeys.derive(crypto, newer.toCharArray(), Bytes.fromB64(a.kdfSalt), a.kdfParams, served = true))
        for (p in e.everything().values.flatMap { v -> Regex("[A-Za-z0-9+/_-]{40,}={0,2}").findAll(v).map { it.value }.toList() }) {
            assertNull(runCatching { Envelope.openB64(crypto, keys.wrapKey, p, Ad.uvk(a.userId)) }.getOrNull(), "a record opened to the account's key")
        }
        keys.wipe()
        // Without the server there is no unlock, after a restart either.
        e.server.down = true
        val again = env(e)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, again.app.unlockWith(newer))
        assertEquals(AppPhase.LOCKED, again.app.snapshot.phase)
    }
}
