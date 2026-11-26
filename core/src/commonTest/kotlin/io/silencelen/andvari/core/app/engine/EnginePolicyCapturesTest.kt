package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.SaveQueue
import io.silencelen.andvari.core.app.SaveQueued
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.content.ContentCapture
import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.app.content.KeptStorage
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Logins the Android app caught, on a phone whose server's policy forbids keeping data on the device (decided on
 * 2026-11-18: they stay on the phone, sealed, until the person answers them, whether caught before the policy or after
 * it). First the condition those decisions rest on: such a login cannot be opened without an unlock that the server
 * answers. Over the real engine and a server that answers as told.
 */
class EnginePolicyCapturesTest {
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

    /** The platform's kept records, by name, kept across a restart. */
    private class Records : KeptStorage {
        val records = HashMap<String, InMemoryFillSnapshots>()
        val blobs = HashMap<String, InMemoryBlobs>()
        override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { InMemoryFillSnapshots() }
        override fun blobs(name: String): BlobStore = blobs.getOrPut(name) { InMemoryBlobs() }
    }

    /** [instance] with an honest item plane; its policy forbids the copy while [forbid]; [down]: no answer at all to anything. */
    private class Server(val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        var forbid = false
        var down = false
        var rev = 1L
        val taken = LinkedHashSet<String>()

        /** True: the items pushed are kept and served by a sync, as a real server does (false: a sync serves no item). */
        var keepsItems = false
        val items = ArrayList<io.silencelen.andvari.core.model.wire.SyncItem>()

        /** True: the policy's read gets no answer (everything else is answered). */
        var policyDown = false

        fun policy(forbids: Boolean): String = WireJson.json.encodeToString(
            ClientPolicy.serializer(),
            ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, !forbids, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false),
        )

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (down || (policyDown && route == WireRoute.CLIENT_POLICY)) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT, neverLeft = true)
            return when (route) {
                WireRoute.CLIENT_POLICY -> WireResult.Ok(decode(policy(forbid)), 200)
                WireRoute.SYNC -> {
                    val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val served = if (keepsItems) items.filter { it.rev > since } else emptyList()
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), served, emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> {
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                    val results = b.mutations.map { m ->
                        if (taken.add(m.mutationId)) {
                            rev++
                            items.removeAll { it.itemId == m.itemId }
                            val up = m.item
                            items += io.silencelen.andvari.core.model.wire.SyncItem(
                                m.itemId, m.vaultId, rev, instance.now, instance.now, m.op == io.silencelen.andvari.core.model.wire.MutationOp.DELETE, false,
                                up?.formatVersion ?: 1, up?.attachmentIds.orEmpty(), up?.blob,
                            )
                        }
                        MutationResult(m.mutationId, MutationStatus.APPLIED, rev)
                    }
                    WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
    }

    private class Env(
        val instance: FakeInstance, val server: Server, val files: Files, val state: MemoryDeviceState, val secure: MemoryDeviceState,
        val records: Records, val queue: InMemorySaveQueue, val app: EngineAppApi,
    )

    /** A process over [from]'s server, files and stores (a restart), or a first one. */
    private fun env(from: Env? = null): Env {
        val instance = from?.instance ?: FakeInstance(crypto)
        val server = from?.server ?: Server(instance)
        val files = from?.files ?: Files()
        val state = from?.state ?: MemoryDeviceState()
        val secure = from?.secure ?: MemoryDeviceState()
        val records = from?.records ?: Records()
        val queue = from?.queue ?: InMemorySaveQueue()
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(instance.origin to server)), state, secure, crypto,
                { instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files, keepsAtRest = { true }, contentStores = ContentStores(crypto, records, queue)),
        ).also { it.start() }
        return Env(instance, server, files, state, secure, records, queue, app)
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

    /** Every byte string on the phone: both stores, the content's kept records, the queue's key and entries. */
    private fun Env.everything(extra: List<ByteArray>): List<String> =
        secure.keys().map { secure.get(it)!! } + state.keys().map { state.get(it)!! } +
            records.records.values.mapNotNull { it.read()?.decodeToString() } +
            listOfNotNull(queue.publication()?.decodeToString()) + queue.entries().values.map { it.decodeToString() } +
            extra.map { it.decodeToString() }

    /** Catch a login as Android's autofill service does, while the app is locked. */
    private fun Env.capture(store: InMemorySaveQueue, site: String, password: String): SaveQueued =
        ContentCapture.queue(store, crypto, site, "me", password, instance.now)

    /**
     * The condition (the owner's decisions of 18 November rest on it): on a phone under a policy that forbids keeping
     * data, a caught login, caught before the wipe or after it, cannot be opened without an unlock the server answers.
     * At rest for the list: the sealed entries (sealed boxes to the account's identity key), the public half of that
     * key (the queue's publication), and nothing else of it: the secret half comes from the identity seed, sealed under
     * the account's key, which is wrapped under the master password; after the wipe the phone keeps neither the sealed
     * seed nor the wrap nor the salt, so they come only from the server at an unlock.
     */
    @Test fun aCaughtLoginCannotBeOpenedWithoutAnUnlockTheServerAnswers() = runBlocking<Unit> {
        val e = env()
        open(e.app)
        e.app.lock()
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        e.app.lock()
        val publication = assertNotNull(e.queue.publication(), "the public half is published for catches while locked")
        assertEquals(SaveQueued.QUEUED, e.capture(e.queue, "https://before.test", "pw-caught-before-77"))
        val before = e.queue.entries().values.single()

        // The policy forbids keeping data: the opening sends what waits and wipes the copy.
        e.server.forbid = true
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        e.app.policyWipe.running?.join()
        assertNotNull(e.app.snapshot.policyWipe)
        e.app.lock()

        // A login caught after the wipe, sealed to the same public half (into a store of its own, so that this holds
        // whatever the phone's queue keeps today).
        val after = InMemorySaveQueue().also { it.publish(publication) }
        assertEquals(SaveQueued.QUEUED, e.capture(after, "https://after.test", "pw-caught-after-88"))
        val afterEntry = after.entries().values.single()

        val a = e.account()
        val all = e.everything(listOf(before, afterEntry))
        for (v in all) {
            assertFalse("pw-caught-before-77" in v || "pw-caught-after-88" in v, "a caught password is in the clear on the phone")
            assertFalse(a.wrappedUvk in v || a.encryptedIdentitySeed in v, "the account's wrapped key or sealed seed is on the phone")
        }
        // The master password, at the server's own salt and cost (which the phone does not keep), opens no piece of
        // anything on the phone as the account's key, and so neither the seed nor any caught login.
        val keys = assertNotNull(PasswordKeys.derive(crypto, strong.toCharArray(), Bytes.fromB64(a.kdfSalt), a.kdfParams, served = true))
        for (p in all.flatMap { v -> Regex("[A-Za-z0-9+/_-]{40,}={0,2}").findAll(v).map { it.value }.toList() }) {
            assertNull(runCatching { Envelope.openB64(crypto, keys.wrapKey, p, Ad.uvk(a.userId)) }.getOrNull(), "a record opened to the account's key")
        }
        keys.wipe()
        // A restart over everything the phone keeps, with no server: no unlock, so nothing opens.
        e.server.down = true
        val again = env(e)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, again.app.unlockWith())
        assertEquals(AppPhase.LOCKED, again.app.snapshot.phase)
        // With the server answering, the unlock opens the account, and its identity key opens both caught logins.
        e.server.down = false
        assertEquals(VaultUnlockResult.DONE, again.app.unlockWith())
        val opened = assertNotNull(again.app.keeper.established).account
        for ((entry, pw) in listOf(before to "pw-caught-before-77", afterEntry to "pw-caught-after-88")) {
            val sealed = Bytes.fromB64(WireJson.json.decodeFromString(io.silencelen.andvari.core.app.QueuedSave.serializer(), entry.decodeToString()).sealed)
            assertTrue(pw in opened.openQueuedSave(crypto, sealed).decodeToString())
        }
        assertEquals(SaveQueue.VERSION, SaveQueue.decodePublication(publication)?.v)
    }

    /** Signed up, opened again (the copy at rest), locked; [before] caught while locked; then the policy forbids and its wipe is made at the next opening. Open at the end. */
    private suspend fun Env.wipedWith(vararg before: Pair<String, String>) {
        open(app)
        app.lock()
        assertEquals(VaultUnlockResult.DONE, app.unlockWith())
        app.lock()
        for ((site, pw) in before) assertEquals(SaveQueued.QUEUED, capture(queue, site, pw))
        // Recorded while locked, as a late answer of a read is; the next opening is the run's.
        app.policies.record(instance.origin, WireJson.json.decodeFromString(ClientPolicy.serializer(), server.policy(true)), instance.now)
        server.forbid = true
        assertEquals(VaultUnlockResult.DONE, app.unlockWith())
        app.policyWipe.running?.join()
        assertNotNull(app.snapshot.policyWipe, "the copy was removed")
        assertTrue(files.deleted.isNotEmpty())
    }

    /**
     * Caught before the wipe: the wipe leaves them and the key they are sealed to; the notice counts nothing for them;
     * the list is read at the unlock as without a policy (what needs no answer is saved, what needs one is asked).
     */
    @Test fun loginsCaughtBeforeTheWipeStayAndAreReadAsWithoutAPolicy() = runBlocking<Unit> {
        val e = env()
        e.wipedWith("https://auto.test" to "pw-auto-1", "ask.test" to "pw-ask-2")
        assertNotNull(e.queue.publication(), "the public half stays")
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertTrue(notice.lines.size <= 2)
        val c = assertNotNull(e.app.content)
        c.readSaveQueue()
        val st = c.state
        println("after the wipe: pending ${st.pendingSaves.map { it.host to it.reason }}, applied ${st.appliedSaves.map { it.host }}")
        assertTrue("ask.test" in st.pendingSaves.map { it.host }, "the one that needs an answer is asked")
        assertTrue(st.appliedSaves.any { it.host == "auto.test" } || st.pendingSaves.any { it.host == "auto.test" }, "the other is read too, never dropped")
        assertTrue(e.queue.entries().isNotEmpty(), "what is not answered stays in the list")
    }

    /**
     * Where the fault found in the test above lies: with a server that keeps what is pushed and serves it at a sync (as
     * a real one does), logins that need no answer are saved by themselves at the opening after the wipe (both of these
     * are new sites, so neither needs one). The test above's server serves no item at any sync, so the copy in memory,
     * which starts from a full sync after the wipe, never lists a new login and the save says it is gone: the double's
     * fault, not the opening's and not the content's save.
     */
    @Test fun loginsCaughtBeforeTheWipeThatNeedNoAnswerAreSavedByThemselvesAfterIt() = runBlocking<Unit> {
        val e = env()
        e.server.keepsItems = true
        e.wipedWith("https://auto.test" to "pw-auto-1", "ask.test" to "pw-ask-2")
        val c = assertNotNull(e.app.content)
        c.readSaveQueue()
        val st = c.state
        assertEquals(listOf("ask.test", "auto.test"), st.appliedSaves.map { it.host }.sorted(), "saved by themselves: pending ${st.pendingSaves.map { it.host to it.reason }}")
        assertEquals(emptyList(), st.pendingSaves.map { it.host })
        assertTrue(st.items.any { it.name == "auto.test" } && st.items.any { it.name == "ask.test" }, "and they are in the list")
        assertTrue(e.queue.entries().isEmpty(), "answered, so nothing stays in the list of caught logins")
    }

    /**
     * Caught after the wipe, while locked: the catch is taken as any catch (no refusal for the policy), it stays sealed,
     * and the next unlock (the server answering) reads it. Settings says that catches are kept sealed on the phone.
     */
    @Test fun aLoginCaughtAfterTheWipeIsKeptSealedAndReadAtTheNextUnlock() = runBlocking<Unit> {
        val e = env()
        e.wipedWith()
        assertEquals(io.silencelen.andvari.core.app.CopyKey.POLICY_CAPTURES_KEPT_SEALED, e.app.snapshot.account?.policy?.capturesKeptLine?.key)
        e.app.lock()
        assertEquals(SaveQueued.QUEUED, e.capture(e.queue, "later.test", "pw-later-3"), "the catch is not refused")
        val all = e.everything(emptyList())
        assertFalse(all.any { "pw-later-3" in it }, "sealed, never in the clear")
        e.server.down = true
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, e.app.unlockWith())
        assertEquals(1, e.queue.entries().size, "nothing removed without the server")
        e.server.down = false
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        val c = assertNotNull(e.app.content)
        c.readSaveQueue()
        assertEquals(listOf("later.test"), c.state.pendingSaves.map { it.host })
    }

    /** A caught login this account cannot open any more is said, with how many, never dropped without a word. */
    @Test fun aCaughtLoginThatCannotBeOpenedIsSaidAndCounted() = runBlocking<Unit> {
        val e = env()
        e.wipedWith()
        e.app.lock()
        val other = io.silencelen.andvari.core.app.QueuedSave(origin = e.instance.origin, userId = "11111111-2222-4333-8444-555555555555", sealed = Bytes.toB64(ByteArray(64) { it.toByte() }))
        assertTrue(e.queue.add("s-0123456789abcdef0123456789abcdef", WireJson.json.encodeToString(io.silencelen.andvari.core.app.QueuedSave.serializer(), other).encodeToByteArray()))
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        val c = assertNotNull(e.app.content)
        c.readSaveQueue()
        assertEquals(io.silencelen.andvari.core.app.content.ContentSaves.savesUnreadable(1), c.state.notice)
        // The line is the shared code's key for one, like every new line a person reads.
        assertEquals(CopyKey.CAPTURES_UNREADABLE_REMOVED_ONE.english, c.state.notice)
        assertEquals(0, e.queue.entries().size)
    }

    /**
     * The condition holds also where the phone's kept record of the policy can no longer be read: after the wipe, with
     * that record damaged, an unlock that gets the keys from the server but no answer to the policy's read keeps none of
     * them at rest (a record whose keys were at the server gets no wrapped key back until a READABLE policy that allows
     * it is kept), so a caught login still cannot be opened without the server. Once such a policy is kept, the next
     * unlock keeps the wrap again, and the device opens by itself.
     */
    @Test fun aPolicyRecordThatCannotBeReadBringsNoKeyBackAtRestUntilAReadableOneAllowsIt() = runBlocking<Unit> {
        val e = env()
        e.wipedWith()
        e.app.lock()
        assertEquals(SaveQueued.QUEUED, e.capture(e.queue, "https://after.test", "pw-caught-after-88"))
        val entry = e.queue.entries().values.single()
        val a = e.account()
        val origin = e.instance.origin

        // The phone's kept record of the policy becomes unreadable; the person unlocks while the server answers the
        // keys but not the policy's read.
        e.state.set(io.silencelen.andvari.core.client.session.KeptPolicies.KEY_PREFIX + origin, "{damaged")
        e.server.policyDown = true
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith(), "the server answered the keys")
        e.app.lock()

        // Every key and value of both stores: no wrapped key of the account, no salt for it, no sealed identity seed.
        for ((name, store) in listOf("secure" to e.secure, "state" to e.state)) {
            for (k in store.keys()) {
                val v = assertNotNull(store.get(k))
                println("at rest after the unlock: $name:$k")
                assertFalse(a.wrappedUvk in v, "$name:$k keeps the wrapped account key")
                assertFalse(a.kdfSalt in v, "$name:$k keeps the salt of the wrap")
                assertFalse(a.encryptedIdentitySeed in v, "$name:$k keeps the sealed identity seed")
                assertFalse(a.personalWrap!!.wrappedVk in v, "$name:$k keeps the personal vault's wrap")
            }
        }
        assertTrue("\"keysAtServer\":true" in assertNotNull(e.secure.get(io.silencelen.andvari.core.client.session.SessionKeeper.KEY)))
        // The master password at the server's own salt opens no piece of anything on the phone as the account's key.
        val keys = assertNotNull(PasswordKeys.derive(crypto, strong.toCharArray(), Bytes.fromB64(a.kdfSalt), a.kdfParams, served = true))
        for (p in e.everything(emptyList()).flatMap { v -> Regex("[A-Za-z0-9+/_-]{40,}={0,2}").findAll(v).map { it.value }.toList() }) {
            assertNull(runCatching { Envelope.openB64(crypto, keys.wrapKey, p, Ad.uvk(a.userId)) }.getOrNull(), "a record opened to the account's key")
        }
        keys.wipe()
        // Without the server there is no unlock: in this process after its lock, and after a restart.
        e.server.down = true
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, e.app.unlockWith(), "the lock left nothing that opens without the server")
        val again = env(e)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, again.app.unlockWith())
        assertEquals(AppPhase.LOCKED, again.app.snapshot.phase)
        assertNull(again.app.keeper.established, "nothing opened, so the caught login stays sealed")

        // The other direction: a readable policy that allows keeping is kept; the next unlock (which asks the server)
        // keeps the wrap again, and then the device opens by itself and opens the caught login.
        e.server.down = false
        e.server.policyDown = false
        e.server.forbid = false
        again.app.policies.record(origin, WireJson.json.decodeFromString(ClientPolicy.serializer(), e.server.policy(false)), e.instance.now)
        assertTrue("\"keysAtServer\":true" in assertNotNull(e.secure.get(io.silencelen.andvari.core.client.session.SessionKeeper.KEY)), "nothing comes back before an unlock")
        assertEquals(VaultUnlockResult.DONE, again.app.unlockWith())
        assertTrue(a.wrappedUvk in assertNotNull(e.secure.get(io.silencelen.andvari.core.client.session.SessionKeeper.KEY)), "the wrap is kept again")
        again.app.lock()
        e.server.down = true
        assertEquals(VaultUnlockResult.DONE, again.app.unlockWith(), "the device's own wrap opens again")
        val sealed = Bytes.fromB64(WireJson.json.decodeFromString(io.silencelen.andvari.core.app.QueuedSave.serializer(), entry.decodeToString()).sealed)
        assertTrue("pw-caught-after-88" in assertNotNull(again.app.keeper.established).account.openQueuedSave(crypto, sealed).decodeToString())
    }

    /**
     * The same rule at a sign-in: after the wipe, the kept record of the policy damaged and the session ended by its
     * server, the person signs in to the same account while the server answers the sign-in but not the policy's read.
     * The keys the sign-in brought stay off the device at rest, so a caught login still cannot be opened without the
     * server.
     */
    @Test fun aSignInWhileThePolicyRecordCannotBeReadBringsNoKeyBackAtRest() = runBlocking<Unit> {
        val e = env()
        e.wipedWith()
        e.app.lock()
        assertEquals(SaveQueued.QUEUED, e.capture(e.queue, "https://after.test", "pw-caught-after-88"))
        val a = e.account()
        val origin = e.instance.origin
        e.state.set(io.silencelen.andvari.core.client.session.KeptPolicies.KEY_PREFIX + origin, "{damaged")
        e.app.keeper.endedByServer(origin)
        e.server.policyDown = true

        e.app.signInAgain(assertNotNull(e.app.snapshot.locked))
        e.app.entry.openSignIn(e.app.at())
        e.app.entry.openPasswordSignIn(e.app.at())
        assertEquals(ServerResult.DONE, e.app.entry.chooseOwnServer(e.app.at(), origin))
        val form = e.app.snapshot.entry
        val signIn = if (form is EntryScreen.TrustGate) {
            assertEquals(ServerResult.DONE, e.app.entry.confirmTrustGate(form))
            e.app.at<EntryScreen.SignIn>()
        } else assertIs<EntryScreen.SignIn>(form)
        assertEquals(io.silencelen.andvari.core.app.SignInAnswer.DONE, e.app.entry.submitSignIn(signIn, "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, e.app.snapshot.phase)
        e.app.lock()

        // Every key and value of both stores: no wrapped key of the account, no salt for it, no sealed identity seed.
        for ((name, store) in listOf("secure" to e.secure, "state" to e.state)) {
            for (k in store.keys()) {
                val v = assertNotNull(store.get(k))
                println("at rest after the sign-in: $name:$k")
                assertFalse(a.wrappedUvk in v, "$name:$k keeps the wrapped account key")
                assertFalse(a.kdfSalt in v, "$name:$k keeps the salt of the wrap")
                assertFalse(a.encryptedIdentitySeed in v, "$name:$k keeps the sealed identity seed")
                assertFalse(a.personalWrap!!.wrappedVk in v, "$name:$k keeps the personal vault's wrap")
            }
        }
        assertTrue("\"keysAtServer\":true" in assertNotNull(e.secure.get(io.silencelen.andvari.core.client.session.SessionKeeper.KEY)))
        // Without the server there is no unlock: in this process after its lock, and after a restart; nothing opens.
        e.server.down = true
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, e.app.unlockWith(), "the lock left nothing that opens without the server")
        val again = env(e)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, again.app.unlockWith())
        assertNull(again.app.keeper.established, "nothing opened, so the caught login stays sealed")
        assertEquals(1, e.queue.entries().size, "the caught login stays")
    }
}
