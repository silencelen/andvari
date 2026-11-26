package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.SaveQueued
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.content.ContentCapture
import io.silencelen.andvari.core.app.content.ContentCopy
import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.app.content.KeptStorage
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
import io.silencelen.andvari.core.model.wire.Mutation
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.SignupPolicy
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Logins the Android app caught, after a server's policy that forbids keeping data on the device removed the copy
 * (they stay on the phone until the person answers them, decided on 2026-11-18), against a server whose item plane
 * stores what it is sent and serves it back at every sync, as a real server does. A caught login is sent at most once
 * however many unlocks follow; one that needs no answer is saved by itself; one that waits for the person's answer
 * shows as that; none is lost.
 */
class EngineCapturesAfterWipeTest {
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

    private class Records : KeptStorage {
        val records = HashMap<String, InMemoryFillSnapshots>()
        val blobs = HashMap<String, InMemoryBlobs>()
        override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { InMemoryFillSnapshots() }
        override fun blobs(name: String): BlobStore = blobs.getOrPut(name) { InMemoryBlobs() }
    }

    /**
     * [instance] with an item plane that keeps what it is sent and serves it back: every stored row at a sync from the
     * start, the rows changed since otherwise. A mutation it already took is answered again and stored once (the dedup
     * window). Its policy forbids the copy while [forbid].
     */
    private class Server(val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        var forbid = false

        /** Armed: the first sync after the next push gets no answer (the push itself is answered). */
        var cutPullAfterPush = false
        private var pullCut = false
        var rev = 1L
        val items = LinkedHashMap<String, SyncItem>()
        private val taken = HashMap<String, Long>()

        /** Every mutation received, replays included, in order. */
        val received = ArrayList<Mutation>()

        fun policy(forbids: Boolean): String = WireJson.json.encodeToString(
            ClientPolicy.serializer(),
            ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, !forbids, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false),
        )

        /** The puts this server stored for items other than [except], by item. */
        fun putsByItem(except: Set<String>): Map<String, Int> =
            received.filter { it.op == MutationOp.PUT && it.itemId !in except }.distinctBy { it.mutationId }.groupingBy { it.itemId }.eachCount()

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            return when (route) {
                WireRoute.CLIENT_POLICY -> WireResult.Ok(decode(policy(forbid)), 200)
                WireRoute.SYNC -> {
                    if (pullCut) {
                        pullCut = false
                        cutPullAfterPush = false
                        return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    }
                    val since = query?.substringAfter("since=")?.substringBefore('&')?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val rows = items.values.filter { since == 0L || it.rev > since }
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), rows, emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> {
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                    if (cutPullAfterPush) pullCut = true
                    val results = b.mutations.map { m ->
                        received += m
                        val at = taken.getOrPut(m.mutationId) {
                            rev++
                            items[m.itemId] = SyncItem(m.itemId, m.vaultId, rev, instance.now, instance.now, m.op == MutationOp.DELETE, false,
                                m.item?.formatVersion ?: 1, m.item?.attachmentIds.orEmpty(), m.item?.blob)
                            rev
                        }
                        MutationResult(m.mutationId, MutationStatus.APPLIED, at)
                    }
                    WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
    }

    private class Env(val instance: FakeInstance, val server: Server, val files: Files, val queue: InMemorySaveQueue, val app: EngineAppApi)

    private fun env(): Env {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val files = Files()
        val queue = InMemorySaveQueue()
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(instance.origin to server)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files, keepsAtRest = { true }, contentStores = ContentStores(crypto, Records(), queue)),
        ).also { it.start() }
        return Env(instance, server, files, queue, app)
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

    private suspend fun EngineAppApi.unlockWith() = unlock(snapshot.locked!!, strong)

    /**
     * Signed up; a login "Ask" for https://ask.test saved by the person; locked; two logins caught while locked: one for
     * a new site (`https://auto.test`, saved by itself) and one for ask.test without a scheme (it waits for the person:
     * andvari cannot tell which login it belongs to). Then the policy forbids keeping data and its wipe is made at the
     * next opening. Answers the id of "Ask".
     */
    private suspend fun Env.wiped(): String {
        open(app)
        app.lock()
        assertEquals(VaultUnlockResult.DONE, app.unlockWith())
        val c = assertNotNull(app.content)
        assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Ask", "me", "pw-ask-old", listOf("https://ask.test"), "", "", false), null))
        val ask = server.items.keys.single()
        app.lock()
        assertEquals(SaveQueued.QUEUED, ContentCapture.queue(queue, crypto, "https://auto.test", "me", "pw-auto-1", instance.now))
        assertEquals(SaveQueued.QUEUED, ContentCapture.queue(queue, crypto, "ask.test", "me", "pw-ask-2", instance.now))
        app.policies.record(instance.origin, WireJson.json.decodeFromString(ClientPolicy.serializer(), server.policy(true)), instance.now)
        server.forbid = true
        assertEquals(VaultUnlockResult.DONE, app.unlockWith())
        app.policyWipe.running?.join()
        assertNotNull(app.snapshot.policyWipe, "the copy was removed")
        assertTrue(files.deleted.isNotEmpty())
        return ask
    }

    /** What the person sees of the caught logins, as "host: reason" ("saved" for one saved by itself). */
    private fun Env.shown(): List<String> {
        val st = assertNotNull(app.content).state
        return st.pendingSaves.map { "${it.host}: ${it.reason}" } + st.appliedSaves.map { "${it.host}: saved" }
    }

    @Test fun caughtLoginsAfterTheWipeAreSentOnceAndShownAsTheyAre() = runBlocking<Unit> {
        val e = env()
        val ask = e.wiped()
        val trace = ArrayList<String>()
        fun step(at: String) {
            trace += "$at: shown ${e.shown()}, stored puts ${e.server.putsByItem(setOf(ask))}, sent ${e.server.received.size}, queue ${e.queue.entries().size}"
        }
        step("the wipe's opening")
        repeat(3) { n ->
            e.app.lock()
            assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
            step("unlock ${n + 1}")
            trace += "  sync: ${assertNotNull(e.app.content).syncQuietly()}"
            step("unlock ${n + 1}, after a sync")
        }
        println(trace.joinToString("\n"))
        val puts = e.server.putsByItem(setOf(ask))
        // The one that needs no answer was saved by itself, once: one new item at the server, one put for it.
        assertEquals(1, puts.size, "one new login at the server, never a second one: $trace")
        assertEquals(1, puts.values.single(), "it was sent once: $trace")
        // The person's own login was never changed by a catch that waits for the person.
        assertEquals(1, e.server.received.count { it.itemId == ask }, "only the person's own save of Ask: $trace")
        val shown = e.shown()
        assertTrue("auto.test: saved" in shown, "the new login is listed as saved by itself: $trace")
        val waiting = shown.filter { it.startsWith("ask.test") }
        assertEquals(1, waiting.size, "the one that needs an answer is listed: $trace")
        assertTrue(shown.none { it.endsWith(ContentCopy.ITEM_GONE) }, "never \"no longer here\": $trace")
        assertEquals(1, e.queue.entries().size, "the one that waits stays in the list, nothing else: $trace")
    }

    /**
     * The server took a caught login, and the read after it got no answer, so the login is not in the list yet: it was
     * saved, so it is never said as "no longer here", it is never written again while it waits to show, and the next
     * read lists it as saved. One login at the server, sent once.
     */
    @Test fun aCaughtLoginTheServerTookIsNeverSaidAsGoneNorSentAgainWhenTheReadAfterItGetsNoAnswer() = runBlocking<Unit> {
        val e = env()
        val ask = e.wiped()
        val before = e.server.putsByItem(setOf(ask)).keys
        e.app.lock()
        assertEquals(SaveQueued.QUEUED, ContentCapture.queue(e.queue, crypto, "https://late.test", "me", "pw-late-3", e.instance.now))
        e.server.cutPullAfterPush = true
        val trace = ArrayList<String>()
        fun step(at: String) {
            trace += "$at: shown ${e.shown()}, stored puts ${e.server.putsByItem(setOf(ask) + before)}, sent ${e.server.received.size}, queue ${e.queue.entries().size}"
        }
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        step("unlock 1")
        assertTrue(e.shown().none { it.endsWith(ContentCopy.ITEM_GONE) }, "the server took it: never \"no longer here\": $trace")
        assertEquals(listOf(1), e.server.putsByItem(setOf(ask) + before).values.toList(), "sent once: $trace")
        // A read of the list while it waits to show writes nothing again.
        assertNotNull(e.app.content).readSaveQueue()
        step("unlock 1, the list read again")
        repeat(2) { n ->
            e.app.lock()
            assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
            trace += "  sync: ${assertNotNull(e.app.content).syncQuietly()}"
            step("unlock ${n + 2}")
        }
        println(trace.joinToString("\n"))
        val late = e.server.putsByItem(setOf(ask) + before)
        assertEquals(1, late.size, "one new login at the server: $trace")
        assertEquals(1, late.values.single(), "sent once: $trace")
        assertTrue("late.test: saved" in e.shown(), "listed as saved: $trace")
        assertTrue(e.shown().none { it.endsWith(ContentCopy.ITEM_GONE) }, "$trace")
        assertEquals(1, e.queue.entries().size, "only the one that waits for the person stays: $trace")
    }
}
