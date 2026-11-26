package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.items.BellLink
import io.silencelen.andvari.core.client.items.BellSocket
import io.silencelen.andvari.core.client.items.BellState
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.EventFrame
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
 * The event bell told lies it understands (spec 03 §6), against the app's real glue (`EngineVault.startBell` and
 * `EngineAppApi.bellRevoked`), which the hostile bench cannot reach: its headless host has no bell glue. The socket is
 * a scripted one in place of the dialer's; the ticket and every sync go to the fake instance.
 */
class EngineBellLiesTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Files : VaultCacheFiles {
        val deleted = ArrayList<String>()
        val caches = ArrayList<InMemoryVaultCache>()
        override fun open(fileName: String, userId: String): VaultCache = InMemoryVaultCache().also { caches += it }
        override fun delete(fileName: String): Boolean {
            deleted += fileName
            return true
        }
    }

    /** A bell socket that plays [frames] after the client's ping, then holds the socket open until it is closed. */
    private class Bell(private val frames: List<String>) : BellSocket {
        override suspend fun <T> open(origin: String, ticket: String, block: suspend (BellLink) -> T): T? {
            val left = ArrayDeque(frames)
            return block(object : BellLink {
                override suspend fun send(text: String): Boolean = true
                override suspend fun receive(): String? = left.removeFirstOrNull() ?: kotlinx.coroutines.awaitCancellation()
            })
        }
    }

    private class Env(val server: FakeInstance, val transport: BearerTransport, val files: Files, val app: EngineAppApi)

    private fun env(bell: BellSocket?, state: MemoryDeviceState = MemoryDeviceState()): Env {
        val server = FakeInstance(crypto)
        server.override[WireRoute.EVENTS_TICKET] = WireResult.Ok("""{"ticket":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","expiresInSeconds":30}""", 200)
        val files = Files()
        val transport = BearerTransport(mapOf(server.origin to server)).also { t -> bell?.let { t.bell = it } }
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", transport, state, MemoryDeviceState(), crypto,
                { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files),
        ).also { it.start() }
        return Env(server, transport, files, app)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Typed address, Trust Gate, sign-up, kit: the vault is open. */
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
    }

    private fun Env.syncs() = server.calls.count { it == WireRoute.SYNC }

    /** A bell socket that hands up each frame the test sends, when it sends it, and holds the socket open meanwhile. */
    private class StagedBell(private val frames: kotlinx.coroutines.channels.Channel<String>) : BellSocket {
        override suspend fun <T> open(origin: String, ticket: String, block: suspend (BellLink) -> T): T? = block(object : BellLink {
            override suspend fun send(text: String): Boolean = true
            override suspend fun receive(): String? = frames.receive()
        })
    }

    /** Every pull is answered at rev [rev] (the fake instance serves no sync of its own), so the opening learns that rev. */
    private fun Env.syncAnswersAt(rev: Long) {
        val personal = assertNotNull(app.keeper.established!!.account.personalVaultId)
        server.override[WireRoute.SYNC] = WireResult.Ok(io.silencelen.andvari.core.model.wire.WireJson.json.encodeToString(
            io.silencelen.andvari.core.model.wire.SyncResponse.serializer(),
            io.silencelen.andvari.core.model.wire.SyncResponse(rev, false, listOf(io.silencelen.andvari.core.model.wire.SyncVault(personal, "personal", 1, "", server.now)),
                emptyList(), emptyList(), emptyList(), emptyList(), 0, 0)), 200)
    }

    /** Waits until the syncs settle, then asserts there are [n]. */
    private suspend fun Env.settlesAt(n: Int, why: String) {
        kotlinx.coroutines.withTimeout(10_000) { while (syncs() < n) kotlinx.coroutines.delay(5) }
        kotlinx.coroutines.delay(100)
        assertEquals(n, syncs(), why)
    }

    private fun rev(r: Long) = """{"type":"rev","rev":$r}"""

    /**
     * A number that goes backwards (an older ring, replayed or reordered) costs no pull. Since H12 the bar is the rev a
     * pull of this opening was ANSWERED at, never a ring's own number (`AnsweredRev`): every ring at or below it costs
     * nothing, in whatever order it comes. (This test was first written against the old bar, the highest rev rung, with every
     * frame at once; it now hands the frames up one at a time and answers the pull at a known rev.)
     */
    @Test fun aRingWhoseNumberGoesBackwardsCostsNoPull() = runBlocking<Unit> {
        val frames = kotlinx.coroutines.channels.Channel<String>(kotlinx.coroutines.channels.Channel.UNLIMITED)
        val e = env(StagedBell(frames))
        open(e.app)
        e.syncAnswersAt(5)
        val start = e.syncs()
        frames.send(EventFrame.PONG)
        e.settlesAt(start + 1, "the registered open pulls, answered at rev 5")
        assertEquals(BellState.OPEN, assertNotNull(e.app.vault?.bell).state)
        for (r in listOf(5L, 3L, 4L, 5L)) frames.send(rev(r))
        e.settlesAt(start + 1, "rev 5, 3, 4 and 5 again pull nothing")
        frames.send(rev(6))
        e.settlesAt(start + 2, "a ring above the answered rev pulls")
    }

    /**
     * Hostile-server finding B1 (app interface, `EngineVault.startBell`): a ring that carries ANOTHER account's number (any number far
     * above this account's own) was taken as the bar, and every later honest ring at or below it was ignored until the
     * vault opened again. The lie: after registration, `{"type":"rev","rev":1000000000000}`, then the honest `rev` 6 and
     * 7. Fixed by `AnsweredRev`: a ring is measured against the highest rev a pull or a push of this opening was
     * ANSWERED at, which a ring never raises, so a lying number costs one pull and each honest ring after it pulls again.
     *
     * The test first sent all four frames at once and counted a sync per ring. H12 (coalescing: rings that arrive while a sync
     * runs cost one more sync after it, never one each) makes that count 2 on any handler that is right, so the frames
     * now come one at a time, each after the last pull settled. On the old handler 6 and 7 pull nothing.
     */
    @Test fun aRingWithAnotherAccountsNumberNeverStopsLaterRingsFromPulling() = runBlocking<Unit> {
        val frames = kotlinx.coroutines.channels.Channel<String>(kotlinx.coroutines.channels.Channel.UNLIMITED)
        val e = env(StagedBell(frames))
        open(e.app)
        e.syncAnswersAt(5)
        val start = e.syncs()
        frames.send(EventFrame.PONG)
        e.settlesAt(start + 1, "the registered open pulls")
        frames.send(rev(1_000_000_000_000))
        e.settlesAt(start + 2, "the lie costs one pull")
        frames.send(rev(6))
        e.settlesAt(start + 3, "an honest ring after the lie pulls")
        frames.send(rev(7))
        e.settlesAt(start + 4, "and the next")
    }

    /**
     * A `revoked` frame for a device the server did not revoke: the bell cannot tell (the server may end a session at
     * will), so the session ends as the server's own end, and that end never deletes the device's copy (design §4.4 "A
     * session the server ends does not delete the device's copy"): no cache file is deleted, nothing is said to the
     * server, the session is kept marked ended by the server (sign in again opens the same copy), and nothing derived
     * from the account's keys is sent after it.
     */
    @Test fun aRevokedFrameForADeviceThatIsNotRevokedEndsTheSessionAndKeepsTheCopy() = runBlocking<Unit> {
        val e = env(null)
        val a = e.app
        open(a)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        a.lock()
        val before = e.server.calls.size
        val deletedBefore = e.files.deleted.toList()
        e.transport.bell = Bell(listOf(EventFrame.PONG, """{"type":"revoked"}"""))
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val kept = assertNotNull(a.keeper.session, "the session is kept, marked as the server's end")
        assertTrue(kept.endedByServer)
        assertEquals(deletedBefore, e.files.deleted, "no copy is deleted by the server's end (before it: $deletedBefore)")
        val after = e.server.calls.drop(before)
        assertTrue(WireRoute.LOGOUT !in after, "nothing is said to the server: $after")
        assertTrue(after.none { it == WireRoute.PUSH || it == WireRoute.LOG_APPEND || it == WireRoute.ACCOUNT_STATE_PUT }, "nothing sealed is sent: $after")
    }

    /** A platform socket that fails to open while [opens] is false, then opens and answers the client's ping. */
    private class Platform : io.silencelen.andvari.core.client.net.PlatformBellSocket {
        @kotlin.concurrent.Volatile var opens = false
        var asked = 0

        override suspend fun <T> connect(url: String, headers: Map<String, String>, maxMessageBytes: Int, block: suspend (BellLink) -> T): T {
            asked++
            if (!opens) throw IllegalStateException("network is unreachable")
            var ponged = false
            return block(object : BellLink {
                override suspend fun send(text: String): Boolean = true
                override suspend fun receive(): String? = if (!ponged) EventFrame.PONG.also { ponged = true } else kotlinx.coroutines.awaitCancellation()
            })
        }
    }

    /**
     * The app's side: live updates that cannot connect are told, as one quiet line on the open vault
     * (`AccountSnapshot.liveUpdates`), from the dialer's own socket; the line goes the moment a socket opens, and a lock
     * ends it with the vault. Before, the app kept only the bell and showed nothing.
     */
    @Test fun liveUpdatesThatCannotConnectAreOneQuietLineThatGoesWhenASocketOpens() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        val platform = Platform()
        val http = io.ktor.client.HttpClient(io.ktor.client.engine.mock.MockEngine { error("the platform's socket is the one used") })
        val socket = io.silencelen.andvari.core.client.net.Dialer(io.silencelen.andvari.core.client.pin.PinStore(state), http, "android", platform)
            .bellSocket("https://h.example")
        val e = env(socket, state)
        val a = e.app
        open(a)
        assertTrue(platform.asked >= 1, "the bell dialed")
        val off = assertNotNull(a.snapshot.account).liveUpdates
        assertTrue(off.running)
        assertFalse(off.connected)
        assertEquals(io.silencelen.andvari.core.app.LiveUpdatesTrouble.NOT_OPENED, off.trouble)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.LIVE_UPDATES_NOT_CONNECTED, off.line?.key)

        platform.opens = true
        a.returnedToForeground()
        kotlinx.coroutines.withTimeout(10_000) { while (!assertNotNull(a.snapshot.account).liveUpdates.connected) kotlinx.coroutines.delay(10) }
        val on = assertNotNull(a.snapshot.account).liveUpdates
        assertTrue(on.running && on.connected)
        assertNull(on.trouble)
        assertNull(on.line, "no line while connected")

        a.lock()
        assertNull(a.snapshot.account, "a lock ends the vault, its bell and the line")
        kotlinx.coroutines.withTimeout(10_000) { while (socket.connected.value) kotlinx.coroutines.delay(10) }
    }

    /**
     * A network that comes back tells live updates alone ([EngineAppApi.networkReturned]). A
     * bell waiting on its ladder dials at once and connects, and nothing else is sent (no sync, no save, no read of the
     * save queue). While locked it does nothing: no dial.
     */
    @Test fun aNetworksReturnDialsTheWaitingBellAloneAndNothingWhileLocked() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        val platform = Platform()
        val http = io.ktor.client.HttpClient(io.ktor.client.engine.mock.MockEngine { error("the platform's socket is the one used") })
        val socket = io.silencelen.andvari.core.client.net.Dialer(io.silencelen.andvari.core.client.pin.PinStore(state), http, "android", platform)
            .bellSocket("https://h.example")
        val e = env(socket, state)
        val a = e.app
        open(a)
        kotlinx.coroutines.withTimeout(10_000) { while (platform.asked < 1) kotlinx.coroutines.delay(10) }
        assertFalse(assertNotNull(a.snapshot.account).liveUpdates.connected)
        val before = e.server.calls.size
        val dials = platform.asked
        platform.opens = true
        a.networkReturned()
        kotlinx.coroutines.withTimeout(10_000) { while (!assertNotNull(a.snapshot.account).liveUpdates.connected) kotlinx.coroutines.delay(10) }
        assertTrue(platform.asked > dials, "the waiting bell dialed at once")
        // The bell's ticket, and what the bell itself asks for once connected (a pull, with its card check); nothing
        // sealed or written.
        val after = e.server.calls.drop(before)
        assertTrue(after.all { it == WireRoute.EVENTS_TICKET || it == WireRoute.SYNC || it == WireRoute.INSTANCE }, "only the bell's own reads: $after")

        a.lock()
        kotlinx.coroutines.withTimeout(10_000) { while (socket.connected.value) kotlinx.coroutines.delay(10) }
        val locked = platform.asked
        val calls = e.server.calls.size
        a.networkReturned()
        kotlinx.coroutines.delay(50)
        assertEquals(locked, platform.asked, "locked: no dial")
        assertEquals(calls, e.server.calls.size, "locked: nothing sent")
    }
}
