package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PolicyWipeNotice
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
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.ClientPolicy
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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * One run, one request per change, at an opening that records a newly forbidding policy (decided on 2026-11-17: the
 * device tries ONCE to send what waits before it removes its copy). The opening's own sync sends what waits; when the
 * forbidding policy is recorded while that request is still out, the policy's attempt waits for it: answered (taken or
 * refused), its changes are counted by that answer and not sent again; ended without an answer, they get the attempt's
 * one try with the rest, and are counted "not sent" only where the server answered for them that it did not take them
 * (the earlier request may have arrived). Over the real engine and a server that holds a push until the test lets it go.
 */
class EnginePolicyOneRequestTest {
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

    /**
     * [instance] with an item plane that keeps what it is pushed (each change once, by its id) and serves it back. [down]:
     * no answer to a sync or a push. Each push
     * is logged with the ids it carried, and push n waits for [hold] (n) when one is set; then [answer] (n) says how it is
     * answered: taken (null), no answer, or a refusal with that status.
     */
    private class Server(val instance: FakeInstance) : WireClient by instance {
        var forbid = false
        var down = false
        val hold = HashMap<Int, CompletableDeferred<Unit>>()
        var answer: (Int) -> Int? = { null }
        var rev = 1L
        val items = LinkedHashMap<String, SyncItem>()
        private val taken = HashMap<String, Long>()

        /** Each call's route, a push with its number and the ids it carried. */
        val calls = ArrayList<String>()
        val pushes = ArrayList<List<String>>()

        /** What the app's state was as each push arrived (whether the policy's wipe was owed then). */
        var seenAtPush: () -> String = { "" }

        fun policy(forbids: Boolean): String = WireJson.json.encodeToString(
            ClientPolicy.serializer(),
            ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, !forbids, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false),
        )

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route != WireRoute.PUSH) calls += route.name + if (down && route == WireRoute.SYNC) "(down)" else ""
            return when (route) {
                WireRoute.CLIENT_POLICY -> WireResult.Ok(decode(policy(forbid)), 200)
                WireRoute.SYNC -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                    val since = query?.substringAfter("since=")?.substringBefore('&')?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val rows = items.values.filter { since == 0L || it.rev > since }
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), rows, emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> {
                    if (down) {
                        calls += "PUSH(down)"
                        return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    }
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                    val n = pushes.size
                    pushes += b.mutations.map { it.mutationId }
                    calls += "PUSH#$n${b.mutations.map { it.mutationId.take(4) }}${seenAtPush()}"
                    hold[n]?.await()
                    val refusal = answer(n)
                    when {
                        refusal == null -> {}
                        refusal == 0 -> return WireResult.NoAnswer(NoAnswerKind.TIMEOUT)
                        else -> return WireResult.Refused(refusal, io.silencelen.andvari.core.model.wire.WireError("unavailable", "unavailable"))
                    }
                    val results = b.mutations.map { m ->
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

    private class Env(val instance: FakeInstance, val server: Server, val files: Files, val app: EngineAppApi)

    private fun env(): Env {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val files = Files()
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(instance.origin to server)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files, keepsAtRest = { true }),
        ).also { it.start() }
        server.seenAtPush = {
            val s = app.keeper.session
            if (s == null) "" else "(owed=${app.policyWipe.owed(s.origin, s.userId)},run=${app.policyWipe.running?.isActive == true})"
        }
        return Env(instance, server, files, app)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry)

    private inline fun <reified T> assertIs(v: Any?): T = kotlin.test.assertIs<T>(v, "on $v")

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

    private suspend fun EngineAppApi.unlockWith() = assertEquals(VaultUnlockResult.DONE, unlock(snapshot.locked!!, strong))

    private fun login(name: String) = LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false)

    /**
     * Signed up, opened again with the copy at rest, two logins saved while the server could not be reached (they wait),
     * locked. Then the server answers again and its policy forbids keeping data: the next opening's own sync sends what
     * waits, and that first push is held until the policy is recorded (by the opening's read of it, or [late] by a read
     * after the opening), then answered as [firstAnswer] says. Answers the notice.
     */
    private suspend fun Env.twoWaitingThenForbidden(firstAnswer: Int?, late: Boolean = false, outlasts: Boolean = false, laterAnswer: Int? = null): PolicyWipeNotice {
        app.policyWipe.requestMs = 1_000
        open(app)
        app.lock()
        app.unlockWith()
        val c = assertNotNull(app.content)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        server.down = true
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("one"), null))
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("two"), null))
        assertTrue(server.pushes.isEmpty(), "nothing reached the server yet: ${server.calls}")
        app.lock()
        // The server answers again: the opening's own sync sends what waits, and its request is held.
        server.down = false
        // Recorded by the opening's own read of the policy, or (late) by a read after the opening.
        server.forbid = !late
        val gate = CompletableDeferred<Unit>()
        server.hold[0] = gate
        server.answer = { if (it == 0) firstAnswer else laterAnswer }
        server.calls.clear()
        app.unlockWith()
        assertTrue(server.calls.any { it.startsWith("PUSH#0") && it.endsWith("(owed=false,run=false)") },
            "the opening's own sync sent what waits before the policy was recorded: ${server.calls}")
        if (late) {
            server.forbid = true
            app.policies.fetch(app.clientFor(instance.origin), instance.now)
        }
        if (outlasts) {
            // The request stays out past one request's limit: the run does not wait longer for it.
            app.policyWipe.running?.join()
            gate.complete(Unit)
        } else {
            gate.complete(Unit)
            app.policyWipe.running?.join()
        }
        assertTrue(files.deleted.isNotEmpty(), "the copy was removed: ${server.calls}")
        return assertNotNull(app.snapshot.policyWipe, "the notice: ${server.calls}")
    }

    /** Every change reached the server in exactly one request. */
    private fun Env.onceEach() {
        val all = server.pushes.flatten()
        assertEquals(2, all.distinct().size, "two changes: ${server.calls}")
        assertEquals(all.distinct(), all, "each change in one request only: ${server.calls}")
    }

    /**
     * The opening's sync sends what waits; the forbidding policy is recorded while that request is out; the request is
     * then taken. The attempt sends nothing again, and the two changes are counted as sent.
     */
    @Test fun aRequestOutWhenThePolicyIsRecordedIsNotSentAgainAndCountsAsTaken() = runBlocking<Unit> {
        val e = env()
        val notice = e.twoWaitingThenForbidden(firstAnswer = null)
        e.onceEach()
        assertEquals(0, notice.notSent, "nothing is lost: ${e.server.calls}")
        assertEquals(0, notice.unsure, "nothing in doubt: ${e.server.calls}")
        assertEquals(2, e.server.items.size)
    }

    /**
     * The same, and the request out dies without an answer (a connection that died while the device slept): its changes
     * still get the attempt's one try, which delivers them; all counted as sent.
     */
    @Test fun aRequestOutThatDiesLeavesItsChangesToTheAttemptWhichDeliversThem() = runBlocking<Unit> {
        val e = env()
        val notice = e.twoWaitingThenForbidden(firstAnswer = 0)
        assertEquals(2, e.server.pushes.size, "the dead request, then the attempt's: ${e.server.calls}")
        assertEquals(2, e.server.items.size, "both delivered")
        assertEquals(0, notice.unsure, "${e.server.calls}")
        assertEquals(0, notice.notSent, "${e.server.calls}")
    }

    /**
     * The request out dies, and the attempt's own first request dies too: the changes may or may not have arrived (never
     * "not sent"), and the pass ends there.
     */
    @Test fun aRequestOutThatDiesAndTheAttemptsRequestThatDiesTooAreMayHaveArrived() = runBlocking<Unit> {
        val e = env()
        val notice = e.twoWaitingThenForbidden(firstAnswer = 0, laterAnswer = 0)
        assertEquals(2, e.server.pushes.size, "${e.server.calls}")
        assertEquals(2, notice.unsure, "${e.server.calls}")
        assertEquals(0, notice.notSent, "${e.server.calls}")
    }

    /**
     * The request out dies, and the attempt's request is refused as a whole: the server said nothing of each change, and
     * the earlier request may have arrived, so they may or may not have arrived; never "not sent".
     */
    @Test fun aRequestOutThatDiesAndTheAttemptsRequestRefusedAsAWholeAreMayHaveArrivedNeverNotSent() = runBlocking<Unit> {
        val e = env()
        val notice = e.twoWaitingThenForbidden(firstAnswer = 0, laterAnswer = 503)
        assertEquals(2, e.server.pushes.size, "${e.server.calls}")
        assertEquals(2, notice.unsure, "${e.server.calls}")
        assertEquals(0, notice.notSent, "${e.server.calls}")
    }

    /**
     * The policy is recorded by a read after the opening: the opening's own sync has sent what waits and its request is
     * out. The attempt does not send the same changes again; the request is taken, and they count as sent.
     */
    @Test fun aRequestOfTheOpeningsSyncOutWhenALaterReadRecordsThePolicyIsNotSentAgain() = runBlocking<Unit> {
        val e = env()
        val notice = e.twoWaitingThenForbidden(firstAnswer = null, late = true)
        e.onceEach()
        assertEquals(0, notice.notSent, "nothing is lost: ${e.server.calls}")
        assertEquals(0, notice.unsure, "nothing in doubt: ${e.server.calls}")
    }

    /** The same, and that request dies without an answer: the attempt's one try delivers its changes. */
    @Test fun aRequestOfTheOpeningsSyncOutWhenALaterReadRecordsThePolicyThatDiesLeavesItsChangesToTheAttempt() = runBlocking<Unit> {
        val e = env()
        val notice = e.twoWaitingThenForbidden(firstAnswer = 0, late = true)
        assertEquals(2, e.server.pushes.size, "${e.server.calls}")
        assertEquals(2, e.server.items.size, "both delivered")
        assertEquals(0, notice.unsure, "${e.server.calls}")
        assertEquals(0, notice.notSent, "${e.server.calls}")
    }

    /** The same, and that request is refused: not sent, and the attempt does not send them again. */
    @Test fun aRequestOfTheOpeningsSyncOutWhenALaterReadRecordsThePolicyThatIsRefusedIsNotSentAgain() = runBlocking<Unit> {
        val e = env()
        val notice = e.twoWaitingThenForbidden(firstAnswer = 503, late = true)
        assertEquals(1, e.server.pushes.size, "one request: ${e.server.calls}")
        assertEquals(2, notice.notSent, "${e.server.calls}")
        assertEquals(0, notice.unsure, "${e.server.calls}")
    }

    /**
     * The request of the opening's sync is still out when one request's limit has passed since the attempt began: the
     * attempt waits no longer, and its own one try delivers the changes; all counted as sent.
     */
    @Test fun aRequestOutPastOneRequestsLimitLeavesItsChangesToTheAttempt() = runBlocking<Unit> {
        val e = env()
        val notice = e.twoWaitingThenForbidden(firstAnswer = null, outlasts = true)
        assertEquals(2, e.server.pushes.size, "${e.server.calls}")
        assertEquals(2, e.server.items.size, "both delivered")
        assertEquals(0, notice.unsure, "${e.server.calls}")
        assertEquals(0, notice.notSent, "${e.server.calls}")
    }

    /** The same, and the request out is refused (the server is unavailable): not sent, and not sent again by the attempt. */
    @Test fun aRequestOutWhenThePolicyIsRecordedThatIsRefusedIsNotSentAndNotTriedAgain() = runBlocking<Unit> {
        val e = env()
        val notice = e.twoWaitingThenForbidden(firstAnswer = 503)
        assertEquals(1, e.server.pushes.size, "one request: ${e.server.calls}")
        assertEquals(2, notice.notSent, "${e.server.calls}")
        assertEquals(0, notice.unsure, "${e.server.calls}")
    }
}
