package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.app.engine.VaultCacheFiles
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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Over the shared code's REAL implementation ([EngineAppApi] over [AppEngine]) and its own test server ([FakeInstance]),
 * with an item plane in front that answers as told, each walk driven through this app's model as the screens drive it:
 *
 * - a server's policy that forbids a copy on devices, from its arrival through the removal (the line where a stopped
 *   server's would be, Save offered, a change refused with that line, the editor's opening kept while the shared code
 *   composes the vault again) to the notice, across a lock and an unlock, and its dismissal, not said again at a restart;
 * - the notice where the server took the changes and its answer never came (they may or may not have arrived);
 * - a move's notes, kept at rest by the shared code, drawn with their lines and their member, and dismissed.
 */
class PolicyWipeEngineWalksTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"

    /** Cache files in memory that answer as durable (the copy is "at rest"), as the phone's database files are. */
    private class Files : VaultCacheFiles {
        val caches = HashMap<String, VaultCache>()
        val deleted = ArrayList<String>()
        override fun open(fileName: String, userId: String): VaultCache =
            caches.getOrPut(fileName) { object : VaultCache by InMemoryVaultCache() { override val durable: Boolean get() = true } }

        override fun delete(fileName: String): Boolean {
            deleted += fileName
            caches.remove(fileName)
            return true
        }
    }

    /**
     * [instance] with an honest item plane: the personal vault's row, the items pushed, each change taken once by its id,
     * and a policy that allows the copy until [forbid]. [down]: no answer to a sync or a push. [pushGate]: every push is
     * taken and its answer waits for it. [pushUnanswered]: a push is taken and no answer comes.
     */
    private class PlaneServer(private val instance: FakeInstance) : WireClient by instance {
        var down = false

        /** The network comes back with the next policy read (so the opening's own sync does not send what waits first). */
        var upAfterPolicy = false
        var forbid = false
        var pushGate: CompletableDeferred<Unit>? = null
        var pushUnanswered = false
        var rev = 1L
        val items = ArrayList<SyncItem>()
        val taken = LinkedHashSet<String>()

        private fun policy(forbids: Boolean): String = WireJson.json.encodeToString(
            ClientPolicy.serializer(),
            ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, !forbids, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false),
        )

        /** Each call's route, with "(down)" where it got no answer for that. */
        val calls = ArrayList<String>()

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            also { calls += route.name + if (down && (route == WireRoute.SYNC || route == WireRoute.PUSH)) "(down)" else "" }.let { _ -> answer(route, pathParams, query, bodyJson, authenticated, decode) }

        private suspend fun <T> answer(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            when (route) {
                WireRoute.CLIENT_POLICY -> {
                    if (upAfterPolicy) down = false
                    WireResult.Ok(decode(policy(forbid)), 200)
                }
                WireRoute.SYNC -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                    val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), items.filter { it.rev > since }, emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                    val results = b.mutations.map { m ->
                        if (taken.add(m.mutationId)) {
                            rev++
                            items.removeAll { it.itemId == m.itemId }
                            val up = m.item
                            items += SyncItem(m.itemId, m.vaultId, rev, instance.now, instance.now, m.op == MutationOp.DELETE, false,
                                up?.formatVersion ?: 1, up?.attachmentIds.orEmpty(), up?.blob)
                        }
                        MutationResult(m.mutationId, MutationStatus.APPLIED, rev)
                    }
                    pushGate?.await()
                    if (pushUnanswered) WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    else WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
    }

    private class Phone(val state: MemoryDeviceState = MemoryDeviceState(), val secure: MemoryDeviceState = MemoryDeviceState(), val files: Files = Files())

    private val opened = ArrayList<EngineAppApi>()

    private fun app(instance: FakeInstance, server: PlaneServer, phone: Phone): EngineAppApi = EngineAppApi(
        AppEngine(
            AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(instance.origin to server)), phone.state, phone.secure, crypto, { instance.now },
            baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
            cacheFiles = phone.files, keepsAtRest = { true },
        ),
    ).also { opened += it }

    private fun model(api: EngineAppApi): TrustModel =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }).also {
            it.start()
            it.onSnapshot(api.snapshot)
        }

    private fun walk(body: suspend () -> Unit) = try {
        runBlocking { body() }
    } finally {
        opened.forEach { runCatching { it.close() } }
    }

    private inline fun <reified T : EntryScreen> AppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private fun <R : IntentResult> TrustModel.done(intent: suspend AppApi.() -> R): R {
        var result: R? = null
        runBlocking { run(intent) { result = it }.join() }
        onSnapshot(api.snapshot)
        return assertNotNull(result, "the intent ended without a result: ${wentWrong.value?.text}")
    }

    private fun TrustModel.step(intent: AppApi.() -> Unit) {
        act(intent)
        onSnapshot(api.snapshot)
    }

    /** A new account for [email] through the first screens, its kit typed back: the vault open. */
    private fun TrustModel.register(email: String) {
        step { entry.openOwnServer(at()) }
        assertEquals(ServerResult.DONE, done { entry.submitServerAddress(at(), "h.example") })
        (api.snapshot.entry as? EntryScreen.TrustGate)?.let { gate -> assertEquals(ServerResult.DONE, done { entry.confirmTrustGate(gate) }) }
        assertEquals(ServerResult.DONE, done { entry.createAccountHere(at()) })
        assertEquals(SignUpStartResult.DONE, done { entry.startSignUp(at(), email, true) })
        assertEquals(CodeResult.DONE, done { entry.verifySignUpCode(at(), "482915") })
        assertEquals(CreateAccountResult.DONE, done { entry.createAccount(at(), NewAccountInput("", "P", strong, true)) })
        val reveal = api.at<EntryScreen.Kit>().kit
        val doc = assertNotNull(api.kit.kitDocument(reveal))
        step { kit.proceedToConfirm(reveal) }
        val confirm = api.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, done { kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
    }

    private fun TrustModel.unlockNow() = assertEquals(VaultUnlockResult.DONE, done { unlock(assertNotNull(snapshot.locked), strong) })

    private fun login(name: String) = LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false)

    /** Signed up, opened again with the copy at rest, [n] logins saved while the server was out of reach, locked. */
    private fun TrustModel.waiting(server: PlaneServer, n: Int) {
        register(alice)
        step { lock() }
        unlockNow()
        val c = assertNotNull(content.value)
        assertEquals(ActionResult.Ok, runBlocking { c.syncQuietly() })
        server.down = true
        for (i in 1..n) assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(null, login("Site$i"), null) })
        step { lock() }
        // Back with the policy's read at the next opening, as the forbidding answer arrives.
        server.upAfterPolicy = true
    }

    @Test
    fun aForbiddingPolicyFromItsArrivalThroughTheRemovalToTheDismissedNotice() = walk {
        val instance = FakeInstance(crypto)
        val server = PlaneServer(instance)
        val phone = Phone()
        val api = app(instance, server, phone)
        val m = model(api)
        m.waiting(server, 2)

        // The policy now forbids the copy; the run's push is taken and its answer waits, so the removal is on show.
        server.forbid = true
        val gate = CompletableDeferred<Unit>()
        server.pushGate = gate
        // Never a hang: should the unlock wait for the run itself, the answer comes after a while and the checks below fail.
        val watchdog = thread(isDaemon = true) { runCatching { Thread.sleep(30_000); gate.complete(Unit) } }
        server.calls.clear()
        m.unlockNow()
        val during = assertIs<GuardedContent>(m.content.value)
        val state = during.states.value
        val line = assertNotNull(state.removingLine, "the copy is being removed (calls ${server.calls}, taken ${server.taken.size}, " +
            "gate done ${gate.isCompleted}, notice ${api.snapshot.policyWipe?.lines?.map { it.key }}, same content ${api.content === during.inner}, " +
            "its line ${api.content?.states?.value?.removingLine}, phase ${api.snapshot.phase}, sync ${state.sync}, queued ${state.queued})")
        assertEquals(UiText.Plain(line).shown(), assertNotNull(syncLine(state)).shown(), "where a stopped server's line would be")
        assertTrue(canSave(state), "Save stays offered")
        assertEquals(emptyList(), during.vaultsForNewItems(), "no vault offered for a new item; the editor says the removal's line")
        assertEquals(ActionResult.Failed(io.silencelen.andvari.core.app.content.ContentCopy.COPY_BEING_REMOVED),
            runBlocking { during.saveLogin(null, login("Typed"), null) }, "a change made now is not made, and says so")
        m.run({ vaults.createVault("Family") })
        m.onSnapshot(m.api.snapshot)
        assertEquals(VaultActionResult.REMOVING_COPY, assertNotNull(m.saidOn(m.api.snapshot)).result, "a shared vault's change says the same line")
        assertNull(m.api.snapshot.policyWipe, "no notice before the copy is gone")

        // The answer comes: both changes were taken, the copy goes, the account goes on from the server.
        gate.complete(Unit)
        watchdog.interrupt()
        m.onSnapshot(m.api.snapshot)
        assertEquals(2, server.taken.size)
        assertTrue(phone.files.deleted.isNotEmpty(), "the copy was removed")
        val after = assertIs<GuardedContent>(m.content.value)
        assertNotSame(during.inner, after.inner, "the shared code composed the vault again")
        assertSame(during.opening, after.opening, "the same opening: the screen on show and what was typed stay")
        assertNull(after.states.value.removingLine)
        val notice = assertNotNull(m.api.snapshot.policyWipe)
        assertEquals(listOf(CopyKey.POLICY_COPY_REMOVED_NOTHING_LOST), notice.lines.map { it.key })
        assertEquals(notice.lines.map { UiText.of(it).shown() }, policyWipeLines(notice).map { it.shown() })

        // Kept across a lock and an unlock; the person's dismissal ends it, and a restart does not bring it back.
        m.step { lock() }
        assertSame(notice, m.api.snapshot.policyWipe, "on the lock screen")
        val beforeLock = after.opening
        m.unlockNow()
        assertSame(notice, m.api.snapshot.policyWipe, "after the unlock")
        assertNotSame(beforeLock, assertIs<GuardedContent>(m.content.value).opening, "a new unlock is a new opening")
        m.dismissPolicyWipe(notice)
        m.onSnapshot(m.api.snapshot)
        assertNull(m.api.snapshot.policyWipe)
        api.close()
        val again = model(app(instance, server, phone))
        assertNull(again.api.snapshot.policyWipe, "not said again at the next start")
    }

    @Test
    fun changesTheServerTookWithNoAnswerAreSaidAsMayOrMayNotHaveArrived() = walk {
        val instance = FakeInstance(crypto)
        val server = PlaneServer(instance)
        val m = model(app(instance, server, Phone()))
        m.waiting(server, 2)
        server.forbid = true
        server.pushUnanswered = true
        m.unlockNow()
        m.onSnapshot(m.api.snapshot)
        val notice = assertNotNull(m.api.snapshot.policyWipe)
        assertEquals(2, server.taken.size, "the server took both")
        assertEquals(2, notice.unsure)
        assertEquals(listOf(CopyKey.POLICY_COPY_REMOVED_NONE_KNOWN_LOST, CopyKey.POLICY_COPY_REMOVED_UNSURE), notice.lines.map { it.key })
        assertEquals(notice.lines.map { UiText.of(it).shown() }, policyWipeLines(notice).map { it.shown() })
    }

    /**
     * A move's notes as the shared code keeps them at rest (ids, key names and numbers): read at the next opening with the
     * vault's name of now and the member as this device names them, drawn line by line with the member after the line that
     * names them, and gone at rest once the person dismisses the note.
     */
    @Test
    fun aMovesNoteIsDrawnWithItsLinesAndItsMemberAndGoesAtItsDismissal() = walk {
        val instance = FakeInstance(crypto)
        val server = PlaneServer(instance)
        val phone = Phone()
        val firstApi = app(instance, server, phone)
        model(firstApi).register(alice)
        firstApi.close()
        val account = instance.account(alice)
        val vault = assertNotNull(account.personalWrap).vaultId
        val key = "ovh.app.movenotes|" + instance.origin + "|" + account.userId
        phone.state.set(key, """[{"old":"o1","vault":"$vault","lines":[""" +
            """{"key":"MOVE_HALF_MADE_KEPT_CANNOT_TELL","values":[null]},""" +
            """{"key":"MOVE_HALF_MADE_KEPT_MEMBER_HOLDS","values":[null]}],"memberId":"someone-else","memberKey":"k"}]""")

        val m = model(app(instance, server, phone))
        m.unlockNow()
        assertEquals(ActionResult.Ok, runBlocking { assertNotNull(m.content.value).syncQuietly() })
        m.onSnapshot(m.api.snapshot)
        val note = assertNotNull(m.api.snapshot.account).moveNotes.single()
        assertEquals(listOf(CopyKey.MOVE_HALF_MADE_KEPT_CANNOT_TELL, CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS), note.lines.map { it.key })
        val member = assertIs<PersonName.Unverified>(note.member, "a member this device does not know: only the server's word")
        assertEquals(
            listOf(UiText.of(note.lines[0]).shown(), UiText.of(note.lines[1]).shown(), personLine(member).shown()),
            moveNoteLines(note).map { it.shown() },
        )
        m.dismissMoveNote(note)
        m.onSnapshot(m.api.snapshot)
        assertEquals(emptyList(), assertNotNull(m.api.snapshot.account).moveNotes)
        assertNull(phone.state.get(key), "gone at rest too")
    }
}
