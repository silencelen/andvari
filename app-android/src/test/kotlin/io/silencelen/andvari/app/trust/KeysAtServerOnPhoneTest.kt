package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.autofill.AutofillSave
import io.silencelen.andvari.app.autofill.SavedCredentials
import io.silencelen.andvari.app.autofill.fillUnlockNotice
import io.silencelen.andvari.app.autofill.overlayUnlock
import io.silencelen.andvari.app.autofill.saveWords
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppApi
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
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LockedScreen
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.content.ContentCopy
import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.app.content.KeptStorage
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
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A server's policy that forbids keeping data on the phone, after its removal of the copy, over the shared code's REAL
 * implementation ([EngineAppApi] over [AppEngine]) and its own test server ([FakeInstance]) with an item plane that keeps
 * what it is sent: the account's keys are kept at the server, every unlock asks it, and the logins the phone's autofill
 * caught stay on the phone, sealed, until the person answers them (decided on 2026-11-18). Each walk is driven through
 * this app's model and its autofill's own calls, as the screens and the service drive them, and checks what the person
 * reads by its key:
 *
 * - the lock screen and the fill unlock window say that the keys are kept at the server;
 * - with the server out of reach an unlock is "the server didn't answer", never "wrong password", nothing is removed;
 * - with the server answering, the unlock opens and the caught logins (one caught before the removal, one after it) are
 *   in the vault's footer as what they are, never "this item is no longer here";
 * - Settings says that caught logins are kept sealed;
 * - a catch is kept, never refused for the policy;
 * - the owner's condition at the phone's own level: with the server stopped, nothing the phone's screens offer opens a
 *   caught login, also after a restart.
 */
class KeysAtServerOnPhoneTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

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

    private class Records : KeptStorage {
        val records = HashMap<String, InMemoryFillSnapshots>()
        val blobs = HashMap<String, InMemoryBlobs>()
        override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { InMemoryFillSnapshots() }
        override fun blobs(name: String): BlobStore = blobs.getOrPut(name) { InMemoryBlobs() }
    }

    /** Everything this phone keeps at rest, shared by every start of the app on it. */
    private class Phone {
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val files = Files()
        val records = Records()
        val queue = InMemorySaveQueue()
    }

    /**
     * [instance] with an item plane that keeps what it is sent and serves it back; its policy forbids the copy while
     * [forbid]. [down]: no answer to anything (the server cannot be reached). [end]: the server ends this device's
     * session (every access token it gave is refused, and the refresh too), as a removed device meets it.
     */
    private class Server(val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        val transport = BearerTransport(mapOf(instance.origin to this))
        var forbid = false
        var down = false
        var rev = 1L
        val items = LinkedHashMap<String, SyncItem>()
        private val taken = HashMap<String, Long>()
        val calls = ArrayList<String>()

        fun end() {
            transport.expired += transport.sent.mapNotNull { it.bearer }
            transport.refreshAnswer = { WireResult.Refused(401, WireError("invalid_refresh", "invalid_refresh")) }
        }

        fun policy(forbids: Boolean): String = WireJson.json.encodeToString(
            ClientPolicy.serializer(),
            ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, !forbids, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false),
        )

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            calls += route.name + if (down) "(down)" else ""
            if (down) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            return when (route) {
                WireRoute.CLIENT_POLICY -> WireResult.Ok(decode(policy(forbid)), 200)
                WireRoute.SYNC -> {
                    val since = query?.substringAfter("since=")?.substringBefore('&')?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val rows = items.values.filter { since == 0L || it.rev > since }
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), rows, emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> {
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
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

    private val opened = ArrayList<EngineAppApi>()

    /** The app as it starts on [phone]: a new process over the same stores. */
    private fun app(server: Server, phone: Phone): EngineAppApi = EngineAppApi(
        AppEngine(
            AppPlatform.ANDROID, "Pixel", server.transport, phone.state, phone.secure, crypto,
            { server.instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
            cacheFiles = phone.files, keepsAtRest = { true }, contentStores = ContentStores(crypto, phone.records, phone.queue),
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

    private fun TrustModel.unlockWith(password: String = strong): VaultUnlockResult = done { unlock(assertNotNull(snapshot.locked), password) }

    private fun TrustModel.locked(): LockedScreen = assertNotNull(api.snapshot.locked, "on the lock screen (${api.snapshot.phase})")

    /** A login typed into a browser the service trusts, caught by this phone's autofill as the service catches it. */
    private fun catch(api: AppApi, queue: InMemorySaveQueue, domain: String, password: String, now: Long, scheme: String? = "https"): AutofillSave.Outcome =
        AutofillSave.capture(queue, crypto, SavedCredentials("me", password, domain, "com.android.chrome", webScheme = scheme), verifiedBrowser = true,
            session = AutofillSave.saveSession(api.snapshot), nowMs = now)

    /** What the vault's footer lists of the caught logins, as "host: reason" ("saved" for one saved by itself). */
    private fun TrustModel.footer(): List<String> {
        val st = assertIs<GuardedContent>(content.value).states.value
        return st.pendingSaves.map { "${it.host}: ${it.reason}" } + st.appliedSaves.map { "${it.host}: saved" }
    }

    /** The caught passwords, as typed: none may be readable in anything the phone keeps at rest. */
    private val caught = listOf("pw-ask-1", "pw-after-2")

    /** Every byte the phone keeps at rest, as text where it is text. */
    private fun Phone.atRest(): List<String> =
        state.keys().mapNotNull { state.get(it) } + secure.keys().mapNotNull { secure.get(it) } +
            queue.entries().values.map { it.decodeToString() } + listOfNotNull(queue.publication()?.decodeToString()) +
            records.records.values.mapNotNull { it.read()?.decodeToString() }

    /**
     * Signed up; a login "Ask" for https://ask.test saved by the person; locked; two logins caught by the autofill while
     * locked: one for a new site (https://new.test, saved by itself at the next opening) and one for ask.test without a
     * scheme (it waits for the person's answer). The server's policy then forbids keeping data, and its removal is made
     * at the next unlock (the server answers). Locked again, with one caught login staying, sealed.
     */
    private fun wiped(server: Server, phone: Phone, m: TrustModel, trace: MutableList<String>) {
        m.register("alice@example.com")
        m.step { lock() }
        assertEquals(VaultUnlockResult.DONE, m.unlockWith())
        val c = assertIs<GuardedContent>(m.content.value)
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(null, LoginInput("Ask", "me", "pw-ask-old", listOf("https://ask.test"), "", "", false), null) })
        m.step { lock() }
        val new = catch(m.api, phone.queue, "new.test", "pw-new-0", server.instance.now)
        val ask = catch(m.api, phone.queue, "ask.test", caught[0], server.instance.now, scheme = null)
        trace += "caught before the policy, locked: new $new, ask $ask (${saveWords(ask).shown()})"
        server.forbid = true
        assertEquals(VaultUnlockResult.DONE, m.unlockWith())
        repeat(300) { if (m.api.snapshot.policyWipe == null) Thread.sleep(10) }
        m.onSnapshot(m.api.snapshot)
        assertNotNull(m.api.snapshot.policyWipe, "the copy was removed")
        assertTrue(phone.files.deleted.isNotEmpty(), "the copy was removed")
        trace += "the removal's opening: footer ${m.footer()}, notice ${m.api.snapshot.policyWipe?.lines?.map { it.key }}, items at the server ${server.items.size}, queue ${phone.queue.entries().size}"
        m.step { lock() }
        assertEquals(1, phone.queue.entries().size, "the caught login that waits for the person stays through the removal")
    }

    /** The vault's footer after an unlock the server answered: the one caught before the removal waits, the one after is saved. */
    private fun assertFooter(footer: List<String>) {
        assertTrue("after.test: saved" in footer, "the one caught after the removal was saved by itself: $footer")
        val ask = footer.filter { it.startsWith("ask.test") }
        assertEquals(1, ask.size, "the one caught before the removal is listed, waiting for the person: $footer")
        assertTrue(footer.none { it.endsWith(ContentCopy.ITEM_GONE) }, "never \"this item is no longer here\": $footer")
    }

    @Test
    fun underAPolicyThatKeepsTheKeysAtTheServerTheLockScreenAnUnlockAndTheFooterSayWhatIsSo() = walk {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val phone = Phone()
        val api = app(server, phone)
        val m = model(api)
        val trace = ArrayList<String>()
        wiped(server, phone, m, trace)

        // The lock screen once such a policy is recorded.
        val locked = m.locked()
        trace += "lock screen: keysAtServerLine ${locked.keysAtServerLine?.key}, quick unlock offered ${locked.quickUnlock}, " +
            "end line ${lockEndLine(locked)?.shown()}, fill window notice ${fillUnlockNotice(locked)?.shown()}"
        val keysLine = assertNotNull(locked.keysAtServerLine, "the shared code hands the line")
        assertFalse(locked.quickUnlock, "no quick unlock while the keys are kept at the server")
        assertEquals(UiText.of(keysLine).shown(), fillUnlockNotice(locked)?.shown(), "the fill unlock window says it before the person types")

        // A login caught after the removal, while locked: kept, as every catch is.
        val after = catch(api, phone.queue, "after.test", caught[1], instance.now)
        trace += "caught after the removal, locked: $after (${saveWords(after).shown()})"
        assertEquals(AutofillSave.Outcome.QUEUED, after)
        assertEquals(2, phone.queue.entries().size)

        // The server cannot be reached: no unlock, nothing removed; said as the server's silence, never a wrong password.
        server.down = true
        val r = m.unlockWith()
        val wrong = m.unlockWith("not the password at all 1")
        trace += "server out of reach: unlock $r (${unlockWords(r, 0)?.shown()}), a wrong password $wrong (${unlockWords(wrong, 0)?.shown()}), " +
            "phase ${m.api.snapshot.phase}, queue ${phone.queue.entries().size}"
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, r)
        assertEquals(r, wrong, "a right and a wrong password read the same: only the server can check it")
        assertEquals(UiText.of(io.silencelen.andvari.core.app.CopyKey.UNLOCK_KEYS_AT_SERVER_UNREACHABLE).shown(), unlockWords(r, 0)?.shown(), "its own sentence")
        assertNotEquals(UiText.ph(Placeholder.TROUBLE_UNREACHABLE).shown(), unlockWords(r, 0)?.shown(), "not the general trouble line")
        assertNotEquals(UiText.ph(Placeholder.UNLOCK_WRONG_PASSWORD).shown(), unlockWords(r, 0)?.shown())
        assertEquals(AppPhase.LOCKED, m.api.snapshot.phase)
        assertNotNull(m.locked().keysAtServerLine, "the line stays with the lock screen")
        assertEquals(2, phone.queue.entries().size, "nothing removed")

        // The server answers: the unlock opens; both caught logins are in the footer as what they are.
        server.down = false
        assertEquals(VaultUnlockResult.DONE, m.unlockWith())
        val footer = m.footer()
        trace += "the unlock the server answered: footer $footer, notice ${m.api.snapshot.policyWipe?.lines?.map { it.key }}"
        assertFooter(footer)

        // Settings, with the server's rules: the line that caught logins are kept sealed.
        val policy = assertNotNull(m.api.snapshot.account?.policy)
        trace += "Settings: ${policyLines(policy).map { it.shown() }}, capturesKeptLine ${policy.capturesKeptLine?.key}"
        val kept = assertNotNull(policy.capturesKeptLine, "the shared code hands the line")
        assertTrue(policyLines(policy).any { it.shown() == UiText.of(kept).shown() }, "Settings draws it with the server's rules")
        println(trace.joinToString("\n"))
    }

    @Test
    fun theLockScreenDrawsTheLineThatTheKeysAreKeptAtTheServer() {
        val source = File("src/main/kotlin/io/silencelen/andvari/app/trust/AccountScreens.kt").readText()
        val lock = source.substringAfter("internal fun LockScreen(").substringBefore("\n}\n")
        assertTrue("lockKeysAtServerLine(locked)?.let { Say(it) }" in lock, "the lock screen draws the shared code's line")
    }

    /**
     * The owner's condition at the phone's own level: with the server stopped, nothing the phone's screens offer opens a
     * caught login: not the lock screen's Unlock (with the right password), not quick unlock, not the fill unlock window,
     * not a restart of the app; no caught password and nothing that opens one is readable in what the phone keeps.
     */
    @Test
    fun withTheServerStoppedNothingThePhoneOffersOpensACaughtLogin() = walk {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val phone = Phone()
        val m = model(app(server, phone))
        val trace = ArrayList<String>()
        wiped(server, phone, m, trace)
        assertEquals(AutofillSave.Outcome.QUEUED, catch(m.api, phone.queue, "after.test", caught[1], instance.now))
        server.down = true

        val locked = m.locked()
        assertFalse(locked.quickUnlock, "quick unlock is not offered")
        assertFalse(locked.signedOutByServer, "no \"Sign in again\" either: the session stands")
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, m.unlockWith())
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, overlayUnlock(m.api, m.locked(), strong), "the fill unlock window")
        val quick = m.done { quickUnlock(m.locked()) }
        trace += "quick unlock asked anyway: $quick"
        assertNull(m.content.value, "nothing opened")
        assertEquals(AppPhase.LOCKED, m.api.snapshot.phase)

        // A new start of the app on the same phone, the server still stopped.
        val again = model(app(server, phone))
        assertEquals(AppPhase.LOCKED, again.api.snapshot.phase)
        assertNotNull(again.locked().keysAtServerLine)
        assertFalse(again.locked().quickUnlock)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, again.unlockWith())
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, overlayUnlock(again.api, again.locked(), strong))
        assertNull(again.content.value, "nothing opened after a restart")

        // What the phone keeps: both catches, sealed; no caught password readable anywhere.
        assertEquals(2, phone.queue.entries().size, "both caught logins stay, sealed")
        val rest = phone.atRest()
        for (p in caught) assertTrue(rest.none { p in it }, "\"$p\" is nowhere in the clear")
        println(trace.joinToString("\n"))

        // The server back: the unlock opens and both are there.
        server.down = false
        assertEquals(VaultUnlockResult.DONE, again.unlockWith())
        assertFooter(again.footer())
    }

    /**
     * A session the server ended under such a policy: no unlock (there are no keys on the phone), "Sign in again" is
     * offered, and nothing on the lock screen or in the fill unlock window says that the password opens a copy here.
     */
    @Test
    fun aSessionTheServerEndedUnderSuchAPolicyIsNeverSaidAsACopyThePasswordOpens() = walk {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val phone = Phone()
        val m = model(app(server, phone))
        val trace = ArrayList<String>()
        wiped(server, phone, m, trace)
        server.end()
        // The unlock at which the server's end is learned (its keys' read is refused): nothing opens.
        val first = m.unlockWith()
        assertEquals(AppPhase.LOCKED, m.api.snapshot.phase)
        // Every unlock after it: there is no token to ask with.
        val r = m.unlockWith()
        val locked = m.locked()
        trace += "ended: first unlock $first (${unlockWords(first, 0)?.shown()}), then $r (${unlockWords(r, 0)?.shown()}), signedOutByServer ${locked.signedOutByServer}, " +
            "keysAtServerLine ${locked.keysAtServerLine?.key}, end line ${lockEndLine(locked)?.shown()}, fill window notice ${fillUnlockNotice(locked)?.shown()}"
        println(trace.joinToString("\n"))
        assertTrue(first != VaultUnlockResult.DONE && first != VaultUnlockResult.WRONG_PASSWORD, "$first")
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, first, "the unlock that learned the end says that end")
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, r)
        assertEquals(UiText.of(io.silencelen.andvari.core.app.CopyKey.UNLOCK_KEYS_AT_SERVER_ENDED).shown(), unlockWords(r, 0)?.shown())
        assertTrue(locked.signedOutByServer, "\"Sign in again\" is offered")
        assertNotNull(locked.keysAtServerLine)
        val opensCopy = setOf(UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER).shown(), UiText.ph(Placeholder.FILL_FROM_COPY).shown())
        assertTrue(lockEndLine(locked)?.shown() !in opensCopy, "the lock screen never says the password opens a copy here")
        assertTrue(fillUnlockNotice(locked)?.shown() !in opensCopy, "nor the fill unlock window")
        assertTrue(io.silencelen.andvari.app.autofill.fillUnlockEndLine(locked)?.shown() !in opensCopy)
        assertEquals(UiText.of(io.silencelen.andvari.core.app.CopyKey.SIGNED_OUT_KEYS_AT_SERVER).shown(), lockEndLine(locked)?.shown(), "the lock screen says the server ended it, as the shared code hands that end")
        assertEquals(lockEndLine(locked)?.shown(), io.silencelen.andvari.app.autofill.fillUnlockEndLine(locked)?.shown(), "and so does the fill unlock window")
        assertEquals(UiText.of(assertNotNull(locked.keysAtServerLine)).shown(), lockKeysAtServerLine(locked)?.shown())
        assertEquals(lockKeysAtServerLine(locked)?.shown(), fillUnlockNotice(locked)?.shown())
    }

    /** Where the keys are kept on the phone as before, every line is as it was: the server's end opens the copy read-only. */
    @Test
    fun withoutSuchAPolicyTheLockScreensLinesAreAsBefore() = walk {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val phone = Phone()
        val m = model(app(server, phone))
        m.register("alice@example.com")
        m.step { lock() }
        val locked = m.locked()
        assertNull(locked.keysAtServerLine)
        assertNull(lockKeysAtServerLine(locked))
        assertNull(fillUnlockNotice(locked))
        assertNull(lockEndLine(locked))
        val policy = assertNotNull(m.api.snapshot.account?.policy ?: run {
            assertEquals(VaultUnlockResult.DONE, m.unlockWith())
            m.api.snapshot.account?.policy
        })
        assertNull(policy.capturesKeptLine)
        assertTrue(policyLines(policy).size <= 3, "no line about caught logins: ${policyLines(policy).map { it.shown() }}")
    }

    /**
     * A catch under such a policy is never refused for the policy: with the account's key published it is kept, and
     * where no key is published (a phone whose earlier version withdrew it) it is "not saved", never "your server
     * doesn't allow andvari to keep data on this device".
     */
    @Test
    fun aCatchUnderSuchAPolicyIsNeverRefusedForThePolicy() = walk {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val phone = Phone()
        val m = model(app(server, phone))
        val trace = ArrayList<String>()
        wiped(server, phone, m, trace)
        val kept = catch(m.api, phone.queue, "after.test", caught[1], instance.now)
        phone.queue.publish(null)
        val noKey = catch(m.api, phone.queue, "other.test", "pw-other-3", instance.now)
        assertEquals(VaultUnlockResult.DONE, m.unlockWith())
        val openNoKey = run {
            phone.queue.publish(null)
            catch(m.api, phone.queue, "third.test", "pw-third-4", instance.now)
        }
        trace += "locked, key published: $kept (${saveWords(kept).shown()}); locked, no key: $noKey (${saveWords(noKey).shown()}); open, no key: $openNoKey (${saveWords(openNoKey).shown()})"
        println(trace.joinToString("\n"))
        assertEquals(AutofillSave.Outcome.QUEUED, kept)
        assertEquals(UiText.ph(Placeholder.SAVE_QUEUED).shown(), saveWords(kept).shown(), "the catch says what every catch says")
        // No key published: only "not saved", never the server's policy (the old app said "your server doesn't allow…").
        for (o in listOf(noKey, openNoKey)) assertEquals(UiText.ph(Placeholder.SAVE_REFUSED).shown(), saveWords(o).shown(), "never refused for the policy")
    }
}
