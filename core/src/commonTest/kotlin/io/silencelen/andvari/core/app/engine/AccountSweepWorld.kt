package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.client.session.SessionRecordReadability
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

/** The prefixes of the records a device keeps by an account's id alone. */
internal val SWEEP_BY_ID = listOf("ovh.acct|", "ovh.log|", "ovh.items|", "ovh.rmirror|", "ovh.escrowfp|", "ovh.identity|")

/** Cache files kept in memory per name; every deletion asked for is recorded. */
internal class SweepFiles : VaultCacheFiles {
    val deleted = ArrayList<String>()
    private val caches = HashMap<String, VaultCache>()
    override fun open(fileName: String, userId: String): VaultCache =
        caches.getOrPut(fileName) { object : VaultCache by InMemoryVaultCache() { override val durable: Boolean get() = true } }
    override fun delete(fileName: String): Boolean {
        deleted += fileName
        caches.remove(fileName)
        return true
    }
}

/**
 * The device state of a test: it can be made to answer that it cannot list its keys ([unlisted]), to throw at the read of
 * chosen keys ([unreadable]), to fail once at the first write after the removal of [armAfterRemovalOf], to fail once at the
 * [failByIdRemoval]-th removal from now (0: the next) of a record kept by an account's id, and to tell [onWrite] of every
 * value written (a removal is not told). As a platform's secure store does while it cannot read its session record, it can
 * answer "nothing" for chosen keys that are there ([handsNothingFor]) and say so ([sessionRecordUnreadable]); a new value
 * written there replaces the record and is read again, and a removal leaves the record where it is.
 */
internal class SweepStore(val inner: MemoryDeviceState) : DeviceState, SessionRecordReadability {
    var unlisted = false
    val unreadable = HashSet<String>()
    val handsNothingFor = HashSet<String>()
    var armAfterRemovalOf: String? = null
    var failByIdRemoval = -1
    var failedOn: String? = null
    var onWrite: ((String) -> Unit)? = null
    private var failNext = false

    override val sessionRecordUnreadable: Boolean
        get() = SessionKeeper.KEY in handsNothingFor && inner.get(SessionKeeper.KEY) != null

    override fun get(key: String): String? {
        if (key in unreadable) throw IllegalStateException("cannot read $key")
        if (key in handsNothingFor) return null
        return inner.get(key)
    }

    override fun keys(): Set<String>? = if (unlisted) null else inner.keys() - handsNothingFor

    /** Told of every write and removal before it is made; it may throw, and the write is then not made. */
    var beforeSet: ((String, String?) -> Unit)? = null

    override fun set(key: String, value: String?) {
        beforeSet?.invoke(key, value)
        if (key in handsNothingFor) {
            if (value == null) return
            handsNothingFor -= key
        }
        if (value == null && failByIdRemoval >= 0 && SWEEP_BY_ID.any { key.startsWith(it) }) {
            if (failByIdRemoval == 0) {
                failByIdRemoval = -1
                failedOn = key
                throw IllegalStateException("store failed on $key")
            }
            failByIdRemoval--
        }
        if (failNext) {
            failNext = false
            failedOn = key
            throw IllegalStateException("store failed on $key")
        }
        inner.set(key, value)
        if (value == null && key == armAfterRemovalOf) {
            armAfterRemovalOf = null
            failNext = true
        }
        if (value != null) onWrite?.invoke(key)
    }

    /** Every key and value as they are now. */
    fun snapshot(): Map<String, String> = inner.keys().sorted().associateWith { inner.get(it).orEmpty() }
}

/** A server that answers the item routes itself (sync and push), and every other route through [instance]. */
internal class SweepItemServer(val instance: FakeInstance, private val vaultOf: () -> String?) : WireClient {
    override val origin: String get() = instance.origin
    var down = false
    var rev = 1L
    val items = ArrayList<SyncItem>()

    override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
        when (route) {
            WireRoute.SYNC -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                val vaults = vaultOf()?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                val r = SyncResponse(rev, since == 0L, vaults, emptyList(), items.filter { it.rev > since }, emptyList(), emptyList(), 0, 0)
                WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
            }
            WireRoute.PUSH -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                val results = b.mutations.map { m ->
                    rev++
                    items.removeAll { it.itemId == m.itemId }
                    val up = m.item
                    items += SyncItem(m.itemId, m.vaultId, rev, instance.now, instance.now, m.op == MutationOp.DELETE, false,
                        up?.formatVersion ?: 1, up?.attachmentIds.orEmpty(), up?.blob)
                    MutationResult(m.mutationId, MutationStatus.APPLIED, rev)
                }
                WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
            }
            else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
}

/** One device (its two stores and its cache files) and the servers it may reach. */
internal class SweepWorld(val home: FakeInstance, val other: FakeInstance, val wires: Map<String, WireClient>) {
    val state = SweepStore(MemoryDeviceState())
    val secure = SweepStore(MemoryDeviceState())
    val files = SweepFiles()
    lateinit var app: EngineAppApi
    lateinit var u: String
}

/** The steps the sweep's tests take over the real engine. */
internal class SweepSteps(val crypto: CryptoProvider) {
    val strong = "correct horse Battery 9 staple"
    val alice = "alice@example.com"
    val bob = "bob@example.com"

    /**
     * A device with h.example (`home`) and other.example (`other`). [sameInstance]: other.example serves the same instance
     * (an account made at one is served at both). [items]: h.example answers sync and push itself.
     */
    fun world(sameInstance: Boolean = false, items: Boolean = false): SweepWorld {
        val home = FakeInstance(crypto)
        val other = if (sameInstance) FakeInstance(crypto, origin = "https://other.example", instanceId = home.instanceId)
            else FakeInstance(crypto, origin = "https://other.example", instanceId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
        val homeWire: WireClient = if (items) SweepItemServer(home) { home.accounts[alice]?.personalWrap?.vaultId } else home
        val w = SweepWorld(home, other, mapOf(home.origin to homeWire, other.origin to other))
        w.app = device(w)
        return w
    }

    /** The engine over [w]'s stores, made and (with [start]) started. */
    fun device(w: SweepWorld, start: Boolean = true): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(w.wires), w.state, w.secure, crypto, { w.home.now }, baked = null,
            storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined, cacheFiles = w.files,
            keepsAtRest = { true }),
    ).also { if (start) it.start() }

    /** Another device of its own, at [server] only. */
    fun otherDevice(server: FakeInstance): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), MemoryDeviceState(), MemoryDeviceState(),
            crypto, { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    inline fun <reified T : EntryScreen> at(a: EngineAppApi): T = assertIs<T>(a.snapshot.entry, "on ${a.snapshot.entry}")

    private fun dismiss(a: EngineAppApi) {
        (a.snapshot.entry as? EntryScreen.FirstRun)?.let { if (it.accountDeleted != null) a.entry.dismissNotice(it) }
    }

    suspend fun registerKeepingKit(a: EngineAppApi, address: String, email: String): Pair<String, KitDocument> {
        dismiss(a)
        a.entry.openOwnServer(at(a))
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(at(a), address))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(at(a)))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(at(a), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(at(a), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(at(a), NewAccountInput("", "Alice", strong, true)))
        val doc = confirmKit(a)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        return assertNotNull(a.keeper.session).userId to doc
    }

    suspend fun register(a: EngineAppApi, address: String, email: String): String = registerKeepingKit(a, address, email).first

    suspend fun confirmKit(a: EngineAppApi): KitDocument {
        val kit = at<EntryScreen.Kit>(a)
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = at<EntryScreen.Kit>(a).kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        return doc
    }

    suspend fun signOut(a: EngineAppApi) = assertEquals(PlainResult.DONE, a.signOutConfirmed(assertNotNull(a.signOutCheck())))

    suspend fun signInAt(a: EngineAppApi, origin: String, email: String, password: String = strong): SignInAnswer {
        dismiss(a)
        if (a.snapshot.entry !is EntryScreen.SignIn) {
            a.entry.openSignIn(at(a))
            a.entry.openPasswordSignIn(at(a))
            assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(at(a), origin))
            (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        }
        return a.entry.submitSignIn(at(a), email, password)
    }

    /** The app stops and starts again over the same stores. */
    fun restart(w: SweepWorld) {
        w.app.close()
        w.app = device(w)
    }

    /** The platform lost the kept session's record (the copy stays held), and the app starts again. */
    fun loseSession(w: SweepWorld) {
        w.app.lock()
        w.app.close()
        w.secure.inner.set(SessionKeeper.KEY, null)
        w.app = device(w)
    }

    /** Back to the first screen: the entry's back, or a start. */
    fun toFirstScreen(w: SweepWorld) {
        var n = 0
        while (w.app.snapshot.entry !is EntryScreen.FirstRun && n++ < 8) if (!w.app.entry.back()) break
        if (w.app.snapshot.entry !is EntryScreen.FirstRun) restart(w)
    }

    /** The kept account's deletion, which [server] confirms. */
    suspend fun deleteAt(w: SweepWorld, server: FakeInstance, email: String = alice) {
        server.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        server.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
        try {
            assertEquals(PlainResult.DONE, w.app.settings.openDeletion())
            assertEquals(DeletionResult.DONE, w.app.settings.deleteAccount(assertNotNull(w.app.snapshot.account!!.deletion), email, strong, null))
        } finally {
            server.override.remove(WireRoute.ACCOUNT_DELETE_PREVIEW)
            server.override.remove(WireRoute.ACCOUNT_DELETE)
        }
    }

    /** The person's "Forget the earlier account", both confirmations, on the offer on show. */
    suspend fun forgetEarlier(w: SweepWorld): ForgetEarlierResult {
        val offer = assertNotNull(w.app.snapshot.earlierAccount)
        kotlin.test.assertTrue(w.app.entry.askToForgetEarlierAccount(offer))
        return w.app.entry.forgetEarlierAccount(assertNotNull(w.app.snapshot.earlierAccount))
    }

    /** The records kept by [u]'s id alone, with their values. */
    fun byId(w: SweepWorld, u: String = w.u): Map<String, String> = w.state.inner.keys().filter { k ->
        SWEEP_BY_ID.any { p -> k == p + u || k.startsWith("$p$u|") }
    }.sorted().associateWith { w.state.inner.get(it).orEmpty() }

    /** Every record of either store whose key or value names [u]. */
    fun naming(w: SweepWorld, u: String = w.u): List<String> = listOf("state" to w.state.inner, "secure" to w.secure.inner).flatMap { (which, s) ->
        s.keys().filter { k -> u in k || u in s.get(k).orEmpty() }.map { "$which:$it" }
    }.sorted()

    /** Every record kept by an account's id, and every address record, of any account. */
    fun watched(w: SweepWorld): Set<String> = w.state.inner.keys().filter { k ->
        SWEEP_BY_ID.any { k.startsWith(it) } || k.startsWith(SessionKeeper.EMAIL_BINDING_PREFIX)
    }.toSet()

    /**
     * From now on, after every value written to a record kept by an account's id or to an address record, a second app
     * (another process over the same stores) starts and is closed again; what it took of those records is noted in
     * [SecondStarts.lost]. Stopped with [SecondStarts.stop].
     */
    fun secondStartAtEachWrite(w: SweepWorld): SecondStarts {
        val s = SecondStarts(w)
        var inside = false
        w.state.onWrite = { key ->
            if (!inside && (SWEEP_BY_ID.any { key.startsWith(it) } || key.startsWith(SessionKeeper.EMAIL_BINDING_PREFIX))) {
                inside = true
                try {
                    val before = watched(w)
                    device(w).close()
                    s.starts++
                    for (k in before - watched(w)) s.lost += "after the write of $key: $k"
                } finally {
                    inside = false
                }
            }
        }
        return s
    }

    class SecondStarts(private val w: SweepWorld) {
        var starts = 0
        val lost = ArrayList<String>()
        fun stop() {
            w.state.onWrite = null
        }
    }
}
