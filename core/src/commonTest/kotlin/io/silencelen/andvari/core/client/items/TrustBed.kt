package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.client.log.VaultLogHost
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.client.state.AccountDocument
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.client.state.AccountStateStore
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.model.wire.LogAppendRequest
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.LogHead
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.SelfWrapPut
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncLogHead
import io.silencelen.andvari.core.model.wire.VaultMemberSummary
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.KnownHashes
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.VaultLog
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer

/**
 * A stand-in for the server's vault-log routes: it stores each vault's frames, verifies an append with the trust layer's
 * [VaultLog] as the real server does, serves pages and the member list, and keeps the grant rows an append makes.
 */
class LogServerStandIn(private val crypto: CryptoProvider) {
    val logs = HashMap<String, MutableList<String>>()
    val grants = HashMap<Pair<String, String>, SyncGrant>()

    /** Vaults for which an append gets no answer (the entry is not stored). */
    val appendsUnanswered = HashSet<String>()

    /** The head the server serves for [vaultId], as a vault row carries it. */
    fun head(vaultId: String): SyncLogHead? {
        val log = logs[vaultId] ?: return null
        if (log.isEmpty()) return null
        return SyncLogHead(log.size - 1L, Bytes.toHexLower(crypto.sha256(Bytes.fromB64(log.last()))))
    }

    private fun page(log: List<String>): String =
        WireJson.json.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(1, LogHead(log.size - 1L, Bytes.toHexLower(crypto.sha256(Bytes.fromB64(log.last()))), 0)))

    fun client(user: String): WireClient = object : WireClient {
        override val origin = "https://h.example"
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            val vaultId = pathParams["vaultId"] ?: return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            val log = logs.getOrPut(vaultId) { ArrayList() }
            return when (route) {
                WireRoute.LOG_FETCH -> {
                    val after = query?.removePrefix("after=")?.toLong()
                    val from = ((after ?: -1) + 1).toInt()
                    val entries = if (from < log.size) log.subList(from, log.size).toList() else emptyList()
                    val head = LogHead(log.size - 1L, if (log.isEmpty()) "0".repeat(64) else Bytes.toHexLower(crypto.sha256(Bytes.fromB64(log.last()))), 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(LogPage.serializer(), LogPage(entries, head, null))), 200)
                }
                WireRoute.LOG_APPEND -> {
                    if (vaultId in appendsUnanswered) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    val req = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!)
                    if (req.entry in log) return WireResult.Ok(decode(page(log)), 200)
                    val frame = Bytes.fromB64(req.entry)
                    val prior = VaultLog.replay(crypto, vaultId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state
                    val entry = VaultLog.parse(crypto, frame).valueOrNull()?.entry
                    if (entry != null && entry.seq != log.size.toLong()) {
                        val h = prior!!.head
                        return WireResult.Refused(409, WireError("log_head_moved", "m", seq = h.seq, hash = h.hash, at = prior.at))
                    }
                    when (val v = VaultLog.verify(crypto, vaultId, prior, frame, KnownHashes.NONE_HELD)) {
                        is Checked.Refused -> return WireResult.Refused(400, WireError(v.verdict.code, "m"))
                        is Checked.Ok -> {}
                    }
                    log += req.entry
                    if (entry is LogEntry.Genesis) grants[vaultId to user] = SyncGrant(vaultId, user, "owner", req.wrappedVk!!, 1)
                    if (entry is LogEntry.Add) grants[vaultId to entry.member] = SyncGrant(vaultId, entry.member, entry.role.literal, "", 1, req.grant)
                    if (entry is LogEntry.Remove) grants.remove(vaultId to entry.member)
                    WireResult.Ok(decode(page(log)), 200)
                }
                WireRoute.VAULT_MEMBERS -> WireResult.Ok(
                    decode(WireJson.json.encodeToString(ListSerializer(VaultMemberSummary.serializer()),
                        grants.values.filter { it.vaultId == vaultId }.map { VaultMemberSummary(it.userId, "e@x.example", "N", it.role, "", 1) })),
                    200,
                )
                WireRoute.VAULT_SELF_WRAP -> {
                    val w = WireJson.json.decodeFromString(SelfWrapPut.serializer(), bodyJson!!)
                    grants[vaultId to user]?.let { grants[vaultId to user] = it.copy(wrappedVk = w.wrappedVk) }
                    WireResult.Ok(decode("{\"rev\":1}"), 200)
                }
                else -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            }
        }
    }
}

/** One account's account state, merged trivially (one writer at a time here). */
class AccountStateStandIn : AccountStateStore {
    var doc = AccountDocument.EMPTY

    /** Answers the next writes with these outcomes instead (a server that refuses, or keeps meeting newer writes), in order. */
    val failNext = ArrayDeque<AccountStateWrite>()

    override fun local() = doc
    override suspend fun read(): AccountStateRead = AccountStateRead.Ok(doc, emptyList())
    override suspend fun update(change: (AccountDocument) -> AccountDocument): AccountStateWrite {
        failNext.removeFirstOrNull()?.let { return it }
        val n = change(doc)
        if (n == doc) return AccountStateWrite.Unchanged(doc)
        doc = n.copy(seq = doc.seq + 1)
        return AccountStateWrite.Written(doc)
    }
}

/**
 * The item engine over the REAL trust engine: [StoredVaultLogs] behind [SessionVaultKeys], for the rig's account, on a
 * stand-in log server ([LogServerStandIn]), a stand-in device state and the rig's clock, which the test drives
 * ([ItemRig.now]). A second account, [owner], owns the shared vaults: it creates them, adds this account, removes it and
 * adds it again through the same real engine. Everything the item engine learns of a vault (held, lost, withheld, a key
 * that ends) is what the product's trust engine concludes from what the servers serve.
 */
class TrustBed(cache: VaultCache = InMemoryVaultCache()) {
    private class Person(crypto: CryptoProvider, val userId: String, seed: Byte) {
        val sign = crypto.signKeypairFromSeed(ByteArray(32) { seed })
        val box = crypto.boxKeypairFromSeed(ByteArray(32) { seed })
        val uvk = ByteArray(32) { (seed + 1).toByte() }
        val pub: String = Bytes.toB64(box.publicKey)
    }

    private inner class Host(val user: String, val contacts: Map<String, String>) : VaultLogHost {
        override fun grantRow(vaultId: String) = logServer.grants[vaultId to user]
        override fun isCurrentContact(userId: String, identityPub: String) = contacts[userId] == identityPub
        override fun currentContact(userId: String) = contacts[userId]?.let { it to true }
        override fun labelFor(userId: String, identityPub: String) = if (contacts[userId] == identityPub) "Owner" else null
        override fun vaultName(vaultId: String, vk: ByteArray) = "Family"
        override fun sealMeta(vaultId: String, vk: ByteArray, name: String) = "meta"
        override fun serverOwnerName(vaultId: String) = "someone"
    }

    private val crypto0: CryptoProvider = io.silencelen.andvari.core.crypto.createCryptoProvider()
    val logServer = LogServerStandIn(crypto0)
    private val ownerP = Person(crypto0, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", 3)
    private val meSeed: Byte = 5

    /** This device's own records (the trust engine's verified states and its held keys): device state. */
    val device = MemoryDeviceState()

    /** This account's contacts as this device holds them (user id to identity key): the owner, until a test removes it. */
    val contacts = HashMap(mapOf(ownerP.userId to ownerP.pub))

    /** This account's account state, which its other devices write too (an answer given on another device lands here). */
    val accountState = AccountStateStandIn()

    /** The owner's user id. */
    val ownerId: String get() = ownerP.userId

    /** This account's real trust engine, as the session built it. */
    lateinit var logs: StoredVaultLogs
        private set

    /** The item rig: its engine reads every key through [SessionVaultKeys] over [logs]. */
    val rig: ItemRig = ItemRig(cache, trust = { r -> keysFor(r) })

    /** The owner of the shared vaults, on its own device, over the same log server and clock. */
    val owner: StoredVaultLogs = StoredVaultLogs(
        ownerP.userId, ownerP.sign, ownerP.box, ownerP.uvk, logServer.client(ownerP.userId), crypto0, MemoryDeviceState(), AccountStateStandIn(),
        Host(ownerP.userId, mapOf(rig.userId to Bytes.toB64(crypto0.boxKeypairFromSeed(ByteArray(32) { meSeed }).publicKey))), { rig.now }, { null },
    )

    private fun keysFor(r: ItemRig): VaultKeySource {
        val account = openedFor(r)
        logs = logsFor(r, account)
        return SessionVaultKeys(account, logs, VaultRows(crypto0), device)
    }

    private fun openedFor(r: ItemRig): OpenedAccount {
        val me = Person(crypto0, r.userId, meSeed)
        val genesis = VerifiedGenesis(GenesisFields(r.userId, me.pub, "instance", r.personal, 0), "00".repeat(32))
        return OpenedAccount(r.userId, me.uvk, me.box, me.sign, genesis, r.personal, r.personalKey.copyOf())
    }

    private fun logsFor(r: ItemRig, account: OpenedAccount = openedFor(r)): StoredVaultLogs =
        StoredVaultLogs.forAccount(account, logServer.client(r.userId), crypto0, device, accountState, Host(r.userId, contacts), { r.now }, { null })

    /**
     * This account's trust engine as the next unlock or a start of the app builds it: a new engine over the same device
     * state and account state, holding nothing in memory of the one before.
     */
    fun logsAfterRestart(): StoredVaultLogs = logsFor(rig)

    /** A shared vault the owner made, with its key (the owner's copy, for sealing rows as the owner's devices do). */
    class Shared(val vaultId: String, val key: ByteArray)

    /** The vault row the server serves for [s], at the log's present head. */
    fun vaultRow(s: Shared, rev: Long = 1) = rig.vaultRow(s.vaultId, s.key, "shared", "Family", rev, logServer.head(s.vaultId))

    /** This account's grant row of [s], as the server serves it. */
    fun grantRow(s: Shared) = logServer.grants.getValue(s.vaultId to rig.userId)

    /** A row of [s] sealed under its key. */
    fun row(s: Shared, itemId: String, name: String, rev: Long) = rig.itemRow(itemId, s.vaultId, s.key, rig.doc.copy(name = name), rev)

    /**
     * The owner makes a vault and adds this account as [role]; this account accepts (the person's answer); the server
     * serves the vault, the grant and [items] at the next pull, which the engine runs.
     */
    fun share(role: String = "writer", items: (Shared) -> List<SyncItem> = { emptyList() }): Shared = runBlocking {
        val made = owner.append(null, LogAction.Create("Family")) as AppendOutcome.Appended
        val vaultId = made.state.vaultId
        rig.now += 1000
        check(owner.append(vaultId, LogAction.Add(rig.userId, role)) is AppendOutcome.Appended)
        logs.refresh(vaultId, null, null, force = true)
        logs.answerIncoming(logs.adoption(vaultId) as Adoption.AskAccept, accept = true)
        val s = Shared(vaultId, owner.withKey(vaultId) { KeyCopy(it.copyOf()) }!!.bytes)
        rig.server.queue.add(rig.response(rig.server.rev + 1, vaults = listOf(vaultRow(s)), grants = listOf(grantRow(s)), items = items(s)))
        rig.engine.sync().ok()
        check(rig.engine.vaults().any { it.vaultId == vaultId }) { "the shared vault opens on this device" }
        s
    }

    /** The owner removes this account from [s]: a signed `remove`; the server's next answer says the grant ended. */
    fun removeMe(s: Shared) = runBlocking {
        rig.now += 1000
        check(owner.append(s.vaultId, LogAction.Remove(rig.userId)) is AppendOutcome.Appended)
        rig.server.queue.add(rig.response(rig.server.rev + 1, removed = listOf(s.vaultId)))
    }

    companion object {
        const val DAY = 86_400_000L
    }
}
