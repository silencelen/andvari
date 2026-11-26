package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AdoptionRefusal
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.LogMember
import io.silencelen.andvari.core.client.log.VaultLogEngine
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.log.VerifiedVaultState
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncLogHead
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [SessionVaultKeys]: how the vault-log engine's statuses and adopted keys, and the opened account's personal vault,
 * become what the item engine may do (design §3.6, §3.9, §5.3). The log engine here is a stand-in whose answers the
 * test sets; the journeys of `andvari-cli` run the same class over the real one.
 */
class SessionVaultKeysTest {
    private val crypto = createCryptoProvider()
    private val me = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private val personal = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private val shared = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    private val owner = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"

    private class Logs : VaultLogEngine {
        val statuses = HashMap<String, VaultLogStatus>()
        val adopted = HashMap<String, ByteArray>()
        val calls = ArrayList<String>()
        override fun status(vaultId: String): VaultLogStatus = statuses[vaultId] ?: VaultLogStatus.Unknown(vaultId)
        override suspend fun refresh(vaultId: String, servedSeq: Long?, servedHash: String?, force: Boolean): VaultLogStatus {
            calls += "refresh:$vaultId:$servedSeq:$force"
            return status(vaultId)
        }
        override suspend fun adoption(vaultId: String): Adoption {
            calls += "adoption:$vaultId"
            return Adoption.Refused(vaultId, AdoptionRefusal.NO_KEY)
        }
        override fun reopenAdopted(vaultId: String): Adoption {
            calls += "reopen:$vaultId"
            return Adoption.Refused(vaultId, AdoptionRefusal.NO_KEY)
        }
        override suspend fun answerIncoming(ask: Adoption.AskAccept, accept: Boolean): Adoption = Adoption.Declined(ask.vaultId)
        override suspend fun noteItemHead(vaultId: String, seq: Long, hash: String): VaultLogStatus {
            calls += "head:$vaultId:$seq"
            return status(vaultId)
        }
        override suspend fun append(vaultId: String?, action: LogAction): AppendOutcome = AppendOutcome.VaultReadOnly
        override suspend fun retryPending() {}
        override fun writeAllowed(vaultId: String): Boolean = false
        override fun copyOutAllowed(vaultId: String): Boolean = adopted.containsKey(vaultId)
        override fun <T> withKey(vaultId: String, block: (ByteArray) -> T): T? = adopted[vaultId]?.let(block)

        /** Each counter told, with how many other calls had been made when it came. */
        val counters = ArrayList<Pair<Long?, Int>>()
        override fun accountStateServed(counter: Long?) {
            counters += counter to calls.size
        }
    }

    private fun account(wrapOpened: Boolean): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(me, Bytes.toB64(identity.publicKey), "instance", personal, 0), "00".repeat(32))
        return OpenedAccount(me, ByteArray(32) { 1 }, identity, crypto.signKeypairFromSeed(seed), genesis, if (wrapOpened) personal else null, if (wrapOpened) ByteArray(32) { 2 } else null)
    }

    private fun state(role: String = "writer", deleted: Boolean = false, member: Boolean = true) = VerifiedVaultState(
        shared, 3, "ab".repeat(32), 0, "cd".repeat(32), owner, "k", "ef".repeat(32),
        if (member) mapOf(me to LogMember(me, "k", role, 1)) else emptyMap(), null, if (deleted) "delete-id" else null,
    )

    private fun row(vaultId: String, type: String = "shared", head: Long? = 3) = SyncVault(vaultId, type, 1, "meta", 0, head?.let { SyncLogHead(it, "ab".repeat(32)) })

    @Test
    fun aSharedVaultIsWhatItsLogAllows_andNothingWithoutAnAdoptedKey() {
        val logs = Logs()
        val keys = SessionVaultKeys(account(true), logs, VaultRows(crypto), MemoryDeviceState())
        fun standing() = keys.access(shared)?.standing

        logs.statuses[shared] = VaultLogStatus.Verified(shared, state(), false)
        assertNull(keys.access(shared), "verified, but no key was adopted (not accepted yet): absent")
        assertNull(keys.keyFor(shared))
        logs.adopted[shared] = ByteArray(32) { 9 }
        val a = keys.access(shared)!!
        assertEquals(listOf(VaultStanding.VERIFIED, "writer", false, true), listOf(a.standing, a.role, a.personal, a.writable))
        assertContentEquals(ByteArray(32) { 9 }, keys.keyFor(shared))
        assertEquals(3, keys.logHead(shared)?.seq)
        logs.statuses[shared] = VaultLogStatus.Verified(shared, state(role = "reader"), false)
        assertEquals(false, keys.access(shared)!!.writable, "the log's role, and a reader does not write")

        logs.statuses[shared] = VaultLogStatus.Withheld(shared, state(), 1)
        assertEquals(VaultStanding.WITHHELD, standing())
        logs.statuses[shared] = VaultLogStatus.Failed(shared, state(), "bad_signature")
        assertEquals(VaultStanding.FAILED, standing())
        logs.statuses[shared] = VaultLogStatus.Frozen(shared, state(), 2)
        assertEquals(VaultStanding.FROZEN, standing())
        assertEquals(false, keys.access(shared)!!.writable)
        assertNull(keys.logHead(shared), "nothing is stamped, because nothing is written, while the log is not verified")
        assertNull(keys.departure(shared), "none of these is a departure: the copy stays")

        logs.statuses[shared] = VaultLogStatus.Failed(shared, null, "bad_signature")
        assertNull(keys.access(shared), "a log that never verified opens nothing")
        logs.statuses[shared] = VaultLogStatus.Verified(shared, state(deleted = true), false)
        assertNull(keys.access(shared))
        assertEquals(VaultDeparture.DELETED, keys.departure(shared))
        logs.statuses[shared] = VaultLogStatus.Removed(shared, state(member = false), byOwner = true)
        assertEquals(listOf(null, VaultDeparture.REMOVED), listOf(keys.access(shared), keys.departure(shared)))
        logs.statuses[shared] = VaultLogStatus.Removed(shared, state(member = false), byOwner = false)
        assertEquals(VaultDeparture.LEFT, keys.departure(shared))
        logs.statuses[shared] = VaultLogStatus.Purged(shared, state(deleted = true), 5)
        assertEquals(listOf(null, VaultDeparture.PURGED), listOf(keys.access(shared), keys.departure(shared)))
    }

    @Test
    fun thePersonalVaultIsTheGenesisVault_withItsWrapOrNotAtAll() = runBlocking<Unit> {
        val logs = Logs()
        val keys = SessionVaultKeys(account(true), logs, VaultRows(crypto), MemoryDeviceState())
        val a = keys.access(personal)!!
        assertEquals(listOf(true, "owner", VaultStanding.VERIFIED, true), listOf(a.personal, a.role, a.standing, a.writable))
        assertContentEquals(ByteArray(32) { 2 }, keys.keyFor(personal))
        assertNull(keys.logHead(personal), "the personal vault has no log")

        // The wrap was withheld or did not open: no personal vault, and nothing stands in for it.
        val none = SessionVaultKeys(account(false), logs, VaultRows(crypto), MemoryDeviceState())
        assertNull(none.personalVaultId)
        assertNull(none.access(personal))
        assertNull(none.keyFor(personal))
        none.served(ServedVaults(true, listOf(row(personal, "personal", head = null), row(shared, "personal")), emptyList(), setOf(personal)))
        none.itemHead(personal, 9, "ab".repeat(32))
        assertTrue(logs.calls.none { personal in it }, "the genesis vault is never handed to the log engine: ${logs.calls}")
        assertTrue("refresh:$shared:3:false" in logs.calls, "and a served `personal` label makes no other vault personal")
    }

    @Test
    fun everySyncTellsTheLogEngineWhatWasServed_andALossItCannotExplainIsWithheld() = runBlocking<Unit> {
        val logs = Logs()
        val keys = SessionVaultKeys(account(true), logs, VaultRows(crypto), MemoryDeviceState())
        logs.statuses[shared] = VaultLogStatus.Verified(shared, state(), false)
        logs.adopted[shared] = ByteArray(32) { 9 }
        val grant = SyncGrant(shared, me, "writer", "", 1, "grant")
        keys.served(ServedVaults(true, listOf(row(personal, "personal", head = null), row(shared)), listOf(grant, grant.copy(vaultId = owner, userId = owner)), emptySet()))
        assertEquals(listOf("refresh:$shared:3:false"), logs.calls, "the served head rides to refresh; a key already adopted is not asked for again")

        // A pull that does not mention the vault still lets the log engine look, against the head last served.
        logs.calls.clear()
        keys.served(ServedVaults(false, emptyList(), emptyList(), emptySet()))
        assertEquals(listOf("refresh:$shared:3:false"), logs.calls)

        // The server says the grant is gone and the log shows no reason: forced refetch, then withheld, durably.
        logs.calls.clear()
        val device = MemoryDeviceState()
        val keys2 = SessionVaultKeys(account(true), logs, VaultRows(crypto), device)
        keys2.reopen(listOf(row(shared)), listOf(grant))
        keys2.served(ServedVaults(false, emptyList(), emptyList(), setOf(shared)))
        assertTrue("refresh:$shared:null:true" in logs.calls)
        assertEquals(VaultStanding.WITHHELD, keys2.access(shared)?.standing)
        assertEquals(VaultStanding.WITHHELD, SessionVaultKeys(account(true), logs, VaultRows(crypto), device).access(shared)?.standing, "it outlives the session")
        // The server serves the grant again: in order.
        keys2.served(ServedVaults(false, listOf(row(shared)), listOf(grant), emptySet()))
        assertEquals(VaultStanding.VERIFIED, keys2.access(shared)?.standing)

        // A vault with a verified log and no key yet is put to the log engine's adoption rules; its verdict is its own.
        logs.adopted.clear()
        logs.calls.clear()
        keys2.served(ServedVaults(false, listOf(row(shared)), listOf(grant), emptySet()))
        assertTrue("adoption:$shared" in logs.calls)
        assertNull(keys2.access(shared))
        keys2.itemHead(shared, 7, "ab".repeat(32))
        assertEquals("head:$shared:7", logs.calls.last())
    }

    @Test
    fun theAccountStatesCounterReachesTheLogEngineBeforeTheRoundsFirstRefresh_andNoneIsToldAsNone() = runBlocking<Unit> {
        val logs = Logs()
        logs.statuses[shared] = VaultLogStatus.Verified(shared, state(), false)
        logs.adopted[shared] = ByteArray(32) { 9 }
        val grant = SyncGrant(shared, me, "writer", "", 1, "grant")
        val keys = SessionVaultKeys(account(true), logs, VaultRows(crypto), MemoryDeviceState())

        keys.served(ServedVaults(true, listOf(row(shared)), listOf(grant), emptySet(), accountStateSeq = 41))
        assertEquals(listOf<Pair<Long?, Int>>(41L to 0), logs.counters, "told once, before any refresh of the round")
        assertEquals(listOf("refresh:$shared:3:false"), logs.calls)

        // An answer without the counter: told as none, so the log engine reads the account state as it always did.
        logs.calls.clear()
        logs.counters.clear()
        keys.served(ServedVaults(false, emptyList(), emptyList(), emptySet()))
        assertEquals(listOf<Pair<Long?, Int>>(null to 0), logs.counters)
        assertEquals(listOf("refresh:$shared:3:false"), logs.calls, "and the round refreshes exactly as before")
    }

    @Test
    fun theSyncAnswersCounterRidesFromThePullToTheTrustEngine() = runBlocking<Unit> {
        val rig = ItemRig()
        rig.server.queue.add(rig.response(6).copy(accountStateSeq = 12))
        rig.engine.sync().ok()
        assertEquals(12L, rig.keys.reports.last().accountStateSeq)
        rig.server.queue.add(rig.response(7))
        rig.engine.sync().ok()
        assertNull(rig.keys.reports.last().accountStateSeq, "an answer without the counter is passed on as none")
    }

    @Test
    fun aColdStartReopensAdoptedKeysOnly_andSoDoesASyncUnderAnOriginThatMayNotBeDialed() = runBlocking<Unit> {
        val logs = Logs()
        logs.statuses[shared] = VaultLogStatus.Verified(shared, state(), false)
        val grant = SyncGrant(shared, me, "writer", "", 1, "grant")
        var dial = true
        val keys = SessionVaultKeys(account(true), logs, VaultRows(crypto), MemoryDeviceState()) { dial }

        // A cold start from the cache: this device's own state only, even while the origin may be dialed.
        keys.reopen(listOf(row(shared)), listOf(grant))
        assertEquals(listOf("reopen:$shared"), logs.calls, "no online adoption (no self-wrap, no record) on a cold start")

        // The first sync with the origin open: the online path.
        logs.calls.clear()
        keys.served(ServedVaults(false, listOf(row(shared)), listOf(grant), emptySet()))
        assertTrue("adoption:$shared" in logs.calls && "reopen:$shared" !in logs.calls, "${logs.calls}")

        // The origin forked or is moving: adopted keys are reopened, nothing is adopted online.
        dial = false
        logs.calls.clear()
        keys.served(ServedVaults(false, listOf(row(shared)), listOf(grant), emptySet()))
        assertTrue("reopen:$shared" in logs.calls && "adoption:$shared" !in logs.calls, "${logs.calls}")
    }
}
