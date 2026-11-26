package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AdoptionRefusal
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogEngine
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.RemovedGrantInfo
import io.silencelen.andvari.core.model.wire.RemovedReason
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * On the shared item engine: a sync answer can never take the personal vault away. A personal vault has no
 * members (design §3.10), so no removal of it can be genuine, and a server must not be able to take a person's saved
 * passwords off their own device (design §4.4). Every variant runs through the real [ItemEngine] over the real
 * [SessionVaultKeys] and an [OpenedAccount]: the items stay, the key stays, the cache's rows stay, saves go on, and the
 * person gets one notice of its own ([ItemNotice.PERSONAL_KEPT]).
 *
 * Before: the engine already skipped the personal vault where it moves vaults to the holding area, and
 * [SessionVaultKeys] already ignored it in a lost-grant report, so the items and the key stayed. But it said nothing,
 * a served grant row of the personal vault under another key replaced the cached one, and metadata under another key
 * replaced the vault's name.
 */
class PersonalVaultKeptTest {
    private val crypto = createCryptoProvider()
    private val me = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private val personal = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private val personalKey = ByteArray(32) { 2 }
    private val otherKey = ByteArray(32) { 5 }
    private val codec = ItemCodec(crypto)

    /** No shared vault in these tests: the log engine knows nothing. */
    private class NoLogs : VaultLogEngine {
        override fun status(vaultId: String): VaultLogStatus = VaultLogStatus.Unknown(vaultId)
        override suspend fun refresh(vaultId: String, servedSeq: Long?, servedHash: String?, force: Boolean): VaultLogStatus = status(vaultId)
        override suspend fun adoption(vaultId: String): Adoption = Adoption.Refused(vaultId, AdoptionRefusal.NO_KEY)
        override suspend fun answerIncoming(ask: Adoption.AskAccept, accept: Boolean): Adoption = Adoption.Declined(ask.vaultId)
        override suspend fun noteItemHead(vaultId: String, seq: Long, hash: String): VaultLogStatus = status(vaultId)
        override suspend fun append(vaultId: String?, action: LogAction): AppendOutcome = AppendOutcome.VaultReadOnly
        override suspend fun retryPending() {}
        override fun writeAllowed(vaultId: String): Boolean = false
        override fun copyOutAllowed(vaultId: String): Boolean = false
        override fun <T> withKey(vaultId: String, block: (ByteArray) -> T): T? = null
    }

    private inner class Rig {
        val seed = ByteArray(32) { 4 }
        val account = OpenedAccount(
            me, ByteArray(32) { 1 }, crypto.boxKeypairFromSeed(seed), crypto.signKeypairFromSeed(seed),
            VerifiedGenesis(GenesisFields(me, Bytes.toB64(crypto.boxKeypairFromSeed(seed).publicKey), "instance", personal, 0), "00".repeat(32)),
            personal, personalKey.copyOf(),
        )
        val server = FakeItemServer()
        val cache = DurableCache()
        val keys = SessionVaultKeys(account, NoLogs(), VaultRows(crypto), MemoryDeviceState())
        val engine = ItemEngine(server, keys, FakeGate(), cache, me, crypto, { 1_763_164_800_000L })
        val itemId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        val vaultRow = SyncVault(personal, "personal", 2, codec.sealVaultMeta(personalKey, personal, "Mine"), 0)
        val grant = SyncGrant(personal, me, "owner", "wrapped-under-the-uvk", 2)
        val doc = ItemDoc(type = "login", name = "Router", login = LoginData(username = "admin", password = "hunter2"))

        init {
            val up = codec.seal(personalKey, personal, itemId, doc)
            val row = SyncItem(itemId, personal, 3, 0, 3, false, false, up.formatVersion, up.attachmentIds, up.blob)
            server.itemRows[itemId] = row
            server.rev = 5
            server.queue.add(SyncResponse(5, true, listOf(vaultRow), listOf(grant), listOf(row), emptyList(), emptyList(), 0, 0))
            runBlocking { engine.sync().ok() }
            check(engine.notices().isEmpty()) { "a genuine first snapshot raises nothing: ${engine.notices()}" }
        }

        fun answer(
            full: Boolean = false, vaults: List<SyncVault> = emptyList(), grants: List<SyncGrant> = emptyList(),
            removed: List<String> = emptyList(), info: List<RemovedGrantInfo> = emptyList(), items: List<SyncItem> = emptyList(),
        ) {
            server.rev += 1
            server.queue.add(SyncResponse(server.rev, full, vaults, grants, items, removed, info, 0, 0))
        }

        /** Everything the class's comment names stays as it was, and a save goes on under the account's own key. */
        suspend fun assertKept(variant: String) {
            assertEquals(listOf("Router"), engine.items().map { it.doc.name }, "$variant: the items stay")
            val view = assertNotNull(engine.vaults().singleOrNull { it.vaultId == personal }, "$variant: the vault stays listed")
            assertEquals("personal", view.type, variant)
            assertEquals("Mine", view.name, "$variant: its name is the one sealed under its own key")
            assertTrue(view.writable, variant)
            assertEquals(VaultStanding.VERIFIED, keys.access(personal)?.standing, "$variant: the key stays")
            assertContentEquals(personalKey, keys.keyFor(personal), variant)
            assertEquals(listOf(vaultRow), cache.vaults().map { SyncVault(it.vaultId, it.type, it.rev, it.metaBlob, it.createdAt) }, "$variant: the cache's vault row stays")
            assertEquals(listOf(grant.wrappedVk), cache.grants().filter { it.vaultId == personal }.map { it.wrappedVk }, "$variant: the cache's grant row stays")
            assertEquals(listOf(itemId), cache.envelopes().filter { !it.deleted }.map { it.itemId }, "$variant: the cache's item row stays")
            assertTrue(cache.heldVaults().isEmpty(), "$variant: nothing went to the holding area")

            val pushesBefore = server.pushes.size
            val saved = engine.save(null, doc.copy(name = "After $variant")).ok()
            assertEquals(Written.APPLIED, saved.outcome, variant)
            val put = server.pushes.drop(pushesBefore).flatten().single { it.itemId == saved.itemId }
            assertEquals(personal, put.vaultId, variant)
            val up = put.item!!
            assertEquals("After $variant", codec.open(personalKey, SyncItem(put.itemId, put.vaultId, 0, 0, 0, false, false, up.formatVersion, up.attachmentIds, up.blob)).name, "$variant: sealed under the account's own key")

            assertEquals(1, engine.notices().count { it.kind == ItemNotice.PERSONAL_KEPT }, "$variant: the person is told, once: ${engine.notices()}")
            assertTrue(engine.notices().none { it.kind == ItemNotice.WITHHELD || it.kind == ItemNotice.REMOVED || it.kind == ItemNotice.DELETED }, variant)

            // After a restart the cache still opens to the same vault.
            val again = ItemEngine(server, keys, FakeGate(), cache, me, crypto, { 1_763_164_800_000L })
            again.hydrate()
            assertTrue(again.items().any { it.itemId == itemId }, "$variant: the rows survive a restart")
        }
    }

    @Test
    fun anAnswerNamingThePersonalVaultAsRemoved_changesNothing() = runBlocking<Unit> {
        val r = Rig()
        r.answer(removed = listOf(personal), info = listOf(RemovedGrantInfo(personal, RemovedReason.REMOVED)))
        r.engine.sync().ok()
        r.assertKept("removed")
        // The same answer again while the notice is shown: still one notice.
        r.answer(removed = listOf(personal), info = listOf(RemovedGrantInfo(personal, RemovedReason.LEFT)))
        r.engine.sync().ok()
        assertEquals(1, r.engine.notices().count { it.kind == ItemNotice.PERSONAL_KEPT })
    }

    @Test
    fun anAnswerNamingThePersonalVaultAsDeleted_changesNothing() = runBlocking<Unit> {
        val r = Rig()
        r.answer(removed = listOf(personal), info = listOf(RemovedGrantInfo(personal, RemovedReason.DELETED, deletedAt = 1, purgeAt = 2)))
        r.engine.sync().ok()
        r.assertKept("deleted")
    }

    @Test
    fun onlyTheCompanionDetailNamingIt_isStillTold() = runBlocking<Unit> {
        val r = Rig()
        r.answer(info = listOf(RemovedGrantInfo(personal, RemovedReason.DELETED)))
        r.engine.sync().ok()
        r.assertKept("info only")
    }

    @Test
    fun aWholeSnapshotWithoutItsGrantRow_changesNothing() = runBlocking<Unit> {
        val r = Rig()
        r.server.goneOnce = true
        r.answer(full = true, vaults = listOf(r.vaultRow), items = listOf(r.server.itemRows.getValue(r.itemId)))
        r.engine.sync().ok()
        r.assertKept("grant row missing")
    }

    @Test
    fun aWholeSnapshotWithoutTheVaultAtAll_changesNothing() = runBlocking<Unit> {
        val r = Rig()
        r.server.goneOnce = true
        r.answer(full = true)
        r.engine.sync().ok()
        r.assertKept("vault missing")
    }

    @Test
    fun itsGrantRowServedUnderAnotherKey_changesNothing() = runBlocking<Unit> {
        val r = Rig()
        r.answer(grants = listOf(r.grant.copy(wrappedVk = "another-wrap", rev = 9)))
        r.engine.sync().ok()
        r.assertKept("grant under another key")
    }

    @Test
    fun itsMetadataServedUnderAnotherKey_changesNothing() = runBlocking<Unit> {
        val r = Rig()
        r.answer(vaults = listOf(r.vaultRow.copy(rev = 9, metaBlob = codec.sealVaultMeta(otherKey, personal, "Taken"))))
        r.engine.sync().ok()
        r.assertKept("metadata under another key")
    }

    @Test
    fun aResyncRemovingItUnderAnotherKey_changesNothing() = runBlocking<Unit> {
        val r = Rig()
        r.server.goneOnce = true
        r.answer(
            full = true,
            vaults = listOf(r.vaultRow.copy(rev = 9, metaBlob = codec.sealVaultMeta(otherKey, personal, "Taken"))),
            grants = listOf(r.grant.copy(wrappedVk = "another-wrap", rev = 9)),
            removed = listOf(personal),
            items = listOf(r.server.itemRows.getValue(r.itemId)),
        )
        r.engine.sync().ok()
        r.assertKept("resync under another key")
    }
}
