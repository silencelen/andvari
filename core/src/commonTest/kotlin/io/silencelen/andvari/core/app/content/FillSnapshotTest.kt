package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.client.items.CopyDeletion
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.client.onboard.VaultKeyReader
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The iPhone's AutoFill snapshot on the new session: the content writes it, sealed under the account's vault key, at
 * unlock, after every completed sync and after the person's writes, and deletes it when there is nothing to offer and
 * on sign-out; the extension opens it from the UVK alone (it holds no identity key) and answers as the app does. A
 * snapshot for another account, purpose or key never opens, and one that cannot be read is unknown, never empty.
 */
class FillSnapshotTest {
    private val uvk = ByteArray(32) { 1 }
    private val origin = "https://vault.example.com"

    private class Host(val r: ItemRig, var allowed: Boolean = true) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = allowed
    }

    private fun account(r: ItemRig, seedByte: Byte = 4, userId: String = r.userId, key: ByteArray = uvk): OpenedAccount {
        val seed = ByteArray(32) { seedByte }
        val identity = r.crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(userId, Bytes.toB64(identity.publicKey), "instance", r.personal, 0), "00".repeat(32))
        return OpenedAccount(userId, key.copyOf(), identity, r.crypto.signKeypairFromSeed(seed), genesis, r.personal, ByteArray(32) { 7 })
    }

    /**
     * What the extension can do with what it holds after its own quick unlock, the UVK and the stored session's user:
     * the engine's derivation for [OpenedAccount.sealUnderVaultKey], from the UVK alone. This is the call the engine
     * is asked for; until it lands, the extension has no opener.
     */
    private fun uvkOnly(r: ItemRig, key: ByteArray = uvk, userId: String = r.userId): FillSnapshotOpener {
        val reader = VaultKeyReader(userId, key)
        return FillSnapshotOpener { purpose, bytes -> reader.openUnderVaultKey(r.crypto, purpose, bytes) }
    }

    private class Rig(val r: ItemRig, val host: Host, val fill: InMemoryFillSnapshots, val account: OpenedAccount, val c: EngineVaultContent)

    private fun rig(r: ItemRig = ItemRig().also { it.openShared() }, host: Host = Host(r), fill: InMemoryFillSnapshots = InMemoryFillSnapshots()): Rig {
        r.server.echo = true
        val a = account(r)
        val keeping = ContentKeeping(a, InMemoryFillSnapshots(), InMemoryFillSnapshots(), InMemoryBlobs(), InMemoryFillSnapshots(), InMemorySaveQueue(), fill)
        return Rig(r, host, fill, a, EngineVaultContent(r.engine, r.crypto, host, keeping))
    }

    private fun login(name: String, uri: String, notes: String = "") = LoginInput(name, "me", "pw-$name", listOf(uri), notes, "", false)

    private fun opened(s: Rig, opener: FillSnapshotOpener = uvkOnly(s.r)): FillSnapshotVault =
        assertIs<FillSnapshotRead.Opened>(FillSnapshotVault.read(s.r.crypto, s.fill, origin, s.r.userId, opener)).vault

    private fun plain(s: Rig): ContentFillSnapshot =
        assertNotNull(ContentFillSnapshot.decode(assertNotNull(s.account.openUnderVaultKey(s.r.crypto, ContentFillSnapshot.PURPOSE, assertNotNull(s.fill.bytes)))))

    @Test
    fun writtenAtUnlock_afterASync_andAfterAWrite_sealed_andOpenedFromTheUvkAlone_asTheAppAnswers() = runBlocking<Unit> {
        val s = rig()
        s.c.syncQuietly()
        assertNull(s.fill.bytes, "nothing to offer yet: no snapshot")
        assertEquals(ActionResult.Ok, s.c.saveLogin(null, login("Mine", "https://mine.test", notes = "the secret note"), null))
        assertEquals(ActionResult.Ok, s.c.saveLogin(null, login("Ours", "https://ours.test"), s.r.shared))
        val bytes = assertNotNull(s.fill.bytes, "written after the person's write")
        val text = bytes.decodeToString()
        for (leak in listOf("pw-Mine", "Mine", "ours.test", s.r.personal, s.r.shared, s.r.userId)) assertFalse(leak in text, "$leak is sealed")

        val v = opened(s)
        assertEquals(s.c.fillLogins(listOf("ours.test")), v.logins(listOf("ours.test")), "the extension offers exactly what the app offers")
        assertEquals(listOf("Ours", "Mine"), v.logins(listOf("ours.test")).map { it.name })
        val ours = v.logins(emptyList()).single { it.name == "Ours" }.itemId
        assertEquals("pw-Ours", v.credential(ours)?.password)
        assertTrue(v.matches(ours, listOf("https://ours.test/login")))
        // The engine's own opener answers the same: the identity key plays no part (another identity, same UVK, opens it).
        assertEquals(v.logins(emptyList()), opened(s, { p, b -> account(s.r, seedByte = 5).openUnderVaultKey(s.r.crypto, p, b) }).logins(emptyList()))
        v.close()
        assertTrue(v.logins(emptyList()).isEmpty())
        assertNull(v.credential(ours))

        // Only what a fill needs: no note, no notes field, no password history; a card is in it, a note item is not.
        assertEquals(ActionResult.Ok, s.c.saveNote(null, NoteInput("Diary", "dear diary", false), null))
        assertEquals(ActionResult.Ok, s.c.saveCard(null, CardInput("Visa", "Ana", "4111111111111111", "07", "31", "123", "", "card note", false), null))
        val snap = plain(s)
        assertEquals(setOf("Mine", "Ours", "Visa"), snap.items.map { it.doc.name }.toSet())
        assertTrue(snap.items.all { it.doc.notes == null && it.doc.attachments.isEmpty() && it.doc.login?.passwordHistory.orEmpty().isEmpty() })
        assertEquals("4111111111111111", opened(s).let { o -> o.cardField(o.cards().single().itemId, "number") })

        // At the next unlock, from this device's copy before anything is asked of the server; and after every sync.
        s.fill.bytes = null
        val again = rig(s.r, fill = s.fill)
        s.r.server.offline = true
        again.c.syncQuietly()
        assertEquals(3, opened(again).logins(emptyList()).size + opened(again).cards().size, "written at unlock, offline")
        s.r.server.offline = false
        s.fill.bytes = null
        again.c.syncQuietly()
        assertNotNull(s.fill.bytes, "written after a completed sync")
    }

    @Test
    fun aFrozenFailedOrWithheldVault_isLeftOut_oneVerifiedAgainIsBack() = runBlocking<Unit> {
        val s = rig()
        s.c.syncQuietly()
        s.c.saveLogin(null, login("Mine", "https://mine.test"), null)
        s.c.saveLogin(null, login("Ours", "https://ours.test"), s.r.shared)
        for (standing in listOf(VaultStanding.FROZEN, VaultStanding.FAILED, VaultStanding.WITHHELD)) {
            s.r.keys.put(s.r.shared, s.r.sharedKey, VaultAccess.ROLE_WRITER, standing)
            s.c.syncQuietly()
            assertTrue(plain(s).items.none { it.vaultId == s.r.shared }, "$standing: left out")
            assertEquals(listOf("Mine"), opened(s).logins(emptyList()).map { it.name })
        }
        s.r.keys.put(s.r.shared, s.r.sharedKey, VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        s.c.syncQuietly()
        assertEquals(listOf("Mine", "Ours"), opened(s).logins(emptyList()).map { it.name })
    }

    @Test
    fun anotherAccount_purpose_key_origin_version_aDamagedSeal_orAStoreThatFails_isUnknown_neverEmpty() = runBlocking<Unit> {
        val s = rig()
        s.c.syncQuietly()
        s.c.saveLogin(null, login("Mine", "https://mine.test"), null)
        val bytes = assertNotNull(s.fill.bytes)
        val crypto = s.r.crypto
        val other = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        fun read(b: ByteArray, opener: FillSnapshotOpener = uvkOnly(s.r), at: String = origin, user: String = s.r.userId) =
            FillSnapshotVault.readBytes(crypto, b, at, user, opener)

        assertSame(FillSnapshotRead.Unreadable, read(bytes, uvkOnly(s.r, key = ByteArray(32) { 2 })), "another key")
        assertSame(FillSnapshotRead.Unreadable, read(bytes, uvkOnly(s.r, userId = other), user = other), "another account, same key")
        assertSame(FillSnapshotRead.Unreadable, read(bytes, at = "https://other.example.com"), "another origin")
        val damaged = bytes.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertSame(FillSnapshotRead.Unreadable, read(damaged), "a damaged seal")
        val plainBytes = plain(s).encode()
        assertSame(FillSnapshotRead.Unreadable, read(s.account.sealUnderVaultKey(crypto, "kept-saves", plainBytes)), "another purpose")
        assertSame(FillSnapshotRead.Unreadable, read(plainBytes), "an unsealed snapshot")
        val v2 = s.account.sealUnderVaultKey(crypto, ContentFillSnapshot.PURPOSE, "{\"v\":2,\"origin\":\"$origin\",\"userId\":\"${s.r.userId}\",\"items\":[],\"writtenAtMs\":0}".encodeToByteArray())
        assertSame(FillSnapshotRead.Unreadable, read(v2), "another version")
        assertSame(FillSnapshotRead.Unreadable, read(bytes, { _, _ -> throw IllegalStateException("wiped") }), "an opener that throws")

        val failing = object : FillSnapshotStore, StrictRecordStore {
            override fun write(bytes: ByteArray) = false
            override fun read(): ByteArray? = null
            override fun delete() = Unit
            override fun readOrThrow(): ByteArray? = throw StoreUnreadableException("the App Group could not be read")
        }
        assertSame(FillSnapshotRead.Unreadable, FillSnapshotVault.read(crypto, failing, origin, s.r.userId, uvkOnly(s.r)), "a store that fails")
        assertSame(FillSnapshotRead.Absent, FillSnapshotVault.read(crypto, InMemoryFillSnapshots(), origin, s.r.userId, uvkOnly(s.r)), "only no file is absent")
        assertIs<FillSnapshotRead.Opened>(read(bytes))
    }

    @Test
    fun deleted_whenThePolicyForbidsIt_whenNothingIsLeft_andOnSignOut_butALockAndAStoppedServerKeepIt() = runBlocking<Unit> {
        val s = rig()
        s.c.syncQuietly()
        s.c.saveLogin(null, login("Mine", "https://mine.test"), null)
        assertNotNull(s.fill.bytes)
        s.host.allowed = false
        s.c.syncQuietly()
        assertNull(s.fill.bytes, "the policy forbids keeping data here")
        s.host.allowed = true
        s.c.syncQuietly()
        val id = assertNotNull(s.fill.bytes).let { opened(s).logins(emptyList()).single().itemId }
        assertEquals(ActionResult.Ok, s.c.deleteItem(id))
        assertNull(s.fill.bytes, "nothing left to offer")

        s.c.saveLogin(null, login("Mine", "https://mine.test"), null)
        s.c.close()
        assertNotNull(s.fill.bytes, "a lock keeps it: the extension fills while the app is locked")
        s.account.wipe()

        // A server stopped on this device: its copy is filled from, so the unlock's snapshot is written from it.
        s.fill.bytes = null
        val stopped = s.r.restarted().also { it.halt() }
        val keeping = ContentKeeping(account(s.r), InMemoryFillSnapshots(), InMemoryFillSnapshots(), InMemoryBlobs(), InMemoryFillSnapshots(), InMemorySaveQueue(), s.fill)
        val b = EngineVaultContent(stopped, s.r.crypto, s.host, keeping)
        b.syncQuietly()
        assertEquals(listOf("Mine"), opened(s).logins(emptyList()).map { it.name })

        // Sign-out (and every other drop) deletes it, locked, whoever's it is; so does a forbidding policy at unlock.
        val stores = ContentStores(s.r.crypto, null, InMemorySaveQueue(), s.fill)
        stores.drop(origin, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", CopyDeletion.SIGNED_OUT)
        assertNull(s.fill.bytes, "sign-out")
        s.fill.bytes = byteArrayOf(1)
        keeping.dropAll(CopyDeletion.SIGNED_OUT)
        assertNull(s.fill.bytes, "dropAll")
        s.fill.bytes = byteArrayOf(1)
        stores.keeping(account(s.r), origin, offlineCacheAllowed = false)
        assertNull(s.fill.bytes, "a policy that forbids it, at unlock")
    }

    @Test
    fun aWriteTheStoreRefuses_deletesTheOldOne_andALockedAccountWritesAndDeletesNothing() = runBlocking<Unit> {
        val s = rig()
        s.c.syncQuietly()
        s.c.saveLogin(null, login("Mine", "https://mine.test"), null)
        val old = assertNotNull(s.fill.bytes)
        s.fill.refuse = true
        s.c.saveLogin(null, login("Second", "https://second.test"), null)
        assertNull(s.fill.bytes, "an older snapshot never stays in place of the one that could not be written")
        s.fill.refuse = false

        s.fill.bytes = old
        s.account.wipe()
        FillSnapshotWriter(s.fill, s.account, s.r.crypto).write(ContentFillSnapshot(origin = origin, userId = s.r.userId, items = emptyList(), writtenAtMs = 0))
        assertSame(old, s.fill.bytes, "a lock is not a reason to delete")
    }
}
