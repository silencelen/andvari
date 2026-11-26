package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.AccountWipedException
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Sealed local records and queued saves on the new account type: the old account's seals, same properties. */
class LocalRecordTest {
    private val crypto = createCryptoProvider()

    private fun account(uvkByte: Int = 1, seedByte: Int = 4): OpenedAccount {
        val seed = ByteArray(32) { seedByte.toByte() }
        val identity = crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields("u1", Bytes.toB64(identity.publicKey), "instance", "v-personal", 0), "00".repeat(32))
        return OpenedAccount("u1", ByteArray(32) { uvkByte.toByte() }, identity, crypto.signKeypairFromSeed(seed), genesis, null, null)
    }

    private val plain = "a kept save".encodeToByteArray()

    @Test
    fun aRecordOpensOnlyForItsAccountAndPurpose() {
        val me = account()
        val record = me.sealLocalRecord(crypto, "moves", plain)
        assertContentEquals(plain, me.openLocalRecord(crypto, "moves", record))
        // A new session of the same account (same UVK and identity) opens it: it is this account's on this device.
        assertContentEquals(plain, account().openLocalRecord(crypto, "moves", record))
        assertNull(me.openLocalRecord(crypto, "saves", record), "another purpose")
        assertNull(account(uvkByte = 9).openLocalRecord(crypto, "moves", record), "another UVK, same identity key")
        assertNull(account(uvkByte = 9, seedByte = 7).openLocalRecord(crypto, "moves", record), "another account")
        assertNull(me.openLocalRecord(crypto, "moves", record.copyOfRange(0, OpenedAccount.LOCAL_RECORD_MAC_BYTES)), "no seal")
        val tampered = record.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertNull(me.openLocalRecord(crypto, "moves", tampered), "a changed seal")
    }

    @Test
    fun aSealedBoxToThePublicKeyAloneIsNotAcceptedAsARecord() {
        val me = account()
        // Anyone holding the public key (every co-member) can make the sealed box; without the UVK-derived MAC it is refused.
        val forged = ByteArray(OpenedAccount.LOCAL_RECORD_MAC_BYTES) + crypto.sealTo(me.identityPub(), plain)
        assertNull(me.openLocalRecord(crypto, "moves", forged))
        val forgedWithPublicMac = crypto.hmacSha256(me.identityPub(), crypto.sealTo(me.identityPub(), plain))
        assertNull(me.openLocalRecord(crypto, "moves", forgedWithPublicMac + crypto.sealTo(me.identityPub(), plain)))
    }

    @Test
    fun theRecordIsTheOldAccountsFormatByteForByte() {
        val me = account()
        val record = me.sealLocalRecord(crypto, "attachments", plain)
        val mac = record.copyOfRange(0, 32)
        val sealed = record.copyOfRange(32, record.size)
        val key = Hkdf.sha256(crypto, ByteArray(32) { 1 }, ByteArray(0), "andvari local record v1|attachments".encodeToByteArray(), 32)
        assertContentEquals(crypto.hmacSha256(key, sealed), mac)
        val identity = crypto.boxKeypairFromSeed(ByteArray(32) { 4 })
        assertContentEquals(plain, crypto.sealOpen(identity.publicKey, identity.privateKey, sealed))
        // And the other way: a record made the old account's way opens here.
        val old = crypto.sealTo(identity.publicKey, plain).let { crypto.hmacSha256(key, it) + it }
        assertContentEquals(plain, me.openLocalRecord(crypto, "attachments", old))
    }

    @Test
    fun aSaveQueuedWhileLockedOpensAfterUnlock() {
        // While locked the host holds only the published public key.
        val published = account().identityPub()
        val queued = crypto.sealTo(published, plain)
        val unlocked = account()
        assertContentEquals(plain, unlocked.openQueuedSave(crypto, queued))
        assertFailsWith<Exception> { account(seedByte = 7).openQueuedSave(crypto, queued) }
        // The public key handed out is a copy: changing it changes nothing.
        published.fill(0)
        assertTrue(unlocked.identityPub().any { it != 0.toByte() })
    }

    @Test
    fun theAccountsOwnSigningKeyIsShownAsAnOperatorKeyIs() {
        val me = account()
        val key = me.signingKeyB64()
        assertContentEquals(crypto.signKeypairFromSeed(ByteArray(32) { 4 }).publicKey, Bytes.fromB64(key))
        assertNotNull(io.silencelen.andvari.core.client.pin.CardTrust.operatorShortFp(crypto, key), "the Trust Gate's short form accepts it")
        me.wipe()
        assertContentEquals(crypto.signKeypairFromSeed(ByteArray(32) { 4 }).publicKey, Bytes.fromB64(me.signingKeyB64()), "public: kept after a wipe")
    }

    @Test
    fun aWipedAccountSealsAndOpensNothing() {
        val me = account()
        val record = me.sealLocalRecord(crypto, "moves", plain)
        val queued = crypto.sealTo(me.identityPub(), plain)
        me.wipe()
        assertFailsWith<AccountWipedException> { me.sealLocalRecord(crypto, "moves", plain) }
        assertFailsWith<AccountWipedException> { me.openLocalRecord(crypto, "moves", record) }
        assertFailsWith<AccountWipedException> { me.openQueuedSave(crypto, queued) }
        // The public key stays readable: the queue is filled while no session holds the private key.
        assertNotNull(me.identityPub())
        assertTrue(me.identityPub().any { it != 0.toByte() })
    }
}
