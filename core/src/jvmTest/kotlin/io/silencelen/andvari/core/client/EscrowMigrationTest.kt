package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.EscrowFormat
import io.silencelen.andvari.core.crypto.EscrowOpenException
import io.silencelen.andvari.core.crypto.EscrowVerdict
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Escrow v1 → v2 migration (security review 2026-10, root cause A §8.4) and the recovered-member
 * backstop (§2.4). The round trip: a member whose escrow is a v1 blob stays recoverable (Q3), re-seals
 * to v2 through the migration path, and the v2 blob recovers the SAME UVK and identity — end to end
 * through a temp-password re-wrap and an unlock, exactly the way the recovery CLI and the member's
 * next sign-in consume it. The legacy blob the server retains stays recoverable too.
 */
class EscrowMigrationTest {
    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"

    private class Member(val userId: String, val keys: AccountKeys, val account: Account)

    /** A pre-A4 member: enrolled, with a v1 escrow blob (what every existing account holds today). */
    private fun legacyMember(orgPub: ByteArray): Pair<Member, ByteArray> {
        val r = Account.enroll("inv", "m@x.com", "m", password, kdf, null, null, "dev", crypto)
        val keys = AccountKeys(r.request.kdfSalt, r.request.kdfParams, r.request.wrappedUvk, r.request.encryptedIdentitySeed, r.request.identityPub, "")
        val v1 = Escrow.sealUvkV1(crypto, orgPub, r.request.userId, r.account.uvkCopyForPlatformWrap())
        return Member(r.request.userId, keys, r.account) to v1
    }

    private fun anchorOf(m: Member) = Escrow.fingerprint(crypto, m.account.identityPub).take(32)
    private fun idCheck(m: Member) = IdentityCheck(m.keys.encryptedIdentitySeed, m.keys.identityPub)

    /** What `recovery-cli recover` does after a successful open, then the member's sign-in with the temp password. */
    private fun recoverAndUnlock(m: Member, uvk: ByteArray, selfIdentityPub: ByteArray?): Account {
        val tempPassword = "temp password for the drill"
        val salt = crypto.randomBytes(KdfParams.SALT_BYTES)
        val mk = Keys.masterKey(crypto, tempPassword, salt, kdf)
        val wrapped = Envelope.sealB64(crypto, Keys.wrapKey(crypto, mk), uvk, Ad.uvk(m.userId))
        val recoveredKeys = m.keys.copy(kdfSalt = Bytes.toB64(salt), kdfParams = kdf, wrappedUvk = wrapped)
        return Account.unlock(m.userId, tempPassword, recoveredKeys, crypto, selfIdentityPub)
    }

    @Test
    fun v1MemberResealsToV2_andStaysRecoverable_endToEnd() {
        val org = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val orgFp = Escrow.fingerprint(crypto, org.publicKey)
        val (m, v1) = legacyMember(org.publicKey)
        val realUvk = m.account.uvkCopyForPlatformWrap()

        // Before migration: the v1 blob recovers, as V1_LEGACY, only through the identity check (Q3).
        val legacy = Escrow.open(crypto, org, v1, m.userId, anchorOf(m), idCheck(m))
        assertEquals(EscrowFormat.V1_LEGACY, legacy.format)
        assertContentEquals(realUvk, legacy.uvk)

        // Migration (§8.4): the member confirms the org key (32 hex from the sheet → the full fp the client
        // holds) and the client re-seals v2. This is exactly Account.resealEscrowFor.
        val upload = m.account.resealEscrowFor(Bytes.toB64(org.publicKey), orgFp)
        assertEquals(orgFp, upload.fingerprint)
        val v2 = Bytes.fromB64(upload.sealed)
        assertTrue(v2.size != 226, "a v2 seal is not v1-sized (the server's migration hint keys on the v1 length)")

        val opened = Escrow.open(crypto, org, v2, m.userId, anchorOf(m), idCheck(m))
        assertEquals(EscrowFormat.V2, opened.format)
        assertContentEquals(realUvk, opened.uvk, "the v2 blob recovers the SAME UVK")
        assertContentEquals(m.account.identityPub, opened.identityKey, "…bound to the SAME identity")

        // The recovered account unlocks under a temp password and derives the same identity; the
        // member's own device (holding the pin) accepts it.
        val recovered = recoverAndUnlock(m, opened.uvk, selfIdentityPub = m.account.identityPub)
        assertContentEquals(m.account.identityPub, recovered.identityPub)
        assertContentEquals(m.account.signPub, recovered.signPub)

        // The server retains the v1 blob (escrow_legacy) until a drill passes on the v2 one: it stays
        // recoverable after the migration, so a defective v2 seal could never strand the member.
        val stillLegacy = Escrow.open(crypto, org, v1, m.userId, anchorOf(m), idCheck(m))
        assertContentEquals(realUvk, stillLegacy.uvk)
    }

    @Test
    fun migrationSeal_refusesAnOrgKeyThatDoesNotMatchTheConfirmedFingerprint() {
        val org = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val swapped = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val (m, _) = legacyMember(org.publicKey)
        // A hostile server serves ITS key beside the fingerprint the member confirmed from the sheet.
        assertFailsWith<IllegalArgumentException> {
            m.account.resealEscrowFor(Bytes.toB64(swapped.publicKey), Escrow.fingerprint(crypto, org.publicKey))
        }
    }

    @Test
    fun v2Blob_ofOneMember_cannotRecoverAnother() {
        val org = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val orgFp = Escrow.fingerprint(crypto, org.publicKey)
        val (a, _) = legacyMember(org.publicKey)
        val (x, _) = legacyMember(org.publicKey)
        val aBlob = Bytes.fromB64(a.account.resealEscrowFor(Bytes.toB64(org.publicKey), orgFp).sealed)
        // The admin asks for X (with X's anchor and identity file); the server serves A's genuine blob.
        val e = assertFailsWith<EscrowOpenException> { Escrow.open(crypto, org, aBlob, x.userId, anchorOf(x), idCheck(x)) }
        assertEquals(EscrowVerdict.USER_MISMATCH, e.verdict)
    }

    @Test
    fun backstop_aDeviceThatKnewTheRealIdentityRefusesAForgedRecovery() {
        val (m, _) = legacyMember(crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey)
        // A forged recovery (A-3, unanchored): the server mints UVK' and a self-consistent seed' / identity'.
        val forgedUvk = crypto.randomBytes(32)
        val forgedSeed = crypto.randomBytes(32)
        val forgedPub = crypto.boxKeypairFromSeed(forgedSeed).publicKey
        val forged = Member(
            m.userId,
            m.keys.copy(
                encryptedIdentitySeed = Envelope.sealB64(crypto, forgedUvk, forgedSeed, Ad.idkey(m.userId)),
                identityPub = Bytes.toB64(forgedPub),
            ),
            m.account,
        )
        // A device with no record (a brand-new device) cannot tell: that is the documented Q2 residual.
        recoverAndUnlock(forged, forgedUvk, selfIdentityPub = null)
        // The member's existing device holds the real identity and hard-fails with the spec 01 §5 copy.
        val e = assertFailsWith<CryptoException> { recoverAndUnlock(forged, forgedUvk, selfIdentityPub = m.account.identityPub) }
        assertEquals(Account.IDENTITY_MISMATCH_MESSAGE, e.message)
        // And the genuine account still unlocks on that device.
        Account.unlock(m.userId, password, m.keys, crypto, selfIdentityPub = m.account.identityPub)
    }

    @Test
    fun selfIdentityPin_decodesOnlyA32ByteRecord() {
        assertEquals(null, SelfIdentityPin.decode(null))
        assertEquals(null, SelfIdentityPin.decode("not base64 !!"))
        assertEquals(null, SelfIdentityPin.decode(Bytes.toB64(ByteArray(31))))
        val (m, _) = legacyMember(crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey)
        assertContentEquals(m.account.identityPub, SelfIdentityPin.decode(SelfIdentityPin.encode(m.account)))
    }
}
