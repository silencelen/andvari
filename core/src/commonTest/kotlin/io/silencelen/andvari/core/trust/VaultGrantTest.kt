package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

/**
 * Grants under design 2026-11-15 §3.5: the ten checks, each with its verdict, and the ORDER (a grant
 * that breaks two rules gets the earlier one). Built from the design's rules with real logs; the
 * rewritten `sharedgrant-v2.json` grades the same verifier once its vector file lands.
 */
class VaultGrantTest {
    private val crypto = createCryptoProvider()
    private val alice = Party(crypto, Ids.ALICE, 1)
    private val bob = Party(crypto, Ids.BOB, 2)
    private val carol = Party(crypto, Ids.CAROL, 3)
    private val grantId = Ids.id16(1)

    /** alice owns the vault and added bob with [grantId]. */
    private fun sharedLog(): LogBuilder = LogBuilder(crypto).also {
        it.genesis(alice)
        it.add(alice, bob, grantId)
    }

    private fun grant(
        from: String = Ids.ALICE,
        to: String = Ids.BOB,
        toKey: String = bob.key,
        vaultId: String = Ids.VAULT,
        id: String = grantId,
        vk: ByteArray,
    ) = GrantFields(from, to, toKey, vaultId, id, Ids.T0 + 5, vk)

    private fun sealedFor(party: Party, frame: ByteArray): ByteArray = VaultGrant.seal(crypto, party.box.publicKey, frame)

    private fun open(sealed: ByteArray, state: VaultState?, me: Party = bob, row: String = Ids.VAULT) =
        VaultGrant.open(crypto, me.userId, me.box.publicKey, me.box.privateKey, row, sealed, state)

    private fun verdict(sealed: ByteArray, state: VaultState?, me: Party = bob, row: String = Ids.VAULT): VaultGrantVerdict =
        assertIs<Checked.Refused<VaultGrantVerdict>>(open(sealed, state, me, row)).verdict

    @Test
    fun aGrantBoundToItsAddEntryOpens() {
        val log = sharedLog()
        val frame = VaultGrant.sign(crypto, alice.sign, grant(vk = log.vk))
        val opened = assertIs<Checked.Ok<OpenedGrant>>(open(sealedFor(bob, frame), log.state)).value
        assertContentEquals(log.vk, opened.vk)
        assertEquals(Ids.ALICE, opened.from)
        assertEquals(grantId, opened.grantId)
        // The add the grant was bound to: its actor is the owner who shared, its seq the addSeq to accept.
        assertEquals(Ids.ALICE, opened.add.actor)
        assertEquals(alice.key, opened.add.ownerKey)
        assertEquals(log.state!!.members.getValue(Ids.BOB).addSeq, opened.add.seq)
        opened.wipe()
        assertContentEquals(ByteArray(32), opened.vk)
    }

    @Test
    fun eachCheckHasItsVerdict() {
        val log = sharedLog()
        val state = log.state
        val good = VaultGrant.sign(crypto, alice.sign, grant(vk = log.vk))

        // 1. The seal does not open: sealed to someone else, or not a sealed box at all.
        assertEquals(VaultGrantVerdict.UNOPENABLE, verdict(sealedFor(carol, good), state))
        assertEquals(VaultGrantVerdict.UNOPENABLE, verdict(ByteArray(10), state))
        assertEquals(VaultGrantVerdict.UNOPENABLE, verdict(ByteArray(200), state))

        // 2. Not a frame of purpose 0x01.
        assertEquals(VaultGrantVerdict.BAD_FRAME, verdict(sealedFor(bob, log.frames[0]), state), "a vault-log frame")
        assertEquals(VaultGrantVerdict.BAD_FRAME, verdict(sealedFor(bob, good.copyOf(50)), state), "truncated")
        assertEquals(VaultGrantVerdict.BAD_FRAME, verdict(sealedFor(bob, ByteArray(2)), state), "shorter than the magic")
        assertEquals(VaultGrantVerdict.UNKNOWN_FORMAT, verdict(sealedFor(bob, "{\"v\":1,\"vaultId\":\"x\"}".encodeToByteArray()), state), "a v1 JSON payload")

        // 3. The strict parse. These statements are signed, so only the parse can refuse them.
        val statement = assertIs<Checked.Ok<FrameParts>>(SignedFrame.split(good)).value.statement.decodeToString()
        fun signedRaw(text: String) = sealedFor(bob, SignedFrame.sign(crypto, alice.sign, TrustPurpose.VAULT_GRANT, text.encodeToByteArray()))
        assertEquals(VaultGrantVerdict.NON_CANONICAL, verdict(signedRaw(statement.replace("\"v\":2", "\"v\": 2")), state))
        assertEquals(VaultGrantVerdict.NON_CANONICAL, verdict(signedRaw(statement.replace(Ids.VAULT, Ids.VAULT.uppercase())), state))
        assertEquals(VaultGrantVerdict.BAD_STATEMENT, verdict(signedRaw(statement.replace("\"v\":2", "\"v\":3")), state))
        assertEquals(VaultGrantVerdict.BAD_STATEMENT, verdict(signedRaw(statement.replace(Ids.ALICE, Ids.BOB)), state), "from == to")

        // 4. Addressed to another account, or to another key.
        val toCarol = VaultGrant.sign(crypto, alice.sign, grant(to = Ids.CAROL, toKey = carol.key, vk = log.vk))
        assertEquals(VaultGrantVerdict.MISADDRESSED, verdict(sealedFor(bob, toCarol), state))
        val otherKey = VaultGrant.sign(crypto, alice.sign, grant(toKey = carol.key, vk = log.vk))
        assertEquals(VaultGrantVerdict.MISADDRESSED, verdict(sealedFor(bob, otherKey), state))

        // 5. For another vault than the row it arrived on.
        assertEquals(VaultGrantVerdict.VAULT_MISMATCH, verdict(sealedFor(bob, good), state, row = Ids.OTHER_VAULT))
        val otherVault = VaultGrant.sign(crypto, alice.sign, grant(vaultId = Ids.OTHER_VAULT, vk = log.vk))
        assertEquals(VaultGrantVerdict.VAULT_MISMATCH, verdict(sealedFor(bob, otherVault), state))

        // 6. No add entry: another grantId, no verified log, or another vault's log.
        val otherId = VaultGrant.sign(crypto, alice.sign, grant(id = Ids.id16(7), vk = log.vk))
        assertEquals(VaultGrantVerdict.NO_ADD_ENTRY, verdict(sealedFor(bob, otherId), state))
        assertEquals(VaultGrantVerdict.NO_ADD_ENTRY, verdict(sealedFor(bob, good), null))
        val elsewhere = LogBuilder(crypto, Ids.OTHER_VAULT).also { it.genesis(alice); it.add(alice, bob, grantId) }
        assertEquals(VaultGrantVerdict.NO_ADD_ENTRY, verdict(sealedFor(bob, good), elsewhere.state))
        // The add names this account under ANOTHER key: it is not an add for this account's key.
        val wrongKeyLog = LogBuilder(crypto).also {
            it.genesis(alice)
            it.append(alice) { p -> LogEntry.Add(Ids.VAULT, p.seq, p.prev, Ids.ALICE, p.at, Ids.BOB, carol.key, MemberRole.WRITER, grantId) }
        }
        assertEquals(VaultGrantVerdict.NO_ADD_ENTRY, verdict(sealedFor(bob, good), wrongKeyLog.state))

        // 7. Not the owner who signed the add: a writer granting (R15(f)), or the owner's name over another signer.
        val byCarolAsHerself = VaultGrant.sign(crypto, carol.sign, grant(from = Ids.CAROL, vk = log.vk))
        assertEquals(VaultGrantVerdict.NOT_AUTHORIZED, verdict(sealedFor(bob, byCarolAsHerself), state))
        val byCarolAsAlice = VaultGrant.sign(crypto, carol.sign, grant(vk = log.vk))
        assertEquals(VaultGrantVerdict.NOT_AUTHORIZED, verdict(sealedFor(bob, byCarolAsAlice), state))

        // 8. A flipped signature bit.
        val flipped = good.copyOf().also { it[50] = (it[50].toInt() xor 0x10).toByte() }
        assertEquals(VaultGrantVerdict.BAD_SIGNATURE, verdict(sealedFor(bob, flipped), state))

        // 9. A key the genesis did not commit to (R15(g)).
        val otherVk = VaultGrant.sign(crypto, alice.sign, grant(vk = ByteArray(32) { 9 }))
        assertEquals(VaultGrantVerdict.VK_COMMIT_MISMATCH, verdict(sealedFor(bob, otherVk), state))

        // 10. Removed, or left, with no later add.
        val removed = sharedLog().also { it.remove(alice, bob) }
        assertEquals(VaultGrantVerdict.REMOVED, verdict(sealedFor(bob, good), removed.state))
        val left = sharedLog().also { it.leave(bob) }
        assertEquals(VaultGrantVerdict.REMOVED, verdict(sealedFor(bob, good), left.state))
    }

    @Test
    fun theFirstFailingCheckDecides() {
        val log = sharedLog()
        val removed = sharedLog().also { it.remove(alice, bob) }
        val wrongVk = ByteArray(32) { 9 }

        // 4 before 5: misaddressed AND another vault.
        val a = VaultGrant.sign(crypto, alice.sign, grant(to = Ids.CAROL, toKey = carol.key, vaultId = Ids.OTHER_VAULT, vk = log.vk))
        assertEquals(VaultGrantVerdict.MISADDRESSED, verdict(sealedFor(bob, a), log.state))
        // 5 before 6: another vault AND no add.
        val b = VaultGrant.sign(crypto, alice.sign, grant(vaultId = Ids.OTHER_VAULT, id = Ids.id16(7), vk = log.vk))
        assertEquals(VaultGrantVerdict.VAULT_MISMATCH, verdict(sealedFor(bob, b), log.state))
        // 6 before 7 and 8: no add AND a stranger's signature AND a flipped bit.
        val c = VaultGrant.sign(crypto, carol.sign, grant(id = Ids.id16(7), vk = log.vk)).also { it[50] = (it[50].toInt() xor 1).toByte() }
        assertEquals(VaultGrantVerdict.NO_ADD_ENTRY, verdict(sealedFor(bob, c), log.state))
        // 7 before 8 and 9: not the owner AND a flipped bit AND a wrong key.
        val d = VaultGrant.sign(crypto, carol.sign, grant(vk = wrongVk)).also { it[50] = (it[50].toInt() xor 1).toByte() }
        assertEquals(VaultGrantVerdict.NOT_AUTHORIZED, verdict(sealedFor(bob, d), log.state))
        // 8 before 9: a flipped bit AND a wrong key.
        val e = VaultGrant.sign(crypto, alice.sign, grant(vk = wrongVk)).also { it[50] = (it[50].toInt() xor 1).toByte() }
        assertEquals(VaultGrantVerdict.BAD_SIGNATURE, verdict(sealedFor(bob, e), log.state))
        // 9 before 10: a wrong key AND removed.
        val f = VaultGrant.sign(crypto, alice.sign, grant(vk = wrongVk))
        assertEquals(VaultGrantVerdict.VK_COMMIT_MISMATCH, verdict(sealedFor(bob, f), removed.state))
    }

    @Test
    fun aGrantIsBoundToTheAccountsLatestAdd_evenWhenAnEarlierOneNamesTheSameGrant() {
        // alice adds bob with grantId G and removes him; ownership moves to carol; carol adds bob with the SAME G.
        val log = LogBuilder(crypto)
        log.genesis(alice)
        log.add(alice, bob, grantId)
        log.remove(alice, bob)
        log.add(alice, carol, Ids.id16(2))
        log.transfer(alice, carol, Ids.id16(9))
        val readd = log.add(carol, bob, grantId)

        // The latest add is carol's, so the owner key a grant must be signed under is carol's.
        val fromAlice = VaultGrant.sign(crypto, alice.sign, grant(vk = log.vk))
        assertEquals(VaultGrantVerdict.NOT_AUTHORIZED, verdict(sealedFor(bob, fromAlice), log.state))
        val fromCarol = VaultGrant.sign(crypto, carol.sign, grant(from = Ids.CAROL, vk = log.vk))
        val opened = assertIs<Checked.Ok<OpenedGrant>>(open(sealedFor(bob, fromCarol), log.state)).value
        assertEquals(readd.entry.seq, opened.add.seq)
        assertEquals(Ids.CAROL, opened.add.actor)
    }

    @Test
    fun afterARemoveAndANewAdd_onlyTheNewAddsGrantOpens() {
        // §3.5 steps 6 and 10: a grant is bound to this account's LATEST add. A server that put the old
        // grant back on the row gets no_add_entry, so the accept prompt can only name the latest adder.
        val log = sharedLog()
        val oldGrant = VaultGrant.sign(crypto, alice.sign, grant(vk = log.vk))
        assertIs<Checked.Ok<OpenedGrant>>(open(sealedFor(bob, oldGrant), log.state))
        log.remove(alice, bob)
        assertEquals(VaultGrantVerdict.REMOVED, verdict(sealedFor(bob, oldGrant), log.state))
        val newId = Ids.id16(5)
        log.add(alice, bob, newId)
        assertEquals(VaultGrantVerdict.NO_ADD_ENTRY, verdict(sealedFor(bob, oldGrant), log.state))
        val newGrant = VaultGrant.sign(crypto, alice.sign, grant(id = newId, vk = log.vk))
        val opened = assertIs<Checked.Ok<OpenedGrant>>(open(sealedFor(bob, newGrant), log.state)).value
        assertEquals(3L, opened.add.seq)
        assertEquals(3L, log.state!!.members.getValue(Ids.BOB).addSeq)
        // The same holds when the re-add was made by a new owner: the old owner's grant names an add that is not the latest.
        log.add(alice, carol, Ids.id16(2))
        log.transfer(alice, carol, Ids.id16(9))
        log.remove(carol, bob)
        val third = Ids.id16(6)
        log.add(carol, bob, third)
        assertEquals(VaultGrantVerdict.NO_ADD_ENTRY, verdict(sealedFor(bob, newGrant), log.state))
        val fromCarol = VaultGrant.sign(crypto, carol.sign, grant(from = Ids.CAROL, id = third, vk = log.vk))
        assertEquals(Ids.CAROL, assertIs<Checked.Ok<OpenedGrant>>(open(sealedFor(bob, fromCarol), log.state)).value.add.actor)
    }

    @Test
    fun sign_refusesWhatTheParseWouldRefuse() {
        val vk = ByteArray(32) { 1 }
        assertFailsWith<IllegalArgumentException> { VaultGrant.sign(crypto, alice.sign, grant(to = Ids.ALICE, toKey = alice.key, vk = vk)) } // from == to
        assertFailsWith<IllegalArgumentException> { VaultGrant.sign(crypto, alice.sign, grant(vk = ByteArray(31))) }
        assertFailsWith<IllegalArgumentException> { VaultGrant.sign(crypto, alice.sign, grant(id = Bytes.toB64(ByteArray(32)), vk = vk)) }
        assertFailsWith<IllegalArgumentException> { VaultGrant.seal(crypto, ByteArray(31), ByteArray(120)) }
    }
}
