package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Rules of design 2026-11-15 §3 that `vaultlog.json` does not carry because they are about this API
 * and not about bytes: what the state derives beside S (`addSeq`, `latestAdds`, `creator`), the builders, the
 * server's signer check of §3.7 step 4, and the stored form of a state.
 */
class VaultLogRulesTest {
    private val crypto = createCryptoProvider()
    private val alice = Party(crypto, Ids.ALICE, 1)
    private val bob = Party(crypto, Ids.BOB, 2)
    private val carol = Party(crypto, Ids.CAROL, 3)

    /** One entry of this file's vault, on a device that holds no hash for any position. */
    private fun verify(prior: VaultState?, frame: ByteArray) = VaultLog.verify(crypto, Ids.VAULT, prior, frame, KnownHashes.NONE_HELD)

    @Test
    fun addSeq_namesTheAddThatMadeAMember_andIsNullOnlyForTheCreatorWhoNeverLeft() {
        val log = LogBuilder(crypto)
        log.genesis(alice)
        assertNull(log.state!!.members.getValue(Ids.ALICE).addSeq, "§3.6 (d), FN-2: the creator has no add")
        assertEquals(Ids.ALICE, log.state!!.creator)
        assertEquals(log.state!!.head.hash, log.state!!.genesisHash)

        val firstAdd = log.add(alice, bob, Ids.id16(1))
        assertEquals(firstAdd.entry.seq, log.state!!.members.getValue(Ids.BOB).addSeq)

        // A leave and a new add: the new add has a higher seq, so an `accepted` record for the old one answers nothing (FS-R6).
        log.leave(bob)
        assertNull(log.state!!.members[Ids.BOB])
        val secondAdd = log.add(alice, bob, Ids.id16(2), MemberRole.READER)
        assertEquals(secondAdd.entry.seq, log.state!!.members.getValue(Ids.BOB).addSeq)
        assertTrue(secondAdd.entry.seq > firstAdd.entry.seq)
        assertEquals(VaultRole.READER, log.state!!.members.getValue(Ids.BOB).role)

        // The state keeps ONE add per account, its latest, with the owner and the owner key at that entry
        // (§3.5 step 6): the first add is gone, so a grant bound to it finds no entry.
        assertEquals(setOf(Ids.BOB), log.state!!.latestAdds.keys)
        val latest = assertNotNull(log.state!!.latestAdd(Ids.BOB))
        assertEquals(AddRecord(secondAdd.entry.seq, Ids.ALICE, alice.key, Ids.BOB, bob.key, MemberRole.READER, Ids.id16(2)), latest)
        assertNull(log.state!!.latestAdd(Ids.ALICE), "the creator was never added")
        // It stays for an account that left: its grant then answers `removed`, not `no_add_entry`.
        log.leave(bob)
        assertEquals(latest, log.state!!.latestAdd(Ids.BOB))
        assertNull(log.state!!.members[Ids.BOB])
    }

    @Test
    fun creatorWhoWasRemovedAndAddedAgain_hasAnAdd() {
        // FN-2: "a genesis owner who left and was added again is asked like anyone else".
        val log = LogBuilder(crypto)
        log.genesis(alice)
        log.add(alice, bob, Ids.id16(1))
        log.transfer(alice, bob, Ids.id16(9))
        assertEquals(Ids.BOB, log.state!!.owner)
        assertEquals(bob.key, log.state!!.ownerKey)
        assertEquals(VaultRole.WRITER, log.state!!.members.getValue(Ids.ALICE).role)
        assertNull(log.state!!.members.getValue(Ids.ALICE).addSeq, "still a member through the genesis")
        assertEquals(Ids.ALICE, log.state!!.creator, "the creator does not change with the owner")

        log.remove(bob, alice)
        val readd = log.add(bob, alice, Ids.id16(3))
        assertEquals(readd.entry.seq, log.state!!.members.getValue(Ids.ALICE).addSeq)
        // The owner key AT that add is bob's: that is the K a grant for it must be signed under.
        assertEquals(bob.key, log.state!!.latestAdd(Ids.ALICE)?.ownerKey)
        assertEquals(Ids.BOB, log.state!!.latestAdd(Ids.ALICE)?.actor)
        // bob's own add, by alice under alice's key, is still his latest.
        assertEquals(alice.key, log.state!!.latestAdd(Ids.BOB)?.ownerKey)
    }

    @Test
    fun position_usesTheLaterOfTheClockAndTheHead() {
        val log = LogBuilder(crypto)
        log.genesis(alice)
        val s = log.state!!
        assertEquals(LogPosition(1, s.head.hash, s.at + 5), VaultLog.position(s, s.at + 5))
        assertEquals(LogPosition(1, s.head.hash, s.at), VaultLog.position(s, s.at - 60_000), "a slow clock never deadlocks the vault (T-R1)")
        assertEquals(LogPosition(8, "ab".repeat(32), 2_000), VaultLog.positionAfter(7, "ab".repeat(32), 2_000, 1_000))
        assertEquals(LogPosition(8, "ab".repeat(32), 3_000), VaultLog.positionAfter(7, "ab".repeat(32), 2_000, 3_000))
    }

    @Test
    fun signChecked_returnsOnlyWhatThisDeviceWouldAccept() {
        val log = LogBuilder(crypto)
        log.genesis(alice)
        val s = log.state!!
        val p = VaultLog.position(s, s.at + 1)

        // The owner removing a non-member: a row condition fails, so no frame comes back.
        val bad = VaultLog.signChecked(crypto, alice.sign, s, LogEntry.Remove(Ids.VAULT, p.seq, p.prev, Ids.ALICE, p.at, Ids.BOB))
        assertEquals(VaultLogVerdict.PRECONDITION, assertIs<Checked.Refused<VaultLogVerdict>>(bad).verdict)
        // A member who is not the owner signing an add.
        val notOwner = VaultLog.signChecked(crypto, bob.sign, s, LogEntry.Add(Ids.VAULT, p.seq, p.prev, Ids.BOB, p.at, Ids.CAROL, carol.key, MemberRole.READER, Ids.id16(1)))
        assertEquals(VaultLogVerdict.NOT_AUTHORIZED, assertIs<Checked.Refused<VaultLogVerdict>>(notOwner).verdict)
        // At a stale position.
        val stale = VaultLog.signChecked(crypto, alice.sign, s, LogEntry.Add(Ids.VAULT, p.seq + 1, p.prev, Ids.ALICE, p.at, Ids.BOB, bob.key, MemberRole.READER, Ids.id16(1)))
        assertEquals(VaultLogVerdict.BAD_SEQ, assertIs<Checked.Refused<VaultLogVerdict>>(stale).verdict)

        // A good one: the frame verifies again from the same state, byte for byte.
        val good = assertIs<Checked.Ok<SignedLogEntry>>(
            VaultLog.signChecked(crypto, alice.sign, s, LogEntry.Add(Ids.VAULT, p.seq, p.prev, Ids.ALICE, p.at, Ids.BOB, bob.key, MemberRole.READER, Ids.id16(1))),
        ).value
        val again = assertIs<Checked.Ok<VaultLogStep>>(verify(s, good.frame)).value
        assertEquals(good.step.state, again.state)
        assertEquals(good.step.hash, again.hash)
    }

    @Test
    fun sign_refusesAnEntryOutsideTheGrammar() {
        val zero = TrustGrammar.ZERO_HASH
        assertFailsWith<IllegalArgumentException> { VaultLog.sign(crypto, alice.sign, LogEntry.Leave(Ids.VAULT, 0, zero, Ids.ALICE, Ids.T0)) } // seq 0 is the genesis's
        assertFailsWith<IllegalArgumentException> { VaultLog.sign(crypto, alice.sign, LogEntry.Leave(Ids.VAULT, 1, zero, Ids.ALICE, 0)) } // `at` is an ms
        assertFailsWith<IllegalArgumentException> { VaultLog.sign(crypto, alice.sign, LogEntry.Leave("not-a-uuid", 1, zero, Ids.ALICE, Ids.T0)) }
        assertFailsWith<IllegalArgumentException> { VaultLog.sign(crypto, alice.sign, LogEntry.Leave(Ids.VAULT, 1, "AB".repeat(32), Ids.ALICE, Ids.T0)) }
        assertFailsWith<IllegalArgumentException> { VaultLog.sign(crypto, alice.sign, LogEntry.Remove(Ids.VAULT, 1, zero, Ids.ALICE, Ids.T0, "x\",\"y\":\"z")) }
        assertFailsWith<IllegalArgumentException> { VaultLog.sign(crypto, alice.sign, LogEntry.Genesis(Ids.VAULT, Ids.ALICE, Ids.T0, alice.key + "=", zero)) }
        assertFailsWith<IllegalArgumentException> { VaultLog.vkCommit(crypto, ByteArray(31), Ids.VAULT) }
    }

    @Test
    fun signedByCaller_theServersHygieneCheck() {
        val log = LogBuilder(crypto)
        log.genesis(alice)
        val s = log.state!!
        val p = VaultLog.position(s, s.at + 1)
        val frame = VaultLog.sign(crypto, alice.sign, LogEntry.Add(Ids.VAULT, p.seq, p.prev, Ids.ALICE, p.at, Ids.BOB, bob.key, MemberRole.READER, Ids.id16(1)))
        val entry = assertIs<Checked.Ok<UnverifiedLogEntry>>(VaultLog.parse(crypto, frame)).value

        assertEquals(LogSignerCheck.OK, VaultLog.signedByCaller(crypto, entry, Ids.ALICE, alice.box.publicKey))
        assertEquals(LogSignerCheck.BAD_SIGNER, VaultLog.signedByCaller(crypto, entry, Ids.BOB, alice.box.publicKey), "the actor is not the caller")
        assertEquals(LogSignerCheck.BAD_SIGNER, VaultLog.signedByCaller(crypto, entry, Ids.ALICE, bob.box.publicKey), "the signer is not the caller's key")
        assertEquals(LogSignerCheck.BAD_SIGNER, VaultLog.signedByCaller(crypto, entry, Ids.ALICE, ByteArray(31)))

        val flipped = frame.copyOf().also { it[40] = (it[40].toInt() xor 1).toByte() } // inside the signature
        val tampered = assertIs<Checked.Ok<UnverifiedLogEntry>>(VaultLog.parse(crypto, flipped)).value
        assertEquals(LogSignerCheck.BAD_SIGNATURE, VaultLog.signedByCaller(crypto, tampered, Ids.ALICE, alice.box.publicKey))
    }

    @Test
    fun storedState_restoresExactly_andRefusesAnythingElse() {
        val log = LogBuilder(crypto)
        log.genesis(alice)
        log.add(alice, bob, Ids.id16(1))
        log.append(alice) { LogEntry.Offer(Ids.VAULT, it.seq, it.prev, Ids.ALICE, it.at, Ids.BOB, bob.key, Ids.id16(4), it.at + 60_000) }
        log.append(alice) { LogEntry.Delete(Ids.VAULT, it.seq, it.prev, Ids.ALICE, it.at, Ids.id16(5)) }
        val s = log.state!!
        assertTrue(s.isDeleted)
        assertNull(s.pending, "a delete clears the pending offer")

        val text = s.encode()
        assertEquals(s, assertNotNull(VaultState.decode(text)))
        assertNull(VaultState.decode(""))
        assertNull(VaultState.decode("{}"))
        assertNull(VaultState.decode(text.replace(Ids.VAULT, "not-a-uuid")))
        assertTrue("\"v\":2," in text && "\"latestAdds\":{" in text, "the stored form of this build")
        assertNull(VaultState.decode(text.replace("\"v\":2", "\"v\":3")), "another build's form")
        assertNull(VaultState.decode(text.replace("\"v\":2", "\"v\":1")), "the earlier form, which kept every add: the log is replayed instead")
        // A member whose add record names another seq is not a state this device wrote.
        val bobAdd = s.members.getValue(Ids.BOB).addSeq
        assertNull(VaultState.decode(text.replace("\"addSeq\":$bobAdd}", "\"addSeq\":${bobAdd!! + 1}}")), "a member's addSeq is its latest add")
        assertNull(VaultState.decode(text.replaceFirst(alice.key, bob.key)), "the owner key must be the owner member's key")
        assertNull(VaultState.decode(text.dropLast(1) + ",\"extra\":1}"), "no unknown field")
    }

    @Test
    fun forkDetection_isNeverOffByDefault_aCallerSaysWhatItHolds() {
        // `known` used to default to "holds nothing", so a
        // caller that left it out got a verifier that could never answer `fork`. It has no default now
        // (leaving it out does not compile), and "nothing" is a value with a name.
        for (seq in listOf(0L, 1L, TrustGrammar.INT_CEILING - 1)) assertNull(KnownHashes.NONE_HELD.at(seq))

        val log = LogBuilder(crypto)
        log.genesis(alice)
        log.add(alice, bob, Ids.id16(1))
        log.add(alice, carol, Ids.id16(2))
        val other = "ab".repeat(32)
        // The same frames, on a device that holds another hash for position 1 and on one that holds none.
        val holdingAnother = VaultLog.replay(crypto, Ids.VAULT, log.frames, from = null, known = { seq -> if (seq == 1L) other else null })
        assertEquals(VaultLogVerdict.FORK, holdingAnother.verdict)
        assertEquals(1, holdingAnother.accepted)
        assertEquals(0L, holdingAnother.state?.head?.seq, "the state is the one after the last good entry")
        val holdingNone = VaultLog.replay(crypto, Ids.VAULT, log.frames, from = null, known = KnownHashes.NONE_HELD)
        assertNull(holdingNone.verdict)
        assertEquals(log.state, holdingNone.state)
        // The hash it holds itself is no fork, and one entry is judged the same way.
        val own = log.frames.map { SignedFrame.hash(crypto, it) }
        assertNull(VaultLog.replay(crypto, Ids.VAULT, log.frames, from = null, known = { seq -> own.getOrNull(seq.toInt()) }).verdict)
        assertEquals(VaultLogVerdict.FORK, VaultLog.verify(crypto, Ids.VAULT, null, log.frames[0]) { other }.verdictOrNull())
        assertIs<Checked.Ok<VaultLogStep>>(VaultLog.verify(crypto, Ids.VAULT, null, log.frames[0]) { own[0] })
        // A builder's own new entry is judged against the head it was signed at, and holds nothing else.
        val s = log.state!!
        val p = VaultLog.position(s, s.at + 1)
        assertIs<Checked.Ok<SignedLogEntry>>(VaultLog.signChecked(crypto, alice.sign, s, LogEntry.Remove(Ids.VAULT, p.seq, p.prev, Ids.ALICE, p.at, Ids.CAROL)))
    }

    @Test
    fun verify_isTotalOnGarbage() {
        val log = LogBuilder(crypto)
        log.genesis(alice)
        for (bytes in listOf(ByteArray(0), ByteArray(3), ByteArray(200), ByteArray(2000), "{\"v\":2}".encodeToByteArray())) {
            assertIs<Checked.Refused<VaultLogVerdict>>(verify(log.state, bytes))
            assertIs<Checked.Refused<VaultLogVerdict>>(verify(null, bytes))
        }
        // A state of another vault than the one being verified is refused, never trusted.
        val other = LogBuilder(crypto, Ids.OTHER_VAULT).also { it.genesis(alice) }
        val p = VaultLog.position(other.state!!, Ids.T0 + 1)
        val frame = VaultLog.sign(crypto, alice.sign, LogEntry.Add(Ids.OTHER_VAULT, p.seq, p.prev, Ids.ALICE, p.at, Ids.BOB, bob.key, MemberRole.READER, Ids.id16(1)))
        assertEquals(VaultLogVerdict.WRONG_VAULT, verify(other.state, frame).verdictOrNull())
        assertEquals(VaultLogVerdict.WRONG_VAULT, verify(log.state, frame).verdictOrNull())
    }
}
