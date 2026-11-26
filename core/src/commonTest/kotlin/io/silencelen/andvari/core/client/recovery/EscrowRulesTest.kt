package io.silencelen.andvari.core.client.recovery

import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.state.RecoveryRecord
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/** Design §4.5's seal decisions; recovery.json grades the rotation facts the shared verifiers feed in. */
class EscrowRulesTest {
    private val a = "a".repeat(64)
    private val b = "b".repeat(64)
    private fun pin(fp: String, kind: String = "private") = CardPin("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", 1, a, "https://h.example", "Home", kind,
        "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f", "K".repeat(43), fp, PinRoot.TRUST_GATE, null, a)
    private val op = RecoveryRecord("operator", a, 10)

    private val r1 = byteArrayOf(1)

    /** A fake of the shared verifiers' rotation checks: [follows] answers the walk; the chain is [r1] when [chain] is set. */
    private fun rules(follows: Boolean = true, chain: Boolean = true) = EscrowRules(object : RotationFacts {
        override fun follows(rotations: List<ByteArray>, instanceId: String, fromFp: String, toFp: String) = follows
        override fun chain(rotations: List<ByteArray>, instanceId: String, fromFp: String, toFp: String) = if (chain) listOf(r1) else null
    })

    private var follows = true
    private var chain = true

    private fun inputs(
        pinFp: String = b, kind: String = "private", record: RecoveryRecord? = op, mirror: RecoveryRecord? = op,
        follows: Boolean = true, escrowFp: String? = a, rotations: List<String>? = listOf("r1"), served: String? = b,
    ): EscrowInputs { this.follows = follows; this.chain = rotations != null; return EscrowInputs(pin(pinFp, kind), record, mirror, escrowFp, listOf(r1), served) }

    private fun decide(i: EscrowInputs) = rules(follows, chain).decide(i)

    @Test fun publicCardNeverSeals() {
        assertEquals(EscrowDecision.None, decide(inputs(kind = "public")))
    }

    @Test fun noConsentNoSeal() {
        assertEquals(EscrowDecision.None, decide(inputs(record = null)))
        assertEquals(EscrowDecision.None, decide(inputs(record = RecoveryRecord("private", "none", 11))))
        assertEquals(EscrowDecision.None, decide(inputs(pinFp = "none")))
    }

    @Test fun signedRotationResealsOnlyWithTheOwnMirror() {
        assertEquals(EscrowDecision.SealNow(b, listOf(io.silencelen.andvari.core.crypto.Bytes.toB64(r1))), decide(inputs()))
        assertIs<EscrowDecision.AskOwnMirror>(decide(inputs(mirror = null)), "a password-only device asks")
        assertIs<EscrowDecision.AskOwnMirror>(decide(inputs(mirror = op.copy(at = 9))), "a replayed older record is not the mirror")
        assertIs<EscrowDecision.AskOwnMirror>(decide(inputs(rotations = null)), "no chain from the current escrow: ask, password needed")
    }

    @Test fun unsignedChangeWarns() {
        val d = assertIs<EscrowDecision.UnsignedChange>(decide(inputs(follows = false)))
        assertEquals(a, d.fromFp)
        assertEquals(b, d.toFp)
    }

    @Test fun currentEscrowOrUnverifiedKeySealsNothing() {
        assertEquals(EscrowDecision.None, decide(inputs(escrowFp = b)))
        assertEquals(EscrowDecision.None, decide(inputs(served = null)))
        assertEquals(EscrowDecision.None, decide(inputs(served = a)), "a served key for another fingerprint never seals")
    }

    @Test fun firstSealAsks() {
        assertIs<EscrowDecision.AskOwnMirror>(decide(inputs(pinFp = a, escrowFp = null, rotations = null, served = a)))
    }
}
