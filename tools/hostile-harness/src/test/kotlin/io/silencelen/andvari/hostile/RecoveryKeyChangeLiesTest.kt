package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.CardOps
import io.silencelen.andvari.cli.CardWrite
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.client.recovery.WireAssistedRecovery
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.RotationFields
import io.silencelen.andvari.core.trust.SignedFrame
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.set
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The server's recovery key changes while a fresh install's assisted-recovery request is open (spec 04 §5;
 * index row 74, `GET /instance`, the rotations served beside the chain). The operator rotates for real: the
 * statement signed offline by the outgoing seed is stored, then the card names the new key. Each device then reads the
 * rotations through a server that tells it something else.
 */
class RecoveryKeyChangeLiesTest {
    private val crypto = createCryptoProvider()
    private val seed = crypto.randomBytes(32)
    private val recoveryPub = crypto.boxKeypairFromSeed(seed).publicKey
    private val fp = Escrow.fingerprint(crypto, recoveryPub)
    private val newSeed = crypto.randomBytes(32)
    private val newSigner: KeyPairBytes = crypto.signKeypairFromSeed(newSeed)
    private val newFp = Escrow.fingerprint(crypto, crypto.boxKeypairFromSeed(newSeed).publicKey)

    /** A fresh device's verified request for Alice, as [tag]. */
    private suspend fun World.asking(tag: String): Pair<Host, AssistedStep.Waiting> {
        val d = device(tag)
        val target = assertIs<AssistedStep.ConfirmTarget>(d.assisted.start("alice@example.org", origin))
        val seen = Steps.mailCount(server, "alice@example.org", "recovery_request_code")
        val requested = assertIs<AssistedStep.Requested>(d.assisted.request(target))
        val code = Steps.awaitCode(server, "alice@example.org", "recovery_request_code", seen)
        return d to assertIs<AssistedStep.Waiting>(d.assisted.verifyCode(requested, code))
    }

    /** [frame]'s statement, unchanged, signed by [signer] instead: what someone holding only the new key can make. */
    private fun resigned(frame: ByteArray, signer: KeyPairBytes): ByteArray {
        val statement = frame.copyOfRange(SignedFrame.STATEMENT_OFFSET, frame.size)
        val sig = crypto.signDetached(signer.privateKey, SignedFrame.signedMessage(frame[4].toInt() and 0xFF, signer.publicKey, statement))
        return frame.copyOfRange(0, SignedFrame.HEADER_BYTES) + signer.publicKey + sig + statement
    }

    /**
     * - Honest: the rotation is served; the request goes on, and the device says that the recovery key changed and when.
     * - Withheld (W): no rotation served. Altered (C): the genuine statement with one byte of its signature changed. Signed
     *   by the new key alone (A): the same statement, signed by the key it moves to. Each: the request stops with the
     *   unsigned-change warning, nothing is polled (so nothing of an answer is fetched or opened), and the request is kept.
     */
    @Test fun aRecoveryKeyRotatedWhileARequestIsOpenIsFollowedOnlyThroughARotationTheDeviceVerifies() =
        world(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(recoveryPub))) {
            val oh = operator()
            val ah = member("alice")
            val settings = ah.recoverySettings(ah.session(origin)!!)
            assertIs<Reauthed.Done<*>>(settings.setPosture(RecoveryChoiceKind.OPERATOR, settings.operatorOffer()!!, true, Steps.PASSWORD.toCharArray()))
            val instanceId = oh.trust.pinFor(origin)!!.instanceId
            val tags = listOf("honest", "withheld", "altered", "newkey")
            val asked = tags.associateWith { asking(it) }

            val at = server.now()
            val genuine = RecoveryRotation.sign(crypto, crypto.signKeypairFromSeed(seed), RotationFields(instanceId, fp, newFp, at))
            val ops = CardOps(oh, oh.session(origin)!!)
            assertIs<CardWrite.Stored>(ops.storeRotation(Bytes.toB64(genuine), Steps.PASSWORD.toCharArray()), "the server takes the genuine rotation")
            assertIs<CardWrite.Stored>(ops.sign(Steps.PASSWORD.toCharArray(), recoveryFp = newFp), "and the card that names the new key")

            fun serve(tag: String, frames: List<ByteArray>) =
                proxy.on(WireRoute.INSTANCE, tag, handler = editAnswer { it.set("rotations", JsonArray(frames.map { f -> JsonPrimitive(Bytes.toB64(f)) })) })
            serve("withheld", emptyList())
            serve("altered", listOf(genuine.copyOf().also { it[60] = (it[60].toInt() xor 1).toByte() }))
            serve("newkey", listOf(resigned(genuine, newSigner)))

            for (tag in tags) {
                val (d, waiting) = asked.getValue(tag)
                val mark = proxy.mark()
                val polled = d.assisted.poll(waiting)
                val change = assertNotNull(d.assisted.recoveryKeyChange(origin), "$tag: the change is never silent")
                assertEquals(fp, change.fromFp, tag)
                assertEquals(newFp, change.toFp, tag)
                if (tag == "honest") {
                    assertIs<AssistedStep.Waiting>(polled, "the request goes on")
                    assertTrue(change.signed)
                    assertEquals(at, change.rotatedAt, "when: the statement's own signed time")
                    assertTrue(proxy.requests(WireRoute.RECOVERY_REQUEST_POLL, tag, mark).isNotEmpty())
                } else {
                    assertEquals(AssistedStep.Stopped(WireAssistedRecovery.RECOVERY_KEY_CHANGED), polled, tag)
                    assertFalse(change.signed, tag)
                    assertNull(change.rotatedAt, tag)
                    assertTrue(proxy.requests(WireRoute.RECOVERY_REQUEST_POLL, tag, mark).isEmpty(), "$tag: nothing was polled")
                    assertEquals(listOf(origin), d.assisted.keptOrigins(), "$tag: the request is kept")
                }
            }
        }
}
