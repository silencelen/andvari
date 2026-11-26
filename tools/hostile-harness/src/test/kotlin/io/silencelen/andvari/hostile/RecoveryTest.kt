package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.CardOps
import io.silencelen.andvari.cli.CardWrite
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.RecoveryPostureView
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.client.recovery.EscrowDecision
import io.silencelen.andvari.core.client.recovery.KitRecoveryStep
import io.silencelen.andvari.core.client.state.RecoveryRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.core.trust.AssistedRecoveryFields
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.RotationFields
import io.silencelen.andvari.hostile.proxy.Frames
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.arr
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.obj
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Recovery under a hostile server (design §4.5, §9.3, §10, §16.2 R27 and R30): the recovery key a device seals to comes
 * from the pinned card, never from what the server serves; a key change without the old key's signature is never
 * followed silently; and a recovery answer is believed only when the offline recovery key signed it for this request
 * and the identity it delivers is the one the seed derives.
 */
class RecoveryTest {
    private val crypto = createCryptoProvider()
    private val password get() = Steps.PASSWORD.toCharArray()

    /** The instance recovery seed, which the operator keeps offline; the scenarios that need "the operator's answer" sign with it. */
    private val seed = crypto.randomBytes(32)
    private val recoveryPub = crypto.boxKeypairFromSeed(seed).publicKey
    private val fp = Escrow.fingerprint(crypto, recoveryPub)

    /** A recovery key of the server's own. */
    private val evilSeed = crypto.randomBytes(32)
    private val evilPub = crypto.boxKeypairFromSeed(evilSeed).publicKey
    private val evilFp = Escrow.fingerprint(crypto, evilPub)

    private fun recoveryWorld(block: suspend World.() -> Unit) = world(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(recoveryPub)), block = block)

    private fun World.serveEvilRecoveryKey() =
        proxy.on(WireRoute.RECOVERY_PUBKEY, handler = answer { Resp(200, mapOf("Content-Type" to "text/plain"), Bytes.toB64(evilPub).encodeToByteArray()) })

    /**
     * §4.5 condition 3: "the served recovery public key hashes to that `recoveryFp` at full length. No human types a
     * fingerprint, and no served value can turn a private account into an escrowed one." A key the server substitutes
     * is not offered, and nothing is sealed to it, at opt-in or afterwards.
     */
    @Test fun aRecoveryPublicKeyTheServerSubstitutesIsNeverOfferedAndNothingIsSealedToIt() = recoveryWorld {
        operator()
        val ah = member("alice")
        val swap = serveEvilRecoveryKey()
        var mark = proxy.mark()
        var settings = ah.recoverySettings(ah.session(origin)!!)
        assertNull(settings.operatorOffer(), "a served key that is not the pinned card's is not an offer")
        assertEquals(Reauthed.Refused("operator_recovery_unavailable"), settings.setPosture(RecoveryChoiceKind.OPERATOR, null, understood = true, password = password))
        assertTrue(sent(ah, WireRoute.ACCOUNT_RECOVERY_PUT, mark).isEmpty() && sent(ah, WireRoute.ESCROW_SELF, mark).isEmpty(), "nothing was sealed")

        // With the genuine key the person opts in; the escrow is sealed to the key the card names.
        swap.remove()
        val offer = assertNotNull(settings.operatorOffer())
        val on = assertIs<Reauthed.Done<RecoveryRecord>>(settings.setPosture(RecoveryChoiceKind.OPERATOR, offer, understood = true, password = password))
        assertEquals(fp, on.value.fp)
        assertEquals(fp, proxy.last(WireRoute.ACCOUNT_RECOVERY_PUT, "alice")!!.req.json!!.obj("escrow")!!.str("fingerprint"), "the escrow names the pinned card's key")

        // The server swaps the key afterwards: the opted-in device seals nothing new.
        serveEvilRecoveryKey()
        mark = proxy.mark()
        settings = ah.recoverySettings(ah.session(origin)!!)
        val view = assertIs<Fetched.Ok<RecoveryPostureView>>(settings.posture()).value
        assertEquals(fp, view.record!!.fp, "the consent still names the key the person agreed to")
        assertTrue(sent(ah, WireRoute.ACCOUNT_RECOVERY_PUT, mark).isEmpty() && sent(ah, WireRoute.ESCROW_SELF, mark).isEmpty(), "nothing is re-sealed to a served key")
    }

    /**
     * §4.5 "Unsigned change", R30 (T2-R-f, FS-R2): a card that changes `recoveryFp` with no rotation signed by the
     * outgoing recovery seed causes "no silent re-seal ever"; the opted-in person gets the takeover warning, and a new
     * consent is warned too. A genuine rotation statement made for another instance, replayed here, changes nothing.
     */
    @Test fun aRecoveryKeyChangeWithoutTheOutgoingKeysSignatureIsNeverFollowedSilently() = recoveryWorld {
        val oh = operator()
        val ah = member("alice")
        val bh = member("bob")
        val instanceId = oh.trust.pinFor(origin)!!.instanceId
        val settings = ah.recoverySettings(ah.session(origin)!!)
        assertIs<Reauthed.Done<RecoveryRecord>>(settings.setPosture(RecoveryChoiceKind.OPERATOR, assertNotNull(settings.operatorOffer()), understood = true, password = password))

        // Whoever holds the operator's signing key publishes a card naming its own recovery key, and serves that key.
        assertEquals(1L, assertIs<CardWrite.Stored>(CardOps(oh, oh.session(origin)!!).sign(password, recoveryFp = evilFp)).seq)
        serveEvilRecoveryKey()
        // A statement the outgoing seed really signed, for ANOTHER instance, replayed here. (A rotation signed by any
        // other key than the one its `fromFp` names cannot even be built with the trust layer's own builder.)
        val otherInstance = Bytes.toB64(RecoveryRotation.sign(crypto, crypto.signKeypairFromSeed(seed), RotationFields("5d1f0c2e-7a3b-4c4d-9e5f-6a7b8c9d0e1f", fp, evilFp, server.now())))

        for ((what, rotations) in listOf("no rotation" to emptyList<String>(), "a genuine rotation made for another instance, replayed" to listOf(otherInstance))) {
            val serving = proxy.on(WireRoute.INSTANCE, "alice", handler = editAnswer { it.set("rotations", JsonArray((it.arr("rotations") ?: JsonArray(emptyList())) + rotations.map(::JsonPrimitive))) })
            val mark = proxy.mark()
            val view = assertIs<Fetched.Ok<RecoveryPostureView>>(ah.recoverySettings(ah.session(origin)!!).posture(), what).value
            val warning = assertIs<EscrowDecision.UnsignedChange>(view.pending, "$what: the takeover warning, not a re-seal: ${view.pending}")
            assertEquals(fp, warning.fromFp)
            assertEquals(evilFp, warning.toFp)
            assertEquals(fp, view.record!!.fp, "$what: the consent is unchanged")
            assertTrue(sent(ah, WireRoute.ESCROW_SELF, mark).isEmpty() && sent(ah, WireRoute.ACCOUNT_RECOVERY_PUT, mark).isEmpty(), "$what: nothing was sealed to the new key")
            serving.remove()
        }
        // Someone turning operator recovery on now is warned as well (the first-consent walk from card 0).
        assertTrue(assertNotNull(bh.recoverySettings(bh.session(origin)!!).operatorOffer()).unsignedChange, "\"Only me\" is preselected")
    }

    /**
     * §10, spec 01 §5: kit recovery's phase 1 hard-fails unless the kit opens the UVK, the UVK the identity seed, and the
     * seed's key is the served `identityPub`. A server that answers with another account's identity or key material is
     * stopped there: no new password is chosen, no commit is sent, and the pin the kit made is dropped.
     */
    @Test fun aKitRecoveryAnswerCarryingAnotherAccountsIdentityStopsBeforeAnyNewPassword() = world {
        operator()
        val ah = member("alice")
        member("bob")
        val bobs = proxy.last(WireRoute.REGISTER, "bob")!!.upstream!!.json!!.obj("accountKeys")!!
        val kit = assertNotNull(RecoveryKit.parseQr(registration(ah).kit.qr))
        val lies: List<Pair<String, (JsonObject) -> JsonObject>> = listOf(
            "another account's identity key" to { r -> r.set("identityPub", bobs.str("identityPub")!!) },
            "another account's identity seed" to { r -> r.set("encryptedIdentitySeed", bobs.str("encryptedIdentitySeed")!!) },
            "another account's wrapped key" to { r -> r.set("recoveryWrappedUvk", bobs.str("wrappedUvk")!!) },
        )
        for ((i, lie) in lies.withIndex()) {
            val tag = "d$i"
            val d = device(tag)
            val target = assertIs<KitRecoveryStep.ConfirmTarget>(d.kitRecovery.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
            proxy.on(WireRoute.RECOVERY_SELF_VERIFY, tag, handler = editAnswer(lie.second))
            val stopped = assertIs<KitRecoveryStep.Stopped>(d.kitRecovery.verify(target), lie.first)
            // §2.4, the row "Account keys at sign-in, unlock, kit recovery and device-link pickup": `identity_mismatch`.
            assertEquals("identity_mismatch", stopped.reason, lie.first)
            assertTrue(proxy.requests(WireRoute.RECOVERY_SELF_COMMIT, tag).isEmpty(), "${lie.first}: nothing is committed")
            assertNull(d.session(origin))
            assertEquals(PinState.None, d.trust.pinState(origin), "${lie.first}: the pin this recovery made is dropped")
        }
    }

    /**
     * §9.3 step 4, §2.4 "Assisted recovery", R27: the server can fake the code, the hold and "ready"; it cannot fake the
     * operator's answer. In order: `unopenable`; `signer_not_pinned_key` (not the recovery key the PINNED card names,
     * "which closes the 'private account, server-made UVK' case"); `request_mismatch`; `identity_mismatch`. And when
     * everything verifies, the person still checks the delivered account before any password is set.
     */
    @Test fun anAssistedRecoveryAnswerIsBelievedOnlyWhenThePinnedRecoveryKeySignedItForThisRequestAndIdentity() = recoveryWorld {
        val oh = operator()
        val ah = member("alice")
        member("bob")
        val alice = ah.session(origin)!!
        val keys = proxy.last(WireRoute.REGISTER, "alice")!!.upstream!!.json!!.obj("accountKeys")!!
        val bobs = proxy.last(WireRoute.REGISTER, "bob")!!.upstream!!.json!!.obj("accountKeys")!!
        val instanceId = oh.trust.pinFor(origin)!!.instanceId

        val d = device("d")
        val target = assertIs<AssistedStep.ConfirmTarget>(d.assisted.start("alice@example.org", origin))
        val requested = assertIs<AssistedStep.Requested>(d.assisted.request(target), "the request is opened")
        val created = proxy.last(WireRoute.RECOVERY_REQUEST_CREATE, "d")!!
        val rPubText = created.req.json!!.str("rPub")!!
        val rPub = Frames.bytes(rPubText)
        val requestId = created.upstream!!.json!!.str("requestId")!!

        // The server says "ready" at once (no code, no hold, no operator), with an answer of its choosing.
        var pollAnswer = buildJsonObject { }
        proxy.on(WireRoute.RECOVERY_REQUEST_POLL, "d", handler = answer { Resp.json(200, pollAnswer) })
        fun ready(sealed: ByteArray, seedEnvelope: String = keys.str("encryptedIdentitySeed")!!, identityPub: String = keys.str("identityPub")!!) = buildJsonObject {
            put("state", JsonPrimitive("ready")); put("sealed", JsonPrimitive(Bytes.toB64(sealed)))
            put("encryptedIdentitySeed", JsonPrimitive(seedEnvelope)); put("identityPub", JsonPrimitive(identityPub))
        }
        val recoverySigner = crypto.signKeypairFromSeed(seed)
        val uvk = alice.session.account.uvk.copyOut()
        // The version-3 answer (spec 04 §7 step 3): the address the copy names, and a commit value.
        fun payload(
            signer: io.silencelen.andvari.core.crypto.KeyPairBytes, request: String = requestId, key: String = rPubText, instance: String = instanceId,
            withUvk: ByteArray = uvk, email: String? = "alice@example.org",
        ) = AssistedRecovery.seal(crypto, rPub, AssistedRecovery.sign(crypto, signer,
            AssistedRecoveryFields(instance, alice.userId, request, key, withUvk, server.now(), email = email, commit = email?.let { crypto.randomBytes(32) })))

        val cases = listOf(
            Triple("bytes of the server's own", "unopenable", ready(ByteArray(160) { 1 })),
            Triple("a payload signed by a key of the server's own", "signer_not_pinned_key", ready(payload(crypto.signKeypairFromSeed(evilSeed)))),
            Triple("the account's own identity key as the signer", "signer_not_pinned_key", ready(alice.session.account.signing.use { payload(it) })),
            Triple("a genuine payload for another request", "request_mismatch", ready(payload(recoverySigner, request = Bytes.toB64(ByteArray(16) { 2 })))),
            Triple("a genuine payload for another request key", "request_mismatch", ready(payload(recoverySigner, key = Bytes.toB64(evilPub)))),
            Triple("a genuine payload for another instance", "request_mismatch", ready(payload(recoverySigner, instance = "5d1f0c2e-7a3b-4c4d-9e5f-6a7b8c9d0e1f"))),
            // The answer says whose account it restores, and it must be the address asked with.
            Triple("a genuine payload naming another address", "request_mismatch", ready(payload(recoverySigner, email = "bob@example.org"))),
            // The old form names no address and no commit value: a device takes only a version-3 answer.
            Triple("a genuine payload of the old form (version 2)", "bad_statement", ready(payload(recoverySigner, email = null))),
            Triple("a genuine payload whose key does not open the served identity seed", "identity_mismatch", ready(payload(recoverySigner, withUvk = ByteArray(32) { 4 }))),
            Triple("a genuine payload beside another account's identity key", "identity_mismatch", ready(payload(recoverySigner), identityPub = bobs.str("identityPub")!!)),
            Triple("a genuine payload beside another account's identity seed", "identity_mismatch", ready(payload(recoverySigner), seedEnvelope = bobs.str("encryptedIdentitySeed")!!)),
        )
        for ((what, verdict, served) in cases) {
            pollAnswer = served
            assertEquals(AssistedStep.Stopped(verdict), d.assisted.poll(requested), what)
        }
        assertTrue(proxy.requests(WireRoute.RECOVERY_REQUEST_COMMIT, "d").isEmpty(), "no refused answer led to a commit")

        // What only the offline key could have made, for this request and this identity: accepted, and the person is
        // shown the delivered account before any password. They say it is not theirs: nothing more is sent.
        pollAnswer = ready(payload(recoverySigner))
        val check = assertIs<AssistedStep.CheckAccount>(d.assisted.poll(requested))
        assertEquals(registration(ah).kit.accountId, check.accountId, "the account ID to compare with an earlier notice")
        assertEquals(AssistedStep.Stopped("account_rejected"), d.assisted.confirmAccount(check, same = false))
        assertTrue(proxy.requests(WireRoute.RECOVERY_REQUEST_COMMIT, "d").isEmpty())
        assertNull(d.session(origin))
    }
}
