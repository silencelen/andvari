package io.silencelen.andvari.core.client.recovery

import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.KeptAccountCheck
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.KnownKdf
import io.silencelen.andvari.core.client.onboard.Opening
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.RevealedKit
import io.silencelen.andvari.core.client.onboard.SessionHow
import io.silencelen.andvari.core.client.onboard.SessionOpener
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.GateDecision
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.GateInput
import io.silencelen.andvari.core.client.pin.GatePayload
import io.silencelen.andvari.core.client.pin.GatePurpose
import io.silencelen.andvari.core.client.pin.InstanceTrust
import io.silencelen.andvari.core.client.pin.PasswordGate
import io.silencelen.andvari.core.client.pin.PinHandle
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.model.wire.MemberRecoveryBlock
import io.silencelen.andvari.core.model.wire.RecoveryCommitRequest
import io.silencelen.andvari.core.model.wire.RecoveryVerifyRequest
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.core.trust.TrustGrammar

/**
 * [KitRecovery] over spec 03 §12 (design §10, §4.4, FS-B1).
 *
 * Trust: a kit is taken only from the kit-recovery screen ([PasswordGate]'s entry rule). A scanned kit pins
 * the server from its `card0Hash` through [InstanceTrust.pinFromKit] (a kit pin, for this account's recovery
 * only); a typed kit, which has none, never does: it uses a pin that already serves this recovery, or the Trust
 * Gate (the baked root on the public instance, inside [InstanceTrust.beginTrustGate]). Nothing is sent before
 * the person confirmed "Recover *email* on *name* (*origin*)" and the gate answered `proceed` for purpose
 * `kit_recovery`. After phase 1 the seed-derived identity key must equal the served one (and this device's own
 * record of it); the commit's session opens through every check of design §5.2 ([SessionOpener]). The commit
 * carries a fresh kit, which replaces the scanned one, and a new device secret's device object.
 *
 * A pin made by [start] is dropped again by [cancel] (design §4.4: only the pin this flow made).
 */
class WireKitRecovery(
    private val clientFor: (String) -> WireClient,
    private val trust: InstanceTrust,
    private val devices: KnownDevices,
    private val sink: SessionSink,
    private val crypto: CryptoProvider,
    private val platform: String,
    private val deviceName: String,
    private val kdfParams: KdfParams = KdfParams.DEFAULT,
    private val knownIdentity: (String) -> ByteArray? = { null },
) : KitRecovery {

    private class Pending(
        val origin: String,
        val email: String,
        val emailNorm: String,
        val secret: ByteArray,
        /** The scanned kit's anchor; null for a typed kit. */
        val card0Hash: String?,
        val made: PinHandle?,
    ) {
        var userId: String? = null
        var ticket: String? = null
        var uvk: ByteArray? = null
        /** The verified identity key (public), for the session keeper's question before the commit. */
        var identityPub: ByteArray? = null

        /** The recovery's hold on its address from its start to its end ([SessionSink.underWay]); released by [wipe]. */
        var held: (() -> Unit)? = null

        fun wipe() {
            secret.fill(0)
            uvk?.fill(0)
            uvk = null
            held?.invoke()
            held = null
        }
    }

    private val pending = HashMap<String, Pending>()
    private val late = LateOutcomes()

    override fun takeLateOutcome(): LateRecoveryOutcome? = late.take()

    override var onLateOutcome: (() -> Unit)?
        get() = late.onPublished
        set(value) { late.onPublished = value }

    private fun handleFor(p: Pending): String {
        // From its first step the recovery is a flow under way for its address, until its commit, a stop or a cancel.
        if (p.held == null) p.held = sink.underWay(p.origin, p.emailNorm)
        val h = Bytes.toB64(crypto.randomBytes(16))
        pending[h] = p
        return h
    }

    /**
     * Whether the flow [handle] stands for is still [p] after a wait: a person who left or
     * started over, or a host that stopped the flow ([cancel]), removed it and wiped its kit secret and UVK copy while the
     * request was in flight. Nothing is then derived, opened or sealed from those zeros: the call answers STALE.
     */
    private fun still(handle: String, p: Pending): Boolean = pending[handle] === p

    private fun stop(handle: String?, reason: String): KitRecoveryStep.Stopped {
        handle?.let { h -> pending.remove(h)?.let { p -> p.made?.let(trust::dropPinMade); p.wipe() } }
        return KitRecoveryStep.Stopped(reason)
    }

    /**
     * The keeper's refusal [reason] of [userId] as a stop, with [KitRecoveryStep.Stopped.anotherAccountServed] set where it
     * is the identity refusal for an address tied here to ANOTHER account (the keeper says which,
     * [SessionSink.refusalIsAnotherAccount]). Asked before [stop] wipes what the flow holds.
     */
    private fun keeperStop(handle: String, reason: String, origin: String, emailNorm: String, userId: String, identityPub: ByteArray?): KitRecoveryStep.Stopped {
        val another = reason == io.silencelen.andvari.core.client.onboard.AccountOpen.SELF_IDENTITY_MISMATCH &&
            sink.refusalIsAnotherAccount(origin, emailNorm, userId, identityPub)
        val s = stop(handle, reason)
        return if (another) KitRecoveryStep.Stopped(reason, userId) else s
    }

    private fun gate(origin: String, emailNorm: String): GateDecision = PasswordGate.decide(
        GateInput(GatePurpose.KIT_RECOVERY, GateEntry.KIT_RECOVERY_SCREEN, GatePayload.KIT, origin, emailNorm, trust.gatePins()),
    )

    private fun entryOk(entry: GateEntry): Boolean = entry == GateEntry.KIT_RECOVERY_SCREEN

    override suspend fun start(kit: RecoveryKit.Kit, entry: GateEntry): KitRecoveryStep {
        if (!entryOk(entry)) return KitRecoveryStep.Stopped(WRONG_SCREEN)
        return startScanned(kit.origin, kit.emailNorm, kit.secret, kit.card0Hash)
    }

    /**
     * The session keeper's answer for a recovery at [origin] that nothing has been sent for yet: a device that keeps an
     * account at another server (or one held as its operator there) could not keep the session the commit opens, so
     * nothing starts; the way out is to sign that account out first. Null: go on (the account itself is asked about once
     * the verify step names it).
     */
    private fun refusedBeforeAnything(origin: String): String? = sink.wouldRefuse(origin, null, null)

    private suspend fun startScanned(origin: String, emailNorm: String, secret: ByteArray, card0Hash: String): KitRecoveryStep {
        refusedBeforeAnything(origin)?.let {
            secret.fill(0)
            return KitRecoveryStep.Stopped(it)
        }
        // A secret of zeros is a bad kit, never "locked": the floor would refuse its HKDF.
        if (io.silencelen.andvari.core.crypto.KeyFloor.allZero(secret)) return KitRecoveryStep.Stopped(BAD_KIT)
        return when (val r = trust.pinFromKit(origin, card0Hash, emailNorm)) {
            is FirstPin.Pinned -> target(Pending(origin, emailNorm, emailNorm, secret, card0Hash, r.handle), r.pin.name, false, null)
            is FirstPin.KitAnchorMismatch -> target(Pending(origin, emailNorm, emailNorm, secret, card0Hash, null), r.gate.name, true, r.gate)
            is FirstPin.OriginMismatch -> KitRecoveryStep.OriginMismatch(r, handleFor(Pending(origin, emailNorm, emailNorm, secret, card0Hash, null)))
            else -> {
                secret.fill(0)
                pinStop(r)
            }
        }
    }

    private fun pinStop(r: FirstPin): KitRecoveryStep = when (r) {
        is FirstPin.PinChanged -> KitRecoveryStep.PinChanged(r)
        is FirstPin.Blocked -> KitRecoveryStep.Stopped(INSTANCE_BLOCKED)
        is FirstPin.PinConflict -> KitRecoveryStep.Stopped(r.verdict)
        is FirstPin.Refused -> KitRecoveryStep.Stopped(r.reason)
        FirstPin.Unreachable -> KitRecoveryStep.Stopped(UNREACHABLE)
        else -> KitRecoveryStep.Stopped(UNREACHABLE)
    }

    /** "Recover *email* on *name* (*origin*)": with the Trust Gate in the same confirmation when the pin does not serve this recovery. */
    private suspend fun target(p: Pending, name: String, anchorMismatch: Boolean, gate: FirstPin.NeedsTrustGate?): KitRecoveryStep {
        if (gate != null) return KitRecoveryStep.ConfirmTarget(p.email, gate.name, p.origin, anchorMismatch, gate, handleFor(p))
        return when (gate(p.origin, p.emailNorm)) {
            GateDecision.PROCEED -> KitRecoveryStep.ConfirmTarget(p.email, name, p.origin, false, null, handleFor(p))
            GateDecision.REFUSE_ENTRY -> {
                p.made?.let(trust::dropPinMade)
                p.wipe()
                KitRecoveryStep.Stopped(INSTANCE_BLOCKED)
            }
            GateDecision.TRUST_GATE -> when (val g = trust.beginTrustGate(p.origin, TrustGateWording.TYPED_ADDRESS)) {
                is FirstPin.NeedsTrustGate -> KitRecoveryStep.ConfirmTarget(p.email, g.name, p.origin, anchorMismatch, g, handleFor(p))
                is FirstPin.Pinned -> if (gate(p.origin, p.emailNorm) == GateDecision.PROCEED) {
                    KitRecoveryStep.ConfirmTarget(p.email, g.pin.name, p.origin, false, null, handleFor(p))
                } else {
                    p.wipe()
                    KitRecoveryStep.Stopped(TRUST_GATE_FIRST)
                }
                else -> {
                    p.made?.let(trust::dropPinMade)
                    p.wipe()
                    pinStop(g)
                }
            }
        }
    }

    override suspend fun startTyped(email: String, origin: String, typedSecret: String, entry: GateEntry): KitRecoveryStep {
        if (!entryOk(entry)) return KitRecoveryStep.Stopped(WRONG_SCREEN)
        if (!TrustGrammar.isOrigin(origin)) return KitRecoveryStep.Stopped(BAD_ORIGIN)
        val emailNorm = TrustGrammar.emailNorm(email) ?: return KitRecoveryStep.Stopped(INVALID_EMAIL)
        refusedBeforeAnything(origin)?.let { return KitRecoveryStep.Stopped(it) }
        // A secret of zeros is a bad kit; the parse itself still answers it, as the normative vectors grade.
        val secret = RecoveryKit.parseSecret(typedSecret)?.takeUnless { io.silencelen.andvari.core.crypto.KeyFloor.allZero(it) }
            ?: return KitRecoveryStep.Stopped(BAD_KIT)
        // A typed kit carries no card0Hash: never the kit root.
        val p = Pending(origin, email, emailNorm, secret, null, null)
        val name = trust.pinFor(origin)?.name ?: ""
        return target(p, name, false, null)
    }

    override suspend fun retargetOrigin(step: KitRecoveryStep.OriginMismatch): KitRecoveryStep {
        val p = pending.remove(step.handle) ?: return KitRecoveryStep.Stopped(STALE)
        val to = step.mismatch.cardOrigin
        val secret = p.secret.copyOf()
        p.wipe()
        if (p.card0Hash != null) return startScanned(to, p.emailNorm, secret, p.card0Hash)
        refusedBeforeAnything(to)?.let {
            secret.fill(0)
            return KitRecoveryStep.Stopped(it)
        }
        return target(Pending(to, p.email, p.emailNorm, secret, null, null), trust.pinFor(to)?.name ?: "", false, null)
    }

    /** The person backed out, or the host stopped the flow: drop the pin this flow made and every secret ([KitRecovery.cancel]). */
    override fun cancel(step: KitRecoveryStep) {
        val h = when (step) {
            is KitRecoveryStep.ConfirmTarget -> step.handle
            is KitRecoveryStep.OriginMismatch -> step.handle
            is KitRecoveryStep.ChoosePassword -> step.handle
            else -> return
        }
        stop(h, STALE)
    }

    override suspend fun verify(step: KitRecoveryStep.ConfirmTarget): KitRecoveryStep {
        val p = pending[step.handle] ?: return KitRecoveryStep.Stopped(STALE)
        // The pin this call's own Trust Gate made: a leave while this call waits drops it, as the assisted recovery drops
        // the pin its request's gate made. Once this call has answered, it stays (see KitRecovery.cancel).
        var gateMade: PinHandle? = null
        fun left(): KitRecoveryStep.Stopped {
            gateMade?.let(trust::dropPinMade)
            return KitRecoveryStep.Stopped(STALE)
        }
        step.gate?.let { g ->
            val pinned = trust.confirmTrustGate(g.confirm) as? FirstPin.Pinned ?: return stop(step.handle, TRUST_GATE_FIRST)
            gateMade = pinned.handle
            // A wait: the kit secret may have been wiped by a leave meanwhile.
            if (!still(step.handle, p)) return left()
        }
        // The rule itself, asked again now: only `proceed` lets recoveryAuthKey go to this origin.
        if (gate(p.origin, p.emailNorm) != GateDecision.PROCEED) return stop(step.handle, TRUST_GATE_FIRST)
        val client = clientFor(p.origin)
        val body = WireJson.json.encodeToString(RecoveryVerifyRequest.serializer(), RecoveryVerifyRequest(p.email, MemberRecovery.deriveAuthKey(crypto, p.secret)))
        val verified = client.call(WireRoute.RECOVERY_SELF_VERIFY, bodyJson = body, decode = { WireJson.json.decodeFromString(RecoveryVerifyResponse.serializer(), it) })
        // Left while the verify was in flight: the kit secret is zeros now; nothing is opened from it, and the flow is not
        // handed on (it would come back as a new step of a flow the person ended).
        if (!still(step.handle, p)) return left()
        val resp = when (val r = verified) {
            is WireResult.Ok -> r.value
            is WireResult.Refused -> return when {
                r.status == 401 -> { stop(step.handle, REJECTED); KitRecoveryStep.Rejected }
                r.status >= 500 -> stop(step.handle, UNREACHABLE)
                else -> stop(step.handle, r.code)
            }
            is WireResult.NoAnswer -> return stop(step.handle, UNREACHABLE)
        }
        if (!TrustGrammar.isUuid(resp.userId) || io.silencelen.andvari.core.client.UserIds.isNil(resp.userId)) return stop(step.handle, BAD_RESPONSE)
        // Phase 1's hard-fail (spec 01 §5): the kit opens the UVK, the UVK the seed, and the seed's key is the served one.
        val uvk = try {
            MemberRecovery.openUvk(crypto, p.secret, resp.recoveryWrappedUvk, resp.userId)
        } catch (e: CryptoException) {
            return stop(step.handle, IDENTITY_MISMATCH)
        } catch (e: IllegalArgumentException) {
            return stop(step.handle, IDENTITY_MISMATCH)
        }
        // Spec 01 §7, a recovery on a device that keeps this account: the key the kit opened must open what the copy holds
        // sealed under the account's key, before anything is asked or sent that would replace it. Another key stops here:
        // no commit is sent, so the server changes nothing and opens no session.
        KeptAccountCheck.recoveredKeyRefusal(crypto, resp.userId, uvk, sink.keptForSignIn(p.origin),
            KeptAccountCheck.identityUnder(crypto, resp.userId, uvk, resp.encryptedIdentitySeed))?.let {
            uvk.fill(0)
            return stop(step.handle, it)
        }
        val seed = try {
            Envelope.openB64(crypto, uvk, resp.encryptedIdentitySeed, Ad.idkey(resp.userId))
        } catch (e: Exception) {
            uvk.fill(0)
            return stop(step.handle, IDENTITY_MISMATCH)
        }
        val identity = try { crypto.boxKeypairFromSeed(seed) } finally { seed.fill(0) }
        identity.privateKey.fill(0)
        val served = Bytes.fromB64Exact(resp.identityPub, 32)
        val known = knownIdentity(resp.userId)
        if (served == null || !Bytes.ctEquals(served, identity.publicKey) || (known != null && !Bytes.ctEquals(known, identity.publicKey))) {
            uvk.fill(0)
            return stop(step.handle, IDENTITY_MISMATCH)
        }
        // The session keeper is asked before the person chooses a password and before anything is committed: a device that
        // keeps another account would refuse the session the commit opens, after the server had already taken the new
        // password and made the old kit useless. Nothing is committed; the way out is to sign that account out first.
        sink.wouldRefuse(p.origin, p.emailNorm, resp.userId, identity.publicKey)?.let {
            uvk.fill(0)
            return keeperStop(step.handle, it, p.origin, p.emailNorm, resp.userId, identity.publicKey)
        }
        p.userId = resp.userId
        p.ticket = resp.recoveryTicket
        p.uvk = uvk
        p.identityPub = identity.publicKey.copyOf()
        pending.remove(step.handle)
        return KitRecoveryStep.ChoosePassword(handleFor(p))
    }

    override suspend fun commit(step: KitRecoveryStep.ChoosePassword, newPassword: CharArray): KitRecoveryStep {
        // A flow under way for the kit's address until the commit is answered ([SessionSink.underWay]).
        val done = pending[step.handle]?.let { sink.underWay(it.origin, it.emailNorm) }
        try {
            return commitHeld(step, newPassword)
        } finally {
            done?.invoke()
        }
    }

    private suspend fun commitHeld(step: KitRecoveryStep.ChoosePassword, newPassword: CharArray): KitRecoveryStep {
        val p = pending[step.handle]
        if (p == null) {
            newPassword.fill('\u0000')
            return KitRecoveryStep.Stopped(STALE)
        }
        if (!Strength.meetsMasterPasswordFloor(newPassword)) {
            newPassword.fill('\u0000')
            return KitRecoveryStep.Stopped(PASSWORD_TOO_WEAK) // the step stays: choose another
        }
        // The rule asked again before newAuthKey goes out: a pin that became forked or damaged (or was forgotten) since
        // the verify step stops the commit here, before anything is derived or sent.
        when (gate(p.origin, p.emailNorm)) {
            GateDecision.PROCEED -> {}
            GateDecision.REFUSE_ENTRY -> { newPassword.fill('\u0000'); return stop(step.handle, INSTANCE_BLOCKED) }
            else -> { newPassword.fill('\u0000'); return stop(step.handle, TRUST_GATE_FIRST) }
        }
        val userId = p.userId!!
        val uvk = p.uvk!!
        val pin = trust.pinFor(p.origin) ?: run { newPassword.fill('\u0000'); return stop(step.handle, TRUST_GATE_FIRST) }
        // Asked again before the commit is sent: what the device keeps may have changed since the verify step.
        val kept = sink.keptForSignIn(p.origin)
        KeptAccountCheck.recoveredKeyRefusal(crypto, userId, uvk, kept, p.identityPub)?.let {
            newPassword.fill('\u0000')
            return stop(step.handle, it)
        }
        // The new password's cost: never below the server's policy, read through the pinned server now ([RecoveryCost]).
        val cost = RecoveryCost.of(clientFor(p.origin), kdfParams, kept, userId)
        // A wait: a leave meanwhile wiped the recovered key; nothing is derived or sent.
        if (!still(step.handle, p)) {
            newPassword.fill('\u0000')
            return KitRecoveryStep.Stopped(STALE)
        }
        // Asked again with nothing more to wait for before the commit is sent: what the device keeps may have changed
        // since the verify step (another account signed in meanwhile). A no sends nothing.
        sink.wouldRefuse(p.origin, p.emailNorm, userId, p.identityPub)?.let {
            newPassword.fill('\u0000')
            return keeperStop(step.handle, it, p.origin, p.emailNorm, userId, p.identityPub)
        }
        val keys = PasswordKeys.derive(crypto, newPassword, crypto.randomBytes(KdfParams.SALT_BYTES), cost, served = false)
            ?: return stop(step.handle, BAD_RESPONSE)
        val piece = MemberRecovery.generate(crypto, userId, uvk)
        try {
            val device = devices.newDevice(p.origin, p.emailNorm, platform, deviceName)
            val body = RecoveryCommitRequest(
                recoveryTicket = p.ticket!!, newAuthKey = keys.authKeyB64, newKdfSalt = Bytes.toB64(keys.salt), newKdfParams = keys.params,
                newWrappedUvk = Envelope.sealB64(crypto, keys.wrapKey, uvk, Ad.uvk(userId)),
                newMemberRecovery = MemberRecoveryBlock(piece.recoveryWrappedUvk, piece.recoveryAuthKey), device = device,
            )
            val r = clientFor(p.origin).call(WireRoute.RECOVERY_SELF_COMMIT, bodyJson = WireJson.json.encodeToString(RecoveryCommitRequest.serializer(), body),
                decode = { WireJson.json.decodeFromString(SessionResponse.serializer(), it) })
            // Left while the commit was in flight: the UVK copy this flow held is zeros now, and the
            // session would be opened under it. Only the shared floor stopped that before. Nothing is opened, kept or sent:
            // STALE, and what the answer came to is published once for the first screen (LateRecoveryOutcome).
            if (!still(step.handle, p)) {
                late.publish(LateRecoveryOutcome(p.origin, p.email, LateRecoveryOutcome.Via.KIT, LateRecoveryOutcome.resultOf(r)))
                return KitRecoveryStep.Stopped(STALE)
            }
            val resp = when (r) {
                is WireResult.Ok -> r.value
                is WireResult.Refused -> return when {
                    r.status == 401 -> { stop(step.handle, REJECTED); KitRecoveryStep.Rejected }
                    r.status >= 500 -> stop(step.handle, UNKNOWN)
                    else -> stop(step.handle, r.code)
                }
                // The commit may have landed: the old kit may be dead and the new one is not shown. Sign in decides.
                is WireResult.NoAnswer -> return stop(step.handle, UNKNOWN)
            }
            // From here the server has opened a session: a refusal on this device ends exactly that session there.
            suspend fun refused(reason: String): KitRecoveryStep.Stopped {
                sink.notTaken(p.origin, resp.accessToken, resp.refreshToken)
                return stop(step.handle, reason)
            }
            val pieceId = resp.recoveryPieceId
            if (pieceId == null || !TrustGrammar.isB64_32(pieceId)) return refused(BAD_RESPONSE)
            val opened = SessionOpener.open(crypto, p.origin, p.emailNorm, resp, uvk.copyOf(), userId, pin.instanceId, knownIdentity(userId),
                device.deviceSecret, SessionHow.RECOVERED, devices, sink, KnownKdf(keys.salt, keys.params, body.newWrappedUvk))
            val (session, notKept) = when (opened) {
                is Opening.Done -> opened.session to opened.notTaken
                is Opening.Fault -> return refused(opened.reason)
                Opening.Bad -> return refused(BAD_RESPONSE)
            }
            // Committed at the server: the new password is in force and this kit is the only one. When the session keeper
            // refused the session all the same (what the device keeps changed while the commit was under way; it ended that
            // session itself), the kit still goes to the caller with the refusal: the old kit is dead, so this one must be
            // shown and kept.
            val qr = RecoveryKit.composeQr(p.origin, pin.card0Hash, p.emailNorm, piece.recoverySecret) ?: return stop(step.handle, BAD_RESPONSE)
            val kit = RevealedKit(RecoveryKit.groups(piece.recoverySecret), qr, pieceId, session.account.accountId(crypto), piece.recoverySecret.copyOf())
            // Done: the flow ends and the pin it made STAYS. The session just opened talks to this origin, and no
            // credential goes to an origin without a pin in force (design §4.4).
            pending.remove(step.handle)?.wipe()
            return KitRecoveryStep.Recovered(userId, kit, notKept)
        } finally {
            keys.wipe()
            piece.recoverySecret.fill(0)
        }
    }

    companion object {
        const val WRONG_SCREEN = "wrong_screen_kit"
        const val BAD_ORIGIN = "bad_origin"
        const val INVALID_EMAIL = "invalid_email"
        const val BAD_KIT = "bad_kit"
        const val INSTANCE_BLOCKED = "instance_blocked"
        const val TRUST_GATE_FIRST = "trust_gate_first"
        const val UNREACHABLE = "unreachable"
        const val UNKNOWN = "unknown"
        const val STALE = "stale"
        const val REJECTED = "rejected"
        const val BAD_RESPONSE = "bad_response"
        /**
         * Design §2.4 "Account keys at … kit recovery": the kit does not open the served wrapped UVK or seed, or the seed's key
         * is not the served (or this device's own) `identityPub`. The person is shown the identity fault; the verdict string is
         * this one name on every client. A fault met when the session opens is named by its own §2.4 verdict.
         */
        const val IDENTITY_MISMATCH = "identity_mismatch"

        /** Not a verdict string any more (design §2.4: one name each); the identity fault is the outcome shown. */
        @Deprecated("use IDENTITY_MISMATCH or the opening's own verdict", ReplaceWith("IDENTITY_MISMATCH"))
        const val IDENTITY_FAULT = "identity_fault"
        const val PASSWORD_TOO_WEAK = "password_too_weak"

        /**
         * Spec 01 §7: this device keeps the account, and the key the kit opened does not open what the copy holds sealed
         * under the account's key (its identity seed, to the identity key kept beside it). Nothing was committed, nothing
         * this device keeps was replaced, and no session was opened. The same code as a sign-in's
         * ([io.silencelen.andvari.core.client.onboard.WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE]).
         */
        const val SERVER_KEYS_NOT_KNOWN_HERE = io.silencelen.andvari.core.client.onboard.WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE

        /**
         * This device keeps another account (or one at another server, or one held as its server's operator), and the
         * session the commit opens could not be kept: stopped before anything was committed (at the start, when the
         * server alone decides it; at the verify step and again just before the commit otherwise). The server changed
         * nothing, and the old kit still opens the account. The way out is to sign that account out first. The session
         * keeper's own code. An address bound here to another account stops as
         * [io.silencelen.andvari.core.client.onboard.AccountOpen.SELF_IDENTITY_MISMATCH], the same way.
         */
        const val ANOTHER_SESSION_KEPT = io.silencelen.andvari.core.client.session.Establishing.ANOTHER_SESSION_KEPT

        /** The account kept here is held as its server's operator account, this one included: stopped as [ANOTHER_SESSION_KEPT] is; the way out is to remove it from this device. */
        const val OPERATOR_ACCOUNT_HELD = io.silencelen.andvari.core.client.session.Establishing.OPERATOR_ACCOUNT_HELD

        /**
         * Spec 01 §7: this device keeps the account and the kit's key does not open the copy's sealed identity seed, because
         * the copy itself is damaged (the kit's key opens the served seed to the identity the copy records, or the copy's
         * records cannot be read). Stopped at the verify step or before the commit: nothing committed or replaced. The way
         * out is to remove this device's copy, then recover.
         */
        const val KEPT_COPY_DAMAGED = io.silencelen.andvari.core.client.session.Establishing.KEPT_COPY_DAMAGED
        private const val DONE = "done"

        /** The account ID on a kit (design §10): the 32-hex short fingerprint of the X25519 identity key. */
        internal fun accountId(crypto: CryptoProvider, identityPub: ByteArray): String = Fingerprint.shortForm(Bytes.toHexLower(crypto.sha256(identityPub)))
    }
}
