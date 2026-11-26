package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.client.onboard.OperatorRecovery
import io.silencelen.andvari.core.client.onboard.OperatorRecoveryOffer
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.RevealedKit
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.InstanceTrust
import io.silencelen.andvari.core.client.recovery.EscrowDecision
import io.silencelen.andvari.core.client.recovery.EscrowInputs
import io.silencelen.andvari.core.client.recovery.EscrowRules
import io.silencelen.andvari.core.client.recovery.EscrowSeen
import io.silencelen.andvari.core.client.recovery.RecoveryMirror
import io.silencelen.andvari.core.client.recovery.TrustRotationFacts
import io.silencelen.andvari.core.client.state.AccountMerge
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.client.state.RecoveryRecord
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.model.wire.AccountRecoveryPut
import io.silencelen.andvari.core.model.wire.AccountStateResponse
import io.silencelen.andvari.core.model.wire.EscrowSelfPut
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.RecoveryPosture
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * [RecoverySettings] over the wire (design §4.5, §7.7; spec 03 §3).
 *
 * Trust: the posture the engine acts on is the account-state `recovery` record, never a served posture. An escrow is
 * sealed only under §4.5: the record says `operator`, the pinned card's `recoveryFp` is the consented one or follows from
 * it by signed rotations, the served key hashes to it at full length; a SILENT re-seal (`PUT /escrow/self`) happens only
 * when this device's own mirror agrees ([EscrowRules]); otherwise the person is asked, with the password. Operator
 * recovery is turned ON only through [setPosture] with the offer this device made from the pinned card and the explicit
 * consent box, and never for a `public` card (variant R). Every `PUT /account/recovery` derives `currentAuthKey` through
 * the one [Reauth] path, and every password array handed in is wiped.
 *
 * [account] is borrowed from the session; [kit] serves [rotateKit].
 */
class WireRecoverySettings(
    private val origin: String,
    private val account: OpenedAccount,
    private val client: WireClient,
    private val crypto: CryptoProvider,
    private val state: DeviceState,
    private val trust: InstanceTrust,
    private val reauth: Reauth,
    private val kit: WireAccountSettings,
    private val clock: () -> Long,
) : RecoverySettings {
    private val lock = Mutex()
    private val mirror = RecoveryMirror(state)
    private val seen = EscrowSeen(state)
    private val rules = EscrowRules(TrustRotationFacts(crypto))
    private val store get() = StoredAccountState(account.userId, account.uvk, client, crypto, state)

    private class Now(val record: RecoveryRecord?, val pin: CardPin, val decision: EscrowDecision)

    /** The record as merged now, the pin, and what §4.5 wants; a [Fetched] when it cannot be read. */
    private suspend fun now(): Any {
        val doc = when (val r = store.read()) {
            is AccountStateRead.Ok -> r.document
            AccountStateRead.Unopenable -> return Fetched.Refused("unopenable")
            AccountStateRead.Unreachable -> return Fetched.Unreachable
            is AccountStateRead.Stopped -> return Fetched.Refused(r.code)
        }
        val record = doc.recovery
        val start = trust.pinFor(origin) ?: return Fetched.Refused(NO_PIN)
        if (record?.posture != RecoveryPosture.OPERATOR || !OperatorRecovery.offered(start)) {
            // Nothing can be sealed: no operator consent, or a card that offers none (variant R for `public`).
            return Now(record, start, rules.decide(EscrowInputs(start, record, mirror.get(account.userId), seen.get(account.userId), emptyList(), null)))
        }
        val served = OperatorRecovery.served(client, trust, crypto, origin) ?: return Fetched.Refused(CARD_UNVERIFIED)
        val pin = served.pin
        val keyFp = OperatorRecovery.recoveryKey(client, crypto, pin.recoveryFp)?.let { pin.recoveryFp }
        val inputs = EscrowInputs(pin, record, mirror.get(account.userId), seen.get(account.userId), served.rotations, keyFp)
        return Now(record, pin, rules.decide(inputs))
    }

    override suspend fun posture(): Fetched<RecoveryPostureView> = lock.withLock {
        val now = when (val n = now()) {
            is Fetched<*> -> @Suppress("UNCHECKED_CAST") return@withLock n as Fetched<RecoveryPostureView>
            else -> n as Now
        }
        var record = now.record
        val decision = now.decision
        if (decision is EscrowDecision.SealNow) {
            // §4.5: the own mirror agrees and signed rotations lead from the escrow to the card's key: re-seal, unasked.
            val key = OperatorRecovery.recoveryKey(client, crypto, decision.toFp) ?: return@withLock Fetched.Refused(OPERATOR_RECOVERY_UNAVAILABLE)
            // Under the account's guard, after the reads' waits; sent at once, with no wait between.
            val sealed = account.signing.use { s -> account.uvk.use { u -> Escrow.sealUvkV3(crypto, key, decision.toFp, account.userId, kit.emailNorm, account.identity.publicKey, s, u, clock()) } }
            val body = WireJson.json.encodeToString(EscrowSelfPut.serializer(), EscrowSelfPut(Bytes.toB64(sealed), decision.toFp, decision.rotations))
            when (val r = client.call(WireRoute.ESCROW_SELF, bodyJson = body, decode = { })) {
                is WireResult.Ok -> {}
                is WireResult.Refused -> return@withLock if (r.status >= 500) Fetched.Unreachable else Fetched.Refused(r.code)
                is WireResult.NoAnswer -> return@withLock Fetched.Unreachable
            }
            seen.put(account.userId, decision.toFp)
            // The consent follows the signed rotation, and this device's own mirror with it (a verified re-seal made here).
            // It supersedes the record it follows (design §5.4): stamped after it, whatever this device's clock says.
            val base = RecoveryRecord(RecoveryPosture.OPERATOR, decision.toFp, clock())
            var next = base
            val w = store.update { doc -> next = AccountMerge.supersedingRecovery(base, doc.recovery); doc.copy(recovery = next) }
            if (w is AccountStateWrite.Written || w is AccountStateWrite.Unchanged) {
                mirror.put(account.userId, next)
                record = next
            }
        }
        Fetched.Ok(RecoveryPostureView(record, OperatorRecovery.offered(now.pin), decision))
    }

    override suspend fun operatorOffer(): OperatorRecoveryOffer? = OperatorRecovery.offer(client, trust, crypto, origin)

    override suspend fun setPosture(choice: RecoveryChoiceKind, offer: OperatorRecoveryOffer?, understood: Boolean, password: CharArray): Reauthed<RecoveryRecord> =
        lock.withLock {
            if (choice == RecoveryChoiceKind.PRIVATE) {
                return@withLock put(RecoveryRecord(RecoveryPosture.PRIVATE, TrustGrammar.NONE, clock()), null, password)
            }
            // Every check that needs no secret, before the password is touched.
            val refusal = run {
                val pin = trust.pinFor(origin) ?: return@run NO_PIN
                if (!OperatorRecovery.offered(pin) || offer == null) return@run OPERATOR_RECOVERY_UNAVAILABLE
                if (offer.origin != origin || offer.pinHash != pin.hash || offer.fp != pin.recoveryFp) return@run STALE_OFFER
                if (!understood) return@run CONSENT_REQUIRED
                null
            }
            if (refusal != null) {
                password.fill('\u0000')
                return@withLock Reauthed.Refused(refusal)
            }
            put(RecoveryRecord(RecoveryPosture.OPERATOR, offer!!.fp, clock()), offer.recoveryPub, password)
        }

    override suspend fun answerEscrowPrompt(prompt: EscrowDecision, keep: Boolean, password: CharArray): Reauthed<RecoveryRecord> = lock.withLock {
        // The prompt is re-derived from this device's own state now; a stale one changes nothing.
        val now = now() as? Now
        if (now == null || now.decision != prompt || (prompt !is EscrowDecision.AskOwnMirror && prompt !is EscrowDecision.UnsignedChange)) {
            password.fill('\u0000')
            return@withLock Reauthed.Refused(STALE_PROMPT)
        }
        if (!keep) return@withLock put(RecoveryRecord(RecoveryPosture.PRIVATE, TrustGrammar.NONE, clock()), null, password)
        val fp = now.pin.recoveryFp
        val key = OperatorRecovery.recoveryKey(client, crypto, fp)
        if (key == null) {
            password.fill('\u0000')
            return@withLock Reauthed.Refused(OPERATOR_RECOVERY_UNAVAILABLE)
        }
        put(RecoveryRecord(RecoveryPosture.OPERATOR, fp, clock()), key, password)
    }

    /**
     * `PUT /account/recovery`† with [record] in the sealed account state and, for `operator`, an escrow sealed to
     * [recoveryPub] (checked against the card at full length by the caller). On success this device's own mirror is set.
     */
    private suspend fun put(record: RecoveryRecord, recoveryPub: ByteArray?, password: CharArray): Reauthed<RecoveryRecord> {
        val key = try {
            reauth.currentAuthKey(password)
        } finally {
            password.fill('\u0000')
        }
        val current = when (key) {
            is ReauthKey.Key -> key.currentAuthKey
            ReauthKey.Refused -> return Reauthed.NoSession
            ReauthKey.Unreachable -> return Reauthed.Unknown
            ReauthKey.WrongPassword -> return Reauthed.WrongPassword
        }
        val escrow = recoveryPub?.let {
            // Under the account's guard, after the re-authentication's wait.
            val sealed = account.signing.use { s -> account.uvk.use { u -> Escrow.sealUvkV3(crypto, it, record.fp, account.userId, kit.emailNorm, account.identity.publicKey, s, u, clock()) } }
            EscrowUpload(Bytes.toB64(sealed), record.fp)
        }
        // The new choice supersedes the record it replaces (design §5.4): stamped after the held one on every attempt,
        // so a device whose clock runs behind still turns operator recovery off for good.
        var written = record
        val w = store.updateVia({ doc -> written = AccountMerge.supersedingRecovery(record, doc.recovery); doc.copy(recovery = written) }) { put ->
            // The escrow was sealed before the account-state read's wait: never sent once the keys are wiped.
            account.guard.check()
            client.call(WireRoute.ACCOUNT_RECOVERY_PUT, bodyJson = WireJson.json.encodeToString(AccountRecoveryPut.serializer(), AccountRecoveryPut(record.posture, escrow, current, put)),
                decode = { WireJson.json.decodeFromString(AccountStateResponse.serializer(), it) })
        }
        return when (w) {
            is AccountStateWrite.Written, is AccountStateWrite.Unchanged -> {
                mirror.put(account.userId, written)
                seen.put(account.userId, if (escrow != null) record.fp else null)
                Reauthed.Done(written)
            }
            // `reauth_failed` included: the server's refusal of the proof is [Reauthed.PROOF_REFUSED], never a wrong password.
            is AccountStateWrite.Refused -> Reauthed.Refused(w.code)
            AccountStateWrite.Contended -> Reauthed.Refused("stale_state")
            AccountStateWrite.Unknown -> Reauthed.Unknown
        }
    }

    override suspend fun rotateKit(password: CharArray): Reauthed<RevealedKit> = kit.rotateKit(password)

    companion object {
        const val NO_PIN = "no_pin"
        const val CARD_UNVERIFIED = "card_unverified"
        const val OPERATOR_RECOVERY_UNAVAILABLE = "operator_recovery_unavailable"
        const val STALE_OFFER = "stale_offer"
        const val CONSENT_REQUIRED = "consent_required"
        const val STALE_PROMPT = "stale_prompt"
    }
}
