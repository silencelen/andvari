package io.silencelen.andvari.core.client.devicelink

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.client.link.ContactCurrency
import io.silencelen.andvari.core.client.link.Currency
import io.silencelen.andvari.core.client.link.LinkAccount
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.AccountOpen
import io.silencelen.andvari.core.client.onboard.AccountOpenResult
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.KnownKdf
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.SessionHow
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.pin.CardStatus
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
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.model.wire.DeviceLinkApproveRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkClaim
import io.silencelen.andvari.core.model.wire.DeviceLinkCreateRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkNonceRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkPickupRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkPickupResponse
import io.silencelen.andvari.core.model.wire.DeviceLinkPollRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkPollResponse
import io.silencelen.andvari.core.model.wire.DeviceLinkRevealRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkView
import io.silencelen.andvari.core.model.wire.InstanceResponse
import io.silencelen.andvari.core.model.wire.LinkCreatedResponse
import io.silencelen.andvari.core.model.wire.PickupDevice
import io.silencelen.andvari.core.model.wire.PreloginRequest
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.BundleContact
import io.silencelen.andvari.core.trust.BundleVault
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.Checkpoint
import io.silencelen.andvari.core.trust.CodeCommit
import io.silencelen.andvari.core.trust.ComparisonCode
import io.silencelen.andvari.core.trust.DeviceClaim
import io.silencelen.andvari.core.trust.DeviceLink
import io.silencelen.andvari.core.trust.DeviceLinkBundle
import io.silencelen.andvari.core.trust.DeviceLinkKeys
import io.silencelen.andvari.core.trust.DeviceLinkOuter
import io.silencelen.andvari.core.trust.DeviceLinkUrl
import io.silencelen.andvari.core.trust.DeviceLinkVerdict
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.ParsedDeviceLink
import io.silencelen.andvari.core.trust.TrustGrammar
import io.silencelen.andvari.core.trust.VerifiedClaim
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import io.silencelen.andvari.core.crypto.KeysGoneException
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer

/**
 * [DeviceLinks] over the wire (design §8.2, §8.3; spec 03 §16), both roles.
 *
 * Trust, new device N:
 * - Only "Link from your other device" (or `andvari-cli link-device`) starts anything (§8.2 step 0, FS-B1).
 * - Before the claim, N holds a PASSWORD pin for the link's origin ([PasswordGate] purpose `device_link`), or the person
 *   passes the device-link Trust Gate; nothing goes to the origin before that.
 * - N keeps the first `nonceE` it was served (`nonce_changed`), and shows the code only once it holds it and revealed.
 * - Before any password prompt it checks `approveMac`, then opens and strictly decodes `outer`, then its origin (the shared verifiers'
 *   [DeviceLink.openOuter], in §2.4's order). Prelogin and `authKey` go only to the pinned origin, after the gate again.
 * - After the pickup it opens the account through every identity check (the genesis first), then the bundle
 *   (`bundle_unopenable`, `bad_bundle`, `identity_mismatch`, `pin_mismatch`); any failure discards the session at once
 *   ([discard]) before it reaches [sink], and `pin_mismatch` also drops the pin this link made in step 0, never another.
 *
 * Trust, existing device E: the claim's MAC is verified and the claim FIXED when E draws `nonceE` (`claim_changed`
 * after); the reveal must open `commitN` (`bad_reveal`); the person types N's digits (`code_mismatch` cancels); only then
 * is the bundle built, with this device's CURRENT contacts and the vault records, most recently verified first, until
 * the shared verifiers' [DeviceLink.fits] says full.
 *
 * [discard] signs out a session the engine refused (POST /auth/logout with that access token); the session keeper binds
 * it. [ephemeral] and [random] are the CSPRNG by default; tests fix them.
 */
class WireDeviceLinks(
    private val clientFor: (String) -> WireClient,
    private val trust: InstanceTrust,
    private val state: DeviceState,
    private val crypto: CryptoProvider,
    private val clock: () -> Long,
    private val account: () -> LinkAccount?,
    private val devices: KnownDevices,
    private val sink: SessionSink,
    private val discard: suspend (origin: String, accessToken: String) -> Unit,
    private val deviceName: String,
    private val platform: String,
    private val ephemeral: () -> KeyPairBytes = { crypto.boxKeypairFromSeed(crypto.randomBytes(32)) },
    private val random: (Int) -> ByteArray = { crypto.randomBytes(it) },
    /**
     * Ends exactly the one session a refused pickup opened, by its refresh token (`POST /auth/end-session`); used in place
     * of [discard] when given. [discard] signs out with the access token, which ends every session of the device at the
     * server, a kept one's too. Null: [discard], as before.
     */
    private val endOne: (suspend (origin: String, refreshToken: String) -> Unit)? = null,
) : DeviceLinks {
    private val lock = Mutex()
    private var counter = 0L

    /**
     * A waiting link's requests that the server refused as too many (`429`): the link waits as long as the answer says and
     * asks again, until its own time runs out ([LIFETIME_MS] from when this device took it up), instead of stopping. Two
     * new devices linking at the same time behind one address share one budget for their polls, and can reach it.
     */
    private class Hold(val since: Long) {
        /** Until when (this device's clock) nothing is asked: a step asked for before then is answered as it was. */
        var until = 0L
    }

    /**
     * [hold] after a refusal for too many requests: true, and the step it was asked for stands (the link is waiting) until
     * the wait the answer named is over; false when that wait outlasts the link's own time, which ends it as expired.
     */
    private fun held(hold: Hold, r: WireResult.Refused): Boolean {
        val now = clock()
        val waitMs = (r.retryAfterSeconds ?: DEFAULT_WAIT_S).coerceIn(1L, LIFETIME_MS / 1000L) * 1000L
        if (now + waitMs > hold.since + LIFETIME_MS) return false
        hold.until = now + waitMs
        return true
    }

    private fun tooMany(r: WireResult<*>): WireResult.Refused? = (r as? WireResult.Refused)?.takeIf { it.status == 429 }

    private class EFlow(val id: String, val acct: LinkAccount, val keys: DeviceLinkKeys, val linkId: String, val hold: Hold) {
        var claim: VerifiedClaim? = null
        var nonceE: String? = null
        var nonceN: String? = null
        var code: String? = null
        var matched = false
    }

    private class NFlow(val id: String, val entry: GateEntry, val link: ParsedDeviceLink, val keys: DeviceLinkKeys, val linkId: String, val hold: Hold) {
        val origin: String get() = link.origin
        var pinMade: PinHandle? = null
        var pair: KeyPairBytes? = null
        var nPub: String = ""
        var nonceN: ByteArray? = null
        var nonceE: String? = null
        var revealed = false
        var code: String? = null
        var outer: DeviceLinkOuter? = null
        var pending: PasswordKeys? = null

        /**
         * The server asked for a two-step code in this link (a `totp_required` to one of its pickups): from then on a 401
         * is a refusal after the code, whatever a later call sends, and never a refused proof told apart.
         */
        var codeAsked = false

        /**
         * The link's hold, from its start to its end, on every address at its origin (its account is named only at step
         * 7): [SessionSink.underWay] with [SessionSink.ANY_ADDRESS]; released by [wipe], which every way out calls.
         */
        var held: (() -> Unit)? = null

        /**
         * What this device keeps of the link's account, with the typed password's keys under each kept wrap at another salt
         * or cost (spec 01 §7, [io.silencelen.andvari.core.client.onboard.KeptAccountCheck]); held with [pending].
         */
        var kept: io.silencelen.andvari.core.client.onboard.KeptWrapKeys? = null

        fun dropKept() {
            kept?.wipe()
            kept = null
        }

        fun wipe() {
            keys.wipe()
            link.wipe()
            pair?.privateKey?.fill(0)
            nonceN?.fill(0)
            pending?.wipe()
            pending = null
            dropKept()
            held?.invoke()
            held = null
        }
    }

    private val existing = HashMap<String, EFlow>()
    private val incoming = HashMap<String, NFlow>()

    private fun stopOf(r: WireResult.Refused): DeviceLinkStop = when {
        r.code == "link_claimed" -> DeviceLinkStop.LINK_CLAIMED
        r.code == "link_expired" || r.status == 410 -> DeviceLinkStop.EXPIRED
        r.code == "bad_proof" -> DeviceLinkStop.BAD_PROOF
        r.code == "bad_reveal" -> DeviceLinkStop.BAD_REVEAL
        r.code == "link_unknown" || r.status == 404 || r.code == "link_state" -> DeviceLinkStop.CANCELLED
        // The server answered: too many requests, at a step that cannot wait (the waiting steps never come here).
        r.status == 429 -> DeviceLinkStop.TOO_MANY
        else -> DeviceLinkStop.UNREACHABLE
    }

    private fun stopOf(r: WireResult<*>): DeviceLinkStop = (r as? WireResult.Refused)?.let(::stopOf) ?: DeviceLinkStop.UNREACHABLE

    /** The wait a refusal for too many requests named, for its stop ([DeviceLinkStop.TOO_MANY]); null for any other answer. */
    private fun waitOf(r: WireResult<*>): Long? = tooMany(r)?.retryAfterSeconds

    private fun verdictStop(v: DeviceLinkVerdict): DeviceLinkStop = DeviceLinkStop.entries.first { it.code == v.code }

    // ---------------------------------------------------------------------------------------------
    // E, the existing device (§8.2 steps 1, 3, 5, 6)
    // ---------------------------------------------------------------------------------------------

    override suspend fun create(): ExistingStep = lock.withLock {
        val acct = account() ?: return@withLock ExistingStep.Stopped(DeviceLinkStop.NO_SESSION)
        val pin = trust.pinFor(acct.origin) ?: return@withLock ExistingStep.Stopped(DeviceLinkStop.INSTANCE_BLOCKED)
        val secret = random(32)
        try {
            val keys = DeviceLink.deriveKeys(crypto, secret)
            val url = DeviceLinkUrl.compose(acct.origin, secret) ?: return@withLock ExistingStep.Stopped(DeviceLinkStop.BAD_LINK)
            val body = WireJson.json.encodeToString(DeviceLinkCreateRequest.serializer(), DeviceLinkCreateRequest(keys.linkId, clock() + LIFETIME_MS))
            val r = clientFor(acct.origin).call(WireRoute.DEVICE_LINK_CREATE, bodyJson = body,
                decode = { WireJson.json.decodeFromString(LinkCreatedResponse.serializer(), it) })
            if (r !is WireResult.Ok) {
                keys.wipe()
                return@withLock ExistingStep.Stopped(stopOf(r), waitOf(r))
            }
            // Creating a link cancels every other of the account, server-side; this device forgets its own too.
            existing.values.forEach { it.keys.wipe() }
            existing.clear()
            val flow = EFlow("e" + (++counter), acct, keys, keys.linkId, Hold(clock()))
            existing[flow.id] = flow
            // The served countdown is bounded by the lifetime this device asked for: a negative one would show
            // a live link as run out, a huge one a link that never runs out (and wrap a deadline added to it).
            ExistingStep.Shown(url, acct.origin, pin.name, r.value.ttlMs.coerceIn(0L, LIFETIME_MS), DeviceLinkToken(flow.id))
        } finally {
            secret.fill(0)
        }
    }

    private fun eToken(step: ExistingStep): DeviceLinkToken? = when (step) {
        is ExistingStep.Shown -> step.token
        is ExistingStep.ClaimFixed -> step.token
        is ExistingStep.TypeDigits -> step.token
        is ExistingStep.Approvable -> step.token
        else -> null
    }

    private suspend fun eStop(flow: EFlow, reason: DeviceLinkStop, retryAfterSeconds: Long? = null): ExistingStep {
        clientFor(flow.acct.origin).call(WireRoute.DEVICE_LINK_CANCEL, pathParams = mapOf("linkId" to flow.linkId), decode = { })
        existing.remove(flow.id)
        flow.keys.wipe()
        return ExistingStep.Stopped(reason, retryAfterSeconds)
    }

    /** The link waits out a refusal for too many requests: the step asked for is answered as it was. */
    private object Waiting

    /**
     * E's view of the link, with the claim checked against the one E fixed; a [ExistingStep.Stopped] when it ends here,
     * [Waiting] while the server asked this device to wait ([held]).
     */
    private suspend fun view(flow: EFlow): Any {
        if (clock() < flow.hold.until) return Waiting
        val r = clientFor(flow.acct.origin).call(WireRoute.DEVICE_LINK_VIEW, pathParams = mapOf("linkId" to flow.linkId),
            decode = { WireJson.json.decodeFromString(DeviceLinkView.serializer(), it) })
        tooMany(r)?.let { return if (held(flow.hold, it)) Waiting else eStop(flow, DeviceLinkStop.EXPIRED) }
        val view = when (r) {
            is WireResult.Ok -> r.value
            is WireResult.Refused -> {
                existing.remove(flow.id)
                flow.keys.wipe()
                return ExistingStep.Stopped(stopOf(r))
            }
            is WireResult.NoAnswer -> return ExistingStep.Stopped(DeviceLinkStop.UNREACHABLE)
        }
        val fixed = flow.claim
        val served = view.claim?.let { DeviceClaim(it.nPub, it.name, it.platform, it.commitN, it.mac) }
        // T2-R-b: once E drew its nonce, the claim it verified is the only claim.
        if (fixed != null && (served == null || !fixed.claim.sameClaim(served))) return eStop(flow, DeviceLinkStop.CLAIM_CHANGED)
        return view
    }

    override suspend fun advance(step: ExistingStep): ExistingStep = lock.withLock {
        val flow = eToken(step)?.let { existing[it.id] } ?: return@withLock if (eToken(step) == null) step else ExistingStep.Stopped(DeviceLinkStop.STALE)
        val view = when (val v = view(flow)) {
            Waiting -> return@withLock step
            is ExistingStep -> return@withLock v
            else -> v as DeviceLinkView
        }
        val served = view.claim ?: return@withLock step
        var claim = flow.claim
        if (claim == null) {
            // Step 3: the claim's fields and MAC, then fix it and draw nonceE only now that commitN is seen.
            claim = when (val c = DeviceLink.verifyClaim(crypto, flow.keys, DeviceClaim(served.nPub, served.name, served.platform, served.commitN, served.mac))) {
                is Checked.Ok -> c.value
                is Checked.Refused -> return@withLock eStop(flow, verdictStop(c.verdict))
            }
            val nonce = random(CodeCommit.NONCE_BYTES)
            val nonceE = Bytes.toB64(nonce)
            nonce.fill(0)
            flow.claim = claim
            flow.nonceE = nonceE
            val proofHash = DeviceLink.proofHash(crypto, DeviceLink.pickupProof(crypto, flow.keys, claim.claim.nPub))
            val body = WireJson.json.encodeToString(DeviceLinkNonceRequest.serializer(), DeviceLinkNonceRequest(nonceE, proofHash))
            val r = clientFor(flow.acct.origin).call(WireRoute.DEVICE_LINK_NONCE, pathParams = mapOf("linkId" to flow.linkId), bodyJson = body, decode = { })
            if (r !is WireResult.Ok) return@withLock eStop(flow, stopOf(r), waitOf(r))
            return@withLock ExistingStep.ClaimFixed(claim.deviceName, claim.claim.platform, DeviceLinkToken(flow.id))
        }
        val nonceN = view.nonceN ?: return@withLock if (flow.code != null) step else ExistingStep.ClaimFixed(claim.deviceName, claim.claim.platform, DeviceLinkToken(flow.id))
        // Step 4: the reveal opens the commitment of the claim E fixed; a second, different value is an anomaly.
        val seen = flow.nonceN
        if (seen != null && seen != nonceN) return@withLock eStop(flow, DeviceLinkStop.BAD_REVEAL)
        if (seen == null) {
            DeviceLink.checkReveal(crypto, claim.claim.commitN, nonceN)?.let { return@withLock eStop(flow, verdictStop(it)) }
            val n = Bytes.fromB64Exact(nonceN, 32)!!
            val e = Bytes.fromB64Exact(flow.nonceE!!, 32)!!
            flow.nonceN = nonceN
            flow.code = ComparisonCode.deviceLink(crypto, flow.linkId, claim.nPub, n, e)
            n.fill(0)
            e.fill(0)
        }
        if (flow.matched) ExistingStep.Approvable(claim.deviceName, claim.claim.platform, DeviceLinkToken(flow.id))
        else ExistingStep.TypeDigits(claim.deviceName, claim.claim.platform, DeviceLinkToken(flow.id))
    }

    override suspend fun typeDigits(step: ExistingStep.TypeDigits, digits: String): ExistingStep = lock.withLock {
        val flow = existing[step.token.id] ?: return@withLock ExistingStep.Stopped(DeviceLinkStop.STALE)
        val claim = flow.claim
        val code = flow.code
        if (claim == null || code == null) return@withLock ExistingStep.Stopped(DeviceLinkStop.STALE)
        // Step 5: the digits must be TYPED into E; a mismatch cancels the link.
        if (!ComparisonCode.matches(digits, code)) return@withLock eStop(flow, DeviceLinkStop.CODE_MISMATCH)
        flow.matched = true
        ExistingStep.Approvable(claim.deviceName, claim.claim.platform, DeviceLinkToken(flow.id))
    }

    override suspend fun approve(step: ExistingStep.Approvable): ExistingStep = lock.withLock {
        val flow = existing[step.token.id] ?: return@withLock ExistingStep.Stopped(DeviceLinkStop.STALE)
        val claim = flow.claim
        if (claim == null || !flow.matched) return@withLock ExistingStep.Stopped(DeviceLinkStop.STALE)
        // The claim must still be the one fixed, now that the person typed the digits.
        val view = view(flow)
        // The server asked this device to wait: nothing is approved yet, and the person may approve again.
        if (view === Waiting) return@withLock step
        if (view is ExistingStep) return@withLock view
        val acct = flow.acct
        // The look was a wait: a cancel, a lock or a sign-out that came in it approves nothing,
        // and the server is told to drop the link by its id.
        if (overtaken(step.token) || acct.uvk.guard.isWiped) return@withLock eStop(flow, DeviceLinkStop.CANCELLED)
        val pin = trust.pinFor(acct.origin) ?: return@withLock eStop(flow, DeviceLinkStop.INSTANCE_BLOCKED)
        val personalVaultId = acct.personalVaultId ?: return@withLock eStop(flow, DeviceLinkStop.NO_SESSION)
        val bundle = fill(acct, personalVaultId, Checkpoint(pin.seq, pin.hash), pin.instanceId)
            ?: return@withLock eStop(flow, DeviceLinkStop.BAD_BUNDLE)
        // A claimed key the box seal cannot use (a low-order point such as 32 zero bytes) throws; it ends the link as a bad
        // claim, and nothing is sent.
        val sealedOuter = try {
            DeviceLink.sealOuter(crypto, claim.nPub, DeviceLinkOuter(acct.origin, acct.userId, acct.emailNorm))
        } catch (e: CryptoException) {
            return@withLock eStop(flow, DeviceLinkStop.BAD_CLAIM)
        }
        // The bundle's key from the UVK under the account's guard: a lock that came since the check above refuses it here.
        val sealedBundle = try {
            acct.uvk.use { DeviceLink.sealBundle(crypto, it, flow.linkId, bundle) }
        } catch (e: KeysGoneException) {
            return@withLock eStop(flow, DeviceLinkStop.CANCELLED)
        }
        val body = DeviceLinkApproveRequest(
            Bytes.toB64(sealedOuter),
            Bytes.toB64(sealedBundle),
            DeviceLink.approveMac(crypto, flow.keys, sealedOuter),
        )
        val r = clientFor(acct.origin).call(WireRoute.DEVICE_LINK_APPROVE, pathParams = mapOf("linkId" to flow.linkId),
            bodyJson = WireJson.json.encodeToString(DeviceLinkApproveRequest.serializer(), body), decode = { })
        existing.remove(flow.id)
        flow.keys.wipe()
        // A cancel, a lock or a sign-out that came while the approval was on its way: the server holds the approval, so it
        // is told to drop the link by its id; the new device then finds nothing to pick up.
        if (overtaken(step.token) || acct.uvk.guard.isWiped) {
            clientFor(acct.origin).call(WireRoute.DEVICE_LINK_CANCEL, pathParams = mapOf("linkId" to flow.linkId), decode = { })
            return@withLock ExistingStep.Stopped(DeviceLinkStop.CANCELLED)
        }
        if (r !is WireResult.Ok) return@withLock ExistingStep.Stopped(stopOf(r), waitOf(r))
        ExistingStep.Approved(claim.deviceName)
    }

    /**
     * The bundle (§8.3): this device's CURRENT contacts, most recently verified first, then the account's vault records,
     * the newest heads first, as many as the shared verifiers' [DeviceLink.fits] lets in (SR-2). The card checkpoint is this
     * device's pin; the account-state checkpoint the last blob it opened (none: seq 0).
     */
    internal fun fill(acct: LinkAccount, personalVaultId: String, card: Checkpoint, instanceId: String): DeviceLinkBundle? {
        val doc = acct.store.local()
        val currency = ContactCurrency(state, crypto, acct.origin, acct.userId)
        val contacts = doc.contacts.values
            .filter { currency.currency(it.userId, it.identityPub) != null }
            .sortedWith(compareByDescending<io.silencelen.andvari.core.client.state.ContactRecord> { it.verifiedAt }.thenBy { it.userId })
            .mapNotNull { c -> currency.keyHash(c.identityPub)?.let { BundleContact(c.userId, it, c.verifiedAt) } }
        // Each vault's checkpoint is the higher of the account's vault record and this device's own verified head of the
        // same log (same genesis): vault records are written in batches, so the record alone lags what this device verified.
        val vaults = doc.vaults.values.map { r ->
            val own = StoredVaultLogs.storedHead(state, acct.userId, r.vaultId, r.genesisHash)
            if (own != null && own.seq > r.seq) BundleVault(r.vaultId, own.seq, own.hash) else BundleVault(r.vaultId, r.seq, r.hash)
        }.sortedWith(compareByDescending<BundleVault> { it.seq }.thenBy { it.vaultId })
        val accountState = acct.store.checkpoint()?.let { Checkpoint(it.first, it.second) }
            ?: Checkpoint(0, Bytes.toHexLower(crypto.sha256(ByteArray(0))))
        fun bundle(c: Int, v: Int) = DeviceLinkBundle(
            acct.origin, instanceId, card, acct.userId, acct.emailNorm, acct.identityPubB64, personalVaultId,
            contacts.take(c), vaults.take(v), accountState, clock(),
        )
        if (!DeviceLink.fits(bundle(0, 0))) return null
        // The largest prefix that fits, by halving: contacts first, then vaults.
        fun largest(max: Int, fits: (Int) -> Boolean): Int {
            var lo = 0
            var hi = max
            while (lo < hi) {
                val mid = (lo + hi + 1) / 2
                if (fits(mid)) lo = mid else hi = mid - 1
            }
            return lo
        }
        val c = largest(minOf(contacts.size, DeviceLink.MAX_BUNDLE_ENTRIES)) { DeviceLink.fits(bundle(it, 0)) }
        val v = largest(minOf(vaults.size, DeviceLink.MAX_BUNDLE_ENTRIES)) { DeviceLink.fits(bundle(c, it)) }
        return bundle(c, v)
    }

    // ---------------------------------------------------------------------------------------------
    // N, the new device (§8.2 steps 0, 2, 4, 7, 8)
    // ---------------------------------------------------------------------------------------------

    private fun gate(flow: NFlow): GateDecision = PasswordGate.decide(
        GateInput(GatePurpose.DEVICE_LINK, flow.entry, GatePayload.D, flow.origin, account = null, pins = trust.gatePins()),
    )

    private fun nStop(
        flow: NFlow, reason: DeviceLinkStop, pinVerdict: String? = null, retryAfterSeconds: Long? = null, addressKnownHere: String? = null,
        anotherAccountServed: String? = null, keeperReason: String? = null,
    ): NewStep {
        incoming.remove(flow.id)
        flow.wipe()
        return NewStep.Stopped(reason, pinVerdict, retryAfterSeconds, addressKnownHere, anotherAccountServed, keeperReason)
    }

    /**
     * The stop for a session keeper's refusal [reason], with the keeper's own code where this flow does not know it, and
     * [anotherAccountServed] only where [addressKnownHere] is set.
     */
    private fun keeperStopped(reason: String, addressKnownHere: String?, anotherAccountServed: String?): NewStep.Stopped {
        val stop = keeperStopOf(reason)
        return NewStep.Stopped(
            stop, addressKnownHere = addressKnownHere, anotherAccountServed = anotherAccountServed.takeIf { addressKnownHere != null },
            keeperReason = reason.takeIf { stop == DeviceLinkStop.KEEPER_REFUSED },
        )
    }

    /**
     * [NewStep.Stopped.addressKnownHere] for a keeper's refusal [reason] of the account [userId] (served with [identityPub]
     * where the stop knows it) under [email] at [origin]: the address, when the refusal is the keeper's identity refusal and
     * the keeper says this device ties the address there to ANOTHER account ([SessionSink.refusalIsAnotherAccount]); else
     * null. Never for the same account under another key.
     */
    private fun knownAsAnother(origin: String, reason: String, email: String?, userId: String?, identityPub: ByteArray? = null): String? {
        if (reason != io.silencelen.andvari.core.client.session.Establishing.IDENTITY_MISMATCH || email == null || userId == null) return null
        val norm = TrustGrammar.emailNorm(email) ?: return null
        return email.takeIf { sink.refusalIsAnotherAccount(origin, norm, userId, identityPub) }
    }

    /** The stop for a session keeper's refusal [reason] (its own, as [SessionSink.take] and [SessionSink.wouldRefuse] name it). */
    private fun keeperStopOf(reason: String): DeviceLinkStop = when (reason) {
        AccountOpen.SELF_IDENTITY_MISMATCH -> DeviceLinkStop.IDENTITY_MISMATCH
        DeviceLinkStop.SERVER_KEYS_NOT_KNOWN_HERE.code -> DeviceLinkStop.SERVER_KEYS_NOT_KNOWN_HERE
        DeviceLinkStop.OPERATOR_ACCOUNT_HELD.code -> DeviceLinkStop.OPERATOR_ACCOUNT_HELD
        DeviceLinkStop.KEPT_COPY_DAMAGED.code -> DeviceLinkStop.KEPT_COPY_DAMAGED
        // Account-key texts not in their canonical form ([io.silencelen.andvari.core.client.session.Establishing.SERVED_KEY_FORM])
        // fall to the last branch: the keeper's own reason, handed through as it is.
        io.silencelen.andvari.core.client.session.Establishing.ANOTHER_SESSION_KEPT -> DeviceLinkStop.ANOTHER_SESSION_KEPT
        // A reason of the keeper's that this flow does not know: handed through unchanged ([NewStep.Stopped.keeperReason]),
        // never said as another account kept.
        else -> DeviceLinkStop.KEEPER_REFUSED
    }

    /**
     * The session keeper's answer for [flow] before the pickup is sent ([SessionSink.wouldRefuse]); a no stops the flow
     * with nothing more sent: the link is not picked up, so the server opens no session and changes nothing.
     */
    private fun keeperStop(flow: NFlow, email: String?, userId: String?): NewStep? =
        sink.wouldRefuse(flow.origin, email?.let { TrustGrammar.emailNorm(it) }, userId)?.let {
            val stopped = keeperStopped(it, knownAsAnother(flow.origin, it, email, userId), userId)
            incoming.remove(flow.id)
            flow.wipe()
            // Marked as the keeper's stop before the pickup ([NewStep.Stopped.keeperBeforePickup]): the layer above tells
            // it apart from the pickup's own identity checks by the stop alone.
            NewStep.Stopped(stopped.reason, stopped.addressKnownHere, stopped.anotherAccountServed, stopped.keeperReason, keeperBeforePickup = true)
        }

    override suspend fun start(text: String, entry: GateEntry): NewStep = lock.withLock {
        // Step 0: only the device-link screen (or the CLI) starts anything.
        if (entry != GateEntry.LINK_DEVICE_SCREEN && entry != GateEntry.CLI_LINK_DEVICE) return@withLock NewStep.Stopped(DeviceLinkStop.WRONG_ENTRY)
        val link = DeviceLinkUrl.parse(text) ?: return@withLock NewStep.Stopped(DeviceLinkStop.BAD_LINK)
        // An `/l` URL whose fragment reads as a device link's (three parts) is an invite that does not parse: `bad_link`.
        if (TrustGrammar.stripAsciiSpace(text).contains("/l#")) {
            link.wipe()
            return@withLock NewStep.Stopped(DeviceLinkStop.BAD_LINK)
        }
        val keys = DeviceLink.deriveKeys(crypto, link.secret)
        val flow = NFlow("n" + (++counter), entry, link, keys, keys.linkId, Hold(clock()))
        flow.held = sink.underWay(flow.origin, io.silencelen.andvari.core.client.onboard.SessionSink.ANY_ADDRESS)
        incoming[flow.id] = flow
        // The session keeper, before anything is claimed: a device that keeps an account at another server (or one held as
        // its operator there) could not keep the session the pickup opens, and a claim spends the link.
        keeperStop(flow, null, null)?.let { return@withLock it }
        when (gate(flow)) {
            GateDecision.REFUSE_ENTRY -> nStop(flow, DeviceLinkStop.INSTANCE_BLOCKED)
            GateDecision.TRUST_GATE -> afterPin(flow, trust.beginTrustGate(flow.origin, TrustGateWording.DEVICE_LINK))
            GateDecision.PROCEED -> when (val s = trust.refresh(flow.origin)) {
                // A password pin exists: the served chain must still extend it, or the move or kind change comes first.
                is CardStatus.Ok, is CardStatus.Withheld -> claim(flow)
                is CardStatus.Moved, is CardStatus.KindChanged -> {
                    incoming.remove(flow.id)
                    flow.wipe()
                    NewStep.PinChanged(FirstPin.PinChanged(s))
                }
                is CardStatus.Fork -> nStop(flow, DeviceLinkStop.INSTANCE_BLOCKED)
                CardStatus.Unreachable -> nStop(flow, DeviceLinkStop.UNREACHABLE)
                is CardStatus.Refused -> nStop(flow, DeviceLinkStop.PIN_REFUSED, s.verdict)
                is CardStatus.PinConflict -> nStop(flow, DeviceLinkStop.PIN_REFUSED, s.verdict)
            }
        }
    }

    private suspend fun afterPin(flow: NFlow, pin: FirstPin): NewStep = when (pin) {
        is FirstPin.Pinned -> {
            if (pin.handle.madeNow) flow.pinMade = pin.handle
            if (gate(flow) != GateDecision.PROCEED) nStop(flow, DeviceLinkStop.PIN_REFUSED, "trust_gate") else claim(flow)
        }
        is FirstPin.NeedsTrustGate -> NewStep.TrustGate(pin, DeviceLinkToken(flow.id))
        is FirstPin.OriginMismatch -> {
            incoming.remove(flow.id)
            flow.wipe()
            NewStep.OriginMismatch(pin)
        }
        is FirstPin.PinChanged -> {
            incoming.remove(flow.id)
            flow.wipe()
            NewStep.PinChanged(pin)
        }
        is FirstPin.Blocked -> nStop(flow, DeviceLinkStop.INSTANCE_BLOCKED)
        is FirstPin.Refused -> nStop(flow, DeviceLinkStop.PIN_REFUSED, pin.reason)
        is FirstPin.PinConflict -> nStop(flow, DeviceLinkStop.PIN_REFUSED, pin.verdict)
        is FirstPin.KitAnchorMismatch -> nStop(flow, DeviceLinkStop.STALE)
        FirstPin.Unreachable -> nStop(flow, DeviceLinkStop.UNREACHABLE)
    }

    override suspend fun afterTrustGate(step: NewStep.TrustGate, confirmed: Boolean): NewStep = lock.withLock {
        val flow = incoming[step.token.id] ?: return@withLock NewStep.Stopped(DeviceLinkStop.STALE)
        if (!confirmed) return@withLock nStop(flow, DeviceLinkStop.TRUST_GATE_DECLINED)
        afterPin(flow, trust.confirmTrustGate(step.gate.confirm))
    }

    /** Step 2: the claim, sent only to the origin pinned in step 0. */
    private suspend fun claim(flow: NFlow): NewStep {
        val name = TrustGrammar.encodeName(deviceName) ?: return nStop(flow, DeviceLinkStop.BAD_NAME)
        if (!TrustGrammar.isPlatform(platform)) return nStop(flow, DeviceLinkStop.BAD_NAME)
        val pair = ephemeral()
        val nonceN = random(CodeCommit.NONCE_BYTES)
        flow.pair = pair
        flow.nonceN = nonceN
        flow.nPub = Bytes.toB64(pair.publicKey)
        val commitN = CodeCommit.commit(crypto, nonceN)
        val mac = DeviceLink.claimMac(crypto, flow.keys, flow.nPub, name, platform, commitN)
        val body = WireJson.json.encodeToString(DeviceLinkClaim.serializer(), DeviceLinkClaim(flow.nPub, name, platform, commitN, mac))
        val r = clientFor(flow.origin).call(WireRoute.DEVICE_LINK_CLAIM, pathParams = mapOf("linkId" to flow.linkId), bodyJson = body, decode = { })
        if (r !is WireResult.Ok) return nStop(flow, stopOf(r), retryAfterSeconds = waitOf(r))
        return NewStep.Claimed(flow.origin, DeviceLinkToken(flow.id))
    }

    private fun nToken(step: NewStep): DeviceLinkToken? = when (step) {
        is NewStep.Claimed -> step.token
        is NewStep.ShowCode -> step.token
        is NewStep.TrustGate -> step.token
        is NewStep.PasswordNeeded -> step.token
        is NewStep.TotpNeeded -> step.token
        is NewStep.WrongPassword -> step.token
        else -> null
    }

    override suspend fun waitingSeconds(step: NewStep): Long? = lock.withLock {
        val flow = nToken(step)?.let { incoming[it.id] } ?: return@withLock null
        ((flow.hold.until - clock() + 999) / 1000).takeIf { it > 0 }
    }

    override suspend fun advance(step: NewStep): NewStep = lock.withLock {
        if (step !is NewStep.Claimed && step !is NewStep.ShowCode) return@withLock step
        val flow = nToken(step)?.let { incoming[it.id] } ?: return@withLock NewStep.Stopped(DeviceLinkStop.STALE)
        // The server asked this device to wait: the link is waiting ([waitingSeconds] says for how long), and nothing is
        // asked before the wait is over.
        if (clock() < flow.hold.until) return@withLock step
        val proof = DeviceLink.pickupProof(crypto, flow.keys, flow.nPub)
        val r = clientFor(flow.origin).call(WireRoute.DEVICE_LINK_POLL, pathParams = mapOf("linkId" to flow.linkId),
            bodyJson = WireJson.json.encodeToString(DeviceLinkPollRequest.serializer(), DeviceLinkPollRequest(proof)),
            decode = { WireJson.json.decodeFromString(DeviceLinkPollResponse.serializer(), it) })
        tooMany(r)?.let { return@withLock if (held(flow.hold, it)) step else nStop(flow, DeviceLinkStop.EXPIRED) }
        val poll = when (r) {
            is WireResult.Ok -> r.value
            is WireResult.Refused -> return@withLock nStop(flow, stopOf(r))
            is WireResult.NoAnswer -> return@withLock step
        }
        val served = poll.nonceE ?: return@withLock step
        // Step 4 (T2-R-b): the first nonceE held is the only one; it must be a b64_32.
        val held = flow.nonceE
        if (held == null) {
            if (Bytes.fromB64Exact(served, 32) == null) return@withLock nStop(flow, DeviceLinkStop.NONCE_CHANGED)
            flow.nonceE = served
        } else if (held != served) {
            return@withLock nStop(flow, DeviceLinkStop.NONCE_CHANGED)
        }
        val nonceE = flow.nonceE!!
        if (!flow.revealed) {
            val body = WireJson.json.encodeToString(DeviceLinkRevealRequest.serializer(), DeviceLinkRevealRequest(Bytes.toB64(flow.nonceN!!), proof))
            val rr = clientFor(flow.origin).call(WireRoute.DEVICE_LINK_REVEAL, pathParams = mapOf("linkId" to flow.linkId), bodyJson = body, decode = { })
            // The reveal draws on the same budget as the poll: a refusal for too many waits too, and the next ask reveals.
            tooMany(rr)?.let { return@withLock if (held(flow.hold, it)) step else nStop(flow, DeviceLinkStop.EXPIRED) }
            when (rr) {
                is WireResult.Ok -> {}
                is WireResult.Refused -> return@withLock nStop(flow, stopOf(rr))
                is WireResult.NoAnswer -> return@withLock step
            }
            flow.revealed = true
            val e = Bytes.fromB64Exact(nonceE, 32)!!
            flow.code = ComparisonCode.deviceLink(crypto, flow.linkId, flow.pair!!.publicKey, flow.nonceN!!, e)
            e.fill(0)
        }
        val outer = poll.outer
        val approveMac = poll.approveMac
        if (outer == null || approveMac == null) return@withLock NewStep.ShowCode(flow.code!!, DeviceLinkToken(flow.id))
        // Step 7, before any password prompt: approveMac first, then the seal, the strict decode, the origin.
        val sealed = Bytes.fromB64Canonical(outer) ?: return@withLock nStop(flow, DeviceLinkStop.OUTER_UNOPENABLE)
        val pair = flow.pair!!
        val opened = when (val o = DeviceLink.openOuter(crypto, flow.keys, pair.publicKey, pair.privateKey, sealed, approveMac, flow.origin)) {
            is Checked.Ok -> o.value
            is Checked.Refused -> return@withLock nStop(flow, verdictStop(o.verdict))
        }
        flow.outer = opened
        // The account is named now: asked before the password is, so that a device keeping another account says so before
        // the person types anything.
        keeperStop(flow, opened.email, opened.userId)?.let { return@withLock it }
        NewStep.PasswordNeeded(opened.email, flow.origin, trust.pinFor(flow.origin)?.name ?: "", DeviceLinkToken(flow.id))
    }

    override suspend fun pickup(step: NewStep, password: CharArray, totp: String?): NewStep {
        // A flow under way for the link's address until the pickup is answered ([SessionSink.underWay]).
        val outer = nToken(step)?.let { t -> lock.withLock { incoming[t.id]?.outer } }
        val done = outer?.let { o -> TrustGrammar.emailNorm(o.email)?.let { sink.underWay(o.origin, it) } }
        try {
            return pickupHeld(step, password, totp)
        } finally {
            done?.invoke()
        }
    }

    private suspend fun pickupHeld(step: NewStep, password: CharArray, totp: String?): NewStep = lock.withLock {
        try {
            if (step !is NewStep.PasswordNeeded && step !is NewStep.TotpNeeded && step !is NewStep.WrongPassword) return@withLock step
            val flow = nToken(step)?.let { incoming[it.id] } ?: return@withLock NewStep.Stopped(DeviceLinkStop.STALE)
            val outer = flow.outer ?: return@withLock NewStep.Stopped(DeviceLinkStop.STALE)
            // The password rule again: prelogin and authKey go only to a password pin for this origin.
            if (gate(flow) != GateDecision.PROCEED || trust.pinFor(flow.origin) == null) return@withLock nStop(flow, DeviceLinkStop.INSTANCE_BLOCKED)
            val client = clientFor(flow.origin)
            val keys = flow.pending ?: run {
                val pre = client.call(WireRoute.PRELOGIN, bodyJson = WireJson.json.encodeToString(PreloginRequest.serializer(), PreloginRequest(outer.email)),
                    decode = { WireJson.json.decodeFromString(PreloginResponse.serializer(), it) })
                // A first exchange with no usable answer ends the pickup with what is so, never with the same step handed
                // back (a caller that asks for the password on that step would ask again without end). A prelogin carries
                // only the salt and the cost: an answer that cannot be read is the server's fault, as a cost outside the
                // fence is (a host's fence at the wire refuses such a cost as an unreadable answer); no answer is not reachable.
                val p = (pre as? WireResult.Ok)?.value ?: return@withLock when (pre) {
                    is WireResult.Refused -> nStop(flow, stopOf(pre), retryAfterSeconds = waitOf(pre))
                    is WireResult.NoAnswer -> nStop(flow, if (pre.kind == io.silencelen.andvari.core.client.net.NoAnswerKind.UNDECODABLE) DeviceLinkStop.KDF_REFUSED else DeviceLinkStop.UNREACHABLE)
                    is WireResult.Ok -> nStop(flow, DeviceLinkStop.UNREACHABLE)
                }
                val salt = Bytes.fromB64Canonical(p.kdfSalt) ?: return@withLock nStop(flow, DeviceLinkStop.UNREACHABLE)
                // Spec 01 §7, a link on a device that keeps this account: what it keeps is compared with the key the pickup
                // opens. A kept wrap at another salt or cost is derived at now, while the typed password is here, and only when
                // the pickup itself derives (a cost the fence passes).
                flow.dropKept()
                flow.kept = sink.keptForSignIn(flow.origin)?.takeIf { it.userId == outer.userId }?.let {
                    if (salt.size == io.silencelen.andvari.core.crypto.KdfParams.SALT_BYTES && io.silencelen.andvari.core.client.KdfUpgrade.withinFence(p.kdfParams)) {
                        io.silencelen.andvari.core.client.onboard.KeptAccountCheck.prepare(crypto, it, password, salt, p.kdfParams)
                    } else {
                        io.silencelen.andvari.core.client.onboard.KeptWrapKeys(it, emptyList())
                    }
                }
                PasswordKeys.derive(crypto, password, salt, p.kdfParams, served = true) ?: return@withLock nStop(flow, DeviceLinkStop.KDF_REFUSED)
            }
            flow.pending = null
            var keep = false
            try {
                // Asked again with nothing more to wait for before the pickup is sent (another account may have signed in
                // since the password was asked for).
                keeperStop(flow, outer.email, outer.userId)?.let { return@withLock it }
                val secret = devices.secret(flow.origin, outer.email)
                val body = DeviceLinkPickupRequest(DeviceLink.pickupProof(crypto, flow.keys, flow.nPub), keys.authKeyB64, totp, PickupDevice(secret))
                val r = client.call(WireRoute.DEVICE_LINK_PICKUP, pathParams = mapOf("linkId" to flow.linkId),
                    bodyJson = WireJson.json.encodeToString(DeviceLinkPickupRequest.serializer(), body),
                    decode = { WireJson.json.decodeFromString(DeviceLinkPickupResponse.serializer(), it) })
                val resp = when (r) {
                    is WireResult.Ok -> r.value
                    is WireResult.Refused -> return@withLock when (r.code) {
                        "totp_required" -> {
                            keep = true
                            flow.pending = keys
                            flow.codeAsked = true
                            NewStep.TotpNeeded(DeviceLinkToken(flow.id))
                        }
                        "invalid_credentials" -> when {
                            // After a code was asked for in this link, the server answers a wrong code and a wrong password
                            // alike, also to a later pickup sent without a code: the refusal is said as what is known, never
                            // as a wrong password. The server keeps the link approved within its time, so the link stays and
                            // asks for the password and the code again; past the link's own time it ends here.
                            flow.codeAsked ->
                                if (clock() >= flow.hold.since + LIFETIME_MS) nStop(flow, DeviceLinkStop.REFUSED_AFTER_CODE)
                                else NewStep.WrongPassword(DeviceLinkToken(flow.id), afterCode = true)
                            // No code asked for in this link, and the typed password opens this device's kept wrap of the
                            // account: the server refused a proof of a password this device knows (a former one, most
                            // often), which is no wrong password. The link stays within its time, as after a refused
                            // code, so the person can type the account's current password; past its time it ends here.
                            totp == null && flow.kept?.let { io.silencelen.andvari.core.client.onboard.KeptAccountCheck.typedPasswordOpensAKeptWrap(crypto, outer.userId, it, keys) } == true ->
                                if (clock() >= flow.hold.since + LIFETIME_MS) nStop(flow, DeviceLinkStop.PROOF_REFUSED)
                                else NewStep.WrongPassword(DeviceLinkToken(flow.id), proofRefused = true)
                            else -> NewStep.WrongPassword(DeviceLinkToken(flow.id))
                        }
                        else -> nStop(flow, stopOf(r), retryAfterSeconds = waitOf(r))
                    }
                    is WireResult.NoAnswer -> return@withLock nStop(flow, DeviceLinkStop.UNREACHABLE)
                }
                finish(flow, outer, keys, secret, resp)
            } finally {
                if (!keep) {
                    keys.wipe()
                    flow.dropKept()
                }
            }
        } finally {
            password.fill('\u0000')
        }
    }

    /** Step 8: the identity checks (the genesis first), the bundle, then the session and the imports. */
    private suspend fun finish(flow: NFlow, outer: DeviceLinkOuter, keys: PasswordKeys, deviceSecret: String, resp: DeviceLinkPickupResponse): NewStep {
        val s = resp.session
        // The wrap key a kept wrap opened under to the pickup's key, for the session keeper's own check ([finish]'s match).
        // Wiped on every way out (the finally below), a cancellation while the chain is read included.
        var proof: ByteArray? = null
        // The account opened below, until a session holds it: wiped when this step is left by a throw (a cancellation).
        var opened: OpenedAccount? = null
        suspend fun refuse(reason: DeviceLinkStop, account: OpenedAccount? = null): NewStep {
            proof?.fill(0)
            account?.wipe()
            val end = endOne
            if (end != null) end(flow.origin, s.refreshToken) else discard(flow.origin, s.accessToken)
            if (reason == DeviceLinkStop.PIN_MISMATCH) flow.pinMade?.let(trust::dropPinMade)
            return nStop(flow, reason)
        }
        try {
            // The answer is a login's SessionResponse: the ids in their grammar, for outer's account, and a role the engine knows.
            if (s.userId != outer.userId || io.silencelen.andvari.core.client.UserIds.isNil(s.userId) || !TrustGrammar.isUuid(s.deviceId) || (s.role != "member" && s.role != "operator")) {
                return refuse(DeviceLinkStop.IDENTITY_MISMATCH)
            }
            // The keys this session keeps must carry the salt and parameters the password was just derived under (the
            // prelogin's): another account's, or an earlier password's, would make the next unlock here "wrong password".
            if (!KnownKdf(keys.salt, keys.params).matches(s.accountKeys)) return refuse(DeviceLinkStop.IDENTITY_MISMATCH)
            // Design §2.2, strict decoding: account-key texts in another form than the canonical one are the server's fault,
            // refused as any other answer that is not the session it must be, before anything is opened or kept.
            if (!io.silencelen.andvari.core.client.onboard.ServedKeyForm.canonical(s.accountKeys)) return refuse(DeviceLinkStop.IDENTITY_MISMATCH)
            val pin = trust.pinFor(flow.origin) ?: return refuse(DeviceLinkStop.PIN_MISMATCH)
            val uvk = try {
                Envelope.openB64(crypto, keys.wrapKey, s.accountKeys.wrappedUvk, Ad.uvk(s.userId))
            } catch (e: CryptoException) {
                return refuse(DeviceLinkStop.IDENTITY_MISMATCH)
            } catch (e: IllegalArgumentException) {
                return refuse(DeviceLinkStop.IDENTITY_MISMATCH)
            }
            // Spec 01 §7, a link on a device that keeps this account: before anything kept is replaced, the key the server's wrap
            // opened must be the account's key as this device knows it (a kept wrap the typed password opens holds it, else the
            // copy's sealed identity seed opens under it). Another key: the session is ended there, nothing kept is touched.
            val keptHere = flow.kept?.takeIf { it.kept.userId == s.userId }
            val match = keptHere?.let {
                io.silencelen.andvari.core.client.onboard.KeptAccountCheck.match(crypto, s.userId, uvk, it, keys, s.accountKeys)
            }
            if (match == io.silencelen.andvari.core.client.onboard.KeptMatch.DIFFERENT) {
                uvk.fill(0)
                return refuse(DeviceLinkStop.SERVER_KEYS_NOT_KNOWN_HERE)
            }
            if (match == io.silencelen.andvari.core.client.onboard.KeptMatch.DAMAGED) {
                uvk.fill(0)
                return refuse(DeviceLinkStop.KEPT_COPY_DAMAGED)
            }
            if (match == io.silencelen.andvari.core.client.onboard.KeptMatch.OPENED && keptHere != null) {
                proof = io.silencelen.andvari.core.client.onboard.KeptAccountCheck.provingKey(crypto, s.userId, uvk, keptHere, keys)
                proof?.let { held -> provingKeyHeld { held.all { it == 0.toByte() } } }
            }
            // The unlock verifies the genesis, as every unlock does, before the bundle is touched (§2.4), and holds the
            // account to this device's own record of its identity key (design §2.4) where it has one, as a sign-in does.
            val account = when (val o = AccountOpen.open(crypto, s.userId, uvk, s.accountKeys, pin.instanceId, sink.knownIdentity(s.userId))) {
                is AccountOpenResult.Opened -> o.account
                is AccountOpenResult.IdentityFault -> return refuse(DeviceLinkStop.IDENTITY_MISMATCH)
            }
            opened = account
            val inner = Bytes.fromB64Canonical(resp.inner) ?: return refuse(DeviceLinkStop.BUNDLE_UNOPENABLE, account)
            val bundle = when (val b = account.uvk.use { DeviceLink.openBundle(crypto, it, flow.linkId, inner) }) {
                is Checked.Ok -> b.value
                is Checked.Refused -> return refuse(verdictStop(b.verdict), account)
            }
            val hashes = verifiedChain(flow.origin, pin.card0Hash) ?: return refuse(DeviceLinkStop.PIN_MISMATCH, account)
            DeviceLink.checkBundle(bundle, s.userId, account.identity.publicKey, account.genesis.fields.personalVaultId, pin.origin, pin.instanceId) { hashes.getOrNull(it.toInt()) }
                ?.let { return refuse(verdictStop(it), account) }
            incoming.remove(flow.id)
            flow.wipe()
            // Role and two-step flags come from the answer, as at a login (the server enforces; the role picks the views).
            val session = EstablishedSession(
                flow.origin, outer.email, s.userId, s.deviceId, role = s.role, totpEnrolled = s.totpEnrolled, mustEnrollTotp = s.mustEnrollTotp,
                recoveryConfirmed = s.accountKeys.recoveryConfirmed, how = SessionHow.LINKED, accessToken = s.accessToken,
                refreshToken = s.refreshToken, accountKeys = s.accountKeys, account = account,
            )
            // From here the session holds the account, and the keeper wipes it on a refusal.
            opened = null
            // The session keeper refused it (and ended it there itself): nothing of the bundle is used, and the device's record of
            // its own id for the address stays as it was.
            session.giveKeptWrapKey(proof)
            proof = null
            val notTaken = try {
                sink.take(session)
            } finally {
                session.takeKeptWrapKey()?.fill(0)
            }
            notTaken?.let { reason ->
                val known = knownAsAnother(flow.origin, reason, outer.email, s.userId, Bytes.fromB64Exact(s.accountKeys.identityPub, 32))
                return keeperStopped(reason, known, s.userId)
            }
            devices.remember(flow.origin, outer.email, deviceSecret, s.deviceId)
            import(session, bundle)
            return NewStep.Linked(s.userId, s.deviceId, copyUnderOtherPassword = match == io.silencelen.andvari.core.client.onboard.KeptMatch.SEALED)
        } catch (t: Throwable) {
            // Left by a throw (a cancellation while the chain is read, say): the opened account goes with this step.
            opened?.wipe()
            throw t
        } finally {
            // The key that proves the typed password is wiped on every way out, that one included.
            proof?.fill(0)
        }
    }

    /**
     * Tests only: told when [finish] holds a proving key, and handed a question that answers whether that key is wiped
     * (all zero) now, to show it is wiped on every way out. No key, no byte of one, reaches the callback.
     */
    internal var provingKeyHeld: (wiped: () -> Boolean) -> Unit = {}

    /** The card hashes by seq of the chain [origin] serves, verified from card 0, when its card 0 is [card0Hash]; null otherwise. */
    private suspend fun verifiedChain(origin: String, card0Hash: String): List<String>? {
        val r = clientFor(origin).call(WireRoute.INSTANCE, decode = { WireJson.json.decodeFromString(InstanceResponse.serializer(), it) })
        val frames = (r as? WireResult.Ok)?.value?.cards?.map { Bytes.fromB64Canonical(it) ?: return null } ?: return null
        val chain = InstanceCard.verifyChain(crypto, frames)
        if (chain.verdict != null) return null
        val hashes = chain.chain.cards.map { it.hash }
        return hashes.takeIf { it.firstOrNull() == card0Hash }
    }

    /**
     * §8.3 imports: the bundle confers CURRENCY on contacts the merged account state already holds under the same key
     * hash, raises the account-state high-water mark, and keeps the vault checkpoints for the vault logs.
     */
    private suspend fun import(session: EstablishedSession, bundle: DeviceLinkBundle) {
        val store = StoredAccountState(session.userId, session.account.uvk, clientFor(session.origin), crypto, state)
        store.raiseHighWater(bundle.accountState.seq)
        val doc = (store.read() as? AccountStateRead.Ok)?.document ?: store.local()
        val currency = ContactCurrency(state, crypto, session.origin, session.userId)
        for (c in bundle.contacts) {
            val held = doc.contacts[c.userId]?.identityPub?.let { Bytes.fromB64Exact(it, 32) }
            if (DeviceLink.confirmsContact(crypto, c, held)) currency.markHash(c.userId, c.keyHash, Currency.BUNDLE)
        }
        BundleCheckpoints(state).put(session.origin, session.userId, bundle.vaults)
    }

    /** Flows a cancel was asked for, marked at once, before the cancel waits for [lock]. */
    private val cancelled = HashSet<String>()
    private val cancelledLock = SynchronizedObject()

    /** Whether a cancel (the person's, or a lock's or a sign-out's) was asked for [token]'s flow while it ran. */
    private fun overtaken(token: DeviceLinkToken): Boolean = synchronized(cancelledLock) { token.id in cancelled }

    override suspend fun cancel(token: DeviceLinkToken) {
        // Marked before the wait: an approval that holds [lock] now sees it after its own wait, approves nothing (or, already
        // sent, tells the server to drop the link), so the cancel is never "done" over an approval the server keeps.
        synchronized(cancelledLock) { cancelled += token.id }
        lock.withLock {
            existing[token.id]?.let { eStop(it, DeviceLinkStop.CANCELLED) }
            incoming[token.id]?.let { nStop(it, DeviceLinkStop.CANCELLED) }
        }
    }

    companion object {
        /** E asks for the longest the server allows (it stores at most 5 minutes, spec 03 §16.2). */
        const val LIFETIME_MS: Long = 5 * 60 * 1000L

        /** The wait taken when a refusal for too many requests names none, in seconds. */
        private const val DEFAULT_WAIT_S = 5L
    }
}

/**
 * The vault checkpoints a device-link bundle carried (design §8.3): verified heads the vault logs on this device hold
 * as lower bounds (a served log that contradicts one is a fork; one that ends below it is withholding).
 */
class BundleCheckpoints(private val state: DeviceState) {
    @Serializable
    private data class Stored(val vaultId: String, val seq: Long, val hash: String)

    private fun key(origin: String, userId: String) = "ovh.bundlevaults|$origin|$userId"

    internal fun put(origin: String, userId: String, vaults: List<BundleVault>) = state.set(
        key(origin, userId),
        if (vaults.isEmpty()) null else WireJson.json.encodeToString(ListSerializer(Stored.serializer()), vaults.map { Stored(it.vaultId, it.seq, it.hash) }),
    )

    /**
     * The checkpoint for [vaultId], or null when the bundle named none. A stored list that does not decode is NOT "none"
     * (design §4.4 "A trust record that cannot be read is not an empty one"): it throws [IllegalStateException], so the
     * vault-log engine reads the vault as unreadable and closes it rather than dropping a lower bound.
     */
    fun get(origin: String, userId: String, vaultId: String): Checkpoint? {
        val text = state.get(key(origin, userId)) ?: return null
        val all = runCatching { WireJson.strict.decodeFromString(ListSerializer(Stored.serializer()), text) }.getOrNull()
            ?: throw IllegalStateException("unreadable bundle checkpoints")
        return all.firstOrNull { it.vaultId == vaultId }?.let { Checkpoint(it.seq, it.hash) }
    }
}
