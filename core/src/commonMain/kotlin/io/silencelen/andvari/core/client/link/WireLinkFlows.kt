package io.silencelen.andvari.core.client.link

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogEngine
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.KeptSetup
import io.silencelen.andvari.core.client.onboard.SetupOffers
import io.silencelen.andvari.core.client.onboard.LinkRegistration
import io.silencelen.andvari.core.client.onboard.LinkRegistrations
import io.silencelen.andvari.core.client.onboard.NewIdentity
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.InstanceTrust
import io.silencelen.andvari.core.client.pin.PinHandle
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.client.state.AccountDocument
import io.silencelen.andvari.core.client.state.AccountMerge
import io.silencelen.andvari.core.client.state.AccountStateStore
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.client.state.ContactRecord
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.InstanceResponse
import io.silencelen.andvari.core.model.wire.LinkAnswerRequest
import io.silencelen.andvari.core.model.wire.LinkCreateRequest
import io.silencelen.andvari.core.model.wire.LinkCreatedResponse
import io.silencelen.andvari.core.model.wire.LinkFetchResponse
import io.silencelen.andvari.core.model.wire.LinkRevealRequest
import io.silencelen.andvari.core.model.wire.LinkState
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.CodeCommit
import io.silencelen.andvari.core.trust.ComparisonCode
import io.silencelen.andvari.core.trust.LinkAnswer
import io.silencelen.andvari.core.trust.LinkAnswerFields
import io.silencelen.andvari.core.trust.LinkKeys
import io.silencelen.andvari.core.trust.LinkKind
import io.silencelen.andvari.core.trust.LinkOffer
import io.silencelen.andvari.core.trust.LinkOfferFields
import io.silencelen.andvari.core.trust.LinkSide
import io.silencelen.andvari.core.trust.LinkUrl
import io.silencelen.andvari.core.trust.LinkVerdict
import io.silencelen.andvari.core.trust.Links
import io.silencelen.andvari.core.trust.OpenedOffer
import io.silencelen.andvari.core.trust.ParsedLink
import io.silencelen.andvari.core.trust.ScanPayload
import io.silencelen.andvari.core.trust.ServedLink
import io.silencelen.andvari.core.trust.SignedFrame
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.builtins.ListSerializer
import io.silencelen.andvari.core.model.wire.LinkAnswer as ServedAnswer

/**
 * Signs the `add` entry and grant for one (vault, contact) pair attached to a link (design §6.10). Called only after
 * this device's own matched code, or for a per-vault release behind the "You haven't compared codes" warning
 * ([uncompared] true). The implementation requires that this account still owns the vault and it is not deleted.
 */
fun interface LinkShareRelease {
    suspend fun release(contactUserId: String, share: LinkShare, uncompared: Boolean): Boolean
}

/** [LinkShareRelease] through the vault-log engine's `add` (design §3.3, §6.10). */
class VaultLogShareRelease(private val logs: VaultLogEngine) : LinkShareRelease {
    override suspend fun release(contactUserId: String, share: LinkShare, uncompared: Boolean): Boolean =
        logs.append(share.vaultId, LogAction.Add(contactUserId, share.role, releaseUncompared = uncompared)) is AppendOutcome.Appended
}

/**
 * [LinkFlows] and [LinkRegistrations] over the wire (design §6, spec 03 §15).
 *
 * Trust:
 * - The recipient runs §2.4's "Opening a link" in order: the link's parse, the server's answer, the shared verifiers'
 *   [LinkOffer.open] (the envelope, the form, the signed helper, the field checks), then the pinning verdicts through
 *   [InstanceTrust] (the link-offer root for connect and register, the Trust Gate for enrol, an empty chain for setup).
 *   Nothing is sent before the person confirms; a served value is compared, never adopted.
 * - The creator keeps the link secret only in this device's state, sealed under the UVK, writes it before
 *   `POST /links`, and drops it at expiry, at revocation and once the answer is processed (T-R3).
 * - `compared` is set only by this device's own typed entry ([typeCode]); no server value or peer message can set it.
 *   Each side fixes its codes once, from the first value it accepted for the other side's nonce (T2-R-b). Each side
 *   shows only its OWN code ([LinkSide]) and [typeCode] accepts only the OTHER side's, which is never shown or kept.
 * - Shares attached to a link are released only after that match, or one by one behind the warning (§6.10).
 *
 * [account] answers the signed-in account (null when signed out: a recipient may still open register, enrol and setup
 * links, and a connect link up to its sign-up form). [setupAllowed] is false in the phone apps (design §9.5).
 */
class WireLinkFlows(
    private val clientFor: (String) -> WireClient,
    private val trust: InstanceTrust,
    private val state: DeviceState,
    private val crypto: CryptoProvider,
    private val clock: () -> Long,
    private val account: () -> LinkAccount?,
    private val setupAllowed: Boolean,
    private val shares: LinkShareRelease? = null,
) : LinkFlows, LinkRegistrations {
    private val lock = Mutex()

    // ---------------------------------------------------------------------------------------------
    // Recipient (design §6.8)
    // ---------------------------------------------------------------------------------------------

    /** A recipient flow in progress. [link] holds the secret until the flow ends. */
    private class Flow(val id: String, val link: ParsedLink, val linkId: String, val offer: OpenedOffer, var view: OfferView) {
        var pinMade: PinHandle? = null
        var replacesKey = false
        var keyChecked = false
        var answer: PendingAnswer? = null

        /** A connect answer posted whose outcome is not known yet: a retry re-sends exactly this one. */
        var sent: SentAnswer? = null

        /**
         * Set by [settle]: the link's secret is wiped and only its answer key is held here (with the link id; the offer
         * key and the register token are not kept), until the flow ends.
         */
        var answerKeys: LinkKeys? = null
    }

    /** A connect answer as posted, with the comparison record it belongs to. */
    private class SentAnswer(val envelope: String, val record: CodeRecord)

    /** A register link's answer, sealed for the new account before the registration (§6.7). */
    private class PendingAnswer(val userId: String, val nonceB: String, val answerHash: String, val at: Long)

    private val flows = HashMap<String, Flow>()
    private var counter = 0L

    private fun flowOf(token: RecipientToken): Flow? = flows[token.id]

    private fun end(flow: Flow) {
        flows.remove(flow.id)
        flow.link.wipe()
        flow.answerKeys?.wipe()
        flow.answerKeys = null
    }

    /** The recipient flows held (tests: a flow that stopped holds nothing). */
    internal fun openFlows(): Int = flows.size

    /** Whether [step]'s flow still holds the link's secret itself (tests: [settle] keeps only the answer key). */
    internal fun holdsLinkSecret(step: RecipientStep.Confirm): Boolean = flowOf(step.token)?.link?.secret?.any { it != 0.toByte() } == true

    override suspend fun open(text: String, entry: GateEntry): RecipientStep {
        // §12.1, FS-B1: the device-link and kit screens take nothing else, and an invite screen takes only an invite.
        if (entry == GateEntry.LINK_DEVICE_SCREEN || entry == GateEntry.CLI_LINK_DEVICE || entry == GateEntry.KIT_RECOVERY_SCREEN) {
            return RecipientStep.Stopped(LinkStop.WRONG_ENTRY)
        }
        val link = LinkUrl.parse(text) ?: return RecipientStep.Stopped(
            // Nothing starts either way. A `/d` or kit payload gets its own copy (§12.1); an `/l` URL that does not parse
            // is `bad_link` (§2.4), even when its fragment would read as a device link's.
            when (ScanPayload.of(text)) {
                ScanPayload.DEVICE_LINK -> if (TrustGrammar.stripAsciiSpace(text).contains("/l#")) LinkStop.BAD_LINK else LinkStop.WRONG_SCREEN_DEVICE_LINK
                ScanPayload.KIT -> LinkStop.WRONG_SCREEN_KIT
                else -> LinkStop.BAD_LINK
            },
        )
        // The mirror case: a `/d` URL whose fragment reads as an invite's (four parts) is a device link that does not
        // parse, `bad_link`, never opened as an invite.
        if (TrustGrammar.stripAsciiSpace(text).contains("/d#")) {
            link.wipe()
            return RecipientStep.Stopped(LinkStop.BAD_LINK)
        }
        val keys = Links.deriveKeys(crypto, link.secret)
        val linkId = keys.linkId
        keys.wipe()
        val step = openParsed(link, linkId)
        if (step is RecipientStep.Stopped || step is RecipientStep.NotTakingAccounts || step is RecipientStep.Answered || step is RecipientStep.PinChanged ||
            // An origin mismatch carries no token, so nothing could end the flow later: it ends here, as a device link's does.
            step is RecipientStep.OriginMismatch) {
            // The flow did not start, or ended here: nothing keeps the secret.
            flows.values.firstOrNull { it.link === link }?.let { f -> f.pinMade?.let(trust::dropPinMade); end(f) } ?: link.wipe()
        }
        return step
    }

    private suspend fun openParsed(link: ParsedLink, linkId: String): RecipientStep {
        // 2. The server's answer.
        val served = when (val r = clientFor(link.origin).call(WireRoute.LINK_FETCH, pathParams = mapOf("linkId" to linkId),
            decode = { WireJson.json.decodeFromString(LinkFetchResponse.serializer(), it) })) {
            is WireResult.Ok -> r.value
            is WireResult.Refused -> return RecipientStep.Stopped(
                when {
                    r.code == "link_unknown" || r.status == 404 -> LinkStop.UNKNOWN
                    r.code == "link_expired" || r.status == 410 -> LinkStop.EXPIRED
                    else -> LinkStop.UNREACHABLE
                },
            )
            is WireResult.NoAnswer -> return RecipientStep.Stopped(LinkStop.UNREACHABLE)
        }
        if (served.state == LinkState.ANSWERED) {
            // `link_used` belongs to a link this device did not answer itself (spec 03 §15.3).
            val acct = account()
            val mine = acct?.takeIf { it.origin == link.origin }?.let { codes(it).byLink(linkId) }?.takeIf { it.role == CodeRecord.ANSWERER }
            return if (mine != null) RecipientStep.Answered(mine.contactUserId, linkId) else RecipientStep.Stopped(LinkStop.ALREADY_USED)
        }
        if (served.state != LinkState.OPEN) return RecipientStep.Stopped(LinkStop.UNKNOWN)
        // 3, 4. The offer, through the shared verifiers' checks in §2.4's order.
        val envelope = served.offer?.let(Bytes::fromB64Canonical) ?: return RecipientStep.Stopped(LinkStop.UNOPENABLE)
        val offer = when (val o = LinkOffer.open(crypto, link, envelope, ServedLink(served.kind, served.creatorUserId, served.creatorIdentityPub), clock())) {
            is Checked.Ok -> o.value
            is Checked.Refused -> return RecipientStep.Stopped(offerStop(o.verdict))
        }
        val view = OfferView(
            kind = offer.kind.literal, origin = link.origin, instanceName = "",
            creatorName = (offer as? OpenedOffer.Signed)?.fields?.name, creatorUserId = (offer as? OpenedOffer.Signed)?.fields?.from,
            expiresAt = offer.expiresAt, boundEmail = (offer as? OpenedOffer.Enrol)?.fields?.email,
        )
        val flow = Flow("r" + (++counter), link, linkId, offer, view)
        flows[flow.id] = flow
        // 5. The card chain, per §4.4's roots.
        return when (offer) {
            is OpenedOffer.Signed -> afterPin(flow, trust.pinFromLinkOffer(link.origin, offer.fields.instanceId, offer.fields.cardHash))
            is OpenedOffer.Enrol -> afterPin(flow, trust.beginTrustGate(link.origin, TrustGateWording.ENROL_LINK))
            is OpenedOffer.Setup -> setupChecks(flow)
        }
    }

    /** A setup link (§6.7, §9.5): only on a computer, and only while the instance serves no card and this device pins none. */
    private suspend fun setupChecks(flow: Flow): RecipientStep {
        if (!setupAllowed) return RecipientStep.Stopped(LinkStop.SETUP_ON_PHONE)
        // Design §4.4: a build that bakes an instance never signs that instance's card 0. The baked checks decide the stop.
        if (trust.isBakedOrigin(flow.link.origin)) {
            val v = trust.setupVerdictAtBaked(flow.link.origin)
            return when (v) {
                LinkStop.ALREADY_SET_UP.code -> RecipientStep.Stopped(LinkStop.ALREADY_SET_UP)
                "damaged" -> RecipientStep.Stopped(LinkStop.DAMAGED)
                "unreachable" -> RecipientStep.Stopped(LinkStop.UNREACHABLE)
                else -> pinRefused(v)
            }
        }
        when (trust.pinState(flow.link.origin)) {
            PinState.Damaged -> return RecipientStep.Stopped(LinkStop.DAMAGED)
            is PinState.Forked -> return RecipientStep.Stopped(LinkStop.FORK)
            is PinState.Pinned -> return RecipientStep.Stopped(LinkStop.ALREADY_SET_UP)
            PinState.None -> {}
        }
        val inst = clientFor(flow.link.origin).call(WireRoute.INSTANCE, decode = { WireJson.json.decodeFromString(InstanceResponse.serializer(), it) })
        when (inst) {
            is WireResult.Ok -> if (inst.value.cards.isNotEmpty()) return RecipientStep.Stopped(LinkStop.ALREADY_SET_UP)
            else -> return RecipientStep.Stopped(LinkStop.UNREACHABLE)
        }
        return decide(flow)
    }

    /** What a root's first-pin call came to, for the flow. */
    private suspend fun afterPin(flow: Flow, pin: FirstPin): RecipientStep = when (pin) {
        is FirstPin.Pinned -> {
            if (pin.handle.madeNow) flow.pinMade = pin.handle
            // An enrol offer names an instance: the pinned card must be that instance (its cardHash is only the host's claim).
            if (flow.offer is OpenedOffer.Enrol && pin.pin.instanceId != flow.offer.instanceId) {
                RecipientStep.Stopped(LinkStop.INSTANCE_MISMATCH)
            } else {
                decide(flow)
            }
        }
        is FirstPin.NeedsTrustGate -> RecipientStep.TrustGate(pin, RecipientToken(flow.id))
        is FirstPin.Refused -> pinRefused(pin.reason)
        is FirstPin.OriginMismatch -> RecipientStep.OriginMismatch(pin.dialedOrigin, pin.cardOrigin)
        is FirstPin.PinChanged -> RecipientStep.PinChanged(pin)
        is FirstPin.Blocked -> RecipientStep.Stopped(if (pin.state is PinState.Damaged) LinkStop.DAMAGED else LinkStop.FORK)
        is FirstPin.PinConflict -> RecipientStep.Stopped(LinkStop.PIN_CONFLICT)
        is FirstPin.KitAnchorMismatch -> RecipientStep.Stopped(LinkStop.STALE)
        FirstPin.Unreachable -> RecipientStep.Stopped(LinkStop.UNREACHABLE)
    }

    /** The account checks after the pin (§6.7 dead ends, §6.8 steps 6 and 7). */
    private suspend fun decide(flow: Flow): RecipientStep {
        val acct = account()
        val origin = flow.link.origin
        // The name a screen shows is the pinned card's (or the setup offer's), always beside the origin (T-R8).
        flow.view = flow.view.copy(instanceName = (flow.offer as? OpenedOffer.Setup)?.fields?.name ?: trust.pinFor(origin)?.name ?: "")
        if (acct != null && acct.origin != origin) return RecipientStep.OtherInstance(flow.view, acct.origin, RecipientToken(flow.id))
        val offer = flow.offer
        if (offer !is OpenedOffer.Signed) return RecipientStep.Confirm(flow.view, needsAccount = true, replacesKey = false, token = RecipientToken(flow.id))
        // A creator whose user id is all zeros is no account: such a link is never a contact.
        if (io.silencelen.andvari.core.client.UserIds.isNil(offer.fields.from)) return RecipientStep.Stopped(LinkStop.BAD_LINK)
        if (acct != null) {
            if (offer.fields.from == acct.userId) return RecipientStep.Stopped(LinkStop.OWN_LINK)
            // 6. The key-change check (T-R5): a prompt, never a verdict, and nothing replaced.
            val known = acct.store.local().contacts[offer.fields.from]
            if (known != null && known.identityPub != offer.fields.fromKey && !flow.replacesKey) {
                return RecipientStep.KeyChanged(flow.view, TrustGrammar.decodeName(known.label) ?: "", RecipientToken(flow.id))
            }
        }
        if (offer.kind != LinkKind.CONNECT) return RecipientStep.Confirm(flow.view, needsAccount = true, replacesKey = flow.replacesKey, token = RecipientToken(flow.id))
        if (acct != null) return RecipientStep.Confirm(flow.view, needsAccount = false, replacesKey = flow.replacesKey, token = RecipientToken(flow.id))
        // A connect link without an account: sign-up comes first, if the instance takes accounts (§6.7).
        val policy = clientFor(origin).call(WireRoute.CLIENT_POLICY, decode = { WireJson.json.decodeFromString(ClientPolicy.serializer(), it) })
        val signup = (policy as? WireResult.Ok)?.value?.signup ?: return RecipientStep.Stopped(LinkStop.UNREACHABLE)
        if (signup.mode != SignupMode.OPEN || signup.full) return RecipientStep.NotTakingAccounts(flow.view, signup.mode, signup.full)
        return RecipientStep.Confirm(flow.view, needsAccount = true, replacesKey = false, token = RecipientToken(flow.id))
    }

    override suspend fun proceed(step: RecipientStep): RecipientStep {
        val token = when (step) {
            is RecipientStep.TrustGate -> step.token
            is RecipientStep.KeyChanged -> step.token
            is RecipientStep.OtherInstance -> step.token
            else -> return step
        }
        val flow = flowOf(token) ?: return RecipientStep.Stopped(LinkStop.STALE)
        val next = when (step) {
            is RecipientStep.TrustGate -> afterPin(flow, trust.confirmTrustGate(step.gate.confirm))
            is RecipientStep.KeyChanged -> {
                flow.replacesKey = true
                decide(flow)
            }
            else -> decide(flow)
        }
        if (next is RecipientStep.Stopped || next is RecipientStep.NotTakingAccounts || next is RecipientStep.PinChanged ||
            next is RecipientStep.OriginMismatch) {
            flow.pinMade?.let(trust::dropPinMade)
            end(flow)
        }
        return next
    }

    override fun settle(step: RecipientStep.Confirm): RecipientStep.Confirm? {
        val flow = flowOf(step.token) ?: return null
        // The account stands on the pin now: no later stop or dismissal of this flow drops it.
        flow.pinMade = null
        val offer = flow.offer
        if (offer !is OpenedOffer.Signed || offer.kind != LinkKind.CONNECT) {
            // Nothing is left for confirm to do with any other link (a registration through it is done or not wanted).
            end(flow)
            return null
        }
        if (flow.answerKeys == null) {
            val keys = Links.deriveKeys(crypto, flow.link.secret)
            val answerKey = keys.answerKey
            keys.wipe()
            // Only the answer key (LinkAnswer.seal reads that and the link id): no offer key, no register token.
            flow.answerKeys = LinkKeys(flow.linkId, ByteArray(32), answerKey, "")
            answerKey.fill(0)
            flow.link.wipe()
        }
        return step
    }

    override fun dismiss(step: RecipientStep) {
        val token = when (step) {
            is RecipientStep.TrustGate -> step.token
            is RecipientStep.KeyChanged -> step.token
            is RecipientStep.OtherInstance -> step.token
            is RecipientStep.Confirm -> step.token
            else -> return
        }
        val flow = flowOf(token) ?: return
        flow.pinMade?.let(trust::dropPinMade)
        end(flow)
    }

    override suspend fun confirm(step: RecipientStep.Confirm): RecipientStep = lock.withLock {
        val flow = flowOf(step.token) ?: return@withLock RecipientStep.Stopped(LinkStop.STALE)
        val offer = flow.offer as? OpenedOffer.Signed ?: return@withLock step
        if (offer.kind != LinkKind.CONNECT) return@withLock step
        // A connect link without an account here: the person registers first; nothing is sent (§6.7).
        val acct = account()?.takeIf { it.origin == flow.link.origin } ?: return@withLock step
        val f = offer.fields
        if (f.from == acct.userId) return@withLock stop(flow, LinkStop.OWN_LINK)
        if (io.silencelen.andvari.core.client.UserIds.isNil(f.from)) return@withLock stop(flow, LinkStop.BAD_LINK)
        if (clock() >= f.expiresAt) return@withLock stop(flow, LinkStop.OFFER_EXPIRED)
        val doc = acct.store.local()
        val known = doc.contacts[f.from]
        if (known != null && known.identityPub != f.fromKey && !flow.replacesKey) {
            return@withLock RecipientStep.KeyChanged(flow.view, TrustGrammar.decodeName(known.label) ?: "", RecipientToken(flow.id))
        }
        if (known == null && doc.contacts.size >= AccountDocument.MAX_CONTACTS) return@withLock stop(flow, LinkStop.TOO_MANY_CONTACTS)
        // A retry after an answer whose outcome was never known re-sends THAT answer, so whichever post landed, the
        // comparison record is the one the server holds.
        val retry = flow.sent
        val sent = retry ?: run {
            val label = TrustGrammar.encodeName(f.name) ?: return@withLock stop(flow, LinkStop.NON_CANONICAL)
            // Signed under the account's guard: the reads above were waits, and a lock in them signs nothing.
            val sealed = acct.signing.use { sealAnswer(flow, acct.userId, acct.identity.publicKey, it, acct.displayName) }
                ?: return@withLock stop(flow, LinkStop.BAD_NAME)
            val replaces = known != null && known.identityPub != f.fromKey
            SentAnswer(sealed.envelope, CodeRecord(
                linkId = flow.linkId, role = CodeRecord.ANSWERER, contactUserId = f.from, contactKey = f.fromKey, label = label,
                offerHash = offer.offerHash, answerHash = sealed.answerHash, nonceB = sealed.nonceB, commit = f.commit,
                replacesKey = replaces, at = clock(),
            ))
        }
        val record = sent.record
        val codes = codes(acct)
        // The record of an answer to this link whose outcome was never known (this flow's retry, or one kept from an
        // earlier flow): if that answer landed, it is the one the server holds, and this device continues with it.
        val kept = if (retry != null) record else codes.byLink(flow.linkId)?.takeIf { it.role == CodeRecord.ANSWERER }
        // The comparison record first, durably, then the answer (§6.7 step 6).
        codes.put(record)
        flow.sent = sent
        val body = WireJson.json.encodeToString(LinkAnswerRequest.serializer(), LinkAnswerRequest(sent.envelope))
        when (val r = clientFor(acct.origin).call(WireRoute.LINK_ANSWER, pathParams = mapOf("linkId" to flow.linkId), bodyJson = body, decode = { })) {
            is WireResult.Ok -> {}
            is WireResult.Refused -> {
                if (r.code == "link_used" && kept != null) {
                    codes.put(kept)
                    flow.pinMade = null
                    end(flow)
                    saveContact(acct, kept)
                    return@withLock RecipientStep.Answered(kept.contactUserId, kept.linkId)
                }
                codes.write(codes.all().filterNot { it.linkId == flow.linkId })
                return@withLock stop(flow, when (r.code) {
                    "link_used" -> LinkStop.ALREADY_USED
                    "link_expired" -> LinkStop.EXPIRED
                    "link_unknown" -> LinkStop.UNKNOWN
                    "kind_mismatch" -> LinkStop.KIND_MISMATCH
                    "cannot_target_self" -> LinkStop.OWN_LINK
                    else -> LinkStop.UNREACHABLE
                })
            }
            is WireResult.NoAnswer -> {
                // The answer may have landed: the comparison record stays until the server's answer is known, so a retry
                // that finds the link answered (link_used, or `answered` on re-opening) continues to the code with it.
                // The flow stays too: a retry of this step is the person's (the server's first answer wins).
                return@withLock RecipientStep.Stopped(LinkStop.UNREACHABLE)
            }
        }
        flow.pinMade = null
        end(flow)
        saveContact(acct, record)
        RecipientStep.Answered(f.from, record.linkId)
    }

    private fun stop(flow: Flow, reason: LinkStop): RecipientStep {
        flow.pinMade?.let(trust::dropPinMade)
        end(flow)
        return RecipientStep.Stopped(reason)
    }

    private class SealedAnswer(val envelope: String, val answerHash: String, val nonceB: String)

    /** Sign and seal the 0x07 answer to [flow]'s offer for the answering account; null when [displayName] is not a `name`. */
    private fun sealAnswer(flow: Flow, userId: String, identityPub: ByteArray, signing: KeyPairBytes, displayName: String): SealedAnswer? {
        val offer = flow.offer as OpenedOffer.Signed
        if (TrustGrammar.encodeName(displayName) == null) return null
        val nonce = crypto.randomBytes(CodeCommit.NONCE_BYTES)
        val nonceB = Bytes.toB64(nonce)
        nonce.fill(0)
        val fields = LinkAnswerFields(
            linkId = flow.linkId, offerHash = offer.offerHash, to = offer.fields.from, toKey = offer.fields.fromKey,
            from = userId, fromKey = Bytes.toB64(identityPub), name = displayName, nonce = nonceB, issuedAt = clock(),
        )
        val frame = LinkAnswer.sign(crypto, signing, fields)
        // A settled flow holds only the answer key (kept until the flow ends); otherwise it is derived for this answer.
        flow.answerKeys?.let { held -> return SealedAnswer(Bytes.toB64(LinkAnswer.seal(crypto, held, frame)), SignedFrame.hash(crypto, frame), nonceB) }
        val keys = Links.deriveKeys(crypto, flow.link.secret)
        try {
            return SealedAnswer(Bytes.toB64(LinkAnswer.seal(crypto, keys, frame)), SignedFrame.hash(crypto, frame), nonceB)
        } finally {
            keys.wipe()
        }
    }

    /**
     * Pin the other side with `compared = false` (§6.7 steps 6 and 7) and make it current here (§6.9 (a)), unless a
     * contact for that userId holds another key: then nothing is replaced until this device's own match.
     */
    private suspend fun saveContact(acct: LinkAccount, record: CodeRecord): CodeRecord {
        if (record.replacesKey || record.contactSaved) return record
        val now = clock()
        val w = acct.store.update { doc ->
            val known = doc.contacts[record.contactUserId]
            when {
                // A contact pinned again after it was removed supersedes its tombstone (design §5.4).
                known == null -> doc.copy(contacts = doc.contacts + (record.contactUserId to
                    ContactRecord(record.contactUserId, record.contactKey, record.label,
                        verifiedAt = AccountMerge.supersedingContactAt(doc, record.contactUserId, now), compared = false, madeOn = acct.deviceId)))
                else -> doc
            }
        }
        val saved = when (w) {
            is AccountStateWrite.Written -> w.document.contacts[record.contactUserId]?.identityPub == record.contactKey
            is AccountStateWrite.Unchanged -> w.document.contacts[record.contactUserId]?.identityPub == record.contactKey
            else -> false
        }
        if (!saved) return record
        currency(acct).mark(record.contactUserId, record.contactKey, Currency.LINK)
        val next = record.copy(contactSaved = true)
        codes(acct).put(next)
        return next
    }

    override suspend fun awaitReveal(step: RecipientStep.Answered): RecipientStep {
        val acct = account() ?: return step
        return when (val s = lock.withLock { reveal(acct, step.linkId) }) {
            null -> RecipientStep.Stopped(LinkStop.STALE)
            is CompareState.Waiting -> step
            is CompareState.Failed -> RecipientStep.Stopped(LinkStop.BAD_REVEAL)
            is CompareState.Ready, is CompareState.Matched -> RecipientStep.CodeReady(step.contactUserId, step.linkId)
        }
    }

    override suspend fun refreshReveal(contactUserId: String): CompareState? {
        val acct = account() ?: return null
        val rec = codes(acct).latestFor(contactUserId) ?: return null
        if (rec.role != CodeRecord.ANSWERER) return view(rec)
        return lock.withLock { reveal(acct, rec.linkId) }
    }

    /**
     * The answerer's pass 3 (§6.11): the reveal must open the offer's commitment (`bad_reveal`), and the first value
     * accepted fixes the code for good; a second, different value fails the link.
     */
    private suspend fun reveal(acct: LinkAccount, linkId: String): CompareState? {
        val store = codes(acct)
        var rec = store.byLink(linkId) ?: return null
        if (rec.role != CodeRecord.ANSWERER || rec.failed) return view(rec)
        val r = clientFor(acct.origin).call(WireRoute.LINK_FETCH, pathParams = mapOf("linkId" to linkId),
            decode = { WireJson.json.decodeFromString(LinkFetchResponse.serializer(), it) })
        val served = (r as? WireResult.Ok)?.value
        val reveal = served?.takeIf { it.state == LinkState.ANSWERED }?.reveal
        if (reveal != null) {
            val firstSeen = rec.nonceA
            when {
                firstSeen != null && firstSeen != reveal -> rec = rec.copy(failed = true)
                firstSeen == null && !CodeCommit.opens(crypto, reveal, rec.commit ?: "") -> rec = rec.copy(failed = true)
                firstSeen == null -> {
                    val nonceA = Bytes.fromB64Exact(reveal, CodeCommit.NONCE_BYTES)
                    val nonceB = Bytes.fromB64Exact(rec.nonceB, CodeCommit.NONCE_BYTES)
                    rec = if (nonceA == null || nonceB == null) {
                        rec.copy(failed = true)
                    } else {
                        // This side's own code, the one its screen shows (§6.11); the creator's is never kept.
                        rec.copy(nonceA = reveal, code = ComparisonCode.link(crypto, LinkSide.ANSWERER, linkId, rec.offerHash, rec.answerHash, nonceA, nonceB))
                    }
                }
            }
            store.put(rec)
        }
        if (!rec.failed) rec = saveContact(acct, rec)
        return view(rec)
    }

    private fun view(rec: CodeRecord): CompareState {
        val label = TrustGrammar.decodeName(rec.label) ?: ""
        val code = rec.code
        return when {
            rec.failed -> CompareState.Failed(rec.contactUserId, label)
            rec.compared -> CompareState.Matched(rec.contactUserId, label)
            code != null -> CompareState.Ready(rec.contactUserId, label, code, rec.replacesKey)
            else -> CompareState.Waiting(rec.contactUserId, label)
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Creator (design §6.7, §6.8 creator side)
    // ---------------------------------------------------------------------------------------------

    private fun records(acct: LinkAccount) = LinkRecordStore(state, crypto, acct.origin, acct.userId)

    private fun codes(acct: LinkAccount) = CodeRecordStore(state, acct.origin, acct.userId)

    private fun currency(acct: LinkAccount) = ContactCurrency(state, crypto, acct.origin, acct.userId)

    override suspend fun create(kind: String, expiresInMs: Long, shares: List<LinkShare>): CreateOutcome = lock.withLock {
        val acct = account() ?: return@withLock CreateOutcome.Refused(NO_SESSION)
        val linkKind = LinkKind.fromLiteral(kind)?.takeIf { it == LinkKind.CONNECT || it == LinkKind.REGISTER }
            ?: return@withLock CreateOutcome.Refused(BAD_KIND)
        val longest = if (linkKind == LinkKind.CONNECT) CONNECT_LONGEST_MS else REGISTER_LONGEST_MS
        if (expiresInMs < SHORTEST_MS || expiresInMs > longest) return@withLock CreateOutcome.Refused(BAD_LIFETIME)
        if (linkKind == LinkKind.REGISTER && shares.isNotEmpty()) return@withLock CreateOutcome.Refused(SHARES_ON_REGISTER)
        if (shares.any { !TrustGrammar.isUuid(it.vaultId) || (it.role != "writer" && it.role != "reader") }) return@withLock CreateOutcome.Refused(BAD_SHARE)
        val pin = trust.pinFor(acct.origin) ?: return@withLock CreateOutcome.Refused(NO_PIN)
        if (acct.store.local().contacts.size >= AccountDocument.MAX_CONTACTS) return@withLock CreateOutcome.Refused(LinkStop.TOO_MANY_CONTACTS.code)
        if (TrustGrammar.encodeName(acct.displayName) == null) return@withLock CreateOutcome.Refused(LinkStop.BAD_NAME.code)
        val secret = crypto.randomBytes(32)
        val nonceA = crypto.randomBytes(CodeCommit.NONCE_BYTES)
        val keys = Links.deriveKeys(crypto, secret)
        try {
            val now = clock()
            val fields = LinkOfferFields(
                linkId = keys.linkId, kind = linkKind, origin = acct.origin, instanceId = pin.instanceId, cardHash = pin.hash,
                from = acct.userId, fromKey = acct.identityPubB64, name = acct.displayName, commit = CodeCommit.commit(crypto, nonceA),
                expiresAt = now + expiresInMs, issuedAt = now,
            )
            val frame = acct.signing.use { LinkOffer.sign(crypto, it, fields) }
            val envelope = Bytes.toB64(LinkOffer.seal(crypto, keys, frame))
            val url = LinkUrl.compose(acct.origin, secret, LinkUrl.creatorFingerprint(crypto, acct.identity.publicKey))
                ?: return@withLock CreateOutcome.Refused(LinkStop.BAD_LINK.code)
            val record = LinkRecord(keys.linkId, Bytes.toB64(secret), Bytes.toB64(nonceA), linkKind.literal, SignedFrame.hash(crypto, frame),
                fields.expiresAt, shares.map { StoredShare(it.vaultId, it.role) }, url, now)
            // §6.7 step 2: the record first, durably; only then the POST.
            val store = records(acct)
            store.put(acct.uvk, record)
            val body = LinkCreateRequest(keys.linkId, linkKind.literal, envelope, fields.expiresAt,
                if (linkKind == LinkKind.REGISTER) Links.tokenHash(crypto, keys.registerToken) else null)
            val r = clientFor(acct.origin).call(WireRoute.LINK_CREATE, bodyJson = WireJson.json.encodeToString(LinkCreateRequest.serializer(), body),
                decode = { WireJson.json.decodeFromString(LinkCreatedResponse.serializer(), it) })
            when (r) {
                is WireResult.Ok -> {
                    // Bounded by the lifetime asked for: never negative, never longer than [expiresInMs].
                    val done = record.copy(ttlMs = r.value.ttlMs.coerceIn(0L, expiresInMs))
                    store.put(acct.uvk, done)
                    CreateOutcome.Created(createdView(done))
                }
                is WireResult.Refused -> if (r.status >= 500) {
                    CreateOutcome.Unknown(createdView(record))
                } else {
                    store.remove(acct.uvk, record.linkId)
                    CreateOutcome.Refused(r.code, r.retryAfterSeconds)
                }
                is WireResult.NoAnswer -> CreateOutcome.Unknown(createdView(record))
            }
        } finally {
            secret.fill(0)
            nonceA.fill(0)
            keys.wipe()
        }
    }

    private fun createdView(r: LinkRecord) = CreatedLink(r.linkId, r.kind, r.url, r.ttlMs, r.shares.map(StoredShare::view))

    override fun createdLinks(): List<CreatedLink> {
        val acct = account() ?: return emptyList()
        return records(acct).all(acct.uvk).map(::createdView)
    }

    override suspend fun revoke(linkId: String): Boolean = lock.withLock {
        val acct = account() ?: return@withLock false
        // T-R3: the record goes first, so a later answer finds none whatever the server says.
        records(acct).remove(acct.uvk, linkId)
        if (!TrustGrammar.isB64_16(linkId)) return@withLock false
        clientFor(acct.origin).call(WireRoute.LINK_REVOKE, pathParams = mapOf("linkId" to linkId), decode = { }) is WireResult.Ok
    }

    override fun expireRecords(nowMs: Long) {
        val acct = account() ?: return
        val store = records(acct)
        val all = store.all(acct.uvk)
        val kept = all.filter { nowMs < it.expiresAt }
        if (kept.size != all.size) store.write(acct.uvk, kept)
        store.pruneDropped(nowMs)
    }

    override suspend fun processAnswers(): List<CreatorStep> = lock.withLock {
        val acct = account() ?: return@withLock emptyList()
        val client = clientFor(acct.origin)
        val served = when (val r = client.call(WireRoute.LINK_ANSWERS, decode = { WireJson.json.decodeFromString(ListSerializer(ServedAnswer.serializer()), it) })) {
            is WireResult.Ok -> r.value
            else -> return@withLock emptyList()
        }
        served.mapNotNull { processOne(acct, client, it) }
    }

    /** One served answer through §6.8's creator steps, in §2.4's order; null when it was finished on an earlier run. */
    private suspend fun processOne(acct: LinkAccount, client: WireClient, a: ServedAnswer): CreatorStep? {
        if (!TrustGrammar.isB64_16(a.linkId)) return CreatorStep.Ignored(a.linkId, LinkVerdict.UNKNOWN_LINK.code)
        val codes = codes(acct)
        val store = records(acct)
        val done = codes.byLink(a.linkId)?.takeIf { it.role == CodeRecord.CREATOR }
        val record = store.get(acct.uvk, a.linkId)
        val now = clock()
        if (record == null && done != null) {
            // Processed before, and only the acknowledgement was missing.
            ack(client, a.linkId)
            return null
        }
        // 1. This device's record, unexpired (T-R3).
        if (record == null) {
            // The inbox lists every answered link of the ACCOUNT (spec 03 §15.6). Only a link this device created and
            // dropped (expired, revoked) is acknowledged here; another device's link is left for that device.
            if (store.wasDropped(a.linkId, now)) ack(client, a.linkId)
            return CreatorStep.Ignored(a.linkId, LinkVerdict.UNKNOWN_LINK.code)
        }
        if (now >= record.expiresAt) {
            store.remove(acct.uvk, a.linkId)
            ack(client, a.linkId)
            return CreatorStep.Ignored(a.linkId, LinkVerdict.UNKNOWN_LINK.code)
        }
        // 2–5. The shared verifiers' checks on the answer.
        fun ignore(code: String): CreatorStep {
            store.remove(acct.uvk, a.linkId)
            return CreatorStep.Ignored(a.linkId, code)
        }
        val envelope = Bytes.fromB64Canonical(a.answer) ?: return ignore(LinkVerdict.UNOPENABLE.code).also { ack(client, a.linkId) }
        val secret = Bytes.fromB64Exact(record.secret, 32) ?: return ignore(LinkVerdict.UNKNOWN_LINK.code).also { ack(client, a.linkId) }
        val opened = try {
            when (val o = LinkAnswer.open(crypto, secret, record.offerHash, acct.userId, acct.identity.publicKey, envelope, a.answererUserId)) {
                is Checked.Ok -> o.value
                is Checked.Refused -> return ignore(o.verdict.code).also { ack(client, a.linkId) }
            }
        } finally {
            secret.fill(0)
        }
        val f = opened.fields
        val nonceA = Bytes.fromB64Exact(record.nonceA, CodeCommit.NONCE_BYTES)
        val nonceB = Bytes.fromB64Exact(f.nonce, CodeCommit.NONCE_BYTES)
        val label = TrustGrammar.encodeName(f.name)
        if (nonceA == null || nonceB == null || label == null) return ignore(LinkVerdict.NON_CANONICAL.code).also { ack(client, a.linkId) }
        // An answerer whose user id is all zeros is no account: never pinned as a contact.
        if (io.silencelen.andvari.core.client.UserIds.isNil(f.from)) return ignore(NIL_ANSWERER).also { ack(client, a.linkId) }
        // 6. The key-change check, from this side: nothing replaced without this device's own match.
        val known = acct.store.local().contacts[f.from]
        val replaces = known != null && known.identityPub != f.fromKey
        // The code is fixed now, once, from the first answer accepted (T2-R-b).
        var rec = done
        if (rec != null && rec.answerHash != opened.answerHash) {
            codes.put(rec.copy(failed = true))
            return ignore(ANSWER_CHANGED).also { ack(client, a.linkId) }
        }
        if (rec == null) {
            rec = CodeRecord(
                linkId = a.linkId, role = CodeRecord.CREATOR, contactUserId = f.from, contactKey = f.fromKey, label = label,
                offerHash = record.offerHash, answerHash = opened.answerHash, nonceB = f.nonce, nonceA = record.nonceA,
                // This side's own code, the one its screen shows (§6.11); the answerer's is never kept.
                code = ComparisonCode.link(crypto, LinkSide.CREATOR, a.linkId, record.offerHash, opened.answerHash, nonceA, nonceB),
                replacesKey = replaces, shares = record.shares, at = now,
            )
            codes.put(rec)
        }
        nonceA.fill(0)
        // 7. Pin compared = false, reveal, delete the secret, acknowledge.
        rec = saveContact(acct, rec)
        val body = WireJson.json.encodeToString(LinkRevealRequest.serializer(), LinkRevealRequest(record.nonceA))
        when (val r = client.call(WireRoute.LINK_REVEAL, pathParams = mapOf("linkId" to a.linkId), bodyJson = body, decode = { })) {
            is WireResult.Ok -> {}
            // The reveal is stored once; a second post after a lost answer is link_state, and the first one stands.
            is WireResult.Refused -> if (r.code != "link_state") return CreatorStep.Deferred(a.linkId, r.code)
            is WireResult.NoAnswer -> return CreatorStep.Deferred(a.linkId, LinkStop.UNREACHABLE.code)
        }
        store.remove(acct.uvk, a.linkId)
        ack(client, a.linkId)
        return if (replaces) {
            CreatorStep.KeyChanged(a.linkId, f.from, TrustGrammar.decodeName(known!!.label) ?: "")
        } else {
            CreatorStep.Processed(a.linkId, f.from, f.name, rec.shares.map(StoredShare::view))
        }
    }

    private suspend fun ack(client: WireClient, linkId: String) {
        if (TrustGrammar.isB64_16(linkId)) client.call(WireRoute.LINK_ACK, pathParams = mapOf("linkId" to linkId), decode = { })
    }

    // ---------------------------------------------------------------------------------------------
    // The comparison (design §6.11) and the shares (design §6.10)
    // ---------------------------------------------------------------------------------------------

    override fun code(contactUserId: String): String? {
        val acct = account() ?: return null
        val rec = codes(acct).latestFor(contactUserId) ?: return null
        return if (rec.failed) null else rec.code
    }

    override fun compareState(contactUserId: String): CompareState? {
        val acct = account() ?: return null
        return codes(acct).latestFor(contactUserId)?.let(::view)
    }

    override suspend fun typeCode(contactUserId: String, digits: String): CompareResult = lock.withLock {
        val acct = account() ?: return@withLock CompareResult.Failed
        val store = codes(acct)
        val rec = store.latestFor(contactUserId) ?: return@withLock CompareResult.Failed
        if (rec.failed || rec.code == null) return@withLock CompareResult.Failed
        if (!rec.compared) {
            // §6.11: the typed digits are checked against the OTHER side's code, never this side's own (which is the one
            // on this screen). It is derived here from the record's fixed inputs, compared in constant time, and kept nowhere.
            val accepted = acceptsTyped(rec, digits) ?: return@withLock CompareResult.Failed
            if (!accepted) return@withLock CompareResult.Mismatch
            // T2-R-i: this device's own correct entry, and nothing else, sets compared.
            store.put(rec.copy(compared = true))
        }
        if (finishCompared(acct, store.byLink(rec.linkId)!!)) CompareResult.Matched else CompareResult.Unsaved
    }

    /**
     * Whether [typed] is the code the OTHER side of [rec]'s link shows (§2.3, §6.11 "Typed input"), through the one typed-input
     * rule ([ComparisonCode.linkAccepts]), from the inputs this side fixed once: both frame hashes and the two nonces as first
     * accepted (T2-R-b). Null when the record holds no fixed pair, or names no side. The other side's code is computed
     * inside the check only; it is never displayed, returned, stored or logged.
     */
    private fun acceptsTyped(rec: CodeRecord, typed: String): Boolean? {
        val side = rec.side() ?: return null
        val nonceA = rec.nonceA?.let { Bytes.fromB64Exact(it, CodeCommit.NONCE_BYTES) } ?: return null
        val nonceB = Bytes.fromB64Exact(rec.nonceB, CodeCommit.NONCE_BYTES) ?: return null
        if (!TrustGrammar.isB64_16(rec.linkId) || !TrustGrammar.isHex64(rec.offerHash) || !TrustGrammar.isHex64(rec.answerHash)) return null
        return ComparisonCode.linkAccepts(crypto, side, typed, rec.linkId, rec.offerHash, rec.answerHash, nonceA, nonceB)
    }

    /**
     * After this device's own match: the contact in account state becomes compared (replacing the key when the match
     * was for a new key, §6.8 step 6), current here, and the vaults attached to the link are shared (§6.10).
     */
    private suspend fun finishCompared(acct: LinkAccount, rec: CodeRecord): Boolean {
        val now = clock()
        val w = acct.store.update { doc ->
            val known = doc.contacts[rec.contactUserId]
            val next = when {
                // A new pin, or a matched new key replacing the old one: it supersedes the held pin and any tombstone (§5.4).
                known == null || known.identityPub != rec.contactKey ->
                    ContactRecord(rec.contactUserId, rec.contactKey, rec.label, verifiedAt = AccountMerge.supersedingContactAt(doc, rec.contactUserId, now),
                        compared = true, madeOn = acct.deviceId)
                known.compared -> known
                else -> known.copy(compared = true)
            }
            if (next == known) doc else doc.copy(contacts = doc.contacts + (rec.contactUserId to next))
        }
        val ok = when (w) {
            is AccountStateWrite.Written -> w.document.contacts[rec.contactUserId]?.let { it.identityPub == rec.contactKey && it.compared } == true
            is AccountStateWrite.Unchanged -> w.document.contacts[rec.contactUserId]?.let { it.identityPub == rec.contactKey && it.compared } == true
            else -> false
        }
        if (!ok) return false
        currency(acct).mark(rec.contactUserId, rec.contactKey, Currency.LINK)
        var left = rec.shares
        val release = shares
        if (release != null) {
            for (s in rec.shares) if (release.release(rec.contactUserId, s.view(), uncompared = false)) left = left - s
        }
        codes(acct).put(rec.copy(contactSaved = true, replacesKey = false, shares = left))
        return true
    }

    override fun pendingShares(): Map<String, List<LinkShare>> {
        val acct = account() ?: return emptyMap()
        return codes(acct).all().filter { it.role == CodeRecord.CREATOR && it.shares.isNotEmpty() && !it.failed }
            .groupBy { it.contactUserId }.mapValues { (_, recs) -> recs.flatMap { r -> r.shares.map(StoredShare::view) } }
    }

    override suspend fun releaseShare(contactUserId: String, share: LinkShare): Boolean = lock.withLock {
        val acct = account() ?: return@withLock false
        val release = shares ?: return@withLock false
        val store = codes(acct)
        val stored = StoredShare(share.vaultId, share.role)
        val rec = store.all().filter { it.contactUserId == contactUserId && it.role == CodeRecord.CREATOR && stored in it.shares && !it.failed }
            .maxByOrNull { it.at } ?: return@withLock false
        // The contact must be the pinned one (an uncompared pin made by the link; a key change pins nothing).
        val pinned = acct.store.local().contacts[contactUserId]
        if (pinned == null || pinned.identityPub != rec.contactKey) return@withLock false
        if (!release.release(contactUserId, share, uncompared = !rec.compared)) return@withLock false
        store.put(rec.copy(shares = rec.shares - stored))
        true
    }

    // ---------------------------------------------------------------------------------------------
    // Registration through a link (LinkRegistrations, design §6.4, §6.7)
    // ---------------------------------------------------------------------------------------------

    override fun resolve(step: RecipientStep.Confirm): LinkRegistration? {
        val flow = flowOf(step.token) ?: return null
        if (clock() >= flow.offer.expiresAt) return null
        // A settled flow is a connect link's and holds no secret to register with.
        if (flow.answerKeys != null) return null
        val keys = Links.deriveKeys(crypto, flow.link.secret)
        val token = keys.registerToken
        keys.wipe()
        val origin = flow.link.origin
        return when (val offer = flow.offer) {
            is OpenedOffer.Signed -> if (offer.kind != LinkKind.REGISTER) {
                null
            } else {
                LinkRegistration.Register(origin, offer.instanceId, flow.linkId, token) { id -> registerAnswer(flow, id) }
            }
            is OpenedOffer.Enrol -> LinkRegistration.Enrol(origin, offer.instanceId, flow.linkId, token, offer.fields.email)
            is OpenedOffer.Setup -> {
                val f = offer.fields
                // §6.7 step 2: the opened offer is kept until card 0 is accepted ("Finish setting up this server").
                SetupOffers(state).put(KeptSetup(origin, f.instanceId, f.name, f.kind.literal, f.recoveryFp ?: TrustGrammar.NONE))
                LinkRegistration.Setup(origin, f.instanceId, f.name, f.kind.literal, f.recoveryFp ?: TrustGrammar.NONE, flow.linkId, token)
            }
        }
    }

    private fun registerAnswer(flow: Flow, id: NewIdentity): String? {
        val sealed = sealAnswer(flow, id.userId, id.identityPub, id.signing, id.displayName) ?: return null
        flow.answer = PendingAnswer(id.userId, sealed.nonceB, sealed.answerHash, clock())
        return sealed.envelope
    }

    override fun stopped(registration: LinkRegistration) {
        flows.values.firstOrNull { it.linkId == registration.linkId }?.let(::end)
    }

    override suspend fun registered(registration: LinkRegistration, session: EstablishedSession) {
        val flow = flows.values.firstOrNull { it.linkId == registration.linkId } ?: return
        try {
            val offer = flow.offer as? OpenedOffer.Signed ?: return
            val answer = flow.answer ?: return
            if (registration !is LinkRegistration.Register || answer.userId != session.userId) return
            if (io.silencelen.andvari.core.client.UserIds.isNil(offer.fields.from)) return
            // The register link pins its creator, compared = false, on the new account (§6.7), and keeps the comparison.
            val label = TrustGrammar.encodeName(offer.fields.name) ?: return
            val record = CodeRecord(
                linkId = flow.linkId, role = CodeRecord.ANSWERER, contactUserId = offer.fields.from, contactKey = offer.fields.fromKey,
                label = label, offerHash = offer.offerHash, answerHash = answer.answerHash, nonceB = answer.nonceB, commit = offer.fields.commit,
                at = answer.at,
            )
            val store: AccountStateStore = StoredAccountState(session.userId, session.account.uvk, clientFor(session.origin), crypto, state)
            val acct = LinkAccount(session.origin, session.emailNorm, session.userId, session.deviceId, "", session.account.uvk,
                session.account.identity, session.account.signing, store)
            codes(acct).put(record)
            saveContact(acct, record)
        } finally {
            end(flow)
        }
    }

    companion object {
        const val SHORTEST_MS: Long = 5 * 60 * 1000L
        const val CONNECT_LONGEST_MS: Long = 7 * 24 * 60 * 60 * 1000L
        const val REGISTER_LONGEST_MS: Long = 72 * 60 * 60 * 1000L

        const val NO_SESSION = "no_session"
        const val BAD_KIND = "bad_kind"
        const val BAD_LIFETIME = "bad_lifetime"
        const val SHARES_ON_REGISTER = "shares_on_register"
        const val BAD_SHARE = "bad_share"
        const val NO_PIN = "no_pin"
        const val ANSWER_CHANGED = "answer_changed"

        /** An answer signed by an account whose user id is all zeros, which is never an account: ignored, nothing pinned. */
        const val NIL_ANSWERER = "nil_answerer"

        private val OFFER_STOPS = setOf(
            LinkStop.UNOPENABLE, LinkStop.UNKNOWN_FORMAT, LinkStop.KIND_MISMATCH, LinkStop.BAD_FRAME, LinkStop.NON_CANONICAL,
            LinkStop.BAD_STATEMENT, LinkStop.CREATOR_MISMATCH, LinkStop.SIGNER_NOT_PINNED_KEY, LinkStop.BAD_SIGNATURE,
            LinkStop.LINK_MISMATCH, LinkStop.ORIGIN_MISMATCH, LinkStop.OFFER_EXPIRED, LinkStop.REPORTED_CREATOR_MISMATCH,
        )
        private val PIN_STOPS = setOf(
            LinkStop.ORIGIN_MISMATCH, LinkStop.CARD0_MISMATCH, LinkStop.INSTANCE_MISMATCH, LinkStop.CARD_NOT_IN_CHAIN, LinkStop.FORK,
            LinkStop.WITHHELD, LinkStop.DAMAGED, LinkStop.PIN_CONFLICT, LinkStop.UPDATE_REQUIRED,
        )

        /** The shared verifiers' verdict on an offer, as the flow's stop. [LinkOffer.open] answers only the recipient's verdicts. */
        internal fun offerStop(v: LinkVerdict): LinkStop = OFFER_STOPS.firstOrNull { it.code == v.code } ?: LinkStop.UNOPENABLE

        /** A pinning refusal: one of §2.4's pinning verdicts, or the served chain's own verdict. */
        internal fun pinRefused(code: String): RecipientStep.Stopped =
            PIN_STOPS.firstOrNull { it.code == code }?.let { RecipientStep.Stopped(it) } ?: RecipientStep.Stopped(LinkStop.BAD_CARD, code)
    }
}
