package io.silencelen.andvari.core.model.wire

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

// =====================================================================================================
// Links (spec 03 §15)
// =====================================================================================================

/** Link kinds (spec 03 §15.1). Only `connect` and `register` are created through `POST /links`. */
object LinkKind {
    const val CONNECT = "connect"
    const val REGISTER = "register"
    const val ENROL = "enrol"
    const val SETUP = "setup"
}

/** Link row states (spec 03 §15.8). */
object LinkState {
    const val OPEN = "open"
    const val ANSWERED = "answered"
    const val REVOKED = "revoked"
    const val EXPIRED = "expired"
}

/**
 * `POST /links` (spec 03 §15.2) → `201 {expiresAt, ttlMs}` ([LinkCreatedResponse]). The creating device writes its link record
 * to its own device state durably BEFORE this call (design §6.7 step 2).
 */
@Serializable
data class LinkCreateRequest(
    /** `b64_16`, derived from the secret */
    val linkId: String,
    /** [LinkKind.CONNECT] or [LinkKind.REGISTER] */
    val kind: String,
    /** `envelope` ≤ 2,732 chars: the sealed 0x06 offer */
    val offer: String,
    /** `ms` */
    val expiresAt: Long,
    /** 43 chars, `b64url(SHA-256(ASCII(registerToken)))`; register only */
    val tokenHash: String? = null,
)

/**
 * `GET /links/{linkId}` (spec 03 §15.3). Two shapes in one type:
 * - open: `{kind, offer, expiresAt, state: "open", creatorUserId, creatorIdentityPub, reveal: null}`;
 *   `creator*` are null for host-minted links;
 * - answered: `{kind, state: "answered", reveal}`, with [offer], [expiresAt] and `creator*` absent.
 *
 * Nothing here is trusted: the recipient opens [offer] under its own `offerKey`, requires the offer's
 * kind to equal [kind] (`kind_mismatch`), and compares the signed `from`/`fromKey` with
 * [creatorUserId]/[creatorIdentityPub] only as an anomaly check (design §6.8). [reveal] is accepted
 * only if it matches the offer's commitment (`bad_reveal`), and only once.
 *
 * Encoded by [LinkFetchResponseSerializer]: the open form carries all seven keys, `creator*` as explicit
 * nulls for a host-minted link (spec 03 §0.1 "Field presence": that row gives `null` its meaning); the
 * answered form carries exactly its three.
 */
@Serializable(with = LinkFetchResponseSerializer::class)
data class LinkFetchResponse(
    val kind: String,
    val state: String,
    /** `b64_32` nonceA once the creator posted it, else null. Not secret (bound by the commitment). */
    val reveal: String?,
    val offer: String? = null,
    val expiresAt: Long? = null,
    val creatorUserId: String? = null,
    val creatorIdentityPub: String? = null,
) {
    companion object {
        /** The open form, with its explicit nulls for host-minted links. */
        fun open(kind: String, offer: String, expiresAt: Long, creatorUserId: String?, creatorIdentityPub: String?) =
            LinkFetchResponse(kind, LinkState.OPEN, null, offer, expiresAt, creatorUserId, creatorIdentityPub)

        /** The answered form. */
        fun answered(kind: String, reveal: String?) = LinkFetchResponse(kind, LinkState.ANSWERED, reveal)
    }

    /** Encodes exactly the fields of this response's form (spec 03 §15.3): the open form keeps its `creator*` nulls. */
    fun toJsonObject(): JsonObject = WireJson.json.encodeToJsonElement(LinkFetchResponseSerializer, this) as JsonObject
}

/** Any form, as received: an optional field absent is null. */
@Serializable
private class LinkFetchAnyForm(
    val kind: String,
    val state: String,
    val reveal: String?,
    val offer: String? = null,
    val expiresAt: Long? = null,
    val creatorUserId: String? = null,
    val creatorIdentityPub: String? = null,
)

/** The open form: every key it lists present, its nulls included (no defaults, so all are encoded). */
@Serializable
private class LinkFetchOpenForm(
    val kind: String,
    val offer: String?,
    val expiresAt: Long?,
    val state: String,
    val creatorUserId: String?,
    val creatorIdentityPub: String?,
    val reveal: String?,
)

/** [LinkFetchResponse]'s two shapes (spec 03 §15.3): the open one with every key, any other with what it has. */
@OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
object LinkFetchResponseSerializer : kotlinx.serialization.KSerializer<LinkFetchResponse> {
    override val descriptor: kotlinx.serialization.descriptors.SerialDescriptor =
        kotlinx.serialization.descriptors.SerialDescriptor("LinkFetchResponse", LinkFetchAnyForm.serializer().descriptor)

    override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: LinkFetchResponse) {
        if (value.state == LinkState.OPEN) {
            encoder.encodeSerializableValue(LinkFetchOpenForm.serializer(), LinkFetchOpenForm(value.kind, value.offer, value.expiresAt,
                value.state, value.creatorUserId, value.creatorIdentityPub, value.reveal))
        } else {
            encoder.encodeSerializableValue(LinkFetchAnyForm.serializer(), LinkFetchAnyForm(value.kind, value.state, value.reveal,
                value.offer, value.expiresAt, value.creatorUserId, value.creatorIdentityPub))
        }
    }

    override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): LinkFetchResponse {
        val f = decoder.decodeSerializableValue(LinkFetchAnyForm.serializer())
        return LinkFetchResponse(f.kind, f.state, f.reveal, f.offer, f.expiresAt, f.creatorUserId, f.creatorIdentityPub)
    }
}

/** `POST /links/{linkId}/answer` (spec 03 §15.4): [answer] the sealed 0x07 `envelope`, ≤ 2,732 chars. */
@Serializable
data class LinkAnswerRequest(val answer: String)

/** `POST /links/{linkId}/reveal` (spec 03 §15.5): [nonce] the creator's `b64_32` nonceA. */
@Serializable
data class LinkRevealRequest(val nonce: String)

/**
 * One entry of `GET /links/answers` (spec 03 §15.6). The creating device ignores an answer for a link
 * it holds no record of (`unknown_link`), whatever the server says, and requires the signed answer's
 * `from` to equal [answererUserId] (design §6.8).
 */
@Serializable
data class LinkAnswer(
    val linkId: String,
    /** `envelope` */
    val answer: String,
    val answererUserId: String,
    val answeredAt: Long,
)

// =====================================================================================================
// Device links (spec 03 §16)
// =====================================================================================================

/** Device-link states (spec 03 §16.2). */
object DeviceLinkState {
    const val OPEN = "open"
    const val CLAIMED = "claimed"
    const val REVEALED = "revealed"
    const val APPROVED = "approved"
}

/** `POST /device-links` (spec 03 §16.2) → `201 {expiresAt, ttlMs}` ([LinkCreatedResponse]); the server stores `min(expiresAt, now + 5 min)`. */
@Serializable
data class DeviceLinkCreateRequest(val linkId: String, val expiresAt: Long)

/**
 * N's claim (spec 03 §16.4): the body of `POST /device-links/{linkId}/claim`, and `claim` in E's view.
 * [nPub] `b64_32` (ephemeral X25519), [name] the `name` type, [platform] a [WirePlatform] value,
 * [commitN] `hex64`, [mac] `b64_32`. E verifies [mac] under its `macKey` and fixes the claim when it
 * draws `nonceE` (design §8.2 step 3).
 */
@Serializable
data class DeviceLinkClaim(
    val nPub: String,
    val name: String,
    val platform: String,
    val commitN: String,
    val mac: String,
)

/** `GET /device-links/{linkId}` (spec 03 §16.3), E's view: each optional field present once it exists. */
@Serializable
data class DeviceLinkView(
    val state: String,
    val expiresAt: Long,
    val claim: DeviceLinkClaim? = null,
    /** `b64_32` */
    val nonceE: String? = null,
    /** `b64_32` */
    val nonceN: String? = null,
)

/** `POST /device-links/{linkId}/nonce` (spec 03 §16.5): [nonceE] `b64_32`, [proofHash] `hex64`. */
@Serializable
data class DeviceLinkNonceRequest(val nonceE: String, val proofHash: String)

/** `POST /device-links/{linkId}/poll` (spec 03 §16.5): `{proof}` (`b64_32`). */
@Serializable
data class DeviceLinkPollRequest(val proof: String)

/**
 * N's view (spec 03 §16.5): `{state}`, then `{state, nonceE}`, then `{state, nonceE, outer, approveMac}`.
 * N holds the FIRST [nonceE] it received; a different one later cancels (design §8.2 step 4). N opens
 * [outer] and checks [approveMac] over it before any password prompt (step 7).
 */
@Serializable
data class DeviceLinkPollResponse(
    val state: String,
    val nonceE: String? = null,
    /** `sealed` to nPub */
    val outer: String? = null,
    /** `b64_32` */
    val approveMac: String? = null,
)

/** `POST /device-links/{linkId}/reveal` (spec 03 §16.5): [nonceN] `b64_32`, [proof] `b64_32`. */
@Serializable
data class DeviceLinkRevealRequest(val nonceN: String, val proof: String)

/** `POST /device-links/{linkId}/approve` (spec 03 §16.6). */
@Serializable
data class DeviceLinkApproveRequest(
    /** `sealed` ≤ 1,400 chars: `crypto_box_seal(nPub, DeviceLinkOuter)` */
    val outer: String,
    /** `envelope`: the bundle under the UVK-derived bundle key */
    val inner: String,
    /** `b64_32` over `outer` only */
    val approveMac: String,
)

/** `POST /device-links/{linkId}/pickup` (spec 03 §16.6). Sent only to the origin N pinned before it claimed. */
@Serializable
data class DeviceLinkPickupRequest(
    val proof: String,
    val authKey: String,
    val totp: String? = null,
    val device: PickupDevice,
)

/** The pickup's device object: only the secret (spec 03 §16.6); the name and platform are the claim's. */
@Serializable
data class PickupDevice(val deviceSecret: String)

/**
 * `200 {inner, session}` (spec 03 §16.6), given once. [session] is the same [SessionResponse] a login answers: the
 * ids, the tokens, the account's keys, the `role` and the two-step flags, so a linked device never guesses them.
 */
@Serializable
data class DeviceLinkPickupResponse(
    /** `envelope` */
    val inner: String,
    val session: SessionResponse,
)

/*
 * `outer`'s plaintext and the bundle (spec 03 §16.6, §16.9) have ONE strict decoder each, the shared verifiers'
 * [io.silencelen.andvari.core.trust.DeviceLink.openOuter] (behind the approveMac) and
 * [io.silencelen.andvari.core.trust.DeviceLink.openBundle] / `decodeBundle` / `checkBundle`, with their types
 * [io.silencelen.andvari.core.trust.DeviceLinkOuter] and [io.silencelen.andvari.core.trust.DeviceLinkBundle]. The wire
 * carries both only as opaque `sealed` and `envelope` strings ([DeviceLinkApproveRequest], [DeviceLinkPollResponse],
 * [DeviceLinkPickupResponse]); nothing here decodes them a second way.
 */
