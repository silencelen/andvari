package io.silencelen.andvari.core.model.wire

import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject

// =====================================================================================================
// Instance and policy (spec 03 §1.1, §17)
// =====================================================================================================

/**
 * `GET /client-policy` (spec 03 §1.1). Read from an unauthenticated endpoint on an untrusted server:
 * every field is either TRUSTED-as-declared (it describes the server's own behaviour), CLIENT-FLOOR-ONLY
 * (applied only through the tighten-only `applyPolicy`, which can never relax a client protection), or
 * DECORATIVE (never rendered as verified identity). The instance's identity, `kind` and recovery key
 * are NOT here: they come only from the signed instance card (§17).
 *
 * A fetch or decode failure means the conservative defaults of §1.1 (sign-up `closed`, durable cache
 * off), never these field defaults.
 */
@Serializable
data class ClientPolicy(
    /** CLIENT-FLOOR-ONLY: force-upgrade only. Keyed by `platform` (§0.1). */
    val minVersion: Map<String, String>,
    /** CLIENT-FLOOR-ONLY: existing floors, incl. the cache-read sub-floor (spec 05 T8). */
    val kdfParams: KdfParams,
    /** CLIENT-FLOOR-ONLY: clamped into `[floor, AUTO_LOCK_MAX_SECONDS]`; 0 clamps to the ceiling. */
    val autoLockSeconds: Long,
    /** CLIENT-FLOOR-ONLY: clamped into `[1, CLIPBOARD_CLEAR_MAX_SECONDS]`. */
    val clipboardClearSeconds: Long,
    /** CLIENT-FLOOR-ONLY (forbid-only): false wipes the declaring origin's namespace; true is never sufficient. */
    val offlineCacheAllowed: Boolean,
    /** TRUSTED (informational). */
    val sessionAccessTtlSeconds: Long,
    /** TRUSTED (informational). */
    val sessionRefreshTtlDays: Long,
    /** TRUSTED (informational): the server's own per-file ceiling. */
    val attachmentMaxBytes: Long,
    /** TRUSTED (informational): the server's own per-item ceiling. */
    val itemAttachmentsMaxBytes: Long,
    /** TRUSTED (informational), `ms`. Never a security anchor. */
    val serverTime: Long,
    /** TRUSTED (UI hint): which sign-up UI renders. Registration stays server-enforced (§14). */
    val signup: SignupPolicy,
    /** TRUSTED (UI hint): pre-shows the TOTP field; the reactive server errors stay authoritative. */
    val totpRequired: Boolean,
    /** DECORATIVE: never rendered as a verified identity; the signed name is the card's. */
    val instanceName: String? = null,
    /** DECORATIVE: a proxy-misconfig diagnostic, never a trust anchor (the card's `origin` is signed). */
    val canonicalOrigin: String? = null,
    /** DECORATIVE: rendered as a raw https URL only. */
    val selfHostDocsUrl: String? = null,
)

/** `ClientPolicy.signup` (spec 03 §1.1): the effective mode, the cap state, and the sign-up form switches. */
@Serializable
data class SignupPolicy(
    /** [SignupMode] value: the stricter of the environment's and the operator's. */
    val mode: String,
    /** True when the effective cap is reached. */
    val full: Boolean,
    val ageConfirmRequired: Boolean,
    /** Leading zero bits of the sign-up proof of work (§14.1); 0 = none. */
    val powBits: Int,
)

/**
 * `GET /instance` (spec 03 §17.1). Normally `{cards, rotations}`: every stored card frame (purpose 0x04),
 * card 0 first, and every stored 0x08 rotation frame, oldest first. Before card 0 exists it is
 * `{cards: [], setup}` and [rotations] is absent.
 *
 * Nothing here is trusted as served: a client verifies the chain forward from its pin (spec 01 §5.3,
 * design §4.4), and [setup] is used only by a signed-in operator resuming setup or by the setup link's
 * "no cards yet" check — never as a pin (§17.1).
 */
@Serializable
data class InstanceResponse(
    /** `frame` list, purpose 0x04. */
    val cards: List<String>,
    /** `frame` list, purpose 0x08; null (absent) in the setup form. */
    val rotations: List<String>? = null,
    /** Present only while no card is stored. */
    val setup: InstanceSetup? = null,
)

/** The values `andvari setup` wrote, served while no card exists (spec 03 §17.1). Never a pin. */
@Serializable
data class InstanceSetup(
    /** `uuid` */
    val instanceId: String,
    /** `origin` */
    val origin: String,
    /** `name` type (base64url of UTF-8, spec 01 §5.1). */
    val name: String,
    /** [InstanceKind] value. */
    val kind: String,
    /** `hex64n` */
    val recoveryFp: String,
)

/** `PUT /instance/card` (spec 03 §17.2), operator†. [card] is a 0x04 `frame`. */
@Serializable
data class InstanceCardPut(val card: String, val currentAuthKey: String)

/** `PUT /instance/card` → `200 {seq, hash}`: the stored card's position and frame hash (`hex64`). */
@Serializable
data class InstanceCardPutResponse(val seq: Long, val hash: String)

/** `PUT /instance/rotation` (spec 03 §17.3), operator†, R. [statement] is a 0x08 `frame`. */
@Serializable
data class InstanceRotationPut(val statement: String, val currentAuthKey: String)

// =====================================================================================================
// Sign-up (spec 03 §14.1, §14.2)
// =====================================================================================================

/** `POST /signup/start` (spec 03 §14.1). [email] is an `emailText`; the server derives `emailNorm`. */
@Serializable
data class SignupStartRequest(
    val email: String,
    val ageConfirmed: Boolean,
    val pow: SignupPow? = null,
)

/** The sign-up proof of work (spec 03 §14.1): [date] the UTC `YYYY-MM-DD` hashed, [nonce] an `int`. */
@Serializable
data class SignupPow(val date: String, val nonce: Long)

/** `202 {"status":"sent"}`, uniform whether or not the address has an account (spec 03 §14.1). */
@Serializable
data class SignupStartResponse(val status: String) {
    companion object {
        const val SENT = "sent"
    }
}

/** `POST /signup/verify` (spec 03 §14.2). [code] is the 6-digit code as typed, a string (leading zeros kept). */
@Serializable
data class SignupVerifyRequest(val email: String, val code: String)

/** `200 {signupTicket, expiresAt}`: [signupTicket] a `b64_32`, single use; [expiresAt] `ms`. */
@Serializable
data class SignupVerifyResponse(val signupTicket: String, val expiresAt: Long)

// =====================================================================================================
// Registration (spec 03 §14.3)
// =====================================================================================================

/**
 * `POST /auth/register` (spec 03 §14.3). The client chooses [userId] (the AEAD ADs bind it).
 *
 * [memberRecovery] is nullable only so that a server can answer its absence with the step-1 code
 * `400 recovery_required` rather than a decode failure; every client sends it.
 */
@Serializable
data class RegisterRequest(
    val auth: RegisterAuth,
    /** `emailText` */
    val email: String,
    /** `text` */
    val displayName: String,
    /** `uuid`, client-chosen */
    val userId: String,
    /** `b64` */
    val kdfSalt: String,
    val kdfParams: KdfParams,
    /** `b64` */
    val authKey: String,
    /** `envelope`, ≤ 1 KiB */
    val wrappedUvk: String,
    /** `b64_32` (X25519) */
    val identityPub: String,
    /** `envelope`, ≤ 1 KiB */
    val encryptedIdentitySeed: String,
    /** `frame`, purpose 0x05 (the account genesis, spec 01 §5.4) */
    val genesis: String,
    val personalVault: PersonalVaultUpload,
    val personalWrap: PersonalWrap,
    val memberRecovery: MemberRecoveryBlock? = null,
    val recovery: RecoveryChoice,
    val ageConfirmed: Boolean,
    val device: NewDevice,
)

/**
 * The `auth` member of a registration (spec 03 §14.3): **exactly one key**, one of `signupTicket`,
 * `link`, `enrol`, `setup`. The decoder is strict about the key set ([RegisterAuthSerializer]); the
 * inner objects follow the lenient rule of §0.1.
 */
@Serializable(with = RegisterAuthSerializer::class)
sealed class RegisterAuth {
    /** `{"signupTicket": <b64_32>}`: an email-verified sign-up ticket (§14.2). */
    data class Ticket(val signupTicket: String) : RegisterAuth()

    /** `{"link": {linkId, registerToken, answer}}`: a register link (§15.1). [answer] is the sealed 0x07 answer `envelope`, ≤ 2,732 chars. */
    data class Link(val linkId: String, val registerToken: String, val answer: String) : RegisterAuth()

    /** `{"enrol": {linkId, registerToken}}`: a host-minted enrol link (§15.1). */
    data class Enrol(val linkId: String, val registerToken: String) : RegisterAuth()

    /** `{"setup": {linkId, registerToken}}`: the setup link that enrols the first operator (§17.5). */
    data class Setup(val linkId: String, val registerToken: String) : RegisterAuth()

    /** The JSON key this variant travels under. */
    val key: String
        get() = when (this) {
            is Ticket -> "signupTicket"
            is Link -> "link"
            is Enrol -> "enrol"
            is Setup -> "setup"
        }
}

@Serializable
private data class RegisterAuthLinkBody(val linkId: String, val registerToken: String, val answer: String)

@Serializable
private data class RegisterAuthTokenBody(val linkId: String, val registerToken: String)

/** Strict `auth` codec: exactly one key, and it must be a known one; anything else is a decode failure (`400 bad_request`). */
object RegisterAuthSerializer : KSerializer<RegisterAuth> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("RegisterAuth")

    override fun serialize(encoder: Encoder, value: RegisterAuth) {
        val enc = encoder as? JsonEncoder ?: throw SerializationException("RegisterAuth is JSON-only")
        val j = enc.json
        val obj = buildJsonObject {
            when (value) {
                is RegisterAuth.Ticket -> put("signupTicket", kotlinx.serialization.json.JsonPrimitive(value.signupTicket))
                is RegisterAuth.Link -> put("link", j.encodeToJsonElement(RegisterAuthLinkBody.serializer(), RegisterAuthLinkBody(value.linkId, value.registerToken, value.answer)))
                is RegisterAuth.Enrol -> put("enrol", j.encodeToJsonElement(RegisterAuthTokenBody.serializer(), RegisterAuthTokenBody(value.linkId, value.registerToken)))
                is RegisterAuth.Setup -> put("setup", j.encodeToJsonElement(RegisterAuthTokenBody.serializer(), RegisterAuthTokenBody(value.linkId, value.registerToken)))
            }
        }
        enc.encodeJsonElement(obj)
    }

    override fun deserialize(decoder: Decoder): RegisterAuth {
        val dec = decoder as? JsonDecoder ?: throw SerializationException("RegisterAuth is JSON-only")
        val obj = dec.decodeJsonElement() as? JsonObject ?: throw SerializationException("auth: not an object")
        if (obj.size != 1) throw SerializationException("auth: exactly one key required")
        val (k, v) = obj.entries.single()
        val j = dec.json
        return when (k) {
            "signupTicket" -> {
                val p = v as? kotlinx.serialization.json.JsonPrimitive
                if (p == null || !p.isString) throw SerializationException("auth.signupTicket: not a string")
                RegisterAuth.Ticket(p.content)
            }
            "link" -> j.decodeFromJsonElement(RegisterAuthLinkBody.serializer(), v).let { RegisterAuth.Link(it.linkId, it.registerToken, it.answer) }
            "enrol" -> j.decodeFromJsonElement(RegisterAuthTokenBody.serializer(), v).let { RegisterAuth.Enrol(it.linkId, it.registerToken) }
            "setup" -> j.decodeFromJsonElement(RegisterAuthTokenBody.serializer(), v).let { RegisterAuth.Setup(it.linkId, it.registerToken) }
            else -> throw SerializationException("auth: unknown kind")
        }
    }
}

/** `personalVault` of a registration (spec 03 §14.3): the personal vault row. */
@Serializable
data class PersonalVaultUpload(
    /** `uuid`; must equal the genesis' `personalVaultId` (§14.3 step 9). */
    val vaultId: String,
    /** `envelope`, ≤ 1 KiB */
    val wrappedVk: String,
    /** `envelope`, ≤ 4 KiB */
    val metaBlob: String,
)

/**
 * The personal vault's key under the UVK (spec 03 §3; AD `andvari/v1|vk-personal|…`, spec 01 §6). Set
 * once at registration, never replaced (design §5.3). Served in [AccountKeys.personalWrap].
 *
 * A device puts it in force only when it opens under the UVK AND [vaultId] equals the verified
 * genesis' `personalVaultId` (design §5.2, §5.3); the server can withhold it but never relabel it.
 */
@Serializable
data class PersonalWrap(
    /** `uuid` */
    val vaultId: String,
    /** `envelope`, ≤ 1 KiB */
    val wrappedVk: String,
)

/** The member-recovery block (spec 03 §12): the UVK under the kit's wrap key, and the kit's auth proof. */
@Serializable
data class MemberRecoveryBlock(
    /** `envelope`, ≤ 1 KiB, AD `andvari/v1|recovery-uvk|{userId}` */
    val recoveryWrappedUvk: String,
    /** `b64` */
    val recoveryAuthKey: String,
)

/**
 * `recovery` of a registration (spec 03 §14.3): `{"posture":"private"}` or
 * `{"posture":"operator","escrow":{sealed, fingerprint}}`. [escrow] is present exactly when
 * [posture] is `operator`; the server answers the other combinations with its own codes
 * (`escrow_not_allowed`, `bad_escrow`), so the decoder does not enforce the pairing.
 */
@Serializable
data class RecoveryChoice(
    /** [RecoveryPosture] value. */
    val posture: String,
    val escrow: EscrowUpload? = null,
)

/** An escrow (spec 04 §3): [sealed] the 0x02 `sealed` blob, [fingerprint] the `hex64` of the recovery key it is sealed to. */
@Serializable
data class EscrowUpload(val sealed: String, val fingerprint: String)

/**
 * The device object of every device-creating call that names a new device (spec 03 §14.3, §12, §18.5):
 * [platform] a [WirePlatform] value, [name] a `text`, [deviceSecret] the device's own `b64_32` (§0.3).
 */
@Serializable
data class NewDevice(val platform: String, val name: String, val deviceSecret: String)

// =====================================================================================================
// Sessions (spec 03 §2)
// =====================================================================================================

/** `POST /auth/prelogin` (spec 03 §2). Sent only under the password rule (design §4.4). */
@Serializable
data class PreloginRequest(val email: String)

/** `200 {kdfSalt, kdfParams}`. Unknown emails get a deterministic fake salt and the current default params. */
@Serializable
data class PreloginResponse(val kdfSalt: String, val kdfParams: KdfParams)

/**
 * `POST /auth/login` (spec 03 §2). [totp] is the 6-digit code when two-step sign-in asks for it. [replacesRefreshToken]
 * names the session this sign-in replaces, by the refresh token the device last held for it: set only for a session of
 * the same account at the same origin that this device keeps on the very row the login names ([LoginDevice.deviceId]).
 * Once the whole sign-in has succeeded, the server ends exactly that session in the same transaction, also when the token
 * is one it had already replaced (an answer the device lost), which it then records as such and never as a reuse.
 * Omitted when null; a server without the field ignores it.
 */
@Serializable
data class LoginRequest(
    val email: String,
    /** `b64` */
    val authKey: String,
    val device: LoginDevice,
    val totp: String? = null,
    val replacesRefreshToken: String? = null,
)

/**
 * The login device object (spec 03 §2): `{platform, name, deviceSecret, deviceId?}`. The login is from a
 * **known device** only when [deviceId] AND [deviceSecret] both match a live, unrevoked device of the
 * account; anything else creates a new device row.
 */
@Serializable
data class LoginDevice(
    val platform: String,
    val name: String,
    val deviceSecret: String,
    /** `uuid`, sent by a device that already holds a device row on this account. */
    val deviceId: String? = null,
)

/**
 * The session answer of login, register, both recovery commits (spec 03 §2). [role] is an
 * [AccountRole] value. [recoveryPieceId] is present only on the routes that commit a new recovery
 * piece (register and both recovery commits).
 *
 * Every served id here is checked against the canonical lowercase UUID grammar at decode by the
 * engine (spec 05 R18); [role] decides only which views a native client offers (the server enforces).
 */
@Serializable
data class SessionResponse(
    val userId: String,
    val deviceId: String,
    val accessToken: String,
    val refreshToken: String,
    val accountKeys: AccountKeys,
    val role: String,
    val totpEnrolled: Boolean,
    val mustEnrollTotp: Boolean,
    val recoveryPieceId: String? = null,
)

/** `POST /auth/refresh` (spec 03 §2). */
@Serializable
data class RefreshRequest(val refreshToken: String)

/** `200 {accessToken, refreshToken}`: the rotated pair. */
@Serializable
data class TokenPair(val accessToken: String, val refreshToken: String)

// ---- server TOTP (spec 03 §2) ----

/** `GET /account/totp`. */
@Serializable
data class TotpStatus(val enrolled: Boolean, val pendingSetup: Boolean)

/** `POST /account/totp/setup` optional body: [code] rotates an enrolled factor; [currentAuthKey] proves the password for a first enrollment. */
@Serializable
data class TotpSetupRequest(val code: String? = null, val currentAuthKey: String? = null)

/** `200 {secretBase32, otpauthUri}`, pending until confirmed. */
@Serializable
data class TotpSetupResponse(val secretBase32: String, val otpauthUri: String)

/** `POST /account/totp/confirm`: `{code}`. (Before 2026-11-16 the disable took it too; it now takes [TotpDisableRequest].) */
@Serializable
data class TotpCodeRequest(val code: String)

/**
 * `POST /account/totp/disable` (†): a current code and a fresh master-password proof. The server checks the proof first,
 * on its own back-off, and looks at the code only after a right one (decided on 2026-11-16): a session alone can no
 * longer remove the second factor by guessing codes. [currentAuthKey] is sent only to the session's own origin.
 */
@Serializable
data class TotpDisableRequest(val code: String, val currentAuthKey: String)

/** The `{currentAuthKey}` body of † routes that take nothing else (spec 03 §0.1). */
@Serializable
data class ReauthRequest(
    /** `b64`: a fresh master-password proof. Sent only to the origin of this account's session (design §4.4). */
    val currentAuthKey: String,
)
