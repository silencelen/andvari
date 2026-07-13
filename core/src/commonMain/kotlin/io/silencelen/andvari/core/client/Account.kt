package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.EscrowUpload
import io.silencelen.andvari.core.model.ItemUpload
import io.silencelen.andvari.core.model.ItemVersion
import io.silencelen.andvari.core.model.MemberRecoveryBlock
import io.silencelen.andvari.core.model.PersonalVaultUpload
import io.silencelen.andvari.core.model.RecoveryCommitRequest
import io.silencelen.andvari.core.model.RecoverySelfSetupRequest
import io.silencelen.andvari.core.model.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.KeepGeneratedSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.elementNames
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * Spec 02 §3 unknown-field contract: JSON keys this client version does not know MUST be
 * preserved on rewrite (forward compatibility within a formatVersion). Every level of the
 * item document carries a decode-computed [extras] overlay; this wrapper splits the JSON
 * object into typed fields (delegated to the plugin-generated serializer) plus the
 * remainder, and re-merges on encode. Typed fields always win over a same-named extras
 * entry, judged against the generated DESCRIPTOR's element names — never the emitted
 * object — so encodeDefaults can never let a stale extras copy shadow a defaulted field.
 * JSON-only by design: item documents are (de)serialized solely by [Account] (the durable
 * cache and offline queue store ciphertext envelopes, never decoded docs).
 */
@OptIn(ExperimentalSerializationApi::class)
internal abstract class ExtrasOverlaySerializer<T>(
    private val delegate: KSerializer<T>,
    private val extrasOf: (T) -> Map<String, JsonElement>,
    private val withExtras: (T, Map<String, JsonElement>) -> T,
) : KSerializer<T> {
    override val descriptor: SerialDescriptor get() = delegate.descriptor
    private val known = delegate.descriptor.elementNames.toSet()

    override fun deserialize(decoder: Decoder): T {
        val jd = decoder as? JsonDecoder ?: throw SerializationException("item documents are JSON-only")
        val obj = jd.decodeJsonElement().jsonObject
        // Delegate only the known keys (a strict Json instance would throw on unknowns).
        val typed = jd.json.decodeFromJsonElement(delegate, JsonObject(obj.filterKeys { it in known }))
        val rest = obj.filterKeys { it !in known }
        return if (rest.isEmpty()) typed else withExtras(typed, rest)
    }

    override fun serialize(encoder: Encoder, value: T) {
        val je = encoder as? JsonEncoder ?: throw SerializationException("item documents are JSON-only")
        val emitted = je.json.encodeToJsonElement(delegate, value).jsonObject
        val rest = extrasOf(value).filterKeys { it !in known }
        je.encodeJsonElement(JsonObject(emitted + rest))
    }
}

/** Item plaintext document (spec 02 §3) — shared client model. The [extras] overlays are
 *  @Transient so the mechanism never leaks a literal "extras" key into the wire format;
 *  `copy()` carries them, which is what keeps edits and conflict materialization lossless. */
@OptIn(ExperimentalSerializationApi::class)
@kotlinx.serialization.Serializable(with = LoginDataSerializer::class)
@KeepGeneratedSerializer
data class LoginData(
    val username: String? = null,
    val password: String? = null,
    val uris: List<String> = emptyList(),
    val totp: String? = null,
    val passwordHistory: List<PasswordHistoryEntry> = emptyList(),
    @kotlinx.serialization.Transient val extras: Map<String, JsonElement> = emptyMap(),
)

@OptIn(ExperimentalSerializationApi::class)
@kotlinx.serialization.Serializable(with = PasswordHistoryEntrySerializer::class)
@KeepGeneratedSerializer
data class PasswordHistoryEntry(
    val password: String,
    val retiredAt: Long,
    @kotlinx.serialization.Transient val extras: Map<String, JsonElement> = emptyMap(),
)

/** Card fields (spec 02 §3, formatVersion 2) — all ciphertext inside the item envelope;
 *  the server sees only the plaintext formatVersion integer. Canonical stored forms
 *  (adapters derive display/fill variants): number digits-only, expMonth "01".."12",
 *  expYear 4-digit, securityCode 3-4 digits (storing it is an explicit per-card choice),
 *  brand visa|mastercard|amex|discover derived from the IIN at every save — display-only,
 *  never authored, so it can't go stale. */
@OptIn(ExperimentalSerializationApi::class)
@kotlinx.serialization.Serializable(with = CardDataSerializer::class)
@KeepGeneratedSerializer
data class CardData(
    val cardholderName: String? = null,
    val number: String? = null,
    val expMonth: String? = null,
    val expYear: String? = null,
    val securityCode: String? = null,
    val brand: String? = null,
    @kotlinx.serialization.Transient val extras: Map<String, JsonElement> = emptyMap(),
)

/** Mirrors the plaintext attachment entry (spec 02 §3) — the SECRET half of attachmentIds. */
@OptIn(ExperimentalSerializationApi::class)
@kotlinx.serialization.Serializable(with = AttachmentRefSerializer::class)
@KeepGeneratedSerializer
data class AttachmentRef(
    val id: String,
    val name: String,
    val size: Long,
    val fileKey: String,
    @kotlinx.serialization.Transient val extras: Map<String, JsonElement> = emptyMap(),
)

@OptIn(ExperimentalSerializationApi::class)
@kotlinx.serialization.Serializable(with = ItemDocSerializer::class)
@KeepGeneratedSerializer
data class ItemDoc(
    val type: String, // "login" | "note" | "card" — chosen at creation, never changes
    val name: String,
    val notes: String? = null,
    val favorite: Boolean = false,
    val login: LoginData? = null,
    val card: CardData? = null,
    val attachments: List<AttachmentRef> = emptyList(),
    @kotlinx.serialization.Transient val extras: Map<String, JsonElement> = emptyMap(),
)

@OptIn(ExperimentalSerializationApi::class)
internal object LoginDataSerializer : ExtrasOverlaySerializer<LoginData>(LoginData.generatedSerializer(), LoginData::extras, { v, e -> v.copy(extras = e) })

@OptIn(ExperimentalSerializationApi::class)
internal object PasswordHistoryEntrySerializer : ExtrasOverlaySerializer<PasswordHistoryEntry>(PasswordHistoryEntry.generatedSerializer(), PasswordHistoryEntry::extras, { v, e -> v.copy(extras = e) })

@OptIn(ExperimentalSerializationApi::class)
internal object CardDataSerializer : ExtrasOverlaySerializer<CardData>(CardData.generatedSerializer(), CardData::extras, { v, e -> v.copy(extras = e) })

@OptIn(ExperimentalSerializationApi::class)
internal object AttachmentRefSerializer : ExtrasOverlaySerializer<AttachmentRef>(AttachmentRef.generatedSerializer(), AttachmentRef::extras, { v, e -> v.copy(extras = e) })

@OptIn(ExperimentalSerializationApi::class)
internal object ItemDocSerializer : ExtrasOverlaySerializer<ItemDoc>(ItemDoc.generatedSerializer(), ItemDoc::extras, { v, e -> v.copy(extras = e) })

/**
 * The result of [Account.enroll]: the one-shot [RegisterRequest], the unlocked [Account], and the
 * SHOWN-ONCE [recoverySecret] — the raw 32 CSPRNG bytes of the member's self-service recovery piece
 * (design 2026-07-12 §F.6/§F.7). The UI displays [recoverySecret] once (via
 * [io.silencelen.andvari.core.crypto.MemberRecovery.displayForm]) for the member to save, gates
 * account use behind an un-skippable type-it-back confirm
 * ([io.silencelen.andvari.core.crypto.MemberRecovery.confirmMatches]), then DROPS it — it is never
 * persisted or logged. Destructures as `(request, account)` so existing call sites are unchanged;
 * the secret is [component3].
 */
class EnrollResult(val request: RegisterRequest, val account: Account, val recoverySecret: ByteArray) {
    operator fun component1(): RegisterRequest = request
    operator fun component2(): Account = account
    operator fun component3(): ByteArray = recoverySecret
}

/**
 * The result of [Account.setupMemberRecovery]: the [RecoverySelfSetupRequest] to PUT and the same
 * SHOWN-ONCE [recoverySecret] discipline as [EnrollResult] (design §F.6/§F.7).
 */
class SelfSetupResult(val request: RecoverySelfSetupRequest, val recoverySecret: ByteArray)

/**
 * An unlocked account — the Kotlin sibling of web/src/vault/account.ts. Holds the
 * in-memory UVK + personal vault key and performs item AEAD (AD-bound to
 * userId/vaultId/itemId, spec 02 §2). Nothing here is persisted in the clear.
 * Native clients (Android/desktop) and the JVM tests share this exact logic.
 */
class Account private constructor(
    private val crypto: CryptoProvider,
    val userId: String,
    private val uvk: ByteArray,
    val identityPub: ByteArray,
    private val identityPriv: ByteArray,
    var personalVaultId: String,
    private val vaultKeys: MutableMap<String, ByteArray>,
    private val vaultRoles: MutableMap<String, String> = mutableMapOf(),
) {
    companion object {
        /** Highest item formatVersion this client can decrypt (spec 02 §3 fail-closed). */
        const val ITEM_FORMAT_VERSION = 2

        /**
         * Lowest formatVersion a doc may seal at (spec 02 §3): card-bearing docs 2,
         * logins/notes 1. The floor is the one plaintext signal a zero-knowledge server
         * gets — it turns a pre-card client's rewrite (a plain decode silently drops the
         * unknown `card` key) into a server-refused fv downgrade instead of silent loss,
         * while fv1 docs stay fully readable on every fielded client.
         */
        fun docFloor(doc: ItemDoc): Int = if (doc.card != null || doc.type == "card") 2 else 1

        private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

        // platform must match the AndvariApi wire tag ("android" | "windows" | "linux") so
        // device rows and audit entries agree with the minVersion gate's view of the client.
        fun deviceInfo(name: String, platform: String = "android"): DeviceInfo = DeviceInfo(platform, name)

        /** Derive the login authKey a fresh device sends after prelogin. */
        fun deriveAuthKey(password: String, kdfSaltB64: String, params: KdfParams, crypto: CryptoProvider = createCryptoProvider()): String {
            val mk = Keys.masterKey(crypto, password, Bytes.fromB64(kdfSaltB64), params)
            return Bytes.toB64(Keys.authKey(crypto, mk))
        }

        /**
         * Enrollment (design 2026-07-12 §F.4): generate all keys, ALWAYS mint the per-member
         * self-service recovery piece, CONDITIONALLY seal org escrow, and return the one-shot
         * register request plus the SHOWN-ONCE recovery secret.
         *
         * Escrow is policy-driven by the org key: pass [recoveryPublicKey] (+ its verified
         * [recoveryFingerprint]) for a `required` invite → the UVK is sealed to the org key with the
         * existing verified-fingerprint discipline (spec 05 T10 / [resealEscrowFor]). Pass null (the
         * `waived` posture) → NO org escrow blob (per-member piece only; server rejects escrow if the
         * invite is waived). The member-recovery piece is MANDATORY regardless, so an account can
         * never be created with neither recovery path.
         *
         * Returns [EnrollResult] — `(request, account)` destructures as before; [EnrollResult.recoverySecret]
         * is the raw 32 bytes the UI must show ONCE and then drop.
         */
        fun enroll(
            inviteToken: String,
            email: String,
            displayName: String,
            password: String,
            params: KdfParams,
            recoveryPublicKey: ByteArray?,
            recoveryFingerprint: String?,
            deviceName: String,
            crypto: CryptoProvider = createCryptoProvider(),
        ): EnrollResult {
            val userId = uuid(crypto)
            val personalVaultId = uuid(crypto)
            val kdfSalt = crypto.randomBytes(KdfParams.SALT_BYTES)
            val mk = Keys.masterKey(crypto, password, kdfSalt, params)
            val authKey = Keys.authKey(crypto, mk)
            val wrapKey = Keys.wrapKey(crypto, mk)

            val uvk = crypto.randomBytes(32)
            val identitySeed = crypto.randomBytes(32)
            val identity = crypto.boxKeypairFromSeed(identitySeed)
            val vk = crypto.randomBytes(32)

            // Org escrow is CONDITIONAL (§F.4): sealed only for a `required` invite (org key present),
            // preserving the verified-fingerprint discipline — refuse to seal the UVK to a key whose
            // fingerprint the enrollee did not confirm out-of-band. Waived ⇒ no escrow blob.
            val escrow: EscrowUpload? = if (recoveryPublicKey != null) {
                val fp = requireNotNull(recoveryFingerprint) { "recoveryFingerprint is required when sealing org escrow" }
                val computedFp = Escrow.fingerprint(crypto, recoveryPublicKey)
                if (computedFp != fp) throw CryptoException("recovery public key does not match its fingerprint")
                EscrowUpload(Bytes.toB64(Escrow.sealUvk(crypto, recoveryPublicKey, userId, uvk)), fp)
            } else {
                null
            }

            // Per-member self-service recovery piece — MANDATORY for every new account (§F.4). The
            // 256-bit recoverySecret is GENERATED (never user input) and returned to be SHOWN ONCE.
            val recovery = MemberRecovery.generate(crypto, userId, uvk)

            val req = RegisterRequest(
                inviteToken = inviteToken,
                userId = userId,
                email = email,
                displayName = displayName,
                kdfSalt = Bytes.toB64(kdfSalt),
                kdfParams = params,
                authKey = Bytes.toB64(authKey),
                wrappedUvk = Envelope.sealB64(crypto, wrapKey, uvk, Ad.uvk(userId)),
                identityPub = Bytes.toB64(identity.publicKey),
                encryptedIdentitySeed = Envelope.sealB64(crypto, uvk, identitySeed, Ad.idkey(userId)),
                escrow = escrow,
                memberRecovery = MemberRecoveryBlock(recovery.recoveryWrappedUvk, recovery.recoveryAuthKey),
                personalVault = PersonalVaultUpload(
                    vaultId = personalVaultId,
                    wrappedVk = Envelope.sealB64(crypto, uvk, vk, Ad.vk(personalVaultId, userId)),
                    metaBlob = Envelope.sealB64(crypto, vk, """{"name":"Personal"}""".encodeToByteArray(), Ad.vaultMeta(personalVaultId)),
                ),
                device = DeviceInfo("android", deviceName),
            )
            val account = Account(
                crypto, userId, uvk, identity.publicKey, identity.privateKey, personalVaultId,
                mutableMapOf(personalVaultId to vk), mutableMapOf(personalVaultId to "owner"),
            )
            return EnrollResult(req, account, recovery.recoverySecret)
        }

        /**
         * Self-service account recovery (design §F.3, client half of `POST /recovery/self/commit`).
         * Opens the SAME UVK from the recovery piece, routes it through the shared unlock tail so the
         * spec 01 §5 identity-pubkey HARD-FAIL fires (a server that substituted an identity key is
         * caught BEFORE commit), then derives fresh {kdfSalt, authKey, wrapKey} from [newPassword] and
         * re-wraps the UVK — producing the commit body. It MUST NOT regenerate UVK / identitySeed /
         * identityPub: the new `newWrappedUvk` wraps the invariant UVK, so both the org-escrow and
         * member-recovery blobs stay valid. A wrong secret / hostile blob fails closed (AEAD tag).
         */
        fun recover(
            recoverySecret: ByteArray,
            verifyResponse: RecoveryVerifyResponse,
            newPassword: String,
            newParams: KdfParams = KdfParams.DEFAULT,
            crypto: CryptoProvider = createCryptoProvider(),
        ): RecoveryCommitRequest {
            val userId = verifyResponse.userId
            // 1. Recover the SAME UVK (fail-closed: wrong secret / wrong-or-tampered blob → AEAD tag fail).
            val uvk = MemberRecovery.openUvk(crypto, recoverySecret, verifyResponse.recoveryWrappedUvk, userId)

            // 2. Route through the SHARED unlock tail purely for its identity-pubkey hard-fail (§F.8):
            //    it opens encryptedIdentitySeed under the recovered UVK and refuses if the seed-derived
            //    pubkey ≠ verifyResponse.identityPub (possible server compromise). Only those two fields
            //    are consulted, so the other AccountKeys slots are unused placeholders here.
            unlockFromUvk(
                userId,
                uvk,
                AccountKeys(
                    kdfSalt = "",
                    kdfParams = newParams,
                    wrappedUvk = "",
                    encryptedIdentitySeed = verifyResponse.encryptedIdentitySeed,
                    identityPub = verifyResponse.identityPub,
                    escrowFingerprint = "",
                ),
                crypto,
            )

            // 3. Derive fresh password material and re-wrap the SAME UVK (invariant).
            val newKdfSalt = crypto.randomBytes(KdfParams.SALT_BYTES)
            val newMk = Keys.masterKey(crypto, newPassword, newKdfSalt, newParams)
            return RecoveryCommitRequest(
                recoveryTicket = verifyResponse.recoveryTicket,
                newAuthKey = Bytes.toB64(Keys.authKey(crypto, newMk)),
                newKdfSalt = Bytes.toB64(newKdfSalt),
                newKdfParams = newParams,
                newWrappedUvk = Envelope.sealB64(crypto, Keys.wrapKey(crypto, newMk), uvk, Ad.uvk(userId)),
            )
        }

        /** Unlock a device holding only the password + the server's account keys. */
        fun unlock(userId: String, password: String, keys: AccountKeys, crypto: CryptoProvider = createCryptoProvider()): Account {
            val mk = Keys.masterKey(crypto, password, Bytes.fromB64(keys.kdfSalt), keys.kdfParams)
            val wrapKey = Keys.wrapKey(crypto, mk)
            val uvk = try {
                Envelope.openB64(crypto, wrapKey, keys.wrappedUvk, Ad.uvk(userId))
            } catch (e: CryptoException) {
                throw CryptoException("wrong master password")
            }
            // Password path validates the password by the wrappedUvk open above; from here the
            // work is identical to the UVK (quick-unlock) path — one shared tail, no drift.
            return unlockFromUvk(userId, uvk, keys, crypto)
        }

        /**
         * Unlock from a platform-recovered UVK (quick unlock, spec 01 §8.1) — the shared tail
         * of [unlock] with the password/wrapKey/wrappedUvk stage removed (there is no password;
         * the caller hands over the UVK a hardware-backed Keystore just decrypted).
         *
         * VALIDATION BY CONSEQUENCE (design §1): a wrong/stale/foreign UVK is not checked
         * against anything server-sent — it simply fails the [encryptedIdentitySeed] AEAD open
         * inside the shared tail, surfacing as a plain [CryptoException] (NEVER softened to
         * "wrong master password"; there is no password to be wrong). The caller treats that as
         * an invalid quick-unlock secret → wipe the blob + fall back to the password prompt
         * (spec 01 §8.1 failure table), never as a soft/retriable error.
         *
         * The spec 01 §5 seed-derived identityPub substitution check runs here too — it is IN
         * the shared tail, so a quick unlock can NEVER skip it and let a hostile server slip in a
         * pubkey it controls; that hard-fail keeps its distinct identity-mismatch message.
         *
         * The returned [Account] keeps the passed [uvk] reference (see [enroll]/[unlock]: the
         * private ctor owns it). The caller must hand over a fresh array and not reuse/zero it.
         */
        fun unlockWithUvk(userId: String, uvk: ByteArray, keys: AccountKeys, crypto: CryptoProvider = createCryptoProvider()): Account =
            unlockFromUvk(userId, uvk, keys, crypto)

        /**
         * Shared unlock tail (spec 01 §5) reached by BOTH [unlock] (after it recovers the UVK
         * from the password) and [unlockWithUvk] (given the UVK directly). Keeping it single-
         * sourced is the invariant that stops the quick-unlock path from ever diverging on the
         * pubkey-substitution hard-fail below.
         *
         * The identity keypair is DERIVED from the UVK-sealed seed — which the server cannot
         * forge. Fingerprints and sealed-grant opening must use this derived keypair, never a
         * server-sent value; a mismatching server identityPub is a pubkey-substitution attempt
         * (spec 01 §5) and unlock hard-fails with a DISTINCT message (not the wrong-password /
         * wrong-UVK CryptoException the AEAD open throws) so callers can tell a security fault
         * apart from a bad secret. The `encryptedIdentitySeed` open is left un-caught on purpose:
         * on the UVK path its failure is exactly the "the recovered UVK is not this account's UVK"
         * signal (validation by consequence); on the password path an honest server's UVK always
         * opens it, so it never fires there.
         */
        private fun unlockFromUvk(userId: String, uvk: ByteArray, keys: AccountKeys, crypto: CryptoProvider): Account {
            val identitySeed = Envelope.openB64(crypto, uvk, keys.encryptedIdentitySeed, Ad.idkey(userId))
            val identity = crypto.boxKeypairFromSeed(identitySeed)
            if (!identity.publicKey.contentEquals(Bytes.fromB64(keys.identityPub))) {
                throw CryptoException(
                    "identity key mismatch — the server returned an identity public key that " +
                        "your account's sealed seed does not derive; possible server compromise. Do not proceed.",
                )
            }
            return Account(crypto, userId, uvk, identity.publicKey, identity.privateKey, "", mutableMapOf())
        }

        private fun uuid(crypto: CryptoProvider): String =
            Bytes.uuidV4FromBytes(crypto.randomBytes(16)) // RFC 4122 v4 from 16 random bytes
    }

    /**
     * Apply an incoming grant (spec 01 §6). The ROLE update is unconditional — a role
     * change re-delivers the grant with a bumped rev and must take effect even though the
     * VK is already held; the key itself is opened only when missing. Member grants carry
     * sealedVk (crypto_box_seal to our identity); owner/personal grants carry wrappedVk
     * (under UVK).
     */
    fun addGrant(grant: WireGrant) {
        if (grant.role.isNotEmpty()) vaultRoles[grant.vaultId] = grant.role
        if (vaultKeys.containsKey(grant.vaultId)) return
        val sealed = grant.sealedVk
        val vk = if (!sealed.isNullOrEmpty()) {
            SharedGrant.open(crypto, identityPub, identityPriv, grant.vaultId, Bytes.fromB64(sealed))
        } else {
            Envelope.openB64(crypto, uvk, grant.wrappedVk, Ad.vk(grant.vaultId, userId))
        }
        vaultKeys[grant.vaultId] = vk
    }

    @Deprecated("shared grants exist now — use addGrant", ReplaceWith("addGrant(grant)"))
    fun addPersonalGrant(grant: WireGrant) = addGrant(grant)

    fun setPersonalVault(vaultId: String) {
        if (personalVaultId.isEmpty()) personalVaultId = vaultId
    }

    fun hasVault(vaultId: String): Boolean = vaultKeys.containsKey(vaultId)

    /** Server-declared role for a vault we hold (null when unknown). */
    fun roleFor(vaultId: String): String? = vaultRoles[vaultId]

    /** Drop a vault's key + role (removedGrants purge) so later writes fail fast client-side. */
    fun removeVault(vaultId: String) {
        vaultKeys.remove(vaultId)
        vaultRoles.remove(vaultId)
    }

    // ---- shared vaults (spec 01 §6 / spec 03 §10) ----

    class NewSharedVault(val request: CreateVaultRequest, val vaultId: String)

    /** Create a shared vault locally: fresh VK, meta under VK, owner grant under OUR UVK. */
    fun buildCreateSharedVault(name: String): NewSharedVault {
        val vaultId = uuid(crypto)
        val svk = crypto.randomBytes(32)
        val metaPlain = buildJsonObject { put("name", name) }.toString()
        val req = CreateVaultRequest(
            vaultId = vaultId,
            metaBlob = Envelope.sealB64(crypto, svk, metaPlain.encodeToByteArray(), Ad.vaultMeta(vaultId)),
            wrappedVk = Envelope.sealB64(crypto, uvk, svk, Ad.vk(vaultId, userId)),
        )
        vaultKeys[vaultId] = svk
        vaultRoles[vaultId] = "owner"
        return NewSharedVault(req, vaultId)
    }

    /** Seal a vault's VK to a member's (out-of-band verified!) identity pubkey. */
    fun wrapVkForMember(memberIdentityPub: ByteArray, vaultId: String): String =
        Bytes.toB64(SharedGrant.seal(crypto, memberIdentityPub, vaultId, vk(vaultId)))

    /** Short identity fingerprint over the SEED-DERIVED pubkey (spec 01 §5) — what a
     *  family member reads out when someone shares a vault with them. */
    fun identityFingerprintShort(): String = SharedGrant.shortFingerprint(crypto, identityPub)

    /** Decrypt a vault's display name from its metaBlob (null when the VK is missing). */
    fun decryptVaultName(vaultId: String, metaBlob: String): String? = runCatching {
        val plain = Envelope.openB64(crypto, vk(vaultId), metaBlob, Ad.vaultMeta(vaultId)).decodeToString()
        Json.parseToJsonElement(plain).jsonObject["name"]?.jsonPrimitive?.content
    }.getOrNull()

    // ---- vault lifecycle (spec 03 §11) — narrow accessors, mirrors of web account.ts ----

    /**
     * The lifecycle key for a vault: `HKDF-SHA-256(VK, "andvari/v1|lifecycle")` — domain-
     * separated from the AEAD key. Callers mint/verify destructive-op proofs under it; the
     * VK itself never leaves this class (ZK: proofs are MACs the server can neither mint
     * nor open).
     */
    fun lifecycleKeyFor(vaultId: String): ByteArray =
        io.silencelen.andvari.core.crypto.LifecycleProof.lifecycleKey(crypto, vk(vaultId))

    /**
     * Transfer accept (spec 03 §11): the new owner re-wraps the VK it ALREADY holds (via its
     * sealed member grant) under its OWN UVK — identical construction to vault creation
     * (`seal(UVK, VK, Ad.vk(vaultId, me))`). Round-trip-verified before returning, so a
     * garbage wrap that would lock the new owner out never gets posted.
     */
    fun buildOwnerWrap(vaultId: String): String {
        val vk = vk(vaultId)
        val wrapped = Envelope.sealB64(crypto, uvk, vk, Ad.vk(vaultId, userId))
        if (!Envelope.openB64(crypto, uvk, wrapped, Ad.vk(vaultId, userId)).contentEquals(vk)) {
            throw CryptoException("owner wrap failed round-trip verification")
        }
        return wrapped
    }

    /** The full vault-meta plaintext object (spec 02 §4) — `name`, the monotonic `metaV`
     *  counter, and any unknown fields a future client wrote. Throws if the VK is missing
     *  or the blob doesn't open. Callers that only need the name use [decryptVaultName]. */
    fun decryptVaultMeta(vaultId: String, metaBlob: String): JsonObject {
        val plain = Envelope.openB64(crypto, vk(vaultId), metaBlob, Ad.vaultMeta(vaultId)).decodeToString()
        return Json.parseToJsonElement(plain).jsonObject
    }

    /**
     * Rename (spec 03 §11 / Q6): read-modify-write the metaBlob under the SAME VK/AD —
     * change ONLY `name`, PRESERVE every unknown field (spec 02 §4), and increment the
     * monotonic plaintext `metaV` counter (anti-replay). Returns the new metaBlob
     * (base64url). The name stays E2E ciphertext; the server only ever sees an opaque blob.
     */
    fun buildRenameMeta(vaultId: String, metaBlob: String, newName: String): String {
        val meta = decryptVaultMeta(vaultId, metaBlob)
        val metaV = (meta["metaV"] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toLongOrNull() ?: 0L
        val next = buildJsonObject {
            for ((k, v) in meta) if (k != "name" && k != "metaV") put(k, v)
            put("name", newName)
            put("metaV", metaV + 1)
        }
        return Envelope.sealB64(crypto, vk(vaultId), next.toString().encodeToByteArray(), Ad.vaultMeta(vaultId))
    }

    /**
     * Decrypt a HELD (revoked) vault's name from its retained grant blob + metaBlob WITHOUT
     * re-admitting the key to the live key map — the holding area (spec 03 §11) lists
     * soft-hidden vaults after a restart, but a removed vault must never become writable
     * again through the display path. Null when the grant/blob doesn't open.
     */
    fun peekVaultName(grant: WireGrant, metaBlob: String): String? = runCatching {
        val sealed = grant.sealedVk
        val heldVk = if (!sealed.isNullOrEmpty()) {
            SharedGrant.open(crypto, identityPub, identityPriv, grant.vaultId, Bytes.fromB64(sealed))
        } else {
            Envelope.openB64(crypto, uvk, grant.wrappedVk, Ad.vk(grant.vaultId, userId))
        }
        val plain = Envelope.openB64(crypto, heldVk, metaBlob, Ad.vaultMeta(grant.vaultId)).decodeToString()
        Json.parseToJsonElement(plain).jsonObject["name"]?.jsonPrimitive?.content
    }.getOrNull()

    private fun vk(vaultId: String): ByteArray =
        vaultKeys[vaultId] ?: throw CryptoException("no key for vault $vaultId")

    /** itemId → highest formatVersion this session decrypted or sealed it at. Reseals take
     *  maxOf(docFloor, this): the server enforces per-item monotonic fv, so an edit must
     *  never re-seal below the version it arrived at. In-memory only by design — the durable
     *  cache stores envelopes, and hydrate decrypts every held envelope before any reseal. */
    private val itemFv = mutableMapOf<String, Int>()

    /**
     * Seal an item doc under its vault VK. The formatVersion — also bound into the AD —
     * is maxOf([docFloor], the fv this itemId was last decrypted/sealed at), so callers
     * never thread fv explicitly: new docs seal at their floor, existing items re-seal
     * monotonically ([decryptItem]/[decryptItemVersion] feed the per-item memory).
     */
    fun encryptItem(vaultId: String, itemId: String, doc: ItemDoc): ItemUpload {
        val fv = maxOf(docFloor(doc), itemFv[itemId] ?: 1)
        itemFv[itemId] = fv
        val blob = Envelope.sealB64(crypto, vk(vaultId), json.encodeToString(ItemDoc.serializer(), doc).encodeToByteArray(), Ad.item(vaultId, itemId, fv))
        return ItemUpload(formatVersion = fv, attachmentIds = doc.attachments.map { it.id }, blob = blob)
    }

    /** Random per-file key (spec 02 §6) — lives only inside item ciphertext. */
    fun newFileKey(): ByteArray = crypto.randomBytes(32)

    fun cryptoProvider(): CryptoProvider = crypto

    /**
     * Quick-unlock ENROLLMENT ONLY (spec 01 §8.1, design §1): returns a COPY of the UVK for a
     * platform's hardware-backed cipher to wrap (Android Keystore AES-GCM). Pass it STRAIGHT
     * into the cipher and DROP/zero the reference immediately (R1) — a COPY, so a caller that
     * forgets to zero cannot corrupt this session's live UVK.
     *
     * This is the ONE deliberate widening of the class's key encapsulation. The honest defense:
     * the UVK already lives in this process's heap for the whole unlocked session, so a same-
     * process accessor adds no new EXPOSURE CLASS (T5/R1 unchanged); the rejected alternative —
     * threading a `javax.crypto.Cipher` into commonMain to wrap the UVK internally — leaks a JVM
     * platform type into the multiplatform core for zero security delta. Do NOT reach for this
     * for anything other than quick-unlock enrollment.
     */
    fun uvkCopyForPlatformWrap(): ByteArray = uvk.copyOf()

    fun decryptItem(item: WireItem): ItemDoc {
        val blob = item.blob ?: throw CryptoException("item has no blob (tombstone?)")
        // Fail closed on documents from a NEWER format: unknown-field preservation (spec 02
        // §3) is scoped WITHIN a formatVersion, and editing a v2 doc here would re-seal it
        // silently downgraded to v1. CryptoException rides the existing runCatching sync
        // paths ("undecryptable, retried on hydrate") — never a crash, envelope persists.
        if (item.formatVersion > ITEM_FORMAT_VERSION) throw CryptoException("item formatVersion ${item.formatVersion} is newer than this client supports")
        val plain = Envelope.openB64(crypto, vk(item.vaultId), blob, Ad.item(item.vaultId, item.itemId, item.formatVersion))
        val doc = json.decodeFromString(ItemDoc.serializer(), plain.decodeToString())
        // Remember the fv monotonically (an OLDER archived version arriving via
        // decryptItemVersion must not lower it) so a later re-seal can't downgrade.
        itemFv[item.itemId] = maxOf(itemFv[item.itemId] ?: 1, item.formatVersion)
        return doc
    }

    fun newItemId(): String = uuid(crypto)

    /**
     * Feature: item history — decrypt one archived [ItemVersion] under the vault VK. The item AD
     * binds (vaultId, itemId, formatVersion), NOT rev, so an old version opens with the CURRENT key
     * — no crypto change (until a VK rotation, which resets history; see the design doc). Reuses
     * [decryptItem] (same fail-closed-on-newer-formatVersion behavior). The caller supplies the
     * vaultId (the version DTO carries none) — the live item the history belongs to.
     */
    fun decryptItemVersion(vaultId: String, itemId: String, version: ItemVersion): ItemDoc =
        decryptItem(WireItem(itemId, vaultId, version.rev, 0, version.archivedAt, false, false, version.formatVersion, emptyList(), version.blob))

    /**
     * F57: build a fresh escrow blob re-sealing THIS account's UVK to the current org recovery
     * key after a re-ceremony (spec 04 §4). SECURITY: [verifiedFingerprint] MUST be the value the
     * user just confirmed against the NEW printed recovery sheet (short-form). We bind the
     * server-fetched [recoveryPubB64] to that fingerprint here and refuse to seal if they differ,
     * so a hostile server cannot redirect the UVK escrow to an attacker-held recovery key. The UVK
     * never leaves the client except sealed to the verified recovery public key (zero-knowledge).
     */
    fun resealEscrowFor(recoveryPubB64: String, verifiedFingerprint: String): EscrowUpload {
        val pub = Bytes.fromB64(recoveryPubB64)
        require(Escrow.fingerprint(crypto, pub) == verifiedFingerprint) {
            "recovery public key does not match the verified fingerprint — refusing to re-seal escrow"
        }
        return EscrowUpload(Bytes.toB64(Escrow.sealUvk(crypto, pub, userId, uvk)), verifiedFingerprint)
    }

    /**
     * Migration/rotation path (design §F.3, client half of `PUT /recovery/self-setup`): add or rotate
     * THIS account's per-member self-service recovery piece over the in-memory UVK. [currentAuthKey]
     * (base64url, derived from the just-entered master password via [deriveAuthKey]) is carried so the
     * server can require a FRESH master-password reauth before storing the block — a quick-unlock /
     * biometric session with no password in hand must DEFER this and prompt for the full password.
     * The generated recoverySecret is SHOWN ONCE then dropped (returned in [SelfSetupResult]); the UVK
     * is invariant, so a pre-existing org-escrow blob stays valid alongside the new piece.
     */
    fun setupMemberRecovery(currentAuthKey: String): SelfSetupResult {
        val recovery = MemberRecovery.generate(crypto, userId, uvk)
        val req = RecoverySelfSetupRequest(currentAuthKey, MemberRecoveryBlock(recovery.recoveryWrappedUvk, recovery.recoveryAuthKey))
        return SelfSetupResult(req, recovery.recoverySecret)
    }
}
