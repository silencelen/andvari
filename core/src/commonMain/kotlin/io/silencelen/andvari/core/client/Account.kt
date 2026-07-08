package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.EscrowUpload
import io.silencelen.andvari.core.model.ItemUpload
import io.silencelen.andvari.core.model.PersonalVaultUpload
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
    val type: String, // "login" | "note"
    val name: String,
    val notes: String? = null,
    val favorite: Boolean = false,
    val login: LoginData? = null,
    val attachments: List<AttachmentRef> = emptyList(),
    @kotlinx.serialization.Transient val extras: Map<String, JsonElement> = emptyMap(),
)

@OptIn(ExperimentalSerializationApi::class)
internal object LoginDataSerializer : ExtrasOverlaySerializer<LoginData>(LoginData.generatedSerializer(), LoginData::extras, { v, e -> v.copy(extras = e) })

@OptIn(ExperimentalSerializationApi::class)
internal object PasswordHistoryEntrySerializer : ExtrasOverlaySerializer<PasswordHistoryEntry>(PasswordHistoryEntry.generatedSerializer(), PasswordHistoryEntry::extras, { v, e -> v.copy(extras = e) })

@OptIn(ExperimentalSerializationApi::class)
internal object AttachmentRefSerializer : ExtrasOverlaySerializer<AttachmentRef>(AttachmentRef.generatedSerializer(), AttachmentRef::extras, { v, e -> v.copy(extras = e) })

@OptIn(ExperimentalSerializationApi::class)
internal object ItemDocSerializer : ExtrasOverlaySerializer<ItemDoc>(ItemDoc.generatedSerializer(), ItemDoc::extras, { v, e -> v.copy(extras = e) })

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
        const val ITEM_FORMAT_VERSION = 1
        private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

        // platform must match the AndvariApi wire tag ("android" | "windows" | "linux") so
        // device rows and audit entries agree with the minVersion gate's view of the client.
        fun deviceInfo(name: String, platform: String = "android"): DeviceInfo = DeviceInfo(platform, name)

        /** Derive the login authKey a fresh device sends after prelogin. */
        fun deriveAuthKey(password: String, kdfSaltB64: String, params: KdfParams, crypto: CryptoProvider = createCryptoProvider()): String {
            val mk = Keys.masterKey(crypto, password, Bytes.fromB64(kdfSaltB64), params)
            return Bytes.toB64(Keys.authKey(crypto, mk))
        }

        /** Enrollment: generate all keys, seal escrow, return the one-shot register request. */
        fun enroll(
            inviteToken: String,
            email: String,
            displayName: String,
            password: String,
            params: KdfParams,
            recoveryPublicKey: ByteArray,
            recoveryFingerprint: String,
            deviceName: String,
            crypto: CryptoProvider = createCryptoProvider(),
        ): Pair<RegisterRequest, Account> {
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

            val computedFp = Escrow.fingerprint(crypto, recoveryPublicKey)
            if (computedFp != recoveryFingerprint) throw CryptoException("recovery public key does not match its fingerprint")

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
                escrow = EscrowUpload(Bytes.toB64(Escrow.sealUvk(crypto, recoveryPublicKey, userId, uvk)), recoveryFingerprint),
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
            return req to account
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
            // The identity keypair is DERIVED from the UVK-sealed seed — which the server
            // cannot forge. Fingerprints and sealed-grant opening must use this derived
            // keypair, never a server-sent value; a mismatching server identityPub is a
            // pubkey-substitution attempt (spec 01 §5) and unlock hard-fails.
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

    fun encryptItem(vaultId: String, itemId: String, doc: ItemDoc): ItemUpload {
        val blob = Envelope.sealB64(crypto, vk(vaultId), json.encodeToString(ItemDoc.serializer(), doc).encodeToByteArray(), Ad.item(vaultId, itemId, ITEM_FORMAT_VERSION))
        return ItemUpload(formatVersion = ITEM_FORMAT_VERSION, attachmentIds = doc.attachments.map { it.id }, blob = blob)
    }

    /** Random per-file key (spec 02 §6) — lives only inside item ciphertext. */
    fun newFileKey(): ByteArray = crypto.randomBytes(32)

    fun cryptoProvider(): CryptoProvider = crypto

    fun decryptItem(item: WireItem): ItemDoc {
        val blob = item.blob ?: throw CryptoException("item has no blob (tombstone?)")
        // Fail closed on documents from a NEWER format: unknown-field preservation (spec 02
        // §3) is scoped WITHIN a formatVersion, and editing a v2 doc here would re-seal it
        // silently downgraded to v1. CryptoException rides the existing runCatching sync
        // paths ("undecryptable, retried on hydrate") — never a crash, envelope persists.
        if (item.formatVersion > ITEM_FORMAT_VERSION) throw CryptoException("item formatVersion ${item.formatVersion} is newer than this client supports")
        val plain = Envelope.openB64(crypto, vk(item.vaultId), blob, Ad.item(item.vaultId, item.itemId, item.formatVersion))
        return json.decodeFromString(ItemDoc.serializer(), plain.decodeToString())
    }

    fun newItemId(): String = uuid(crypto)
}
