package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.GrantOutcome
import io.silencelen.andvari.core.crypto.GrantPin
import io.silencelen.andvari.core.crypto.GrantVerdict
import io.silencelen.andvari.core.crypto.LegacyGrant
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.UsageKey
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.SignedGrant
import io.silencelen.andvari.core.crypto.SignedStatement
import io.silencelen.andvari.core.crypto.Statement
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.EscrowUpload
import io.silencelen.andvari.core.model.ItemUpload
import io.silencelen.andvari.core.model.ItemVersion
import io.silencelen.andvari.core.model.MemberRecoveryBlock
import io.silencelen.andvari.core.model.PersonalVaultUpload
import io.silencelen.andvari.core.model.PersonalWrap
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
    // G3 billing postal (design 2026-07-23-card-autofill-gated §G3 [X3-N1]): a TYPED optional
    // field, serializer-safe cross-version (ExtrasOverlaySerializer round-trips it; a pre-G3
    // 0.19.x client sees it as an unknown key and preserves it — NO formatVersion bump).
    // Alphanumeric internationally, so stored VERBATIM (never digits-only). Appended LAST with a
    // null default so every existing positional/copy() card writer stays bit-identical.
    val postalCode: String? = null,
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

/**
 * The last recorded HUMAN verdict on whether a login still works (spec 02 §3, 2026-08-22) —
 * the Kotlin sibling of web's `ItemCheck` in `web/src/api/types.ts`.
 *
 * Doc-level for the same reason `dupeAck` is: the verdict is about the ITEM, not the viewer, so
 * one household member's confirmation quiets it for everyone.
 *
 * **[result] is an OPEN vocabulary and must never become an enum.** `ok`/`bad`/`gone`/`blocked`
 * are what ships today; a value this client does not recognize means "checked, verdict unknown"
 * and must degrade to a neutral row, NEVER a failing one ([Staleness.isFailing] is the one place
 * that decides). A future client's verdict cannot be allowed to turn this one red.
 *
 * **Times are client clocks: ADVISORY ONLY, never a security input** (spec 02 §1). In a shared
 * vault an [at] can arrive from another member's skewed — or hostile — device, so readers clamp
 * it to "now" rather than trusting it (see [Staleness.stalenessRows]).
 */
@OptIn(ExperimentalSerializationApi::class)
@kotlinx.serialization.Serializable(with = ItemCheckSerializer::class)
@KeepGeneratedSerializer
data class ItemCheck(
    /** When this verdict was recorded (epoch ms, client clock — advisory). */
    val at: Long,
    /** Open vocabulary; unknown values render as "checked" with no verdict styling. */
    val result: String,
    /** The most recent [at] whose result was "ok", carried forward across later non-ok verdicts
     *  so "last worked in March, failed in August" survives without an array. */
    val okAt: Long? = null,
    /** Snooze horizon: do not resurface in the staleness list before this. */
    val until: Long? = null,
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
    // dupeAck + check (2026-08-23): promoted from the extras overlay to typed fields so the
    // native clients can read and write them without hand-parsing JsonElement at every call
    // site. APPENDED LAST WITH NULL DEFAULTS — the `postalCode` precedent above — so every
    // existing positional and copy() writer stays bit-identical. Both are additive doc-level
    // keys within fv1/fv2: NO formatVersion bump, and a client that predates them preserves
    // them as unknown keys exactly as it did before they were typed.
    /** Duplicate-checker acknowledgment: the cluster signature the user marked "not duplicates
     *  — keep both". A cluster is dismissed only while EVERY member carries the signature of
     *  the cluster as currently constituted, so any membership change resurfaces it. */
    val dupeAck: String? = null,
    /** Login verification ledger — see [ItemCheck]. */
    val check: ItemCheck? = null,
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
internal object ItemCheckSerializer : ExtrasOverlaySerializer<ItemCheck>(ItemCheck.generatedSerializer(), ItemCheck::extras, { v, e -> v.copy(extras = e) })

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
 * Audit H67 (spec 01 §4, spec 02 §2): the server-supplied `wrappedUvk` is not a well-formed
 * envelope AT ALL — it is not valid base64url, or its public header says "too short" / an
 * envelope version or AEAD alg this build does not know. TWIN of web
 * `web/src/vault/account.ts` `VaultKeyDamagedError` and of the extension's `keys_damaged`
 * unlock code; the sentence lives once per canon ([HouseholdCopy.ACCOUNT_KEYS_DAMAGED]).
 *
 * WHY THIS IS A SEPARATE TYPE, at length, because the whole point is that it must never be
 * relabelled: only the AEAD tag failure at the end of an envelope open is genuinely
 * indistinguishable from a wrong master password — it is precisely what a wrong password
 * produces. The four structural refusals (undecodable base64url, too short,
 * unknown envelope version, unknown AEAD alg) are decided from the blob's PUBLIC header,
 * BEFORE the wrap key is used, so no password could ever have made them pass. Folding them
 * into "Wrong email or master password" (which every client did before this row) tells a
 * household member whose account row was corrupted by a partial DB restore — or who is on an
 * old build that a newer server just fed a v2 envelope — to reset a password that works, and
 * then to burn their recovery secret when the reset does not help. Deliberately NOT a
 * [CryptoException] (the [KdfPolicyViolationException] precedent, and web's
 * `IdentityMismatchError`): every unlock ladder maps a plain CryptoException to
 * "wrong master password", so being outside that type is what makes the collapse structurally
 * impossible rather than merely un-coded-for today.
 *
 * It is TERMINAL, not retryable: the same blob fails identically forever, so the copy must not
 * invite a retry — it points at the two things that can actually help (an admin, a backup).
 */
class VaultKeyDamagedException(message: String, cause: Throwable? = null) :
    Exception("account key material is unreadable: $message", cause)

/**
 * A grant row carries OUR UVK wrap (`wrappedVk`) for a vault, and it does not open: it fails a
 * structural check or its AEAD tag (security review 2026-10, root cause A §3.1; the spec 01 §4
 * classification extended to VK wraps). By the time a grant is applied the UVK has already
 * proven itself on the account-key blobs, so an AEAD failure here cannot mean "wrong password";
 * it is a damaged or substituted row, and the vault shows as "key unreadable — tell your admin".
 *
 * Deliberately NOT a [CryptoException], and deliberately terminal: the one thing the client must
 * not do is fall back to a `sealedVk` on the same row, because a seal is `crypto_box_seal` to our
 * PUBLIC key and the server can mint one around a key it chose. Web twin: `VaultGrantKeyUnreadableError`.
 */
class VaultGrantKeyUnreadableException(val vaultId: String, reason: String, cause: Throwable? = null) :
    Exception("vault key for $vaultId is unreadable ($reason)", cause)

/**
 * INV-WRITE-KEY (security review 2026-10, root cause A §5.1, §8.2; branch A6): this vault's key came ONLY from
 * a v1 `sealedVk`, which anyone holding our public key (the server included) can mint, and nobody has vouched
 * for it yet: no verified v2 grant, no pre-upgrade evidence, no human "Accept". It is readable, but nothing is
 * ever sealed under it. Deliberately NOT a [CryptoException]: the save ladders read a CryptoException as "wrong
 * master password" ([HouseholdCopy.forSaveError]); this one has its own copy.
 */
class VaultKeyNotVerifiedException(val vaultId: String) :
    Exception("the key for vault $vaultId is not verified yet (legacy grant): review the vault before writing to it")

/** §1.6: a v2 grant from a sender this account has not pinned (or whose pin is not current on this device). The
 *  vault is NOT adopted; [fromUserId] is unverified routing data naming whom to verify. */
data class PendingGrant(val vaultId: String, val fromUserId: String, val grantIdB64: String)

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
    /**
     * The JOINT Ed25519 signing key (security review 2026-10, root cause A §1.1, owner decision: joint key):
     * `crypto_sign_seed_keypair` over the same identity seed, so `ed25519PkToCurve25519(signPub) ==
     * identityPub` and no fingerprint changes. Derived at enrol/unlock from the UVK-sealed seed, held
     * in memory for the session exactly like [identityPriv], never persisted or sent anywhere.
     */
    val signPub: ByteArray,
    private val signSecret: ByteArray,
    personalVaultId: String,
    private val vaultKeys: MutableMap<String, ByteArray>,
    private val vaultRoles: MutableMap<String, String> = mutableMapOf(),
) {
    /**
     * The personal vault (security review 2026-10, root cause A §4): the vault named by
     * `AccountKeys.personalWrap`, which only this user's UVK can mint ([applyPersonalWrap]), or the
     * vault the human chose ([SyncEngine.designatePersonalVault]). Empty means "no personal vault": no
     * default save destination, no usage ledger. NEVER set from a server `type` label or `role`, and
     * never from an automatic pick: without a wrap the human chooses (review H-1).
     */
    var personalVaultId: String = personalVaultId
        private set

    /** Where [personalVaultId] came from (root cause A §4.3, §8.5). */
    enum class PersonalStatus {
        /** A served `personalWrap` opened under our UVK and names [personalVaultId]. */
        CONFIRMED,

        /**
         * ANOMALY (A5 review H-1): the server served no wrap, but this device had already seen one and kept
         * it (UVK-sealed, so caching it is safe). [personalVaultId] comes from that cached wrap; the
         * migration question is NOT re-asked and no label is consulted.
         */
        WITHHELD,

        /** No wrap served and none ever seen here: the human must choose. [personalVaultId] is empty. */
        ABSENT,

        /** A wrap was served and it does NOT open, and this device had none of its own: an anomaly.
         *  [personalVaultId] is empty, and only a re-designation (password reauth) can replace it. */
        UNREADABLE,

        /**
         * ANOMALY (A5 re-review L-1): a wrap was served and it does NOT open, but this device holds a cached wrap
         * that does. The cached wrap stays in force ([personalVaultId] comes from it); junk from the server
         * never discards a valid local copy. A re-designation (password reauth) repairs the server's copy.
         */
        UNREADABLE_CACHED,

        /**
         * A served wrap OPENS but names a different vault than the one this device cached (A5 re-review M-2,
         * L-2): a re-designation on another device, or the server replaying an older wrap. The device does NOT
         * switch: [personalVaultId] stays the cached vault until the human confirms the change
         * ([acceptPersonalChange]) or re-designates the current one. [pendingPersonalChange] holds the served wrap.
         */
        CHANGED,
    }

    var personalStatus: PersonalStatus = PersonalStatus.ABSENT
        private set

    /** Vaults whose key opened from a UVK wrap of OURS (our own grant row's `wrappedVk`, or the
     *  personal wrap), never from a seal: the only vaults a personal wrap may be minted for (§4.3). */
    internal val uvkWrappedVaults: MutableSet<String> = mutableSetOf()

    /**
     * Vaults whose VK arrived by MEMBER grant (`sealedVk`) rather than wrapped under our own
     * UVK — see [keyArrivedByMemberGrant]. In-memory only, like the keys it annotates, and
     * rebuilt from the persisted grant rows on every hydrate (spec 03 §4 makes cold start
     * replay them anyway), so it cannot go stale across a restart.
     */
    private val memberGrantedVaults: MutableSet<String> = mutableSetOf()

    /**
     * Vaults whose grant row carried a seal that opened to a DIFFERENT key than the one we hold
     * from our own UVK wrap: the "vault key mismatch" anomaly (root cause A §3.1). The wrapped key
     * was kept and the seal refused; this records only that the server served a second key.
     * Rebuilt from the persisted rows on every hydrate, like [memberGrantedVaults].
     */
    private val vkMismatchVaults: MutableSet<String> = mutableSetOf()

    /** Vaults whose UVK wrap is present but does not open ("key unreadable — tell your admin"). */
    private val unreadableKeyVaults: MutableSet<String> = mutableSetOf()

    /** Where a held vault key came from (root cause A §3.1 precedence), recorded when it is adopted. */
    enum class KeySource {
        /** `AccountKeys.personalWrap`, under our UVK with the `vk-personal` AD (rule 1). */
        PERSONAL_WRAP,

        /** Our own UVK wrap on our grant row: owner wrap, transfer wrap, member self-wrap (rule 2). */
        UVK_WRAP,

        /** A v2 grant verified per §1.4 against our PIN for the sender it names (rule 3). */
        SIGNED_GRANT,

        /** A v1 `sealedVk` (rule 4): legacy-read-only until frozen or confirmed ([authorizeLegacyKey]). */
        LEGACY_SEAL,
    }

    private val keySources: MutableMap<String, KeySource> = mutableMapOf()

    /** For keys adopted from a verified v2 grant: the userId the VERIFIED statement names as sender. */
    private val signedGrantFrom: MutableMap<String, String> = mutableMapOf()

    /**
     * Pins as the grant verifier sees them (root cause A §1.4 step 7). The host (SyncEngine) wires this to the
     * account-state contacts, reporting a pin as current only when it may skip verification on this device
     * (A5 review L-3). The default knows no one: every v2 grant is a pending invitation.
     */
    var grantPins: (String) -> GrantPin? = { null }

    /**
     * v1-only keys this device vouches for (§8.2: pre-upgrade evidence, or the human accepted), by vaultId → the
     * [legacyKeyTag] of the EXACT key vouched for. Binding the decision to the key means a server that later
     * swaps the seal for the same vaultId (before the self-wrap reached the row) is not covered by it.
     */
    private val legacyAuthorized: MutableMap<String, LegacyVouch> = mutableMapOf()

    /** A §8.2 vouch: the tag of the exact key, and whether it came from pre-upgrade evidence or the human. */
    class LegacyVouch(val tag: String, val frozen: Boolean)

    private fun tagOf(vk: ByteArray): String = Bytes.toHexLower(crypto.sha256(vk))

    /**
     * The §8.2 / §8.6 decision for a v1-only key, routed through the graded [LegacyGrant.decide] (A6 review LOW-3;
     * `sharedgrant.json` → `legacyMode`): evidence and confirmation count only for the EXACT key vouched for.
     */
    private fun legacyMode(vaultId: String, vk: ByteArray?): LegacyGrant.Mode {
        val v = legacyAuthorized[vaultId]
        val matches = vk != null && v != null && v.tag == tagOf(vk)
        return LegacyGrant.decide(LegacyGrant.IN_WINDOW, preUpgradeEvidence = matches && v!!.frozen, confirmed = matches && !v!!.frozen)
    }

    /** The result of [vouchGate]. */
    enum class VouchGate { NO_VOUCH, OK, MISMATCH }

    /**
     * THE vouch gate (A6 re-review round 3: one rule, every key-source path). While this device holds a §8.2 vouch
     * for [vaultId], a [key] whose SHA-256 differs from the vouch tag is MISMATCH: it is never adopted writable,
     * never promoted, never self-wrapped, owner-wrapped, signed onward or transferred, and never offered for
     * "Accept anyway". The only path that still USES such a key is rule 2 (our own UVK wrap is canonical, A1), and
     * it is flagged vk_mismatch. Every key-source decision in this class routes through here.
     */
    fun vouchGate(vaultId: String, key: ByteArray?): VouchGate {
        val v = legacyAuthorized[vaultId] ?: return VouchGate.NO_VOUCH
        return if (key != null && v.tag == tagOf(key)) VouchGate.OK else VouchGate.MISMATCH
    }

    /** True when the key HELD for [vaultId] contradicts this device's vouch for it. */
    fun heldKeyContradictsVouch(vaultId: String): Boolean =
        vaultKeys.containsKey(vaultId) && vouchGate(vaultId, vaultKeys[vaultId]) == VouchGate.MISMATCH

    /** The row's v1 seal key, only when the gate says it IS the vouched key. */
    private fun vouchedSealKey(vaultId: String, sealed: String?): ByteArray? =
        sealed?.takeIf { it.isNotEmpty() }?.let { openSealOrNull(vaultId, it) }?.takeIf { vouchGate(vaultId, it) == VouchGate.OK }

    private fun legacyVouched(vaultId: String, vk: ByteArray?): Boolean =
        legacyMode(vaultId, vk).let { it == LegacyGrant.Mode.FROZEN || it == LegacyGrant.Mode.CONFIRMED }

    /** SHA-256 (hex) of the held key for [vaultId]: what a host persists beside a §8.2 vouch. Null when not held. */
    fun legacyKeyTag(vaultId: String): String? = vaultKeys[vaultId]?.let { tagOf(it) }

    /** §1.6 pending invitations, by vaultId (rebuilt from the cached rows on every hydrate). */
    private val pendingGrants: LinkedHashMap<String, PendingGrant> = LinkedHashMap()

    /** §1.4 anomaly verdicts by vaultId (display only; nothing was adopted). */
    private val grantAnomalies: MutableMap<String, GrantVerdict> = mutableMapOf()

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

        /** 2^53 − 1 = JS Number.MAX_SAFE_INTEGER — the [parseMetaV] ceiling (see below). */
        const val METAV_MAX: Long = 9007199254740991L

        /**
         * spec 02 §4 metaV parse — the ONE rule every client applies ([SyncEngine.metaV],
         * [buildRenameMeta], and the web twins store.ts metaVOf + account.ts buildRenameMeta).
         * [content] is the RAW JSON *number* token; callers reject a string-typed primitive FIRST
         * ("2" is not a counter). It counts iff it parses to a finite, integral, non-negative Double
         * ≤ [METAV_MAX] → its Long value; else 0. This matches web MATHEMATICALLY: web reads the
         * JSON.parse'd number under Number.isSafeInteger, so `2.0`→2, `2e3`→2000, and a >2^63 literal
         * (e.g. 99999999999999999999, which overflows the safe-integer ceiling) → 0 on BOTH. Closes
         * the fleet fork where the old raw-token toLongOrNull read those three as 0 on Kotlin while
         * web read their numeric value — a divergence in exactly this adversarial anti-replay guard.
         */
        fun parseMetaV(content: String): Long {
            val d = content.toDoubleOrNull() ?: return 0L
            if (!d.isFinite() || d < 0.0 || d > METAV_MAX.toDouble() || d != kotlin.math.floor(d)) return 0L
            return d.toLong()
        }

        /**
         * Derive the login authKey a fresh device sends after prelogin.
         *
         * ZEROIZATION (audit H80, spec 01 §2 "MK never leaves the KDF step"): MK and the derived
         * authKey are dead the moment the base64 string exists, and are `fill(0)`-ed in a
         * `finally` — the same discipline the backup path already applies to MKx/exportKey
         * (spec 07 §2.3, [Backup]). Best-effort by nature (the JVM may have copied the arrays,
         * and the caller holds the encoded string), but it takes the MK — from which the login
         * credential AND the UVK wrap key re-derive — off the heap for a heap dump or swap page
         * instead of leaving it until GC. Every MK-derivation site in this class does the same:
         * [enroll], [unlock], [recover], and the identity seed in [unlockFromUvk].
         */
        fun deriveAuthKey(password: String, kdfSaltB64: String, params: KdfParams, crypto: CryptoProvider = createCryptoProvider()): String {
            val mk = Keys.masterKey(crypto, password, Bytes.fromB64(kdfSaltB64), params)
            try {
                val authKey = Keys.authKey(crypto, mk)
                try {
                    return Bytes.toB64(authKey)
                } finally {
                    authKey.fill(0)
                }
            } finally {
                mk.fill(0)
            }
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
            // Must match the AndvariApi wire tag ("android" | "windows" | "linux") — the [deviceInfo]
            // invariant — so the device row + audit entry agree with the X-Andvari-Client header this
            // session sends. Defaulted for source compat; desktop passes desktopPlatform(). Appended
            // LAST so every existing positional caller keeps compiling.
            platform: String = "android",
        ): EnrollResult {
            val userId = uuid(crypto)
            val personalVaultId = uuid(crypto)
            val kdfSalt = crypto.randomBytes(KdfParams.SALT_BYTES)
            // ZEROIZATION (audit H80; see [deriveAuthKey]): MK lives only long enough to split
            // into its two purposes (spec 01 §2 "MK never leaves the KDF step"); authKey, wrapKey
            // and the raw identity seed die once the request carries their encoded/sealed forms.
            // The UVK and VK are NOT wiped — the returned [Account] owns them for the session.
            val mk = Keys.masterKey(crypto, password, kdfSalt, params)
            val (authKey, wrapKey) = try {
                Keys.authKey(crypto, mk) to Keys.wrapKey(crypto, mk)
            } finally {
                mk.fill(0)
            }

            val uvk = crypto.randomBytes(32)
            val identitySeed = crypto.randomBytes(32)
            // The joint signing secret embeds the seed: if anything below throws before the Account
            // takes ownership of it, it is wiped with the seed.
            var signingForCleanup: ByteArray? = null
            try {
                val identity = crypto.boxKeypairFromSeed(identitySeed)
                val signing = crypto.signKeypairFromSeed(identitySeed)
                signingForCleanup = signing.privateKey
                val vk = crypto.randomBytes(32)

                // Org escrow is CONDITIONAL (§F.4): sealed only for a `required` invite (org key present),
                // preserving the verified-fingerprint discipline — refuse to seal the UVK to a key whose
                // fingerprint the enrollee did not confirm out-of-band. Waived ⇒ no escrow blob.
                // Escrow v2 from this release (security review 2026-10, root cause A §2.1, §8.4): the UVK
                // travels inside a statement signed with the joint key, binding this account's userId and
                // identity key and the FULL org fingerprint, so recovery can prove whose blob it is.
                val escrow: EscrowUpload? = if (recoveryPublicKey != null) {
                    val fp = requireNotNull(recoveryFingerprint) { "recoveryFingerprint is required when sealing org escrow" }
                    val computedFp = Escrow.fingerprint(crypto, recoveryPublicKey)
                    if (computedFp != fp) throw CryptoException("recovery public key does not match its fingerprint")
                    EscrowUpload(
                        Bytes.toB64(Escrow.sealUvkV2(crypto, recoveryPublicKey, fp, userId, identity.publicKey, signing, uvk, nowMs())),
                        fp,
                    )
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
                    device = DeviceInfo(platform, deviceName),
                    // Root cause A §4.1: "personal" is this UVK-authenticated wrap from day one.
                    personalWrap = PersonalWrap(personalVaultId, Envelope.sealB64(crypto, uvk, vk, Ad.vkPersonal(personalVaultId, userId))),
                )
                val account = Account(
                    crypto, userId, uvk, identity.publicKey, identity.privateKey, signing.publicKey, signing.privateKey, personalVaultId,
                    mutableMapOf(personalVaultId to vk), mutableMapOf(personalVaultId to "owner"),
                )
                account.personalStatus = PersonalStatus.CONFIRMED
                account.personalWrap = req.personalWrap
                account.uvkWrappedVaults.add(personalVaultId)
                signingForCleanup = null // owned by the returned Account now
                return EnrollResult(req, account, recovery.recoverySecret)
            } finally {
                signingForCleanup?.fill(0)
                authKey.fill(0)
                wrapKey.fill(0)
                identitySeed.fill(0)
            }
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
            //    ZEROIZATION (audit H80; see [deriveAuthKey]): the new MK dies after its purpose
            //    split, its two children once the commit body carries their encoded/sealed forms —
            //    and so does the recovered UVK: recover() returns a commit body, not a session (the
            //    commit revokes every session and the member signs in afresh), so no caller holds
            //    this copy. The throw-away Account the step-2 probe built shares the reference and
            //    is already unreachable.
            val newKdfSalt = crypto.randomBytes(KdfParams.SALT_BYTES)
            val newMk = Keys.masterKey(crypto, newPassword, newKdfSalt, newParams)
            val (newAuthKey, newWrapKey) = try {
                Keys.authKey(crypto, newMk) to Keys.wrapKey(crypto, newMk)
            } finally {
                newMk.fill(0)
            }
            try {
                return RecoveryCommitRequest(
                    recoveryTicket = verifyResponse.recoveryTicket,
                    newAuthKey = Bytes.toB64(newAuthKey),
                    newKdfSalt = Bytes.toB64(newKdfSalt),
                    newKdfParams = newParams,
                    newWrappedUvk = Envelope.sealB64(crypto, newWrapKey, uvk, Ad.uvk(userId)),
                )
            } finally {
                newAuthKey.fill(0)
                newWrapKey.fill(0)
                uvk.fill(0)
            }
        }

        /** Unlock a device holding only the password + the server's account keys. */
        /**
         * [selfIdentityPub] (design §2.4, the recovered-member backstop): the seed-derived identityPub
         * THIS device recorded the first time it unlocked this account ([SelfIdentityPin]). When given,
         * the shared tail hard-fails with the spec 01 §5 security-fault copy if the seed now derives a
         * different key — a forged recovery would have to change the identity seed, and every device
         * that knew the real one refuses it. Null = this device never unlocked the account before.
         */
        fun unlock(
            userId: String,
            password: String,
            keys: AccountKeys,
            crypto: CryptoProvider = createCryptoProvider(),
            selfIdentityPub: ByteArray? = null,
        ): Account {
            // ZEROIZATION (audit H80; see [deriveAuthKey]): after the wrappedUvk open the session
            // needs only the UVK — MK and wrapKey are wiped on the way out, success or failure.
            val mk = Keys.masterKey(crypto, password, Bytes.fromB64(keys.kdfSalt), keys.kdfParams)
            val wrapKey = try {
                Keys.wrapKey(crypto, mk)
            } finally {
                mk.fill(0)
            }
            // H67: STRUCTURE first, secret second. A blob that is not decodable base64url, or whose
            // public header is too short / carries an envelope version or alg this build does not
            // know, is refused BEFORE the wrap key is applied and surfaces as the distinct terminal
            // [VaultKeyDamagedException] — those refusals cannot possibly mean "wrong password"
            // (no password participates in them), and saying so sent members to reset a working
            // password. Only what remains — the AEAD tag failure, the one genuinely ambiguous
            // outcome — keeps the "wrong master password" relabel.
            val uvk = try {
                val envelope = try {
                    Bytes.fromB64(keys.wrappedUvk)
                } catch (e: CryptoException) {
                    throw VaultKeyDamagedException("wrappedUvk is not valid base64url", e)
                }
                Envelope.structuralRefusal(envelope)?.let { throw VaultKeyDamagedException("wrappedUvk: $it") }
                try {
                    Envelope.open(crypto, wrapKey, envelope, Ad.uvk(userId))
                } catch (e: CryptoException) {
                    throw CryptoException("wrong master password")
                }
            } finally {
                wrapKey.fill(0)
            }
            // Password path validates the password by the wrappedUvk open above; from here the
            // work is identical to the UVK (quick-unlock) path — one shared tail, no drift.
            return unlockFromUvk(userId, uvk, keys, crypto, selfIdentityPub)
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
        fun unlockWithUvk(
            userId: String,
            uvk: ByteArray,
            keys: AccountKeys,
            crypto: CryptoProvider = createCryptoProvider(),
            selfIdentityPub: ByteArray? = null,
        ): Account = unlockFromUvk(userId, uvk, keys, crypto, selfIdentityPub)

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
         * apart from a bad secret.
         *
         * R38 (H67's missing leg): `encryptedIdentitySeed` gets the SAME public-header gate as
         * `wrappedUvk` one line earlier. It is the sibling account-key blob in the same damaged
         * row — a partial DB restore or an old build fed a v2 envelope damages both — and without
         * the gate a structurally broken seed collapsed into "Wrong master password" on the
         * password path, which is exactly the sentence H67 exists to stop being said about a
         * damaged row. The old KDoc conceded the gap and justified it with "an honest server's
         * UVK always opens it": true, and beside the point, because a DIShonest or half-restored
         * server row is the trigger.
         *
         * Safe on the QUICK-UNLOCK path too, which is why the gate can live in the shared tail:
         * a wrong or stale UVK produces an AEAD TAG failure, never a base64/version/alg refusal
         * (those are decided from the public header before any key is used). So the "validation
         * by consequence" signal this path relies on — the UVK is not this account's — is
         * untouched: it still arrives as the plain [CryptoException] the callers wipe the
         * quick-unlock blob on. Only the four structural refusals, which no secret could ever
         * have made pass, are re-labelled as the damaged-keys terminal.
         */
        private fun unlockFromUvk(
            userId: String,
            uvk: ByteArray,
            keys: AccountKeys,
            crypto: CryptoProvider,
            selfIdentityPub: ByteArray? = null,
        ): Account {
            val seedEnvelope = try {
                Bytes.fromB64(keys.encryptedIdentitySeed)
            } catch (e: CryptoException) {
                throw VaultKeyDamagedException("encryptedIdentitySeed is not valid base64url", e)
            }
            Envelope.structuralRefusal(seedEnvelope)?.let { throw VaultKeyDamagedException("encryptedIdentitySeed: $it") }
            val identitySeed = Envelope.open(crypto, uvk, seedEnvelope, Ad.idkey(userId))
            // ZEROIZATION (audit H80): the seed's only job is to derive the keypairs the Account
            // holds — it never needs to be resident after that (a compromise of the seed IS a
            // compromise of the identity key, so it gets the same care as the MK). Both the X25519
            // identity and the joint Ed25519 signing key (root cause A §1.1) come from it here.
            val identity: KeyPairBytes
            val signing: KeyPairBytes
            try {
                identity = crypto.boxKeypairFromSeed(identitySeed)
                signing = crypto.signKeypairFromSeed(identitySeed)
            } finally {
                identitySeed.fill(0)
            }
            // spec 01 §5 (web account.ts parity): a MALFORMED/undecodable server identityPub is itself
            // the tampering signal — decode defensively so garbage-where-the-key-belongs raises the
            // SAME "possible server compromise" CryptoException, never a generic base64 decode error.
            val serverIdentityPub = runCatching { Bytes.fromB64(keys.identityPub) }.getOrNull()
            if (serverIdentityPub == null || !identity.publicKey.contentEquals(serverIdentityPub)) {
                // The signing secret embeds the seed (libsodium's seed ‖ pk layout): never leave it
                // behind on the refusal path.
                signing.privateKey.fill(0)
                identity.privateKey.fill(0)
                throw CryptoException(IDENTITY_MISMATCH_MESSAGE)
            }
            // Design §2.4: this device's own record of the identity key wins over anything the server
            // can change. A recovery that swapped the identity seed (A-3 against a member whose admin
            // had no anchor) is refused here on every device that unlocked the account before.
            if (selfIdentityPub != null && !Bytes.ctEquals(identity.publicKey, selfIdentityPub)) {
                signing.privateKey.fill(0)
                identity.privateKey.fill(0)
                throw CryptoException(IDENTITY_MISMATCH_MESSAGE)
            }
            val account = Account(crypto, userId, uvk, identity.publicKey, identity.privateKey, signing.publicKey, signing.privateKey, "", mutableMapOf())
            // Root cause A §4.3: the personal vault comes from the UVK-authenticated wrap and nothing else.
            account.applyPersonalWrap(keys.personalWrap)
            return account
        }

        /** spec 01 §5 security-fault copy, shared by the server-identityPub check and the §2.4 backstop. */
        const val IDENTITY_MISMATCH_MESSAGE =
            "identity key mismatch — the server returned an identity public key that " +
                "your account's sealed seed does not derive; possible server compromise. Do not proceed."

        private fun nowMs(): Long = kotlinx.datetime.Clock.System.now().toEpochMilliseconds()

        private fun uuid(crypto: CryptoProvider): String =
            Bytes.uuidV4FromBytes(crypto.randomBytes(16)) // RFC 4122 v4 from 16 random bytes
    }

    /**
     * Sign [statement] with this account's joint key and return the v2 frame (spec 01 §5.1). A3 ships
     * it with NO product caller: escrow v2 and signed grants (later branches) seal the frame to the
     * recipient. Internal so only core can sign.
     */
    internal fun signStatement(statement: Statement): ByteArray =
        SignedStatement.build(crypto, KeyPairBytes(signPub, signSecret), statement)

    /**
     * Apply an incoming grant (spec 01 §6). The ROLE update is unconditional — a role
     * change re-delivers the grant with a bumped rev and must take effect even though the
     * VK is already held; the key itself is opened only when missing, by [openGrantVk]'s
     * canonical-key precedence (security review 2026-10, root cause A §3.1).
     *
     * Throws [VaultGrantKeyUnreadableException] when the row carries our UVK wrap and it does
     * not open: that vault stays keyless (no seal fallback) and [keyUnreadable] says so.
     */
    fun addGrant(grant: WireGrant) {
        if (grant.role.isNotEmpty()) vaultRoles[grant.vaultId] = grant.role
        val held = vaultKeys[grant.vaultId]
        if (held != null) {
            // A key held ONLY from a v1 seal is confirmed (same key) by a verified v2 grant on a re-delivered row:
            // the owner's re-issue, root cause A §8.2 step 3 first bullet. A verified grant naming a DIFFERENT key
            // never replaces it (A6 review MED-2: any pinned contact can sign a grant, and nothing yet binds a grant
            // to the vault's owner): it is the vk_mismatch anomaly, the held key stays, and an unvouched one stays
            // read-only.
            if (keySources[grant.vaultId] == KeySource.LEGACY_SEAL && !grant.signedGrant.isNullOrEmpty()) {
                when (val o = openSigned(grant, heldVk = null)) {
                    is GrantOutcome.Adopted -> {
                        // Round 3 MEDIUM-B: promotion goes through the gate too — a held key that contradicts the
                        // vouch is never promoted, even when a verified grant carries that same key.
                        if (!Bytes.ctEquals(o.vk, held) || vouchGate(grant.vaultId, held) == VouchGate.MISMATCH) {
                            grantAnomalies[grant.vaultId] = GrantVerdict.VK_MISMATCH
                            vkMismatchVaults.add(grant.vaultId)
                            return
                        }
                        keySources[grant.vaultId] = KeySource.SIGNED_GRANT
                        signedGrantFrom[grant.vaultId] = o.from
                        pendingGrants.remove(grant.vaultId)
                        grantAnomalies.remove(grant.vaultId)
                        return
                    }
                    is GrantOutcome.Pending -> pendingGrants[grant.vaultId] = PendingGrant(grant.vaultId, o.from, o.grantIdB64)
                    // A6 review LOW-2: a present v2 field that fails any step is an anomaly here too.
                    is GrantOutcome.Refused -> grantAnomalies[grant.vaultId] = o.verdict
                }
            }
            // Already held: the row cannot change our key (the warm-session guard), but a
            // re-delivered row that now carries a DIFFERENT key is still worth surfacing.
            if (rowCarriesOtherKey(grant, held)) vkMismatchVaults.add(grant.vaultId)
            return
        }
        val opened = try {
            openGrantVk(grant)
        } catch (e: VaultGrantKeyUnreadableException) {
            unreadableKeyVaults.add(grant.vaultId)
            throw e
        } catch (e: GrantPendingException) {
            // §1.6: not adopted, and no fallback to the v1 seal on the same row.
            pendingGrants[grant.vaultId] = e.pending
            grantAnomalies.remove(grant.vaultId)
            return
        } catch (e: GrantRefusedException) {
            grantAnomalies[grant.vaultId] = e.verdict
            pendingGrants.remove(grant.vaultId)
            return
        }
        val vk = opened.vk
        // The same 32-byte assertion [SharedGrant.open] makes on the sealed branch, on the
        // wrapped one (audit F32). Nothing downstream re-checks: a wrong-length VK went into
        // the key map and only surfaced at the next envelope operation, as an
        // IllegalArgumentException from a `require` deep in the crypto provider — which
        // SyncEngine's runCatching paths classify differently from a CryptoException, so the
        // same broken grant produced two different verdicts depending on which branch minted it.
        if (vk.size != 32) throw CryptoException("vault key for ${grant.vaultId} is not 32 bytes")
        vaultKeys[grant.vaultId] = vk
        keySources[grant.vaultId] = opened.source
        opened.from?.let { signedGrantFrom[grant.vaultId] = it }
        pendingGrants.remove(grant.vaultId)
        grantAnomalies.remove(grant.vaultId)
        unreadableKeyVaults.remove(grant.vaultId)
        if (opened.sealMismatch) vkMismatchVaults.add(grant.vaultId)
        opened.anomaly?.let { grantAnomalies[grant.vaultId] = it }
        if (opened.source == KeySource.UVK_WRAP && grant.userId == userId) uvkWrappedVaults.add(grant.vaultId)
        // Provenance of the KEY, recorded at the one moment it is knowable (audit H64), and NOT
        // re-stamped by a later re-delivery (the early return above). Since root cause A §3.2 a
        // member's own row can carry a UVK self-wrap, so "opened from a seal" alone no longer
        // separates "shared" from "mine alone". A row is member-granted when the key came from a
        // seal, OR the row carries any seal at all (a member row, or a post-transfer owner row
        // that retains one), OR its role is not owner (a member self-wrap whose seal the server
        // dropped). Since root cause A §4 this bit no longer decides "personal" (the personal wrap
        // does); it feeds only the display and the §8.5 migration's candidate filter.
        if (opened.viaSeal || !grant.sealedVk.isNullOrEmpty() || !grant.signedGrant.isNullOrEmpty() || grant.role != "owner") {
            memberGrantedVaults.add(grant.vaultId)
        }
    }

    private class GrantPendingException(val pending: PendingGrant) : Exception("grant pending verification")
    private class GrantRefusedException(val verdict: GrantVerdict) : Exception("grant refused: ${verdict.code}")

    /** Run §1.4 on the row's v2 grant ([SignedGrant.open]); [heldVk] only when held from our OWN wrap. */
    private fun openSigned(grant: WireGrant, heldVk: ByteArray?): GrantOutcome {
        val sealed = try {
            Bytes.fromB64(grant.signedGrant ?: "")
        } catch (e: CryptoException) {
            return GrantOutcome.Refused(GrantVerdict.UNOPENABLE)
        }
        return SignedGrant.open(crypto, userId, identityPub, identityPriv, grant.vaultId, sealed, grantPins, heldVk)
    }

    /** A key opened from a grant row, with how it was reached ([viaSeal]) and whether a seal on
     *  the same row opened to a different key ([sealMismatch], the §3.1 anomaly). */
    private class OpenedVk(
        val vk: ByteArray,
        val source: KeySource,
        val sealMismatch: Boolean,
        val from: String? = null,
        /** A §1.4 anomaly recorded although a key was adopted (the vouched legacy key kept over a different v2 key). */
        val anomaly: GrantVerdict? = null,
    ) {
        val viaSeal: Boolean get() = source == KeySource.LEGACY_SEAL || source == KeySource.SIGNED_GRANT
    }

    /**
     * Canonical-key precedence (security review 2026-10, root cause A §3.1). The VK comes from
     * the FIRST of these that the row carries:
     *
     *  1. the personal wrap (§4): applied at unlock by [applyPersonalWrap], so its key is already
     *     held when the grant row arrives and the row can only be compared against it (a different
     *     key is the [vkMismatch] anomaly);
     *  2. our own UVK wrap, `wrappedVk` = `Envelope(UVK, VK, Ad.vk(vaultId, userId))`: the owner
     *     wrap, the post-transfer new-owner wrap and the member self-wrap (§3.2);
     *  3. a v2 signed grant (§1.4): not yet built, the hook for the signed-grants branch;
     *  4. a v1 `sealedVk`, legacy only.
     *
     * A server-delivered seal is never preferred over a UVK wrap. When the wrap opens, a seal on
     * the same row is still opened, only to compare: the same key is silent, a different key is
     * reported as [OpenedVk.sealMismatch] (the wrapped key wins), and a seal that does not open
     * is ignored (an honest post-transfer row can retain a seal for an earlier identity).
     *
     * When the wrap is PRESENT but does not open, this throws [VaultGrantKeyUnreadableException]
     * and never tries the seal: a damaged or substituted wrap must not hand the decision to a
     * blob the server can mint.
     */
    private fun openGrantVk(grant: WireGrant): OpenedVk {
        val sealed = grant.sealedVk
        if (grant.wrappedVk.isNotEmpty()) {
            val vk = try {
                val envelope = Bytes.fromB64(grant.wrappedVk)
                Envelope.structuralRefusal(envelope)?.let { throw VaultGrantKeyUnreadableException(grant.vaultId, it) }
                Envelope.open(crypto, uvk, envelope, Ad.vk(grant.vaultId, userId))
            } catch (e: VaultGrantKeyUnreadableException) {
                throw e
            } catch (e: Exception) {
                throw VaultGrantKeyUnreadableException(grant.vaultId, "wrap does not open", e)
            }
            // A wrap that OPENS under our UVK was minted by one of our own clients, so a wrong
            // length is a buggy writer, not a substitution: it keeps the audit F32 CryptoException
            // classification (still terminal, still no seal fallback).
            if (vk.size != 32) throw CryptoException("vault key for ${grant.vaultId} is not 32 bytes")
            val sealVk = if (sealed.isNullOrEmpty()) null else openSealOrNull(grant.vaultId, sealed)
            // A v2 grant beside our wrap is compared too; only a VERIFIED one can disagree with it.
            val signedDiffers = !grant.signedGrant.isNullOrEmpty() && openSigned(grant, heldVk = vk).verdict == GrantVerdict.VK_MISMATCH
            // Rule 2 is canonical (A1) and is USED even against this device's vouch, but flagged (round 3 LOW-F).
            val gateAnomaly = if (vouchGate(grant.vaultId, vk) == VouchGate.MISMATCH) GrantVerdict.VK_MISMATCH else null
            return OpenedVk(vk, KeySource.UVK_WRAP, sealMismatch = (sealVk != null && !Bytes.ctEquals(sealVk, vk)) || signedDiffers, anomaly = gateAnomaly)
        }
        // (3) v2 signed grant, verified per root cause A §1.4 against our PIN for the sender it names.
        if (!grant.signedGrant.isNullOrEmpty()) {
            when (val o = openSigned(grant, heldVk = null)) {
                is GrantOutcome.Adopted -> {
                    // A6 review MED-2 / re-review MEDIUM-A, cold start: a vault this device vouched for is decided
                    // from the device-local vouch TAG, not from whether the server kept the v1 seal. A verified grant
                    // naming a DIFFERENT key than the vouched one is the vk_mismatch anomaly: keep the vouched key
                    // when the row's seal still opens to it, otherwise refuse the row with no key. Never adopt it.
                    if (vouchGate(grant.vaultId, o.vk) == VouchGate.MISMATCH) {
                        val vouched = vouchedSealKey(grant.vaultId, sealed)
                        if (vouched != null) {
                            return OpenedVk(vouched, KeySource.LEGACY_SEAL, sealMismatch = true, anomaly = GrantVerdict.VK_MISMATCH)
                        }
                        throw GrantRefusedException(GrantVerdict.VK_MISMATCH)
                    }
                    return OpenedVk(o.vk, KeySource.SIGNED_GRANT, sealMismatch = false, from = o.from)
                }
                is GrantOutcome.Pending -> {
                    // A pending invitation is never satisfied by the v1 seal on the same row, EXCEPT for a vault
                    // this device already vouched for (§8.2 freeze or the human's Accept) whose self-wrap has not
                    // reached the row yet: that key stays exactly as trusted as it was.
                    vouchedSealKey(grant.vaultId, sealed)?.let { return OpenedVk(it, KeySource.LEGACY_SEAL, sealMismatch = false) }
                    throw GrantPendingException(PendingGrant(grant.vaultId, o.from, o.grantIdB64))
                }
                is GrantOutcome.Refused ->
                    // Any refusal refuses the ROW, and the v1 seal beside it is no fallback: an anomaly (misaddressed,
                    // wrong vault, wrong signer, bad signature) means the server tampered; a field that is PRESENT but
                    // does not open or parse (A6 review LOW-2) must not turn into an "Accept anyway" on the seal.
                    // Only an ABSENT field leaves the decision to the legacy rule below (Q7).
                    throw GrantRefusedException(o.verdict)
            }
        }
        // (4) v1 `sealedVk`: LEGACY_SEAL, read-only until vouched for (§8.2); the graded decision refuses it once
        // the compatibility window closes (A8), unless this device holds evidence for that exact key.
        if (!sealed.isNullOrEmpty()) {
            val vk = SharedGrant.open(crypto, identityPub, identityPriv, grant.vaultId, Bytes.fromB64(sealed))
            // Round 3 LOW-E: a seal for another key than this device's vouch is vk_mismatch, not a read-only key
            // waiting for an "Accept anyway" that would overwrite the vouch.
            if (vouchGate(grant.vaultId, vk) == VouchGate.MISMATCH) throw GrantRefusedException(GrantVerdict.VK_MISMATCH)
            if (legacyMode(grant.vaultId, vk) == LegacyGrant.Mode.REFUSED) throw CryptoException("legacy grant refused outside the compatibility window")
            return OpenedVk(vk, KeySource.LEGACY_SEAL, sealMismatch = false)
        }
        throw CryptoException("grant for ${grant.vaultId} carries no key")
    }

    private fun openSealOrNull(vaultId: String, sealed: String): ByteArray? =
        runCatching { SharedGrant.open(crypto, identityPub, identityPriv, vaultId, Bytes.fromB64(sealed)) }.getOrNull()

    /** A re-delivered row for a vault whose key we hold: does any key it carries differ from it? */
    private fun rowCarriesOtherKey(grant: WireGrant, held: ByteArray): Boolean {
        val fromWrap = if (grant.wrappedVk.isEmpty()) null else runCatching {
            Envelope.openB64(crypto, uvk, grant.wrappedVk, Ad.vk(grant.vaultId, userId))
        }.getOrNull()
        val fromSeal = grant.sealedVk?.takeIf { it.isNotEmpty() }?.let { openSealOrNull(grant.vaultId, it) }
        val fromSigned = if (grant.signedGrant.isNullOrEmpty()) null else (openSigned(grant, heldVk = null) as? GrantOutcome.Adopted)?.vk
        return listOfNotNull(fromWrap, fromSeal, fromSigned).any { !Bytes.ctEquals(it, held) }
    }

    /** True when a grant row for this vault carried a seal whose key differs from the one we
     *  hold (the "vault key mismatch" anomaly, root cause A §3.1). Display only: the held key
     *  is already the canonical one. */
    fun vkMismatch(vaultId: String): Boolean = vaultId in vkMismatchVaults

    /** Vault ids currently flagged by [vkMismatch]. */
    fun vkMismatchVaultIds(): Set<String> = vkMismatchVaults.toSet()

    /** True when this vault's grant carries our UVK wrap and it does not open (no seal fallback). */
    fun keyUnreadable(vaultId: String): Boolean = vaultId in unreadableKeyVaults

    /** Vault ids currently flagged by [keyUnreadable]. */
    fun keyUnreadableVaultIds(): Set<String> = unreadableKeyVaults.toSet()

    /**
     * True when we hold this vault's key from a v1 seal and the row has no UVK wrap of ours yet:
     * a candidate for the member self-wrap of root cause A §3.2 ([buildSelfWrap]).
     *
     * NOT A TRUST SIGNAL. A v1 seal is server-mintable, so wrapping its key under our UVK would
     * launder a possibly server-chosen key into the canonical slot for every device. No caller
     * posts on this alone: [selfWrapAuthorized] (a verified v2 grant, or a v1 key this device
     * froze or the human confirmed) is the gate.
     */
    fun needsSelfWrap(grant: WireGrant): Boolean =
        vaultKeys.containsKey(grant.vaultId) && grant.wrappedVk.isEmpty() &&
            (!grant.sealedVk.isNullOrEmpty() || !grant.signedGrant.isNullOrEmpty()) &&
            grant.role != "owner" && grant.userId == userId

    /**
     * Root cause A §3.2 / §8.2, the ONLY gate on minting a member self-wrap: the held key came from a v2 grant
     * VERIFIED against our pin for its sender, or from a v1 seal this device vouched for (pre-upgrade evidence,
     * or the human's Accept, [authorizeLegacyKey]). A key only an unconfirmed v1 seal vouches for is never
     * wrapped: that auto-post was the A1 trust-laundering bug.
     */
    fun selfWrapAuthorized(vaultId: String): Boolean = vaultKeys.containsKey(vaultId) && !heldKeyContradictsVouch(vaultId) && when (keySources[vaultId]) {
        KeySource.SIGNED_GRANT -> true
        KeySource.LEGACY_SEAL -> legacyVouched(vaultId, vaultKeys[vaultId])
        else -> false
    }

    /** Where this vault's held key came from (null when not held). */
    fun keySource(vaultId: String): KeySource? = if (vaultKeys.containsKey(vaultId)) keySources[vaultId] else null

    /** INV-WRITE-KEY: a key only an unconfirmed v1 seal vouches for. Readable; never written under. */
    fun isLegacyReadOnly(vaultId: String): Boolean =
        vaultKeys.containsKey(vaultId) && keySources[vaultId] == KeySource.LEGACY_SEAL && !legacyVouched(vaultId, vaultKeys[vaultId])

    /** Vault ids [isLegacyReadOnly] answers true for. */
    fun legacyReadOnlyVaultIds(): Set<String> = vaultKeys.keys.filter { isLegacyReadOnly(it) }.toSet()

    /**
     * §8.2: this device vouches for the v1-only key of [vaultId], because it holds pre-upgrade evidence (the
     * freeze) or because the human accepted it on the review card (trust on first use). The host persists the
     * decision; this lifts the read-only state and permits the self-wrap.
     */
    fun authorizeLegacyKey(vaultId: String, keyTag: String? = null, frozen: Boolean = false) {
        val tag = keyTag ?: legacyKeyTag(vaultId) ?: return
        legacyAuthorized[vaultId] = LegacyVouch(tag, frozen)
    }

    /** The sender the VERIFIED v2 grant for [vaultId] names (null unless the key came from one). */
    fun signedGrantSender(vaultId: String): String? = if (keySources[vaultId] == KeySource.SIGNED_GRANT) signedGrantFrom[vaultId] else null

    /** §1.6 pending invitations (vaults NOT adopted). */
    fun pendingGrants(): List<PendingGrant> = pendingGrants.values.toList()

    /** §1.4 anomaly verdicts by vaultId (nothing adopted for these rows). */
    fun grantAnomalies(): Map<String, GrantVerdict> = grantAnomalies.toMap()

    /**
     * Owner side (root cause A §1.5): grant v2 for [vaultId] to the member [pin] names. The statement's `toKey`
     * is the PINNED key and the frame is sealed to it, never to a key fresh from `/users/lookup`. Refuses a key
     * this account itself holds only from an unconfirmed v1 seal (signing it would launder it to the member).
     */
    fun buildSignedGrant(vaultId: String, pin: Contact): String {
        if (isLegacyReadOnly(vaultId) || heldKeyContradictsVouch(vaultId)) throw VaultKeyNotVerifiedException(vaultId)
        if (pin.userId == userId) throw CryptoException("a vault grant cannot be addressed to its sender")
        val pinKey = Bytes.fromB64(pin.identityPub)
        val st = Statement.VaultGrant(
            from = userId, to = pin.userId, toKey = pinKey, vaultId = vaultId,
            grantId = crypto.randomBytes(16), issuedAt = nowMs(), vk = vk(vaultId),
        )
        return Bytes.toB64(SignedGrant.seal(crypto, pinKey, signStatement(st)))
    }

    /**
     * True when this vault's VK reached us through a member grant (`sealedVk`,
     * `crypto_box_seal` to our identity pubkey) rather than wrapped under our own UVK.
     *
     * WHY this distinction is security-relevant and not bookkeeping: a `sealedVk` is
     * ANONYMOUS — anybody holding our public identity key can mint one, and the VK inside it
     * is by construction a key at least one other person already has. A `wrappedVk` opens
     * only under our UVK with AD `andvari/v1|vk|{vaultId}|{userId}`, so it is unforgeable
     * evidence that this client itself sealed that key for itself (enrollment, shared-vault
     * creation, password change re-wrap, transfer accept). "Which vault is mine alone" must
     * rest on the second kind of evidence, never the first.
     *
     * Since the member self-wrap (root cause A §3.2) a member's row can carry a `wrappedVk` too,
     * so this also answers true for a row that carries any seal or whose role is not owner (see
     * [addGrant]). The name is kept because callers ask the same question: "is this a vault
     * somebody else can read?"
     */
    fun keyArrivedByMemberGrant(vaultId: String): Boolean = vaultId in memberGrantedVaults

    /**
     * Root cause A §4.3: adopt the personal vault from `AccountKeys.personalWrap`, the ONLY
     * authenticated statement of which vault is ours alone. `Envelope(UVK, VK, Ad.vkPersonal(vaultId,
     * userId))` opens only under this user's UVK and only for that purpose, so the server can neither
     * relabel nor forge it, only withhold it.
     *
     *  - null (absent): [PersonalStatus.ABSENT], no personal vault until the §8.5 migration resolves.
     *  - present and opens: [PersonalStatus.CONFIRMED]; its VK is held FIRST (precedence rule 1), so a
     *    grant row for the same vault can only be compared against it.
     *  - present and does not open: [PersonalStatus.UNREADABLE] (an anomaly), no personal vault, and no
     *    fallback to any label.
     *
     * Replaces the pre-A5 `setPersonalVault(label candidate)`, which trusted the server's `type` label
     * plus a provenance heuristic (audit H64) and could be fooled by a server that stripped a seal and
     * relabelled `role=owner`. A server `type` label or `role` never reaches this decision.
     */
    fun applyPersonalWrap(wrap: PersonalWrap?) {
        if (wrap == null) {
            if (personalStatus == PersonalStatus.ABSENT || personalStatus == PersonalStatus.UNREADABLE) {
                personalStatus = PersonalStatus.ABSENT
                personalVaultId = ""
            }
            return
        }
        pendingPersonalChange = null
        if (openAndInstallPersonalWrap(wrap)) personalStatus = PersonalStatus.CONFIRMED
        else {
            personalStatus = PersonalStatus.UNREADABLE
            personalVaultId = ""
            personalWrap = null
        }
    }

    /**
     * The wrap THIS DEVICE cached the last time it authenticated one (UVK-sealed), applied after the served
     * wrap was judged (A5 review H-1; A5 re-review L-1). Only while nothing usable was served:
     *  - ABSENT (none served): success is [PersonalStatus.WITHHELD]; a cached blob that does not open is
     *    [PersonalStatus.UNREADABLE];
     *  - UNREADABLE (junk served): success is [PersonalStatus.UNREADABLE_CACHED], the cached wrap in force;
     *    a cached blob that does not open changes nothing.
     * The migration question and every server label stay out of it.
     */
    fun applyCachedPersonalWrap(wrap: PersonalWrap) {
        when (personalStatus) {
            PersonalStatus.ABSENT ->
                if (openAndInstallPersonalWrap(wrap)) personalStatus = PersonalStatus.WITHHELD
                else {
                    personalStatus = PersonalStatus.UNREADABLE
                    personalVaultId = ""
                }
            PersonalStatus.UNREADABLE ->
                if (openAndInstallPersonalWrap(wrap)) personalStatus = PersonalStatus.UNREADABLE_CACHED
            else -> {}
        }
    }

    /**
     * A5 re-review M-2 / L-2: the served wrap opened ([PersonalStatus.CONFIRMED]) but this device's cached wrap
     * names a DIFFERENT vault. If the cached wrap opens, it stays in force and the served one waits in
     * [pendingPersonalChange] ([PersonalStatus.CHANGED]) until the human confirms. Returns false (nothing held)
     * when the status is not CONFIRMED, the vaults agree, or the cached blob does not open (then the served
     * wrap stands and the caller re-caches it).
     */
    fun holdPersonalChange(cached: PersonalWrap): Boolean {
        val served = personalWrap ?: return false
        if (personalStatus != PersonalStatus.CONFIRMED || cached.vaultId == served.vaultId) return false
        if (!openAndInstallPersonalWrap(cached)) return false // openAndInstall mutates only on success
        pendingPersonalChange = served
        personalStatus = PersonalStatus.CHANGED
        return true
    }

    /** The human confirmed a [PersonalStatus.CHANGED] notice: the served wrap (already authenticated under
     *  our UVK) is now in force. Mints nothing. */
    fun acceptPersonalChange() {
        val served = pendingPersonalChange ?: throw IllegalStateException("no personal-vault change is pending")
        check(personalStatus == PersonalStatus.CHANGED) { "no personal-vault change is pending" }
        check(openAndInstallPersonalWrap(served)) { "the served personal wrap no longer opens" }
        pendingPersonalChange = null
        personalStatus = PersonalStatus.CONFIRMED
    }

    /** The served wrap waiting for the human while [personalStatus] is [PersonalStatus.CHANGED]. */
    var pendingPersonalChange: PersonalWrap? = null
        private set

    /** The wrap that decided [personalVaultId] (served or cached), for the device's local cache. */
    var personalWrap: PersonalWrap? = null
        private set

    private fun openAndInstallPersonalWrap(wrap: PersonalWrap): Boolean {
        val vk = runCatching { Envelope.openB64(crypto, uvk, wrap.wrappedVk, Ad.vkPersonal(wrap.vaultId, userId)) }.getOrNull()
        if (vk == null || vk.size != 32) return false
        val held = vaultKeys[wrap.vaultId]
        if (held != null && !Bytes.ctEquals(held, vk)) vkMismatchVaults.add(wrap.vaultId)
        vaultKeys[wrap.vaultId] = vk
        keySources[wrap.vaultId] = KeySource.PERSONAL_WRAP
        unreadableKeyVaults.remove(wrap.vaultId)
        uvkWrappedVaults.add(wrap.vaultId)
        personalVaultId = wrap.vaultId
        personalWrap = wrap
        return true
    }

    /** True when this vault's key opened from a UVK wrap of ours (never a seal): a vault the
     *  re-designation may offer (§4.3, "offers only vaults whose VK opens under the user's UVK"). */
    fun keyFromOwnUvkWrap(vaultId: String): Boolean = vaultId in uvkWrappedVaults && vaultKeys.containsKey(vaultId)

    /** Vault ids [keyFromOwnUvkWrap] answers true for. */
    fun ownUvkWrappedVaultIds(): Set<String> = uvkWrappedVaults.filter { vaultKeys.containsKey(it) }.toSet()

    /**
     * Mint the personal wrap for [vaultId] (§4.1): its held VK under our UVK with `Ad.vkPersonal`,
     * round-trip verified. Refuses a vault whose key did not open from our own UVK wrap, so a key a
     * server-mintable seal delivered can never be laundered into "personal".
     */
    fun buildPersonalWrap(vaultId: String): PersonalWrap {
        if (!keyFromOwnUvkWrap(vaultId)) throw CryptoException("vault $vaultId is not wrapped under this account's key")
        val vk = vk(vaultId)
        val wrapped = Envelope.sealB64(crypto, uvk, vk, Ad.vkPersonal(vaultId, userId))
        if (!Envelope.openB64(crypto, uvk, wrapped, Ad.vkPersonal(vaultId, userId)).contentEquals(vk)) {
            throw CryptoException("personal wrap failed round-trip verification")
        }
        return PersonalWrap(vaultId, wrapped)
    }

    /** Seal an account-state document (root cause A §4.2) under the UVK, bound to this userId. */
    fun sealAccountState(doc: AccountStateDoc): String {
        require(doc.userId == userId) { "account state belongs to another user" }
        return Envelope.sealB64(crypto, uvk, AccountState.encode(doc).encodeToByteArray(), Ad.accountState(userId))
    }

    /**
     * Open an account-state blob. Throws [CryptoException] when it does not open under our UVK with this
     * user's AD (a substituted or injected blob) and [AccountStateException] when it opens but is not a
     * v1 document for this user.
     */
    fun openAccountState(sealed: String): AccountStateDoc {
        val plain = Envelope.openB64(crypto, uvk, sealed, Ad.accountState(userId)).decodeToString()
        return AccountState.decode(userId, plain)
    }

    fun hasVault(vaultId: String): Boolean = vaultKeys.containsKey(vaultId)

    /**
     * The EFFECTIVE role for a vault we hold (null when unknown): the server-declared role, except that a vault
     * whose key is legacy-read-only ([isLegacyReadOnly], INV-WRITE-KEY) reads as `reader`, so every write path
     * that already refuses readers (save, conflict copy, health actions, autofill targets) refuses it too.
     */
    fun roleFor(vaultId: String): String? = if (isLegacyReadOnly(vaultId)) "reader" else vaultRoles[vaultId]

    /** The role exactly as the server declared it. */
    fun serverRoleFor(vaultId: String): String? = vaultRoles[vaultId]

    /** Drop a vault's key + role (removedGrants purge) so later writes fail fast client-side. */
    fun removeVault(vaultId: String) {
        vaultKeys.remove(vaultId)
        vaultRoles.remove(vaultId)
        memberGrantedVaults.remove(vaultId) // provenance dies with the key it describes (H64)
        uvkWrappedVaults.remove(vaultId)
        vkMismatchVaults.remove(vaultId)
        unreadableKeyVaults.remove(vaultId)
        keySources.remove(vaultId)
        signedGrantFrom.remove(vaultId)
        legacyAuthorized.remove(vaultId)
        pendingGrants.remove(vaultId)
        grantAnomalies.remove(vaultId)
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
        keySources[vaultId] = KeySource.UVK_WRAP
        uvkWrappedVaults.add(vaultId)
        return NewSharedVault(req, vaultId)
    }

    /** Seal a vault's VK to a member's (out-of-band verified!) identity pubkey. */
    fun wrapVkForMember(memberIdentityPub: ByteArray, vaultId: String): String =
        Bytes.toB64(SharedGrant.seal(crypto, memberIdentityPub, vaultId, vk(vaultId)))

    /** Short identity fingerprint (32 hex / 128 bits, spec 01 §5) over the SEED-DERIVED pubkey —
     *  what a family member reads out when someone shares a vault with them. */
    fun identityFingerprintShort(): String = SharedGrant.shortFingerprint(crypto, identityPub)

    /** Full identity fingerprint (64 hex, spec 01 §5) over the SEED-DERIVED pubkey — printed on the
     *  per-member recovery sheet (spec 04 §6) beside the short form, as the CLI's recovery anchor. */
    fun identityFingerprintFull(): String = SharedGrant.fingerprint(crypto, identityPub)

    /** Decrypt a vault's display name from its metaBlob (null when the VK is missing). */
    fun decryptVaultName(vaultId: String, metaBlob: String): String? = runCatching {
        val plain = Envelope.openB64(crypto, vk(vaultId), metaBlob, Ad.vaultMeta(vaultId)).decodeToString()
        // spec 02 §4: only a JSON string is a name (web/extension parity — ItemDocShape.vaultName).
        ItemDocShape.vaultName(Json.parseToJsonElement(plain))
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
        // A transfer accept must not launder a key only an unconfirmed v1 seal vouches for (root cause A §8.2).
        if (isLegacyReadOnly(vaultId) || heldKeyContradictsVouch(vaultId)) throw VaultKeyNotVerifiedException(vaultId)
        return roundTripWrap(vaultId, "owner wrap")
    }

    /**
     * Member self-wrap (security review 2026-10, root cause A §3.2): the VK this member already
     * holds, wrapped under its OWN UVK with the same construction as [buildOwnerWrap], round-trip
     * verified, for `PUT /vaults/{id}/grant/self-wrap`. Once it is on the row, every device of
     * this member takes the key from the wrap (precedence rule 2) and the seal stops being
     * load-bearing. Call it only for a key whose origin is authenticated (see [needsSelfWrap]).
     */
    fun buildSelfWrap(vaultId: String): String {
        if (!selfWrapAuthorized(vaultId)) throw VaultKeyNotVerifiedException(vaultId)
        return roundTripWrap(vaultId, "self wrap")
    }

    private fun roundTripWrap(vaultId: String, what: String): String {
        val vk = vk(vaultId)
        val wrapped = Envelope.sealB64(crypto, uvk, vk, Ad.vk(vaultId, userId))
        if (!Envelope.openB64(crypto, uvk, wrapped, Ad.vk(vaultId, userId)).contentEquals(vk)) {
            throw CryptoException("$what failed round-trip verification")
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
        if (isLegacyReadOnly(vaultId)) throw VaultKeyNotVerifiedException(vaultId)
        val meta = decryptVaultMeta(vaultId, metaBlob)
        // spec 02 §4: metaV via the SINGLE [parseMetaV] rule SyncEngine.metaV also applies, so
        // write and apply agree on every client (a string primitive is not a counter → 0).
        val metaV = (meta["metaV"] as? kotlinx.serialization.json.JsonPrimitive)
            ?.takeIf { !it.isString }?.let { parseMetaV(it.content) } ?: 0L
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
        // Same canonical-key precedence as [addGrant] (root cause A §3.1): our UVK wrap wins,
        // and a damaged wrap is null here, never a seal fallback.
        val heldVk = openGrantVk(grant).vk
        val plain = Envelope.openB64(crypto, heldVk, metaBlob, Ad.vaultMeta(grant.vaultId)).decodeToString()
        ItemDocShape.vaultName(Json.parseToJsonElement(plain))
    }.getOrNull()

    private fun vk(vaultId: String): ByteArray =
        vaultKeys[vaultId] ?: throw CryptoException("no key for vault $vaultId")

    /**
     * Seal the usage ledger (spec 02 §8.2). Keyed by HKDF from the PERSONAL VAULT KEY, not the
     * UVK — see [UsageKey]: the browser extension's UVK is memory-only (breaker B1) and an
     * evicted MV3 worker restores a session with vault keys but no UVK, so a UVK-bound ledger
     * would be unwritable from the client that does most of the filling. Every unlocked client
     * holds the personal VK. The AD still binds the blob to this userId, so a hostile endpoint
     * cannot serve one member's ledger into another's slot.
     *
     * Throws when there is no personal vault key — callers treat that exactly like "no ledger".
     */
    fun sealUsage(plaintext: ByteArray): String =
        Envelope.sealB64(crypto, UsageKey.usageKey(crypto, vk(personalVaultId)), plaintext, Ad.usage(userId))

    /** Open a ledger sealed by [sealUsage] — on this device or any other client. Throws on a
     *  wrong key or a substituted blob, which callers treat as "no ledger", never an empty one. */
    fun openUsage(sealedUsage: String): ByteArray =
        Envelope.openB64(crypto, UsageKey.usageKey(crypto, vk(personalVaultId)), sealedUsage, Ad.usage(userId))

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
        if (isLegacyReadOnly(vaultId)) throw VaultKeyNotVerifiedException(vaultId) // INV-WRITE-KEY
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
        // spec 02 §3.2 (security review 2026-10): the plaintext opened under the VK, but any writer
        // of a shared vault holds that VK — check its shape BEFORE anything reads it. A failure
        // rides the same runCatching paths as an undecryptable envelope: quarantined, never a crash.
        val tree = runCatching { json.parseToJsonElement(plain.decodeToString()) }
            .getOrElse { throw MalformedItemException("item document is not JSON") }
        ItemDocShape.problem(tree)?.let { throw MalformedItemException("item document is malformed: $it") }
        val doc = json.decodeFromJsonElement(ItemDoc.serializer(), tree)
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
        // Escrow v2 (security review 2026-10, root cause A §2.1 / §8.4): this is also the v1 → v2
        // migration seal. The server keeps the previous blob as `escrow_legacy` until a fleet drill
        // passes on this one, so a defective v2 seal cannot strand the member.
        val sealed = Escrow.sealUvkV2(
            crypto, pub, verifiedFingerprint, userId, identityPub, KeyPairBytes(signPub, signSecret), uvk, nowMs(),
        )
        return EscrowUpload(Bytes.toB64(sealed), verifiedFingerprint)
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
