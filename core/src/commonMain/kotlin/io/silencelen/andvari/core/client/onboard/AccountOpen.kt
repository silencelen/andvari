package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.AccountWipedException
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.PersonalWrap
import io.silencelen.andvari.core.trust.AccountGenesis
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.VerifiedGenesis

/**
 * An account's keys once every identity check passed (design §5.2, §5.3). Owned by whoever holds it: [wipe]
 * when the session ends. [personalVaultId] and [personalVk] are set only when the served personal wrap names
 * the genesis' `personalVaultId` AND opens under the UVK; otherwise the account has no personal vault in force
 * (an anomaly, never the identity fault).
 */
class OpenedAccount internal constructor(
    val userId: String,
    uvk: ByteArray,
    identity: KeyPairBytes,
    signing: KeyPairBytes,
    val genesis: VerifiedGenesis,
    val personalVaultId: String?,
    personalVk: ByteArray?,
) {
    /**
     * The one guard over every key of this account: a key is used only inside its guarded `use`, which
     * refuses once [wipe] ran and which [wipe] waits for. Code that built something from a key and then waited asks
     * [KeyGuard.check] before it sends it.
     */
    internal val guard = KeyGuard()

    /** The UVK, reachable only inside its guarded use. No code outside the account holds the array. */
    internal val uvk = GuardedKey(uvk, guard)

    /** The X25519 identity pair: its public key readable at any time, its private key only inside its guarded use. */
    internal val identity = GuardedKeyPair(identity, guard)

    /** The joint Ed25519 signing pair, as [identity]. */
    internal val signing = GuardedKeyPair(signing, guard)

    /** The personal vault's key, when the personal wrap opened ([personalVaultId] non-null), under the same guard. */
    internal val personalVk: GuardedKey? = personalVk?.let { GuardedKey(it, guard) }

    /** Whether [wipe] ran: this account's keys are zeros and it seals, signs and derives nothing more. */
    val isWiped: Boolean get() = guard.isWiped

    /** The account ID shown on a kit and in notices: the 32-hex short identity fingerprint (spec 01 §5). */
    fun accountId(crypto: CryptoProvider): String = Fingerprint.shortForm(Bytes.toHexLower(crypto.sha256(identity.publicKey)))

    /**
     * The account's own Ed25519 signing public key, base64url as a card's `operatorSignKey` carries it (design §4.1,
     * §9): what a handover names when this account becomes an instance's operator, shown so the person can compare
     * it. Public material; readable after [wipe]. Its short form for a screen is
     * `CardTrust.operatorShortFp(crypto, signingKeyB64())`, the value the Trust Gate shows for an operator key.
     */
    fun signingKeyB64(): String = Bytes.toB64(signing.publicKey)

    /** Runs [block] with the keys held against [wipe], and refuses once they are wiped ([AccountWipedException]). */
    private inline fun <T> withKeys(crossinline block: () -> T): T = guard.use { block() }

    /**
     * The account's X25519 identity public key (a copy): the key a save queued while the app is LOCKED is sealed to.
     * Public material only. A host publishes it for its extension with the unlocked session (`SaveQueue.publication`)
     * and removes the publication with the session. Readable after [wipe] too: it is public, and the queue is filled
     * exactly while no session holds the private key.
     */
    fun identityPub(): ByteArray = identity.publicKey.copyOf()

    /**
     * Open a save queued while the app was locked: a libsodium sealed box to [identityPub] (the save queue's entries).
     * The plaintext is a proposal the person confirms, never a key: the caller checks its magic and its account before
     * showing it. A seal that does not open throws [CryptoException]; a wiped account throws [AccountWipedException].
     * Same seal as the old account's `openQueuedSave`, so saves queued under either open here.
     */
    fun openQueuedSave(crypto: CryptoProvider, sealed: ByteArray): ByteArray =
        identity.use { id -> crypto.sealOpen(id.publicKey, id.privateKey, sealed) }

    /**
     * Seal [plain] for this app's own storage on this device, for [purpose] (the list of automatic saves, kept moves,
     * kept saves with files, attachment drafts). A sealed box to [identityPub] with, in front of it, an HMAC-SHA-256
     * over the box under a key only this account holds: HKDF-SHA-256 from its UVK, info `andvari local record v1|<purpose>`
     * (domain-separated per purpose). Every co-member has the public key, so the sealed box alone could be forged by
     * anyone who wrote into the container; the MAC is what makes it this account's own. Byte for byte the old
     * account's `sealLocalRecord` (same UVK, same identity key), so records kept before the move open here and back.
     * A wiped account throws [AccountWipedException]: nothing is ever sealed under wiped (zero) keys.
     */
    fun sealLocalRecord(crypto: CryptoProvider, purpose: String, plain: ByteArray): ByteArray = withKeys {
        val sealed = crypto.sealTo(identity.publicKey, plain)
        val key = localRecordKey(crypto, purpose)
        try {
            crypto.hmacSha256(key, sealed) + sealed
        } finally {
            key.fill(0)
        }
    }

    /**
     * What [sealLocalRecord] sealed for [purpose] under this account; null for anything else: a record too short, a MAC
     * that does not hold (another purpose, another account, a forgery with the public key) or a seal that does not open.
     * A wiped account throws [AccountWipedException] rather than answering null, so a lock is never mistaken for a
     * forged record (a caller that drops unreadable records must not drop them because the app locked).
     */
    fun openLocalRecord(crypto: CryptoProvider, purpose: String, record: ByteArray): ByteArray? = withKeys {
        if (record.size <= LOCAL_RECORD_MAC_BYTES) return@withKeys null
        val sealed = record.copyOfRange(LOCAL_RECORD_MAC_BYTES, record.size)
        val key = localRecordKey(crypto, purpose)
        val genuine = try {
            Bytes.ctEquals(record.copyOfRange(0, LOCAL_RECORD_MAC_BYTES), crypto.hmacSha256(key, sealed))
        } finally {
            key.fill(0)
        }
        if (!genuine) return@withKeys null
        try {
            identity.use { id -> crypto.sealOpen(id.publicKey, id.privateKey, sealed) }
        } catch (e: CryptoException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private fun localRecordKey(crypto: CryptoProvider, purpose: String): ByteArray =
        uvk.use { Hkdf.sha256(crypto, it, ByteArray(0), "$LOCAL_RECORD_INFO$purpose".encodeToByteArray(), 32) }

    /**
     * Seal [plain] under this account's vault key for [purpose], for a reader on this device that opens the same account
     * (the iPhone's fill snapshot, which its AutoFill extension reads after its own unlock): the key never leaves the
     * engine. An envelope (spec 02 §2, XChaCha20-Poly1305) under a key derived for the purpose, HKDF-SHA-256 from the UVK
     * with info `andvari vault-key seal v1|<purpose>` (never the UVK itself, so nothing sealed here can be taken for one of
     * the UVK's own envelopes), and associated data the engine fixes: `andvari/v2|vault-key-seal|<userId>|<purpose>`. So
     * a seal made for one account or one purpose does not open as another ([openUnderVaultKey]).
     *
     * [purpose] is a short label: lowercase letters, digits, `.` and `-`, at most 64, starting with a letter or digit
     * (`IllegalArgumentException` otherwise). A wiped account throws [AccountWipedException]: nothing is ever sealed
     * under wiped (zero) keys. The caller wipes [plain] when it is done with it.
     */
    fun sealUnderVaultKey(crypto: CryptoProvider, purpose: String, plain: ByteArray): ByteArray {
        require(VaultKeySeal.isPurpose(purpose)) { "not a seal purpose" }
        return uvk.use { VaultKeySeal.seal(crypto, it, userId, purpose, plain) }
    }

    /**
     * What [sealUnderVaultKey] sealed for [purpose] under this account; null for anything else (another account, another
     * purpose, a damaged or forged seal), so a reader that cannot open a snapshot treats it as absent. A [purpose] outside
     * the label grammar is null too. A wiped account throws [AccountWipedException] rather than answering null, so a lock
     * is never mistaken for a damaged snapshot.
     */
    fun openUnderVaultKey(crypto: CryptoProvider, purpose: String, sealed: ByteArray): ByteArray? =
        uvk.use { VaultKeySeal.open(crypto, it, userId, purpose, sealed) }

    /**
     * Sign the instance card [fields] with this account's own Ed25519 key (design §4.1: the operator signs the next card
     * of its instance): the signed 0x04 frame, for `PUT /instance/card`. Only a card that names this account as its
     * operator, with this account's own key ([signingKeyB64]), is signed; anything else is `IllegalArgumentException`,
     * and so is a card [io.silencelen.andvari.core.trust.InstanceCard.sign] refuses. A wiped account throws
     * [AccountWipedException]. The key itself is never handed out.
     */
    fun signInstanceCard(crypto: CryptoProvider, fields: io.silencelen.andvari.core.trust.CardFields): ByteArray {
        require(fields.operator == userId) { "the card names another operator" }
        require(fields.operatorSignKey == signingKeyB64()) { "the card names another operator key" }
        return signing.use { io.silencelen.andvari.core.trust.InstanceCard.sign(crypto, it, fields) }
    }

    /**
     * Zero every key this account holds, and every key registered under its guard (the vault keys the log engine
     * adopted). A use already running finishes first, on whole keys; none starts after. Idempotent.
     */
    fun wipe() = guard.wipe()

    companion object {
        /** The MAC in front of a local record ([sealLocalRecord]): HMAC-SHA-256. */
        const val LOCAL_RECORD_MAC_BYTES = 32

        /** The HKDF info prefix of a local record's MAC key; the purpose follows it. Same as the old account's. */
        internal const val LOCAL_RECORD_INFO = "andvari local record v1|"

        /** The HKDF info prefix of a [sealUnderVaultKey] key; the purpose follows it ([VaultKeySeal]). */
        internal const val VAULT_KEY_SEAL_INFO = "andvari vault-key seal v1|"
    }
}

/** What [AccountOpen.openWithPassword] came to. */
sealed class PasswordOpen {
    class Opened internal constructor(val account: OpenedAccount) : PasswordOpen()

    /** The password does not unwrap the served UVK (or the served wrap is damaged: the two look the same). */
    data object WrongPassword : PasswordOpen()

    /** Nothing was derived: [code] is [BAD_KDF_SALT] or [KDF_REFUSED] (served parameters outside the fence). */
    data class Refused(val code: String) : PasswordOpen()

    /** The identity security fault, as [AccountOpenResult.IdentityFault]: every key is wiped. */
    data class IdentityFault(val reason: String) : PasswordOpen()

    companion object {
        const val BAD_KDF_SALT = "bad_kdf_salt"
        const val KDF_REFUSED = "kdf_refused"
    }
}

/** What opening an account's served keys came to. */
sealed class AccountOpenResult {
    class Opened internal constructor(val account: OpenedAccount) : AccountOpenResult()

    /**
     * The identity security fault (`IDENTITY_MISMATCH` copy, design §5.2): [reason] is the first failing check,
     * a §2.4 genesis verdict (`bad_frame` … `personal_vault_mismatch`), or `seed_unopenable`,
     * `identity_mismatch`, `no_genesis`, `self_identity_mismatch`. Nothing is opened and every key is wiped.
     */
    data class IdentityFault(val reason: String) : AccountOpenResult()
}

/**
 * The identity checks every session open runs (design §5.2, §2.4 VR-13), before a session is handed to the
 * session layer: sign-in, registration (the server's echo of what this device sent), the recovery commits and
 * the device-link pickup.
 */
object AccountOpen {
    /**
     * Open [keys] with [uvk] (taken: wiped on every refusal, owned by the result on success) for [userId] at the
     * pinned card's [pinnedInstanceId]. [knownIdentityPub] is this device's own earlier record of the account's
     * identity key (design §2.4), or null when it has none.
     */
    fun open(
        crypto: CryptoProvider,
        userId: String,
        uvk: ByteArray,
        keys: AccountKeys,
        pinnedInstanceId: String,
        knownIdentityPub: ByteArray? = null,
    ): AccountOpenResult {
        val seed = try {
            Envelope.openB64(crypto, uvk, keys.encryptedIdentitySeed, Ad.idkey(userId))
        } catch (e: CryptoException) {
            uvk.fill(0)
            return AccountOpenResult.IdentityFault(SEED_UNOPENABLE)
        } catch (e: IllegalArgumentException) {
            uvk.fill(0)
            return AccountOpenResult.IdentityFault(SEED_UNOPENABLE)
        }
        val identity: KeyPairBytes
        val signing: KeyPairBytes
        try {
            identity = crypto.boxKeypairFromSeed(seed)
            signing = crypto.signKeypairFromSeed(seed)
        } finally {
            seed.fill(0)
        }
        return check(crypto, userId, uvk, identity, signing, keys.identityPub, keys.genesis, keys.personalWrap, pinnedInstanceId, knownIdentityPub)
    }

    /**
     * Open [keys] (as `GET /account/keys` served them) with the master [password], on this device only: the password's
     * keys are derived under the served salt and parameters (which pass the KDF fence first, spec 05 T1), the UVK is
     * unwrapped, and [open] runs every identity check. Nothing is sent and no key is handed out; [password] and every
     * derived key are wiped, whatever happens. What a host needs to reopen a session it kept (the command-line tool's
     * saved session) without holding the password's wrap key.
     */
    fun openWithPassword(
        crypto: CryptoProvider,
        userId: String,
        password: CharArray,
        keys: AccountKeys,
        pinnedInstanceId: String,
        knownIdentityPub: ByteArray? = null,
    ): PasswordOpen {
        val salt = Bytes.fromB64Canonical(keys.kdfSalt)
        if (salt == null) {
            password.fill('\u0000')
            return PasswordOpen.Refused(PasswordOpen.BAD_KDF_SALT)
        }
        val pk = PasswordKeys.derive(crypto, password, salt, keys.kdfParams, served = true) ?: return PasswordOpen.Refused(PasswordOpen.KDF_REFUSED)
        val uvk = try {
            Envelope.openB64(crypto, pk.wrapKey, keys.wrappedUvk, Ad.uvk(userId))
        } catch (e: CryptoException) {
            return PasswordOpen.WrongPassword
        } catch (e: IllegalArgumentException) {
            return PasswordOpen.WrongPassword
        } finally {
            pk.wipe()
        }
        return when (val o = open(crypto, userId, uvk, keys, pinnedInstanceId, knownIdentityPub)) {
            is AccountOpenResult.Opened -> PasswordOpen.Opened(o.account)
            is AccountOpenResult.IdentityFault -> PasswordOpen.IdentityFault(o.reason)
        }
    }

    /**
     * The checks after the seed is open, in order (graded by `accountgenesis.json`): the served `identityPub`
     * equals the seed-derived key; a genesis is served; [AccountGenesis.verify] with the seed-derived keys (the Ed25519 signer, byte for byte), the
     * session's user, the pinned instance and the served wrap's `vaultId`; this device's own record of the key.
     * Then the personal wrap (§5.3). Every key is wiped on a refusal.
     */
    internal fun check(
        crypto: CryptoProvider,
        userId: String,
        uvk: ByteArray,
        identity: KeyPairBytes,
        signing: KeyPairBytes,
        servedIdentityPub: String,
        genesisB64: String?,
        wrap: PersonalWrap?,
        pinnedInstanceId: String,
        knownIdentityPub: ByteArray?,
    ): AccountOpenResult {
        fun fault(reason: String): AccountOpenResult {
            uvk.fill(0)
            identity.privateKey.fill(0)
            signing.privateKey.fill(0)
            return AccountOpenResult.IdentityFault(reason)
        }
        val served = Bytes.fromB64Exact(servedIdentityPub, 32)
        if (served == null || !Bytes.ctEquals(served, identity.publicKey)) return fault(IDENTITY_MISMATCH)
        if (genesisB64 == null) return fault(NO_GENESIS)
        val frame = Bytes.fromB64Canonical(genesisB64) ?: return fault("bad_frame")
        val genesis = when (val v = AccountGenesis.verify(crypto, frame, signing.publicKey, identity.publicKey, userId, pinnedInstanceId, wrap?.vaultId)) {
            is Checked.Ok -> v.value
            is Checked.Refused -> return fault(v.verdict.code)
        }
        if (knownIdentityPub != null && !Bytes.ctEquals(knownIdentityPub, identity.publicKey)) return fault(SELF_IDENTITY_MISMATCH)
        // §5.3: a wrap naming the genesis vault that opens is in force on any device; otherwise no personal vault.
        // Spec 01 §8 rule 4: a vault key of zeros is no key. Such a wrap does not open: no personal vault, as for any wrap
        // that does not open, rather than a key every later open under it refuses as though the account were locked.
        val vk = wrap?.let {
            try {
                Envelope.openB64(crypto, uvk, it.wrappedVk, Ad.vkPersonal(it.vaultId, userId))
            } catch (e: CryptoException) {
                null
            } catch (e: IllegalArgumentException) {
                null
            }
        }?.takeUnless { io.silencelen.andvari.core.crypto.KeyFloor.allZero(it) }
        val vaultId = if (vk != null) genesis.fields.personalVaultId else null
        return AccountOpenResult.Opened(OpenedAccount(userId, uvk, identity, signing, genesis, vaultId, vk))
    }

    const val SEED_UNOPENABLE = "seed_unopenable"
    /**
     * Design §2.4 "Account keys at sign-in, unlock, kit recovery and device-link pickup": the served `identityPub` is not
     * the key derived from the opened seed. One name on every client (it was the engine-private `identity_pub_mismatch`).
     */
    const val IDENTITY_MISMATCH = "identity_mismatch"

    /** The old name of [IDENTITY_MISMATCH]; same value, kept so callers elsewhere in the code compile until they move. */
    @Deprecated("one verdict name each (design §2.4): use IDENTITY_MISMATCH", ReplaceWith("IDENTITY_MISMATCH"))
    const val IDENTITY_PUB_MISMATCH = IDENTITY_MISMATCH
    const val NO_GENESIS = "no_genesis"
    const val SELF_IDENTITY_MISMATCH = "self_identity_mismatch"
}
