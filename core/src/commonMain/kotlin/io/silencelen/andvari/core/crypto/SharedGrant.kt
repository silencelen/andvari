package io.silencelen.andvari.core.crypto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** spec 01 §6 — the sealed shared-vault grant payload (canonical JSON: exact key order, no whitespace). */
@Serializable
data class SharedGrantPayload(
    @SerialName("v") val v: Int,
    @SerialName("vaultId") val vaultId: String,
    @SerialName("vk") val vk: String,
)

/**
 * Shared-vault key grants (spec 01 §6). A member grant seals the vault key to the
 * member's X25519 identity public key with `crypto_box_seal` (anonymous, no AD — the
 * vaultId rides inside the payload and the recipient re-checks it). The server stores
 * only the opaque `sealedVk` ciphertext; it can neither read nor redirect it. Sibling of
 * [Escrow]; the fingerprint construction is shared.
 */
object SharedGrant {
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Canonical bytes — string template guarantees key order and no whitespace (matches web).
     * [vaultId] comes from a server-supplied vault row, so it is held to [requireJsonSafe] for
     * the reason that helper documents: a template composes the structure, and only a value that
     * cannot escape its JSON string leaves the structure ours.
     */
    fun canonicalPayload(vaultId: String, vk: ByteArray): ByteArray {
        requireJsonSafe(vaultId, "shared grant vaultId")
        return """{"v":1,"vaultId":"$vaultId","vk":"${Bytes.toB64(vk)}"}""".encodeToByteArray()
    }

    fun seal(crypto: CryptoProvider, memberIdentityPub: ByteArray, vaultId: String, vk: ByteArray): ByteArray =
        crypto.sealTo(memberIdentityPub, canonicalPayload(vaultId, vk))

    /**
     * Open a sealed grant and return the 32-byte VK. The recipient MUST bind the sealed
     * payload to the grant row it arrived on: [expectedVaultId] must equal the payload's
     * vaultId. NOTE (security review 2026-10): a v1 seal is an anonymous sealed box, so a
     * hostile server that holds the member's identity pubkey CAN forge one; this check only
     * rejects a replay onto the wrong row. A v1 seal is therefore never preferred over the
     * UVK-wrapped VK and yields a legacy-read-only key (see the VK precedence rule); sender
     * authentication arrives with the v2 signed grant.
     */
    fun open(
        crypto: CryptoProvider,
        memberIdentityPub: ByteArray,
        memberIdentityPriv: ByteArray,
        expectedVaultId: String,
        sealed: ByteArray,
    ): ByteArray {
        val payload = json.decodeFromString<SharedGrantPayload>(
            crypto.sealOpen(memberIdentityPub, memberIdentityPriv, sealed).decodeToString(),
        )
        if (payload.v != 1) throw CryptoException("unsupported shared-grant payload version ${payload.v}")
        if (payload.vaultId != expectedVaultId) throw CryptoException("shared grant vaultId mismatch")
        val vk = Bytes.fromB64(payload.vk)
        if (vk.size != 32) throw CryptoException("shared grant VK is not 32 bytes")
        return vk
    }

    /**
     * spec 01 §5 — identity fingerprint = lowercase hex SHA-256 of the identity public key.
     * CALLERS MUST pass the SEED-DERIVED pubkey (boxKeypairFromSeed(seed).publicKey), never
     * the server-supplied identityPub — else a malicious server can pass an out-of-band check.
     */
    fun fingerprint(crypto: CryptoProvider, identityPub: ByteArray): String =
        Bytes.toHexLower(crypto.sha256(identityPub))

    /**
     * The HUMAN short form of the identity fingerprint — first 32 hex (128 bits), the same length
     * a member TYPES/reads elsewhere (security review 2026-10, §7). This is a display value a
     * household member reads out when someone shares a vault with them; [Fingerprint] owns the
     * length. (The recovery short id, [Escrow.shortFingerprint], is a separate 16-hex machine value.)
     */
    fun shortFingerprint(crypto: CryptoProvider, identityPub: ByteArray): String =
        Fingerprint.shortForm(fingerprint(crypto, identityPub))
}
