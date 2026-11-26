package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.X25519

/** A parsed `/d` link (design 2026-11-15 §8.1): the instance [origin] and the 32-byte secret `s`. It expires after 5 minutes. */
class ParsedDeviceLink internal constructor(val origin: String, secret: ByteArray) {
    private val secretBytes = secret.copyOf()
    val secret: ByteArray get() = secretBytes.copyOf()
    fun wipe() = secretBytes.fill(0)
}

/**
 * The device-link URL and QR payload (§8.1):
 *
 * ```
 * https://andvaripass.com/d#v2.<O>.<S>        (§6.1's encoding without F)
 * ```
 *
 * `/d` is NOT an app link (T2-B1): a device acts on one only when it was scanned or pasted on its own
 * "Link from your other device" screen, or given to `andvari-cli link-device`. That entry rule and
 * the pin the new device needs before it claims (§8.2 step 0) are the engine's `PasswordGate`; this
 * object only parses.
 */
object DeviceLinkUrl {
    /**
     * The link for [origin] and [secret] (32 bytes). Null when a part is outside its grammar or the
     * result is longer than 512 characters.
     */
    fun compose(origin: String, secret: ByteArray): String? {
        if (secret.size != 32) return null
        val url = LinkUrl.JOIN_BASE + "/d#" + LinkText.fragment(origin, secret)
        val parsed = parse(url) ?: return null
        parsed.wipe()
        return url
    }

    /**
     * Total parse (§8.1, FI-B12): null on any malformed input, never a throw. As [LinkUrl.parse], but
     * the fragment has EXACTLY THREE `.`-separated parts: `v2`, `O`, `S`. ASCII white space is
     * stripped first; at most 512 characters; `O` decodes to an `origin`; `O` and `S` are canonical
     * base64url; `S` decodes to exactly 32 bytes.
     */
    fun parse(input: String): ParsedDeviceLink? {
        val parts = LinkText.fragmentParts(input) ?: return null
        if (parts.size != 3) return null
        val origin = LinkText.origin(parts[1]) ?: return null
        val secret = Bytes.fromB64Exact(parts[2], 32) ?: return null
        // No real link's secret is all zeros, and nothing is derived from one: a bad link, never a lock.
        if (io.silencelen.andvari.core.crypto.KeyFloor.allZero(secret)) return null
        return ParsedDeviceLink(origin, secret).also { secret.fill(0) }
    }
}

/** What a scanned or pasted payload is (§12.1 "Three scanners, three jobs", FS-B1). Each entry screen accepts exactly one kind. */
enum class ScanPayload {
    /** A `/l` invite or connect link ([LinkUrl]). Accepted only on "Scan an invite" and its paste field. */
    LINK,

    /** A `/d` device link ([DeviceLinkUrl]). Accepted only on "Link from your other device". */
    DEVICE_LINK,

    /** An `andvari-kit:` payload ([RecoveryKit]). Accepted only on "Scan your recovery kit". */
    KIT,

    /** None of the three. */
    UNKNOWN,
    ;

    companion object {
        /**
         * Classify [input] by the one parser that accepts it. Total. The fragment alone decides
         * between a link and a device link (four parts or three), because the path before `#` is not
         * authenticated (§6.1).
         */
        fun of(input: String): ScanPayload {
            LinkUrl.parse(input)?.let {
                it.wipe()
                return LINK
            }
            DeviceLinkUrl.parse(input)?.let {
                it.wipe()
                return DEVICE_LINK
            }
            RecoveryKit.parseQr(input)?.let {
                it.wipe()
                return KIT
            }
            return UNKNOWN
        }
    }
}

/** The values derived from a device-link secret `s` (§2.3, §8.1): [linkId] (`b64_16` text) and the MAC key. */
class DeviceLinkKeys internal constructor(val linkId: String, macKey: ByteArray) {
    private val macKeyBytes = macKey.copyOf()
    val macKey: ByteArray get() = macKeyBytes.copyOf()
    fun wipe() = macKeyBytes.fill(0)
}

/**
 * The claim the new device N posts, as the existing device E reads it back from the server (§8.2 steps
 * 2 and 3). Every field is the wire text and is untrusted until [DeviceLink.verifyClaim] passes:
 * [nPub] a `b64_32` X25519 key, [name] the `name` type (base64url, exactly as sent: the same string
 * goes into the MAC), [platform] one of §2.3's values, [commitN] a `hex64`, [mac] a `b64_32`.
 */
data class DeviceClaim(val nPub: String, val name: String, val platform: String, val commitN: String, val mac: String) {
    /**
     * Whether [later], a claim read on a later poll, is still THIS claim (§8.2 step 3, T2-R-b): the same
     * `nPub`, `name`, `platform` and `commitN`. E fixes the claim when it draws `nonceE`; a later poll
     * for which this is false cancels the link (the engine's `claim_changed`).
     */
    fun sameClaim(later: DeviceClaim): Boolean =
        nPub == later.nPub && name == later.name && platform == later.platform && commitN == later.commitN
}

/** A claim whose fields are in their grammar and whose MAC verifies under the link's MAC key. [deviceName] is the decoded name, to show as plain text. */
class VerifiedClaim internal constructor(val claim: DeviceClaim, nPub: ByteArray, val deviceName: String) {
    private val nPubBytes = nPub.copyOf()

    /** The new device's ephemeral X25519 public key, 32 bytes. */
    val nPub: ByteArray get() = nPubBytes.copyOf()
}

/** `outer` (§8.2 step 6): just enough for the new device to sign in. [email] is the `emailNorm` string. */
data class DeviceLinkOuter(val origin: String, val userId: String, val email: String)

/** `contacts[]` of the bundle: [keyHash] is the lowercase hex SHA-256 over the contact's raw 32 key bytes. */
data class BundleContact(val userId: String, val keyHash: String, val verifiedAt: Long)

/** `vaults[]` of the bundle: a verified head of that vault's log. */
data class BundleVault(val vaultId: String, val seq: Long, val hash: String)

/**
 * The device-link bundle (§8.3), carried as `inner`. Field types are §8.3's table: `origin` an
 * `origin`; ids `uuid`; `seq` values `int`; hashes `hex64`; [email] the `emailNorm` string;
 * [identityPub] a `b64_32`; times `ms`; [contacts] and [vaults] at most 1000 entries each.
 * [accountState]`.seq` is the counter INSIDE the sealed account-state document, not the server's
 * compare-and-set token (FI-B14), and its `hash` is SHA-256 over the ASCII bytes of the served
 * `sealedState` string.
 *
 * How the new device imports it (§8.3): [contacts] make a contact CURRENT only where its merged
 * account state holds that `userId` with the same key hash (the bundle confers currency, never
 * contacts); [vaults] and [card] are verified checkpoints ([Checkpoints]); [accountState] is a
 * high-water mark and NOT a recovery mirror (FS-R1).
 */
data class DeviceLinkBundle(
    val origin: String,
    val instanceId: String,
    val card: Checkpoint,
    val userId: String,
    val email: String,
    val identityPub: String,
    val personalVaultId: String,
    val contacts: List<BundleContact>,
    val vaults: List<BundleVault>,
    val accountState: Checkpoint,
    val issuedAt: Long,
)

/**
 * Why a device-link step was refused (§8.2, §8.3). `bad_reveal`, `bundle_unopenable` and `pin_mismatch`
 * are the design's first names; the others were adopted into §2.4 from this package. The entries are in
 * step order: E's checks on the claim and the reveal, N's checks before the password, N's checks after
 * the pickup. After the pickup the account genesis is verified first, when the device unlocks and
 * before the bundle is touched, so its verdicts ([GenesisVerdict]) precede `bundle_unopenable`.
 *
 * Flow steps that are not format checks have names of their own in the engine: `bad_link` (the URL does
 * not parse), `claim_changed` and `nonce_changed` (the single-assignment rule, T2-R-b) and
 * `code_mismatch` (the typed digits). Each cancels the link.
 */
enum class DeviceLinkVerdict(val code: String) {
    /**
     * E, step 3: a claim field is outside its type (`nPub` and `mac` `b64_32`, `name` the `name` type,
     * `platform` one of §2.3's values, `commitN` a `hex64`), or `nPub` is a low-order point, which is no
     * key that `outer` could be sealed to.
     */
    BAD_CLAIM("bad_claim"),

    /**
     * E, step 3: the claim's MAC does not verify. N, step 7: `approveMac` is not a `b64_32` or does not
     * verify over the raw sealed `outer`; N checks it FIRST, before it opens or parses `outer`. An anomaly.
     */
    BAD_MAC("bad_mac"),

    /** E, step 4: the revealed `nonceN` is not a `b64_32` or does not open `commitN`. Cancels the link. */
    BAD_REVEAL("bad_reveal"),

    /** N, step 7: `outer` does not open with the new device's key pair. */
    OUTER_UNOPENABLE("outer_unopenable"),

    /** N, step 7: `outer` opened but is not exactly `{"v":2,"origin","userId","email"}` in compact JSON with every value of its type. */
    BAD_OUTER("bad_outer"),

    /** N, step 7: `outer.origin` is not the origin the new device pinned in step 0. Refused before any password prompt. */
    ORIGIN_MISMATCH("origin_mismatch"),

    /** N, step 8: `inner` does not open under the UVK-derived bundle key with this link's AD. */
    BUNDLE_UNOPENABLE("bundle_unopenable"),

    /** N, step 8: `inner` opened but fails the strict decode of §8.3 (not compact UTF-8 JSON, more than 64 KiB, a missing, extra or repeated key, a value outside its type, more than 1000 entries). */
    BAD_BUNDLE("bad_bundle"),

    /** N, step 8: the bundle's `userId` is not the session's, its `identityPub` is not the seed-derived key, or its `personalVaultId` is not the verified genesis's. */
    IDENTITY_MISMATCH("identity_mismatch"),

    /** N, step 8: the bundle's `origin`, `instanceId` or `card` disagrees with the pin made in step 0 (T2-B1): sign out, remove that pin, "Nothing was linked." */
    PIN_MISMATCH("pin_mismatch"),
}

/**
 * Device linking (design 2026-11-15 §8): derivations, the committed code, the three MACs, `outer` and
 * the bundle. E is the existing device, N the new one. The protocol's ORDER (who posts what, when a
 * nonce is fixed, the single-assignment rule T2-R-b, the states) is the engine's; every byte it sends
 * or checks is made here.
 */
object DeviceLink {
    /** §8.3: the bundle is UTF-8 JSON of at most 64 KiB. */
    const val MAX_BUNDLE_BYTES = 64 * 1024

    /** §8.3: `contacts` and `vaults` hold at most 1000 entries each. */
    const val MAX_BUNDLE_ENTRIES = 1000

    /**
     * From `s` (32 bytes): `linkId = b64url(HKDF(s, "andvari/v2|device-link|id", 16))` and
     * `macKey = HKDF(s, "andvari/v2|device-link|mac", 32)` (§2.3).
     */
    fun deriveKeys(crypto: CryptoProvider, secret: ByteArray): DeviceLinkKeys {
        require(secret.size == 32) { "link secret must be 32 bytes" }
        val id = Hkdf.sha256(crypto, secret, ByteArray(0), "andvari/v2|device-link|id".encodeToByteArray(), 16)
        val macKey = Hkdf.sha256(crypto, secret, ByteArray(0), "andvari/v2|device-link|mac".encodeToByteArray(), 32)
        return DeviceLinkKeys(Bytes.toB64(id), macKey).also { macKey.fill(0) }
    }

    /** `HMAC-SHA-256(macKey, UTF-8 of [text])`, the 32 raw bytes (§2.3: every MAC input is a string of ASCII components). */
    private fun mac(crypto: CryptoProvider, keys: DeviceLinkKeys, text: String): ByteArray {
        val key = keys.macKey
        try {
            // Wiped link keys MAC nothing and verify nothing: KeysGoneException.
            io.silencelen.andvari.core.crypto.KeyFloor.requireKey(key)
            return crypto.hmacSha256(key, text.encodeToByteArray())
        } finally {
            key.fill(0)
        }
    }

    private fun claimText(linkId: String, nPub: String, name: String, platform: String, commitN: String): String =
        "andvari/v2|device-link|claim|$linkId|$nPub|$name|$platform|$commitN"

    private fun claimFieldsInGrammar(nPub: String, name: String, platform: String, commitN: String): Boolean =
        TrustGrammar.isB64_32(nPub) && TrustGrammar.isName(name) && TrustGrammar.isPlatform(platform) && TrustGrammar.isHex64(commitN) &&
            nPubIsUsable(nPub)

    /**
     * [nPub] (`b64_32` text) is a key `outer` can be sealed to: not one of Curve25519's low-order points.
     * A claim names the key E seals `outer` to in step 6, and a box sealed to a low-order point is sealed
     * to nobody. So such a claim is refused where its fields are checked, as `bad_claim`, and E never
     * reaches a seal that its crypto provider would refuse with a throw.
     */
    private fun nPubIsUsable(nPub: String): Boolean = Bytes.fromB64Exact(nPub, 32)?.let { X25519.isUsablePublicKey(it) } == true

    /** [macB64] is a `b64_32` and equals [expected], compared in constant time. */
    private fun macIs(macB64: String, expected: ByteArray): Boolean {
        val given = (if (macB64.length == 43) Bytes.fromB64Exact(macB64, 32) else null) ?: return false
        return Bytes.ctEquals(given, expected)
    }

    /**
     * The claim MAC (§8.2 step 2), computed by N:
     * `b64url(HMAC-SHA-256(macKey, "andvari/v2|device-link|claim|" + linkId + "|" + nPub + "|" + name + "|" + platform + "|" + commitN))`,
     * with [nPub] and [name] as the claim sends them (`b64_32` text; the `name` type's base64url).
     * Refuses (`IllegalArgumentException`) a field outside its type, and an [nPub] that is a low-order
     * point: a device's own fresh key never is one.
     */
    fun claimMac(crypto: CryptoProvider, keys: DeviceLinkKeys, nPub: String, name: String, platform: String, commitN: String): String {
        require(claimFieldsInGrammar(nPub, name, platform, commitN)) { "a claim field is outside its type (§8.2 step 2)" }
        return Bytes.toB64(mac(crypto, keys, claimText(keys.linkId, nPub, name, platform, commitN)))
    }

    /**
     * E's check of the claim it read back (§8.2 step 3): every field in its grammar (`bad_claim`) and
     * the MAC verifies (`bad_mac`, an anomaly). E then FIXES this claim when it draws `nonceE`: a later
     * poll showing a different claim cancels the link (T2-R-b), which the engine enforces by comparing
     * [DeviceClaim] values.
     *
     * An `nPub` that is one of Curve25519's low-order points is `bad_claim` too, with the field checks
     * and so before the MAC: it is 32 bytes of base64url, but it is not a key anything can be sealed to
     * ([X25519.isUsablePublicKey]). The `nPub` of a [VerifiedClaim] is therefore always a key
     * [sealOuter] accepts.
     */
    fun verifyClaim(crypto: CryptoProvider, keys: DeviceLinkKeys, claim: DeviceClaim): Checked<VerifiedClaim, DeviceLinkVerdict> {
        if (!claimFieldsInGrammar(claim.nPub, claim.name, claim.platform, claim.commitN) || !TrustGrammar.isB64_32(claim.mac)) {
            return refuse(DeviceLinkVerdict.BAD_CLAIM)
        }
        val expected = mac(crypto, keys, claimText(keys.linkId, claim.nPub, claim.name, claim.platform, claim.commitN))
        if (!macIs(claim.mac, expected)) return refuse(DeviceLinkVerdict.BAD_MAC)
        val nPub = Bytes.fromB64Exact(claim.nPub, 32) ?: return refuse(DeviceLinkVerdict.BAD_CLAIM)
        val deviceName = TrustGrammar.decodeName(claim.name) ?: return refuse(DeviceLinkVerdict.BAD_CLAIM)
        return Checked.Ok(VerifiedClaim(claim, nPub, deviceName))
    }

    /**
     * E's check of the nonce N revealed (§8.2 step 4): [nonceN] is a `b64_32` and
     * `commit(nonceN) = commitN`, the commitment of the claim E verified. Null when it holds, else
     * `bad_reveal`, which cancels the link: no code is computed from a nonce that was not committed.
     */
    fun checkReveal(crypto: CryptoProvider, commitN: String, nonceN: String): DeviceLinkVerdict? =
        if (CodeCommit.opens(crypto, nonceN, commitN)) null else DeviceLinkVerdict.BAD_REVEAL

    private fun refuse(verdict: DeviceLinkVerdict): Checked.Refused<DeviceLinkVerdict> = Checked.Refused(verdict)

    /**
     * N's pickup proof (§8.2 step 7): `b64url(HMAC-SHA-256(macKey, "andvari/v2|device-link|pickup|" + linkId + "|" + nPub))`.
     * E can compute it too, from `macKey` and the claim's `nPub`.
     */
    fun pickupProof(crypto: CryptoProvider, keys: DeviceLinkKeys, nPub: String): String {
        require(TrustGrammar.isB64_32(nPub)) { "nPub must be a b64_32" }
        return Bytes.toB64(mac(crypto, keys, "andvari/v2|device-link|pickup|${keys.linkId}|$nPub"))
    }

    /**
     * `proofHash = hexLower(SHA-256(proof))` over the ASCII bytes of the 43-character [proof] string
     * (§8.2 step 3, FI-B6). E posts it with `nonceE`; the server checks every later `proof` against it.
     */
    fun proofHash(crypto: CryptoProvider, proof: String): String {
        require(TrustGrammar.isB64_32(proof)) { "a proof is a b64_32" }
        return Bytes.toHexLower(crypto.sha256(proof.encodeToByteArray()))
    }

    /**
     * `approveMac = b64url(HMAC-SHA-256(macKey, "andvari/v2|device-link|approve|" + linkId + "|" + hexLower(SHA-256(raw outer))))`
     * (§8.2 step 6). It covers `outer` ONLY (FC-3), so N can check it before the password; `inner` is
     * bound by its AEAD under the UVK-derived key and this link's AD.
     */
    fun approveMac(crypto: CryptoProvider, keys: DeviceLinkKeys, sealedOuter: ByteArray): String =
        Bytes.toB64(approveMacBytes(crypto, keys, sealedOuter))

    private fun approveMacBytes(crypto: CryptoProvider, keys: DeviceLinkKeys, sealedOuter: ByteArray): ByteArray =
        mac(crypto, keys, "andvari/v2|device-link|approve|${keys.linkId}|" + Bytes.toHexLower(crypto.sha256(sealedOuter)))

    /**
     * E: `outer = crypto_box_seal(nPub, {"v":2,"origin":…,"userId":…,"email":…})` (§8.2 step 6). Refuses
     * (`IllegalArgumentException`) values outside their types, and an [nPub] that is not 32 bytes or is
     * a low-order point; the `nPub` of a [VerifiedClaim] is neither.
     */
    fun sealOuter(crypto: CryptoProvider, nPub: ByteArray, outer: DeviceLinkOuter): ByteArray {
        require(nPub.size == 32) { "nPub must be 32 bytes" }
        require(X25519.isUsablePublicKey(nPub)) { "nPub is a low-order point: nothing can be sealed to it" }
        return crypto.sealTo(nPub, encodeOuter(outer))
    }

    /** `outer`'s JSON, in the design's key order. Refuses values outside their types. */
    internal fun encodeOuter(outer: DeviceLinkOuter): ByteArray {
        val text = StringBuilder().append("{\"v\":2,\"origin\":").str(outer.origin)
            .append(",\"userId\":").str(outer.userId)
            .append(",\"email\":").str(outer.email)
            .append('}').toString()
        val bytes = text.encodeToByteArray()
        require(decodeOuter(bytes) == outer) { "outer holds a value outside its type (§8.2 step 6)" }
        return bytes
    }

    /** The strict decode of `outer` (§2.4): exactly `{v, origin, userId, email}` as compact JSON, or null. */
    internal fun decodeOuter(json: ByteArray): DeviceLinkOuter? {
        val o = compactObject(json) ?: return null
        if (!o.exactly("v", "origin", "userId", "email")) return null
        if (!o.isTwo("v")) return null
        val origin = o.text("origin")?.takeIf(TrustGrammar::isOrigin) ?: return null
        val userId = o.text("userId")?.takeIf(TrustGrammar::isUuid) ?: return null
        val email = o.text("email")?.takeIf { TrustGrammar.emailNorm(it) == it } ?: return null
        return DeviceLinkOuter(origin, userId, email)
    }

    /**
     * N, BEFORE any password prompt (§8.2 step 7, FC-3); the first failure is the verdict, in §2.4's
     * order:
     * 1. [approveMac] is a `b64_32` and verifies over the raw [sealedOuter] (`bad_mac`). The MAC covers
     *    the sealed bytes, so it is checked FIRST, before anything is opened or parsed: nothing that
     *    did not come from a holder of the link secret reaches the opener or the decoder;
     * 2. [sealedOuter] opens with ([nPub], [nSec]) (`outer_unopenable`);
     * 3. it is exactly `{"v":2,"origin","userId","email"}` under [decodeBundle]'s JSON rule: `origin` an
     *    `origin`, `userId` a `uuid`, `email` already its own `emailNorm` (`bad_outer`);
     * 4. its `origin` is [pinnedOrigin], the origin N pinned in step 0 (`origin_mismatch`).
     *
     * A server that alone made up an `outer` for an email of its choosing fails at step 1.
     */
    fun openOuter(
        crypto: CryptoProvider,
        keys: DeviceLinkKeys,
        nPub: ByteArray,
        nSec: ByteArray,
        sealedOuter: ByteArray,
        approveMac: String,
        pinnedOrigin: String,
    ): Checked<DeviceLinkOuter, DeviceLinkVerdict> {
        require(nPub.size == 32 && nSec.size == 32) { "the new device's key pair must be 32 bytes each" }
        if (!macIs(approveMac, approveMacBytes(crypto, keys, sealedOuter))) return refuse(DeviceLinkVerdict.BAD_MAC)
        val plain = try {
            crypto.sealOpen(nPub, nSec, sealedOuter)
        } catch (e: CryptoException) {
            return refuse(DeviceLinkVerdict.OUTER_UNOPENABLE)
        }
        val outer = decodeOuter(plain) ?: return refuse(DeviceLinkVerdict.BAD_OUTER)
        if (outer.origin != pinnedOrigin) return refuse(DeviceLinkVerdict.ORIGIN_MISMATCH)
        return Checked.Ok(outer)
    }

    /**
     * `contacts[].keyHash` (§8.3): the lowercase hex SHA-256 over a contact's raw 32 identity-key bytes.
     * E writes it for each contact it puts in the bundle.
     */
    fun contactKeyHash(crypto: CryptoProvider, identityPub: ByteArray): String {
        require(identityPub.size == 32) { "identity key must be 32 bytes" }
        return Bytes.toHexLower(crypto.sha256(identityPub))
    }

    /**
     * How N imports `contacts` (§8.3): the bundle confers CURRENCY, never contacts. [entry] makes a
     * contact current on N only when N's merged account state already holds that `userId`
     * ([heldIdentityPub], null when it holds none) and the held key hashes to `entry.keyHash`.
     */
    fun confirmsContact(crypto: CryptoProvider, entry: BundleContact, heldIdentityPub: ByteArray?): Boolean =
        heldIdentityPub != null && heldIdentityPub.size == 32 && contactKeyHash(crypto, heldIdentityPub) == entry.keyHash

    /** `bundleKey = HKDF(ikm = UVK, info = "andvari/v2|device-link|bundle|" + linkId, L = 32)` (§2.3, T-B1). */
    fun bundleKey(crypto: CryptoProvider, uvk: ByteArray, linkId: String): ByteArray {
        require(uvk.size == 32) { "the UVK must be 32 bytes" }
        require(TrustGrammar.isB64_16(linkId)) { "linkId must be a b64_16" }
        return Hkdf.sha256(crypto, uvk, ByteArray(0), "andvari/v2|device-link|bundle|$linkId".encodeToByteArray(), 32)
    }

    /** The bundle's JSON (§8.3). Refuses values outside their types, more than 1000 entries in a list, and more than 64 KiB. */
    fun encodeBundle(bundle: DeviceLinkBundle): ByteArray {
        val bytes = bundleText(bundle).encodeToByteArray()
        require(decodeBundle(bytes) == bundle) { "the bundle holds a value outside its type or is over a limit (§8.3)" }
        return bytes
    }

    /**
     * Whether [bundle] can be sent: every value in its type, at most 1000 entries in each list, and at
     * most 64 KiB encoded. E fills a bundle that does not fit by leaving entries out, the most
     * recently verified first in (§8.3 "Filling the 64 KiB", SR-2); which entries those are is the
     * engine's to decide, and this is its test.
     */
    fun fits(bundle: DeviceLinkBundle): Boolean = decodeBundle(bundleText(bundle).encodeToByteArray()) == bundle

    /** The bundle's JSON text in the design's key order (§8.3), not yet checked. */
    private fun bundleText(bundle: DeviceLinkBundle): String {
        val sb = StringBuilder()
        sb.append("{\"v\":2,\"origin\":").str(bundle.origin)
        sb.append(",\"instanceId\":").str(bundle.instanceId)
        sb.append(",\"card\":").checkpoint(bundle.card)
        sb.append(",\"userId\":").str(bundle.userId)
        sb.append(",\"email\":").str(bundle.email)
        sb.append(",\"identityPub\":").str(bundle.identityPub)
        sb.append(",\"personalVaultId\":").str(bundle.personalVaultId)
        sb.append(",\"contacts\":[")
        for ((i, c) in bundle.contacts.withIndex()) {
            if (i > 0) sb.append(',')
            sb.append("{\"userId\":").str(c.userId).append(",\"keyHash\":").str(c.keyHash).append(",\"verifiedAt\":").append(c.verifiedAt).append('}')
        }
        sb.append("],\"vaults\":[")
        for ((i, v) in bundle.vaults.withIndex()) {
            if (i > 0) sb.append(',')
            sb.append("{\"vaultId\":").str(v.vaultId).append(",\"seq\":").append(v.seq).append(",\"hash\":").str(v.hash).append('}')
        }
        sb.append("],\"accountState\":").checkpoint(bundle.accountState)
        sb.append(",\"issuedAt\":").append(bundle.issuedAt).append('}')
        return sb.toString()
    }

    /** A JSON string in the compact form of §2.4: only `"` and `\` are escaped. */
    private fun StringBuilder.str(value: String): StringBuilder {
        append('"')
        for (c in value) {
            if (c == '"' || c == '\\') append('\\')
            append(c)
        }
        return append('"')
    }

    private fun StringBuilder.checkpoint(c: Checkpoint): StringBuilder =
        append("{\"seq\":").append(c.seq).append(",\"hash\":").str(c.hash).append('}')

    /**
     * [json] as a compact JSON object (§2.4), or null. Every value of `outer` and of the bundle is
     * printable ASCII without a space (an origin, a uuid, hex, base64url, an `emailNorm`, a number),
     * and so is every key, so a byte outside `0x20..0x7E` can only stand where the text is refused
     * anyway. Refusing it here keeps invalid UTF-8, a byte-order mark and every non-ASCII character
     * out of the reader, on every engine alike.
     */
    private fun compactObject(json: ByteArray): JsonNode.Obj? {
        if (json.any { it < 0x20 || it > 0x7E }) return null
        return StrictJson.parse(json.decodeToString(), compact = true) as? JsonNode.Obj
    }

    /** Exactly these member names, each once: none missing, none extra, none repeated. */
    private fun JsonNode.Obj.exactly(vararg names: String): Boolean =
        members.size == names.size && names.all { name -> members.count { it.first == name } == 1 }

    /** The member is the JSON number `2`, written `2`. */
    private fun JsonNode.Obj.isTwo(name: String): Boolean = (last(name) as? JsonNode.Num)?.token == "2"

    private fun JsonNode.Obj.text(name: String): String? = (last(name) as? JsonNode.Str)?.value

    private fun JsonNode.Obj.int(name: String): Long? = (last(name) as? JsonNode.Num)?.let { TrustGrammar.parseInt(it.token) }

    private fun JsonNode.Obj.ms(name: String): Long? = (last(name) as? JsonNode.Num)?.let { TrustGrammar.parseMs(it.token) }

    private fun JsonNode.Obj.uuid(name: String): String? = text(name)?.takeIf(TrustGrammar::isUuid)

    private fun JsonNode.Obj.hex64(name: String): String? = text(name)?.takeIf(TrustGrammar::isHex64)

    private fun JsonNode.Obj.checkpoint(name: String): Checkpoint? {
        val c = last(name) as? JsonNode.Obj ?: return null
        if (!c.exactly("seq", "hash")) return null
        return Checkpoint(c.int("seq") ?: return null, c.hex64("hash") ?: return null)
    }

    /** The list member [name] with at most 1000 entries, each an object. */
    private fun JsonNode.Obj.entries(name: String): List<JsonNode.Obj>? {
        val items = (last(name) as? JsonNode.Arr)?.items ?: return null
        if (items.size > MAX_BUNDLE_ENTRIES) return null
        val out = ArrayList<JsonNode.Obj>(items.size)
        for (item in items) out += item as? JsonNode.Obj ?: return null
        return out
    }

    /**
     * The strict decoder of §8.3 (R3): UTF-8 JSON of at most 64 KiB with EXACTLY the listed keys at
     * every level (in any order, none twice, none extra), `v` the number 2, every value of its listed
     * type, and at most 1000 entries in each list. Null otherwise.
     *
     * The JSON rule (adopted into §2.4): the text is COMPACT. No white space outside strings; a string
     * escapes only `"` and `\`; numbers are in the `int` or `ms` text form (`2.0`, `2e0`, `02` and `-0`
     * are refused). In JavaScript terms, a text passes exactly when
     * `JSON.stringify(JSON.parse(text)) === text` and the key sets and types are right.
     */
    fun decodeBundle(json: ByteArray): DeviceLinkBundle? {
        if (json.size > MAX_BUNDLE_BYTES) return null
        val o = compactObject(json) ?: return null
        if (!o.exactly(
                "v", "origin", "instanceId", "card", "userId", "email", "identityPub", "personalVaultId",
                "contacts", "vaults", "accountState", "issuedAt",
            )
        ) {
            return null
        }
        if (!o.isTwo("v")) return null
        val origin = o.text("origin")?.takeIf(TrustGrammar::isOrigin) ?: return null
        val instanceId = o.uuid("instanceId") ?: return null
        val card = o.checkpoint("card") ?: return null
        val userId = o.uuid("userId") ?: return null
        val email = o.text("email")?.takeIf { TrustGrammar.emailNorm(it) == it } ?: return null
        val identityPub = o.text("identityPub")?.takeIf(TrustGrammar::isB64_32) ?: return null
        val personalVaultId = o.uuid("personalVaultId") ?: return null
        val contacts = ArrayList<BundleContact>()
        for (c in o.entries("contacts") ?: return null) {
            if (!c.exactly("userId", "keyHash", "verifiedAt")) return null
            contacts += BundleContact(c.uuid("userId") ?: return null, c.hex64("keyHash") ?: return null, c.ms("verifiedAt") ?: return null)
        }
        val vaults = ArrayList<BundleVault>()
        for (v in o.entries("vaults") ?: return null) {
            if (!v.exactly("vaultId", "seq", "hash")) return null
            vaults += BundleVault(v.uuid("vaultId") ?: return null, v.int("seq") ?: return null, v.hex64("hash") ?: return null)
        }
        val accountState = o.checkpoint("accountState") ?: return null
        val issuedAt = o.ms("issuedAt") ?: return null
        return DeviceLinkBundle(origin, instanceId, card, userId, email, identityPub, personalVaultId, contacts, vaults, accountState, issuedAt)
    }

    /** E: `inner = Envelope(bundleKey, bundle JSON, AD = "andvari/v2|device-link-bundle|" + linkId)` (§8.2 step 6). */
    fun sealBundle(crypto: CryptoProvider, uvk: ByteArray, linkId: String, bundle: DeviceLinkBundle): ByteArray {
        val plain = encodeBundle(bundle)
        val key = bundleKey(crypto, uvk, linkId)
        try {
            return Envelope.seal(crypto, key, plain, Ad.deviceLinkBundle(linkId))
        } finally {
            key.fill(0)
        }
    }

    /**
     * N, after the pickup and after it unlocked the UVK (§8.2 step 8): [inner] opens under the
     * bundle key with this link's AD (`bundle_unopenable`: nobody without the UVK can make or swap
     * it, and an `inner` from another link fails its AD), then the strict decode (`bad_bundle`).
     *
     * The account genesis is verified when the device unlocks, BEFORE the bundle is touched, so in
     * §2.4's order the genesis verdicts ([AccountGenesis.verify]) come first, then this function's
     * two, then [checkBundle]'s.
     */
    fun openBundle(crypto: CryptoProvider, uvk: ByteArray, linkId: String, inner: ByteArray): Checked<DeviceLinkBundle, DeviceLinkVerdict> {
        val key = bundleKey(crypto, uvk, linkId)
        val plain = try {
            Envelope.open(crypto, key, inner, Ad.deviceLinkBundle(linkId))
        } catch (e: CryptoException) {
            return refuse(DeviceLinkVerdict.BUNDLE_UNOPENABLE)
        } finally {
            key.fill(0)
        }
        val bundle = decodeBundle(plain) ?: return refuse(DeviceLinkVerdict.BAD_BUNDLE)
        return Checked.Ok(bundle)
    }


    /**
     * N's remaining checks on an opened bundle (§8.2 step 8); null when all pass:
     * 1. `userId` is [sessionUserId], `identityPub` is [seedIdentityPub] (the key N derived from the
     *    identity seed), and `personalVaultId` is [genesisPersonalVaultId] (from the genesis N verified
     *    with [AccountGenesis.verify] when it unlocked, before the bundle was opened)
     *    (`identity_mismatch`);
     * 2. `origin` is [pinnedOrigin] and `instanceId` is [pinnedInstanceId], and N's verified card chain
     *    has `bundle.card.hash` at `bundle.card.seq` ([cardHashAt]; N fetches forward first if its chain
     *    ends below, and a chain that still ends below it does not confirm the pin) (`pin_mismatch`).
     *
     * On any verdict N signs the fresh session out at once; on `pin_mismatch` it also removes the pin it
     * made in step 0.
     */
    fun checkBundle(
        bundle: DeviceLinkBundle,
        sessionUserId: String,
        seedIdentityPub: ByteArray,
        genesisPersonalVaultId: String,
        pinnedOrigin: String,
        pinnedInstanceId: String,
        cardHashAt: (Long) -> String?,
    ): DeviceLinkVerdict? {
        require(seedIdentityPub.size == 32) { "identity key must be 32 bytes" }
        if (bundle.userId != sessionUserId) return DeviceLinkVerdict.IDENTITY_MISMATCH
        val named = Bytes.fromB64Exact(bundle.identityPub, 32) ?: return DeviceLinkVerdict.IDENTITY_MISMATCH
        if (!Bytes.ctEquals(named, seedIdentityPub)) return DeviceLinkVerdict.IDENTITY_MISMATCH
        if (bundle.personalVaultId != genesisPersonalVaultId) return DeviceLinkVerdict.IDENTITY_MISMATCH
        if (bundle.origin != pinnedOrigin || bundle.instanceId != pinnedInstanceId) return DeviceLinkVerdict.PIN_MISMATCH
        if (cardHashAt(bundle.card.seq) != bundle.card.hash) return DeviceLinkVerdict.PIN_MISMATCH
        return null
    }
}
