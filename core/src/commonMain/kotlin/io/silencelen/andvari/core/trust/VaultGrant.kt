package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes

/**
 * A vault grant statement (purpose 0x01; template unchanged from spec 01 §6):
 *
 * ```
 * {"v":2,"purpose":"vault-grant","from":…,"to":…,"toKey":…,"vaultId":…,"grantId":…,"issuedAt":…,"vk":…}
 * ```
 *
 * [from] and [to] are `uuid`, [toKey] the recipient's X25519 identity key (`b64_32` text), [grantId]
 * a `b64_16` that the `add` entry repeats, [vk] the 32-byte vault key. [vk] is copied in and out.
 */
class GrantFields(
    val from: String,
    val to: String,
    val toKey: String,
    val vaultId: String,
    val grantId: String,
    val issuedAt: Long,
    vk: ByteArray,
) {
    private val vkBytes = vk.copyOf()
    val vk: ByteArray get() = vkBytes.copyOf()

    /** Zero the held key once the grant is signed. */
    fun wipe() = vkBytes.fill(0)
}

/**
 * Why [VaultGrant.open] refused a grant (design 2026-11-15 §3.5, the ten checks in order). The [code]
 * is the design's name for the check that failed.
 */
enum class VaultGrantVerdict(val code: String) {
    /** 1. The seal does not open under this account's identity key. */
    UNOPENABLE("unopenable"),

    /** 2. Not a frame of purpose 0x01: too short, a bad length, a reserved purpose code or another purpose. */
    BAD_FRAME("bad_frame"),

    /** 2. The opened plaintext does not start with the frame magic (§2.4: the magic is checked before the length). */
    UNKNOWN_FORMAT("unknown_format"),

    /** 3. The statement is not its canonical encoding. */
    NON_CANONICAL("non_canonical"),

    /** 3. `v` is not 2, the purpose literal is not `vault-grant`, or `from == to`. */
    BAD_STATEMENT("bad_statement"),

    /** 4. `to` is not this account, or `toKey` is not its seed-derived key. */
    MISADDRESSED("misaddressed"),

    /** 5. `vaultId` is not the vault of the grant row it arrived on. */
    VAULT_MISMATCH("vault_mismatch"),

    /** 6. The verified log has no `add` entry with this `grantId`, this account as `member` and its key as `memberKey`. */
    NO_ADD_ENTRY("no_add_entry"),

    /** 7. `from` is not the actor of that `add` entry, or the signer does not map to the owner key at that entry. */
    NOT_AUTHORIZED("not_authorized"),

    /** 8. The Ed25519 signature does not verify. */
    BAD_SIGNATURE("bad_signature"),

    /** 9. `vk` does not match the log's `vkCommit` (§3.4). */
    VK_COMMIT_MISMATCH("vk_commit_mismatch"),

    /** 10. A later `remove` or `leave` of this account, with no later `add`: it is not a member at the verified head. */
    REMOVED("removed"),
}

/**
 * A grant that passed all ten checks of §3.5. [vk] is the vault key, already matched against the
 * log's commitment. [add] is the `add` entry the grant was bound to: its `actor` is the owner who
 * shared the vault (the contact §3.6 (d) requires to be current on this device) and its `seq` is the
 * `addSeq` an `accepted` record must answer (FS-R6).
 *
 * Passing these checks is NOT adoption. §3.6 still requires a current contact for [add]`.actor` with
 * the same key, the person's accept for this `addSeq`, and the account's vault record to agree.
 */
class OpenedGrant internal constructor(vk: ByteArray, val from: String, val grantId: String, val issuedAt: Long, val add: AddRecord) {
    private val vkBytes = vk.copyOf()
    val vk: ByteArray get() = vkBytes.copyOf()

    /** Zero the held key once the caller has wrapped it under the UVK. */
    fun wipe() = vkBytes.fill(0)
}

/**
 * Vault grants under the amended binding of design 2026-11-15 §3.5: a grant is honoured only when the
 * vault's VERIFIED LOG carries the owner-signed `add` entry it belongs to, and its key matches the
 * commitment fixed at genesis. This closes R15(f) (a pinned non-owner can no longer grant) and R15(g)
 * (no fresh device can be pushed onto another key). It replaces `crypto.SignedGrant.open`, which
 * trusted a contact pin and a held key instead of the log.
 */
object VaultGrant {
    /**
     * Encode and sign a grant with [signer], the OWNER's joint Ed25519 key. Refuses
     * (`IllegalArgumentException`) values outside the grammar and `from == to`. The owner signs it for
     * the `add` entry that carries the same `grantId` (§3.7: `add` takes the grant as side data).
     *
     * The frame returned holds the vault key in the clear: the caller seals it ([seal]) and zeroes it.
     * Everything else that held the key here is zeroed before this returns.
     */
    fun sign(crypto: CryptoProvider, signer: KeyPairBytes, grant: GrantFields): ByteArray {
        val vk = grant.vk
        try {
            // A wiped vault key is never granted: KeysGoneException. A key of the wrong length is the
            // statement's own refusal (IllegalArgumentException), below.
            if (vk.size == 32) io.silencelen.andvari.core.crypto.KeyFloor.requireKey(vk)
            // The key goes into the statement from its bytes: it never becomes a String.
            val statement = StatementCodec.encode(
                TrustPurpose.VAULT_GRANT,
                mapOf(
                    "from" to grant.from, "to" to grant.to, "toKey" to grant.toKey, "vaultId" to grant.vaultId,
                    "grantId" to grant.grantId, "issuedAt" to grant.issuedAt.toString(),
                ),
                secrets = mapOf("vk" to vk),
            )
            try {
                return SignedFrame.sign(crypto, signer, TrustPurpose.VAULT_GRANT, statement)
            } finally {
                statement.fill(0)
            }
        } finally {
            vk.fill(0)
        }
    }

    /** `crypto_box_seal` of a signed grant [frame] to the member's identity key [memberKey] (32 bytes), the `memberKey` of its `add` entry. */
    fun seal(crypto: CryptoProvider, memberKey: ByteArray, frame: ByteArray): ByteArray {
        require(memberKey.size == 32) { "member key must be 32 bytes" }
        return crypto.sealTo(memberKey, frame)
    }

    /**
     * The recipient's checks, in §3.5's order; the first failure is the verdict.
     *
     * 1. The seal opens with ([myIdentityPub], [myIdentityPriv]) (`unopenable`).
     * 2. A frame of purpose 0x01 (`bad_frame`; `unknown_format` for another magic, §2.4).
     * 3. Strict parse (`non_canonical`, `bad_statement`).
     * 4. `to` is [myUserId] and `toKey` is [myIdentityPub], the SEED-DERIVED key (`misaddressed`).
     * 5. `vaultId` is [rowVaultId], the vault of the grant row it arrived on (`vault_mismatch`).
     * 6. In [state], the vault's verified log state, THIS ACCOUNT'S LATEST `add` entry has this
     *    `grantId` and `memberKey` [myIdentityPub]. Call its actor O and the owner key at that entry K.
     *    A grant bound to an earlier `add` of the account, or to none, is `no_add_entry` (also when
     *    [state] is null or is another vault's: no verified log, no entry). So after a remove and a
     *    re-add only the new `add`'s grant opens: a server that put an old grant back on the row would
     *    otherwise make the accept prompt name whoever owned the vault at the earlier `add`.
     * 7. `from` is O, and the signer maps to K (`not_authorized`).
     * 8. The signature verifies (`bad_signature`).
     * 9. `vk` is 32 bytes and `commit(vk)` is the state's `vkCommit` (`vk_commit_mismatch`).
     * 10. This account is a member at the verified head: no later `remove` or `leave` without a later
     *     `add` (`removed`).
     *
     * [state] is a [VaultState], which only [VaultLog] builds from verified entries: that is step 6's
     * "the vault's log verifies".
     *
     * The opened frame, the statement the parser worked on and the decoded key are zeroed before this
     * returns, on every path; the result holds its own copy, which [OpenedGrant.wipe] zeroes. One copy
     * is out of reach: the provider's, on its way through the native call that opens the seal.
     */
    fun open(
        crypto: CryptoProvider,
        myUserId: String,
        myIdentityPub: ByteArray,
        myIdentityPriv: ByteArray,
        rowVaultId: String,
        sealed: ByteArray,
        state: VaultState?,
    ): Checked<OpenedGrant, VaultGrantVerdict> {
        // 1. The seal. A wiped identity key opens nothing and is a lock, never an unopenable grant.
        io.silencelen.andvari.core.crypto.KeyFloor.requireKey(myIdentityPriv)
        val frame = try {
            crypto.sealOpen(myIdentityPub, myIdentityPriv, sealed)
        } catch (e: Exception) {
            return refuse(VaultGrantVerdict.UNOPENABLE)
        }
        // The frame holds the vault key in the clear. Whatever the outcome, the frame and its split parts
        // are zeroed before this returns; the key is read from the statement bytes into one array, which
        // is zeroed too once the result holds its own copy.
        var parts: FrameParts? = null
        try {
            // 2, 3. The frame and the strict parse. Nothing below is trusted until step 8.
            val parsed = when (val p = StatementCodec.parseFrame(frame, TrustPurpose.VAULT_GRANT)) {
                is Checked.Ok -> p.value
                is Checked.Refused -> return refuse(
                    when (p.verdict) {
                        FrameVerdict.BAD_FRAME -> VaultGrantVerdict.BAD_FRAME
                        FrameVerdict.UNKNOWN_FORMAT -> VaultGrantVerdict.UNKNOWN_FORMAT
                        FrameVerdict.NON_CANONICAL -> VaultGrantVerdict.NON_CANONICAL
                        FrameVerdict.BAD_STATEMENT -> VaultGrantVerdict.BAD_STATEMENT
                    },
                )
            }
            parts = parsed.parts
            val raw = parsed.raw
            val myKey = Bytes.toB64(myIdentityPub)
            // 4. Addressed to this account and its seed-derived key.
            if (raw.str("to") != myUserId || raw.str("toKey") != myKey) return refuse(VaultGrantVerdict.MISADDRESSED)
            // 5. For the vault of the row it arrived on.
            if (raw.str("vaultId") != rowVaultId) return refuse(VaultGrantVerdict.VAULT_MISMATCH)
            // 6. This account's LATEST `add` in the verified log must be the one this grant names.
            val log = state?.takeIf { it.vaultId == rowVaultId } ?: return refuse(VaultGrantVerdict.NO_ADD_ENTRY)
            val grantId = raw.str("grantId")
            //    The state keeps exactly that one add per account, so an earlier add's grant finds no entry.
            val add = log.latestAdd(myUserId)?.takeIf { it.grantId == grantId && it.memberKey == myKey }
                ?: return refuse(VaultGrantVerdict.NO_ADD_ENTRY)
            // 7. Signed by the owner who signed that entry: `from` is its actor, the signer maps to the owner key there.
            if (raw.str("from") != add.actor) return refuse(VaultGrantVerdict.NOT_AUTHORIZED)
            val ownerKey = Bytes.fromB64Exact(add.ownerKey, 32) ?: return refuse(VaultGrantVerdict.NOT_AUTHORIZED)
            if (!SignedFrame.signerMapsTo(crypto, parsed.parts, ownerKey)) return refuse(VaultGrantVerdict.NOT_AUTHORIZED)
            // 8. The signature.
            if (!SignedFrame.signatureValid(crypto, parsed.parts)) return refuse(VaultGrantVerdict.BAD_SIGNATURE)
            // 9. The key against the commitment fixed at genesis (§3.4). It is read straight from the
            //    statement bytes: no String is ever made of it.
            val vk = raw.secret("vk")
            try {
                if (!VaultLog.keyMatches(crypto, log, vk)) return refuse(VaultGrantVerdict.VK_COMMIT_MISMATCH)
                // 10. Still a member at the verified head.
                if (myUserId !in log.members) return refuse(VaultGrantVerdict.REMOVED)
                return Checked.Ok(OpenedGrant(vk, raw.str("from"), grantId, raw.long("issuedAt"), add))
            } finally {
                vk.fill(0)
            }
        } finally {
            frame.fill(0) // the frame carries the vault key in base64
            parts?.wipe() // and so does the statement the parser worked on
        }
    }

    private fun refuse(verdict: VaultGrantVerdict): Checked.Refused<VaultGrantVerdict> = Checked.Refused(verdict)
}
