package io.silencelen.andvari.core.crypto

/**
 * The §1.4 verdict for a v2 grant (security review 2026-10, root cause A, branch A6). The wire [code] is shared
 * with the web twin and pinned by `spec/test-vectors/sharedgrant-v2.json`; the FIRST failing step decides it.
 * [anomaly] verdicts raise the "the server may be misbehaving — tell your admin" notice.
 */
enum class GrantVerdict(val code: String, val anomaly: Boolean) {
    /** Step 12: every check passed; the key is adopted. */
    ADOPT("adopt", false),

    /** Step 1: the seal does not open under our identity key (ignore the field, log). */
    UNOPENABLE("unopenable", false),

    /** Step 2: not a v2 frame, or not purpose `vault-grant`. */
    BAD_FRAME("bad_frame", false),

    /** Step 3: the statement is not its canonical encoding. */
    NON_CANONICAL("non_canonical", false),

    /** Step 4: `v != 2`, a purpose literal that is not the code's, or `from == to`. */
    BAD_STATEMENT("bad_statement", false),

    /** Step 5: `to` is not this account, or `toKey` is not our seed-derived identity key. */
    MISADDRESSED("misaddressed", true),

    /** Step 6: the statement names another vault than the grant row it arrived on. */
    VAULT_MISMATCH("vault_mismatch", true),

    /** Step 7: the named sender is not pinned here, or the pin is not current on this device. Not adopted. */
    PENDING_INVITATION("pending_invitation", false),

    /** Step 8: the signer key does not map to the pinned identity of the NAMED sender. */
    SIGNER_NOT_PINNED_KEY("signer_not_pinned_key", true),

    /** Step 9: the signature does not verify. */
    BAD_SIGNATURE("bad_signature", true),

    /** Step 10: the vault key is not 32 bytes (unreachable through the strict parse; kept for the table). */
    BAD_VK("bad_vk", false),

    /** Step 11: a valid grant carries a different key than the one held from our own UVK wrap; ours is kept. */
    VK_MISMATCH("vk_mismatch", true),
}

/** What a v2 grant comes to for this account (§1.4). */
sealed class GrantOutcome {
    abstract val verdict: GrantVerdict

    /** Every check passed. [vk] comes from the VERIFIED statement only. */
    class Adopted internal constructor(vk: ByteArray, val from: String, val grantIdB64: String, val issuedAt: Long) : GrantOutcome() {
        private val vkBytes = vk.copyOf()
        val vk: ByteArray get() = vkBytes.copyOf()
        override val verdict get() = GrantVerdict.ADOPT
    }

    /** §1.6: the named sender is not pinned (or not current here). [from] is UNVERIFIED routing data: it names
     *  whom to verify, nothing more. No key is exposed. */
    class Pending internal constructor(val from: String, val grantIdB64: String) : GrantOutcome() {
        override val verdict get() = GrantVerdict.PENDING_INVITATION
    }

    class Refused internal constructor(override val verdict: GrantVerdict) : GrantOutcome()
}

/**
 * A pinned contact as the grant verifier sees it: the identity key a HUMAN verified, and whether the pin is
 * [current] on this device (A5 review L-3: a pin a fresh device only read from an account-state blob, with no
 * high-water mark of its own, may be one that was later removed, so it cannot stand in for verification).
 */
class GrantPin(identityPub: ByteArray, val current: Boolean) {
    private val key = identityPub.copyOf()
    val identityPub: ByteArray get() = key.copyOf()
}

/**
 * Signed vault grants, format v2 (security review 2026-10, root cause A §1.4–§1.5; spec 01 §6). The sender
 * builds a `vault-grant` [Statement] with `toKey` taken from ITS PIN for the member, signs it with its joint key
 * and seals the frame to that pinned key; the recipient opens it with [open], which runs DESIGN §1.4 in order.
 *
 * THE INVARIANT (no laundering): a key is adopted only when the frame verifies under the identity this account
 * PINNED for the sender the statement NAMES (`contacts[from]`), and the pin is current. [SignedStatement.verify]
 * binds the signer to a pin but not to `from`, so the pin is chosen here, by `from`, and the VERIFIED statement's
 * `from`, `to`, `toKey` and `vaultId` are checked again after the signature; the key returned is the verified
 * statement's, never the unverified parse output's. Web twin: `web/src/crypto/signedgrant.ts`.
 */
object SignedGrant {
    /** Build the signed frame (no seal). Core-internal callers sign with the account's joint key. */
    fun buildFrame(crypto: CryptoProvider, signer: KeyPairBytes, statement: Statement.VaultGrant): ByteArray =
        SignedStatement.build(crypto, signer, statement)

    /** Seal a signed frame to the member's PINNED identity key. */
    fun seal(crypto: CryptoProvider, pinnedMemberIdentityPub: ByteArray, frame: ByteArray): ByteArray {
        if (pinnedMemberIdentityPub.size != 32) throw CryptoException("member identity key must be 32 bytes")
        return crypto.sealTo(pinnedMemberIdentityPub, frame)
    }

    /**
     * Recipient verification (DESIGN §1.4, normative order; the first failing step decides):
     *  1 open the seal with our identity keypair (`unopenable`);
     *  2 v2 frame with purpose `vault-grant` (`bad_frame`);
     *  3 strict canonical parse (`non_canonical`); 4 `v`, purpose, `from != to` (`bad_statement`);
     *  5 `to == me` and `toKey == my seed-derived identityPub` (`misaddressed`);
     *  6 `vaultId == the row's vaultId` (`vault_mismatch`);
     *  7 pin = [pinFor] (`from`), present AND current, else `pending_invitation`;
     *  8 signer key → the pin's identity key (`signer_not_pinned_key`); 9 signature (`bad_signature`);
     *  10 a 32-byte key (`bad_vk`); 11 when [heldVk] (from our OWN UVK wrap or personal wrap) is given, it must
     *  equal the granted key (`vk_mismatch`; the held key wins).
     *
     * Steps 5–7 read the UNVERIFIED routing fields only to refuse or to choose the pin; after the signature the
     * same fields are re-checked on the verified statement and the key comes from it.
     */
    fun open(
        crypto: CryptoProvider,
        myUserId: String,
        myIdentityPub: ByteArray,
        myIdentityPriv: ByteArray,
        rowVaultId: String,
        sealed: ByteArray,
        pinFor: (String) -> GrantPin?,
        heldVk: ByteArray?,
    ): GrantOutcome {
        val frame = try {
            crypto.sealOpen(myIdentityPub, myIdentityPriv, sealed)
        } catch (e: Exception) {
            return GrantOutcome.Refused(GrantVerdict.UNOPENABLE)
        }
        val unverified: Statement.VaultGrant = try {
            val f = SignedStatement.parseFrame(frame)
            if (f.purposeCode != StatementPurpose.VAULT_GRANT.code) return GrantOutcome.Refused(GrantVerdict.BAD_FRAME)
            SignedStatement.parseStatement(f.purposeCode, f.statement).parsed as Statement.VaultGrant
        } catch (e: SignedStatementException) {
            return GrantOutcome.Refused(fromStatement(e.verdict))
        }
        if (unverified.to != myUserId || !Bytes.ctEquals(unverified.toKey, myIdentityPub)) return GrantOutcome.Refused(GrantVerdict.MISADDRESSED)
        if (unverified.vaultId != rowVaultId) return GrantOutcome.Refused(GrantVerdict.VAULT_MISMATCH)
        val pinUserId = unverified.from
        val pin = pinFor(pinUserId)
        if (pin == null || !pin.current) return GrantOutcome.Pending(pinUserId, Bytes.toB64(unverified.grantId))

        val verified = try {
            SignedStatement.verify(crypto, frame, StatementPurpose.VAULT_GRANT, pin.identityPub)
        } catch (e: SignedStatementException) {
            return GrantOutcome.Refused(fromStatement(e.verdict))
        }
        // Use the VERIFIED result only, and bind it to the pin we chose: the signer maps to contacts[from], and
        // the verified statement must name that same sender, this account, our key and this row's vault.
        val st = verified.statement as? Statement.VaultGrant ?: return GrantOutcome.Refused(GrantVerdict.BAD_FRAME)
        if (st.from != pinUserId) return GrantOutcome.Refused(GrantVerdict.SIGNER_NOT_PINNED_KEY)
        if (st.to != myUserId || !Bytes.ctEquals(st.toKey, myIdentityPub)) return GrantOutcome.Refused(GrantVerdict.MISADDRESSED)
        if (st.vaultId != rowVaultId) return GrantOutcome.Refused(GrantVerdict.VAULT_MISMATCH)
        val vk = st.vk
        if (vk.size != 32) return GrantOutcome.Refused(GrantVerdict.BAD_VK)
        if (heldVk != null && !Bytes.ctEquals(heldVk, vk)) return GrantOutcome.Refused(GrantVerdict.VK_MISMATCH)
        return GrantOutcome.Adopted(vk, st.from, Bytes.toB64(st.grantId), st.issuedAt)
    }

    private fun fromStatement(v: StatementVerdict): GrantVerdict = when (v) {
        StatementVerdict.UNKNOWN_FORMAT, StatementVerdict.BAD_FRAME -> GrantVerdict.BAD_FRAME
        StatementVerdict.NON_CANONICAL -> GrantVerdict.NON_CANONICAL
        StatementVerdict.BAD_STATEMENT -> GrantVerdict.BAD_STATEMENT
        StatementVerdict.SIGNER_NOT_PINNED_KEY -> GrantVerdict.SIGNER_NOT_PINNED_KEY
        StatementVerdict.BAD_SIGNATURE -> GrantVerdict.BAD_SIGNATURE
        // Escrow-only verdicts never come out of a grant verify; refuse as a frame problem if they ever do.
        StatementVerdict.USER_MISMATCH, StatementVerdict.RECOVERY_FP_MISMATCH, StatementVerdict.IDENTITY_MISMATCH -> GrantVerdict.BAD_FRAME
    }
}

/**
 * What a client does with a vault key whose ONLY origin is a v1 `sealedVk` (root cause A §8.2 step 3, §8.6),
 * pinned by `sharedgrant.json` → `legacyMode`. A v1 seal is `crypto_box_seal` to our PUBLIC key: anyone, the
 * server included, can mint one, so its key is trusted only on evidence or a human's say-so.
 */
object LegacyGrant {
    /** Release N (branches A6/A7) is inside the compatibility window; branch A8 flips this. */
    const val IN_WINDOW = true

    enum class Mode(val code: String) {
        /** Pre-upgrade evidence on this device (the TOFU we already had): self-wrap silently. */
        FROZEN("frozen"),

        /** The human pressed Accept on the review card (trust on first use): self-wrap. */
        CONFIRMED("confirmed"),

        /** Readable, never written under (INV-WRITE-KEY), listed on the "Review your shared vaults" card. */
        READ_ONLY("read_only"),

        /** Post-window: not adopted at all ("ask the owner to re-share"). */
        REFUSED("refused"),
    }

    fun decide(inWindow: Boolean, preUpgradeEvidence: Boolean, confirmed: Boolean): Mode = when {
        preUpgradeEvidence -> Mode.FROZEN
        !inWindow -> Mode.REFUSED
        confirmed -> Mode.CONFIRMED
        else -> Mode.READ_ONLY
    }
}
