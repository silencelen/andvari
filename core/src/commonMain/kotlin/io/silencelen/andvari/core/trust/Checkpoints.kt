package io.silencelen.andvari.core.trust

/**
 * A `{seq, hash}` head a device HOLDS for a chain it verified: the verified head of a vault log (§3.9),
 * a pinned card (§4.4), a device-link bundle's `card` and `vaults[]` entries (§8.3), the account's
 * vault record (§3.6 (e)), or the account-state high-water mark (§8.3, FI-B14).
 */
data class Checkpoint(val seq: Long, val hash: String)

/** What a served chain or state means against a head a device holds (design 2026-11-15 §2.4 "Checkpoints", VR-17). */
enum class CheckpointVerdict(val code: String) {
    /** The served chain has the held hash at the held `seq` (it may go on past it). */
    OK("ok"),

    /** The served chain ends below the held head (or nothing was served). Not a stop: the device keeps its own state. */
    WITHHELD("withheld"),

    /** The served chain has ANOTHER hash at the held `seq`. */
    FORK("fork"),

    /** Account state only: the served document is below the high-water mark. It is kept out. */
    ROLLBACK("rollback"),
}

/**
 * Comparing a served chain with a held head (§2.4 "Checkpoints", VR-17; §3.9, §4.4, §8.3): ONE pure
 * function for vault logs and card chains, shared with the web twin
 * (`web/src/crypto/trust/checkpoints.ts`) and graded by `vaultlog.json` and `instancecard.json`.
 *
 * It compares hashes only. Whether the served entries VERIFY is the verifier's question
 * ([VaultLog.verify], [InstanceCard.verify]); a device asks both.
 */
object Checkpoints {
    /**
     * [held] against a served chain whose last entry has `seq` [servedHeadSeq] (null: nothing was
     * served) and whose frame hash at a `seq` is [servedHashAt].
     *
     * - The served chain ends below `held.seq`: `withheld`.
     * - The served hash at `held.seq` is not `held.hash` (or the server skipped that position while
     *   serving past it): `fork`.
     * - Otherwise `ok`.
     */
    fun compare(held: Checkpoint, servedHeadSeq: Long?, servedHashAt: (Long) -> String?): CheckpointVerdict = when {
        servedHeadSeq == null || servedHeadSeq < held.seq -> CheckpointVerdict.WITHHELD
        servedHashAt(held.seq) == held.hash -> CheckpointVerdict.OK
        else -> CheckpointVerdict.FORK
    }

    /**
     * [compare] for a chain served from its start: `servedHashes[i]` is the frame hash of the entry
     * with `seq = i` (a log fetched without `after`; `GET /instance`'s cards, card 0 first).
     */
    fun compare(held: Checkpoint, servedHashes: List<String>): CheckpointVerdict =
        compare(held, if (servedHashes.isEmpty()) null else servedHashes.size - 1L) { seq ->
            if (seq in 0 until servedHashes.size) servedHashes[seq.toInt()] else null
        }

    /**
     * The card form (§4.4, §2.4 "Pinning"): a pinned card [held] of the chain whose card 0 hashes to
     * [card0Hash], against a chain served from card 0 (`servedHashes[i]` is the hash of the card with
     * `seq = i`).
     *
     * - No card served: `withheld`.
     * - Card 0 of the served chain is not [card0Hash]: `fork`, HOWEVER SHORT the served chain is. It is
     *   another chain (an operator reset under the same `instanceId`, §4.6, or another instance), and
     *   `withheld` is only the SAME chain ending below the pin.
     * - Otherwise [compare]: `withheld` below the pin, `fork` for another hash at its `seq`, else `ok`.
     */
    fun compareCard(card0Hash: String, held: Checkpoint, servedHashes: List<String>): CheckpointVerdict = when {
        servedHashes.isEmpty() -> CheckpointVerdict.WITHHELD
        servedHashes[0] != card0Hash -> CheckpointVerdict.FORK
        else -> compare(held, servedHashes)
    }

    /**
     * A served account state against the high-water [mark] (§8.3, FI-B14): [servedSeq] is the counter
     * INSIDE the opened document (not the server's compare-and-set token) and [servedHash] the hex
     * SHA-256 over the ASCII bytes of the served `sealedState` string. Below the mark is `rollback`
     * (kept out); a different hash at the same `seq` is `fork`; otherwise `ok`.
     */
    fun compareAccountState(mark: Checkpoint, servedSeq: Long, servedHash: String): CheckpointVerdict = when {
        servedSeq < mark.seq -> CheckpointVerdict.ROLLBACK
        servedSeq == mark.seq && servedHash != mark.hash -> CheckpointVerdict.FORK
        else -> CheckpointVerdict.OK
    }
}
