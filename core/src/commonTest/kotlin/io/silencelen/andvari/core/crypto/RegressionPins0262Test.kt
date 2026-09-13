package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H41: the 0.26.2 (2026-08-30 audit) core fix that shipped with no test — G51.
 * A fix nothing pins is a fix nothing keeps; this file makes dropping it fail `:core:allTests`.
 *
 * G51 (security): every lifecycle-proof MAC domain is a `|`-joined tuple, and most of its
 * components arrive on SERVER rows (vaultId, deleteId, offerId, userIds, nonce, wrapHash). With
 * no separator guard, a `|` inside one component shifts the tuple boundaries, so two DIFFERENT
 * tuples — ("a|b", "c") and ("a", "b|c") — MAC identically: a server that mints ids could alias
 * one vault's proof onto another. Ad.join and the F33 seams enforce that rule as code;
 * LifecycleProof was the one seam still enforcing it by comment until 0.26.2 added
 * `requireDomainSafe` to every mint. Pinned per mint AND per component, so removing the guard
 * from any one function (or forgetting one argument) fails here, not in a member's client.
 * The web twin lives in web/src/regression-pins-0262.test.ts.
 */
class RegressionPins0262Test {
    private val crypto = createCryptoProvider()
    private val key = crypto.randomBytes(32)
    private val vaultId = "55555555-5555-4555-8555-555555555555"
    private val id = "66666666-6666-4666-8666-666666666666"
    private val userId = "44444444-4444-4444-8444-444444444444"
    private val wrapHash = "00ff".repeat(16)
    private val bad = "a|b"

    @Test
    fun g51_everyMintRefusesASeparatorInEveryServerSuppliedComponent() {
        // delete / restore: (vaultId, deleteId)
        assertFailsWith<IllegalArgumentException> { LifecycleProof.delete(crypto, key, bad, id) }
        assertFailsWith<IllegalArgumentException> { LifecycleProof.delete(crypto, key, vaultId, bad) }
        assertFailsWith<IllegalArgumentException> { LifecycleProof.restore(crypto, key, bad, id) }
        assertFailsWith<IllegalArgumentException> { LifecycleProof.restore(crypto, key, vaultId, bad) }
        // offer: (vaultId, offerId, toUserId) — expiresAt/seq are numbers and cannot carry a bar
        assertFailsWith<IllegalArgumentException> { LifecycleProof.offer(crypto, key, bad, id, userId, 1L, 1L) }
        assertFailsWith<IllegalArgumentException> { LifecycleProof.offer(crypto, key, vaultId, bad, userId, 1L, 1L) }
        assertFailsWith<IllegalArgumentException> { LifecycleProof.offer(crypto, key, vaultId, id, bad, 1L, 1L) }
        // acceptFromHash: (vaultId, offerId, newOwnerUserId, wrapHash) — the wrapHash is the one
        // component other members receive from the server VERBATIM (spec 03 §11), so it is guarded.
        assertFailsWith<IllegalArgumentException> { LifecycleProof.acceptFromHash(crypto, key, bad, id, userId, 1L, wrapHash) }
        assertFailsWith<IllegalArgumentException> { LifecycleProof.acceptFromHash(crypto, key, vaultId, bad, userId, 1L, wrapHash) }
        assertFailsWith<IllegalArgumentException> { LifecycleProof.acceptFromHash(crypto, key, vaultId, id, bad, 1L, wrapHash) }
        assertFailsWith<IllegalArgumentException> { LifecycleProof.acceptFromHash(crypto, key, vaultId, id, userId, 1L, bad) }
        // remove: (vaultId, targetUserId, nonce)
        assertFailsWith<IllegalArgumentException> { LifecycleProof.remove(crypto, key, bad, userId, id) }
        assertFailsWith<IllegalArgumentException> { LifecycleProof.remove(crypto, key, vaultId, bad, id) }
        assertFailsWith<IllegalArgumentException> { LifecycleProof.remove(crypto, key, vaultId, userId, bad) }
    }

    /** The alias the guard exists for: both halves of the colliding pair refuse — the guard does
     *  not get to pick a winner, because the verify side (runCatching) reads either throw as
     *  "unverified" → retain-and-warn, the same posture as a bad proof. */
    @Test
    fun g51_bothHalvesOfTheAliasingPairRefuse() {
        assertFailsWith<IllegalArgumentException> { LifecycleProof.delete(crypto, key, "a|b", "c") }
        assertFailsWith<IllegalArgumentException> { LifecycleProof.delete(crypto, key, "a", "b|c") }
    }

    /** Honest input (UUIDs, hex, base64url can never contain `|`) is untouched — the vectors
     *  suite proves the bytes; this proves the guard has no false positive on the happy path and
     *  that `accept` still HASHES the wrap before interpolating (the hash is the tuple component,
     *  so a bar inside the raw wrap is not a tuple boundary and must not throw). */
    @Test
    fun g51_honestInputStillMintsAndTheHashedWrapIsNotAComponent() {
        val proof = LifecycleProof.delete(crypto, key, vaultId, id)
        assertTrue(LifecycleProof.verify(proof, LifecycleProof.delete(crypto, key, vaultId, id)))
        val a = LifecycleProof.accept(crypto, key, vaultId, id, userId, 1L, "wrap|with|bars")
        assertEquals(a, LifecycleProof.accept(crypto, key, vaultId, id, userId, 1L, "wrap|with|bars"))
    }
}
