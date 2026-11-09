package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * A10 review LOW-1 (security review 2026-10): an in-window v1 removal nonce that the consumed-record encoder cannot
 * represent used to be VERIFIED but never consumed — `RemovalProof.legacy` accepted any nonce without a `|`, while
 * the consumed record keeps only the token grammar (`[A-Za-z0-9_-]{1,128}`), so such a nonce replayed on that
 * device. A v1 nonce outside the token grammar is now the `fields` anomaly, before any MAC. Web twin in
 * lifecycleproof.test.ts.
 */
class LegacyNonceGrammarTest {
    private val crypto = createCryptoProvider()
    private val key = LifecycleProof.lifecycleKey(crypto, ByteArray(32) { 5 })
    private val vaultId = "0b7aa1e4-31f5-4f0a-9a6e-0e6a3a3d7d10"
    private val me = "f42e08cb-8cd4-435c-9599-83b519815789"

    private fun decide(nonce: String) = RemovalProof.decide(
        crypto, key, vaultId, me, reason = "removed", proofV = null,
        proof = LifecycleProof.remove(crypto, key, vaultId, me, nonce), nonce = nonce, issuedAt = null,
        consumed = emptySet(), consumedAccount = emptySet(), liveSince = null, now = 1_760_000_000_000,
    )

    @Test
    fun aV1NonceOutsideTheTokenGrammarIsTheFieldsAnomaly_andConsumesNothing() {
        for (bad in listOf("a b", "AAECAwQFBgcICQoLDA0ODw\n$vaultId", " ", "nonce\t1", "x".repeat(129), "AAEC+AwQ/Bg=")) {
            val d = decide(bad)
            assertEquals(RemovalProof.Verdict.ANOMALY, d.verdict, "accepted: ${bad.replace("\n", "\\n")}")
            assertEquals("fields", d.step)
            assertNull(d.consumeNonce)
        }
    }

    @Test
    fun theNoncesV1ClientsMintStillVerify() {
        // Pre-A7 clients minted a UUID; the vectors also carry base64url nonces. Both are token-shaped.
        for (ok in listOf("5f2b9a1c-4d3e-4c7a-9b8f-1a2c3d4e5f60", "AAECAwQFBgcICQoLDA0ODw")) {
            val d = decide(ok)
            assertEquals(RemovalProof.Verdict.VALID_LEGACY, d.verdict, ok)
            assertEquals(ok, d.consumeNonce)
        }
    }
}
