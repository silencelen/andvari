package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.EnrollLink
import io.silencelen.andvari.core.client.EnrollPayload
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.SecretStreamResult
import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Security review 2026-10, root cause A, branch A5c (API review LOW item 8): `enrollOp` used to take the
 * in-person verdict as a UI boolean (`inPersonVerified`). The composable computed it from the typed code and
 * the posture, and the state layer believed it. The verdict is now RE-ASSERTED at the state layer from the raw
 * inputs — the link payload, the human's typed code, their first-person affirmation and the field's
 * provenance — exactly as the typed-sheet re-assert and the full-rfp re-assert already are. The in-person
 * code is an unkeyed hash of the link, so a navigated/pasted link plus a correct code (both of which the
 * server that composed the link can supply) is never in-person evidence on its own.
 *
 * The leg stays unreachable on Android today (the invite field's only provenance is Typed, H66), which is
 * precisely why the rule is pinned as a pure function and a seam, not by exercising the form.
 */
class EnrollInPersonVerdictTest {

    private companion object {
        const val ORIGIN = "https://vault.example.org"
        const val RFP = "14f1bf4220e132f3aa00bb11cc22dd33ee44ff5566778899aabbccddeeff0011"
        const val IFP = "a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091"
        const val IU = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    }

    /** The JVM unit-test host has no phone sodium; the code is SHA-256 only, so a digest-only provider suffices. */
    private val crypto = object : CryptoProvider {
        override fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
        override fun randomBytes(n: Int): ByteArray = TODO()
        override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray = TODO()
        override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray = TODO()
        override fun hmacSha1(key: ByteArray, data: ByteArray): ByteArray = TODO()
        override fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray = TODO()
        override fun sha1(data: ByteArray): ByteArray = TODO()
        override fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray = TODO()
        override fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray = TODO()
        override fun boxKeypairFromSeed(seed: ByteArray): KeyPairBytes = TODO()
        override fun sealTo(recipientPublicKey: ByteArray, plaintext: ByteArray): ByteArray = TODO()
        override fun sealOpen(publicKey: ByteArray, privateKey: ByteArray, sealed: ByteArray): ByteArray = TODO()
        override fun secretstreamEncrypt(key: ByteArray, chunks: List<ByteArray>): SecretStreamResult = TODO()
        override fun secretstreamDecrypt(key: ByteArray, header: ByteArray, chunks: List<ByteArray>): List<ByteArray> = TODO()
        override fun signVerifyDetached(publicKey: ByteArray, signature: ByteArray, message: ByteArray): Boolean = TODO()
        override fun signKeypairFromSeed(seed: ByteArray): KeyPairBytes = TODO()
        override fun signDetached(secretKey: ByteArray, message: ByteArray): ByteArray = TODO()
        override fun ed25519PkToCurve25519(ed25519PublicKey: ByteArray): ByteArray = TODO()
    }

    private val payload = EnrollPayload(1, ORIGIN, "tok", "m@example.org", RFP, IFP, IU)
    private val code: String = EnrollLink.checkCode(crypto, payload)!!

    private val vmSource = File("src/main/kotlin/io/silencelen/andvari/app/AndvariViewModel.kt").readText()
    private val mainSource = File("src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt").readText()

    /** Comment-stripped, so a rule written down in prose cannot satisfy a pin about the code. */
    private fun code(src: String) = src
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    // ---- the rule ----

    /** A navigated/pasted link plus a correct code is not in-person evidence: without the human's first-person
     *  affirmation, or from a channel with no provenance, the verdict is false whatever the code says. */
    @Test
    fun aLinkPlusACorrectCodeIsNotInPersonEvidenceOnItsOwn() {
        assertFalse(inPersonVerdict(crypto, payload, code, affirmed = false, provenance = InviteProvenance.ScannedQr), "no first-person affirmation")
        assertFalse(inPersonVerdict(crypto, payload, code, affirmed = true, provenance = InviteProvenance.Typed), "a typed/pasted link has no provenance (H66), tick or no tick")
    }

    /** The genuine in-person path still verifies: a provenance-bearing channel, the code read off the admin's
     *  screen (separators tolerated, as everywhere a human types 32 hex) and the affirmation. */
    @Test
    fun theGenuineInPersonPathStillVerifies() {
        assertTrue(inPersonVerdict(crypto, payload, code, affirmed = true, provenance = InviteProvenance.ScannedQr))
        assertTrue(inPersonVerdict(crypto, payload, code.chunked(4).joinToString(" ").uppercase(), affirmed = true, provenance = InviteProvenance.AppLink))
    }

    /** The state layer re-checks the CODE itself from the raw entry — a wrong code, a prefix, or no link. */
    @Test
    fun theStateLayerRechecksTheCodeFromTheRawEntry() {
        assertFalse(inPersonVerdict(crypto, payload, "", affirmed = true, provenance = InviteProvenance.ScannedQr))
        assertFalse(inPersonVerdict(crypto, payload, code.take(16), affirmed = true, provenance = InviteProvenance.ScannedQr), "a prefix is not the code")
        assertFalse(inPersonVerdict(crypto, payload, "f".repeat(32), affirmed = true, provenance = InviteProvenance.ScannedQr))
        assertFalse(inPersonVerdict(crypto, null, code, affirmed = true, provenance = InviteProvenance.ScannedQr), "no link, no in-person fields")
        // A server that composes its own link (its own ifp) has a different code than the admin's screen shows.
        val forged = payload.copy(ifp = "f".repeat(64))
        assertFalse(inPersonVerdict(crypto, forged, code, affirmed = true, provenance = InviteProvenance.ScannedQr))
    }

    // ---- the seam ----

    /** enrollOp derives the verdict itself, from the raw inputs the form hands over; no `inPersonVerified`
     *  boolean crosses the UI → state boundary any more. */
    @Test
    fun enrollOpDerivesTheVerdictItselfNeverFromAUiBoolean() {
        val vm = code(vmSource)
        assertFalse(vm.contains("inPersonVerified: Boolean"), "the UI boolean parameter must be gone from enroll()/enrollOp()")
        assertTrue(vm.contains("val inPersonVerified = inPersonVerdict("), "enrollOp re-asserts the verdict at the state layer")
        val main = code(mainSource)
        assertTrue(main.contains("inPersonEntry = inPersonEntry"), "the form hands over the RAW typed code")
        assertTrue(main.contains("inPersonAffirmed = affirmed"), "…the human's first-person affirmation")
        assertTrue(main.contains("inviteProvenance = inviteProvenance"), "…and the field's provenance, for the state layer to judge")
        assertFalse(main.contains("inPersonVerified = "), "the form no longer pre-computes the verdict for the state layer")
    }
}
