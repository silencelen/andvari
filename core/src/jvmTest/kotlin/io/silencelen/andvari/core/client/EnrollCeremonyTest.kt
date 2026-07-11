package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Mutation-checked gate test for the shared native enroll predicate (the S4-review
 * coupling tripwire: "the create button stays disabled until shortFormMatches is true").
 * A fully-valid baseline passes; flipping ANY single leg fails — so a refactor that drops
 * a leg (the historical drift: natives at length>=8 while web enforced the F60 floor, and
 * display+checkbox instead of the typed sheet ceremony) goes red here, not to review.
 */
class EnrollCeremonyTest {

    private val fp = "b26efdd3eafc9dad3ba040a73900eb29d23827e0dabfa265222a8998d98d71de"
    private val strongPw = "correct horse battery staple 9!" // 3 classes (no upper), 31 chars → 155 bits → score 4

    private fun ready(
        invite: String = "tok",
        email: String = "a@x.com",
        password: String = strongPw,
        confirm: String = strongPw,
        typedFp: String = fp.take(16),
        attested: Boolean = true,
        serverFp: String = fp,
    ) = EnrollCeremony.ready(invite, email, password, confirm, typedFp, attested, serverFp)

    @Test
    fun baselinePasses() = assertTrue(ready())

    @Test
    fun everySingleLegBlocks() {
        assertFalse(ready(invite = "   "), "blank invite must block")
        assertFalse(ready(email = ""), "blank email must block")
        assertFalse(ready(confirm = strongPw + "x"), "password/confirm mismatch must block")
        assertFalse(ready(attested = false), "unchecked attestation must block")
        assertFalse(ready(serverFp = ""), "absent server recovery key must block")
    }

    @Test
    fun f60FloorIsTheScoreNotALengthCheck() {
        // The exact pre-fix hole: 9+ chars but weak. 'password1' = 2 classes, 9 chars →
        // 31.5 bits → score 0. Old native gate (length >= 8) accepted it.
        assertFalse(ready(password = "password1", confirm = "password1"))
        // Even 4-class but short stays under the floor (score 2 < 3).
        assertFalse(ready(password = "Pw1!Pw1!Pw", confirm = "Pw1!Pw1!Pw"))
        // Long single-class passphrase clears it the same way web does (25 lowercase +
        // spaces = 2 classes → 87.5 bits → score 3).
        val phrase = "horse battery staple mesa"
        assertTrue(ready(password = phrase, confirm = phrase))
    }

    @Test
    fun nonAsciiAdvisoryMirrorsWeb() {
        // web strength.ts: /[^\x20-\x7e]/ — controls, é, emoji fire; printable ASCII doesn't.
        assertFalse(Strength.masterPasswordHasNonAscii("plain ASCII pw 9!~"))
        assertTrue(Strength.masterPasswordHasNonAscii("café"))
        assertTrue(Strength.masterPasswordHasNonAscii("tab\tchar"))
        assertTrue(Strength.masterPasswordHasNonAscii("emoji 🔑"))
    }

    @Test
    fun typedSheetCeremonyIsLoadBearing() {
        assertFalse(ready(typedFp = ""), "nothing typed must block")
        assertFalse(ready(typedFp = fp.take(15)), "15 chars must block")
        assertFalse(ready(typedFp = fp.drop(1).take(16)), "wrong 16 chars must block")
        // Separators/whitespace tolerated, case-insensitive — the printed sheet groups hex.
        assertTrue(ready(typedFp = fp.take(16).uppercase().chunked(4).joinToString(" ")))
        assertTrue(ready(typedFp = fp.take(16).chunked(4).joinToString(":")))
        // Typing MORE than 16 hex chars is not a match (exactly-16 rule, spec 04 §2(3)).
        assertFalse(ready(typedFp = fp.take(17)))
    }
}
