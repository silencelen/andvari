package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Escrow

/**
 * The ONE native enroll submit gate (Android + desktop share it — the two `ready`
 * expressions had already drifted once: both sat at the pre-F60 `length >= 8` while web
 * enforced the score floor, and both displayed the fingerprint instead of requiring it
 * typed). Mirrors web `Enroll`'s canSubmit exactly:
 *
 *  - F60: master password meets the strength floor (score >= 3), not a length check;
 *  - spec 04 §2(3): the user must TYPE the first 16 hex chars of the org recovery
 *    fingerprint from the PRINTED sheet — [Escrow.shortFormMatches] tolerates separators
 *    and is false whenever the server fingerprint is absent, so the "server has a
 *    recovery key" precondition rides the same leg;
 *  - plus the explicit attestation checkbox.
 *
 * Pure and jvm-tested; the UI layers contribute only their busy flag.
 */
object EnrollCeremony {
    fun ready(
        invite: String,
        email: String,
        password: String,
        confirm: String,
        typedFp: String,
        attested: Boolean,
        serverFp: String,
    ): Boolean =
        invite.isNotBlank() &&
            email.isNotBlank() &&
            Strength.meetsMasterPasswordFloor(password) &&
            password == confirm &&
            Escrow.shortFormMatches(typedFp, serverFp) &&
            attested
}
