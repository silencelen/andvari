package io.silencelen.andvari.core.crypto

/**
 * Precondition for the two canonical-JSON payloads that are composed by string TEMPLATE rather
 * than by an encoder — [Escrow.canonicalPayload] (spec 04 §3) and [SharedGrant.canonicalPayload]
 * (spec 01 §6). Both must produce bytes that are identical to the web twins', which is why they
 * are templates and not `Json.encodeToString`: an encoder is free to reorder keys or escape
 * differently, and these bytes are sealed and later re-parsed by another implementation.
 *
 * The cost of hand-composing is that an interpolated value can break out of its JSON string, and
 * every value they interpolate except the base64 ones is SERVER-SUPPLIED (`userId` from the
 * session response, `vaultId` from a synced vault row). This is the same defense [Ad.join] states
 * for its own separator — "conforming components cannot contain `|`" — written as a check rather
 * than a comment: a conforming id is a lowercase UUID, so `"` and `\` (the only two characters
 * that can escape a JSON string) can never appear in one.
 *
 * Fails LOUD and early. A blob whose structure an attacker chose is worse than no blob: it seals
 * and stores fine, and only fails years later at a real recovery.
 */
internal fun requireJsonSafe(value: String, what: String) {
    require('"' !in value && '\\' !in value) { "$what must not contain a quote or backslash" }
}
