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

/**
 * Spec 01 §5.1 "no nesting" (design 2026-11-15 §2.2): a signed statement is ONE flat JSON object, so a
 * `[` anywhere, or a second `{`, makes it `non_canonical`. Every statement parser of core asks this
 * BEFORE it hands the text to the platform JSON parser.
 *
 * Why before: kotlinx's tree reader recurses once per array level with no depth limit, so a statement
 * of a thousand `[` (it fits in the 1,024 bytes a frame allows) overflows a small thread stack. A
 * `StackOverflowError` is not an `Exception`, so no parser's `catch` turns it into a verdict, and on
 * Kotlin/Native it cannot be caught at all: it is a crash that any sender of a frame could cause.
 *
 * Nothing canonical is lost: no value type of the grammar admits `[` or `{`.
 */
internal fun isFlatStatement(statement: ByteArray): Boolean {
    var braces = 0
    for (b in statement) {
        if (b == '['.code.toByte()) return false
        if (b == '{'.code.toByte() && ++braces > 1) return false
    }
    return true
}
