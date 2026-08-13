import { CryptoError } from "./sodium";

/**
 * Precondition for the two canonical-JSON payloads that are composed by string TEMPLATE rather
 * than by an encoder — {@link ../crypto/escrow!canonicalPayload} (spec 04 §3) and
 * {@link ../crypto/sharedgrant!canonicalGrantPayload} (spec 01 §6). Twin of core's
 * `CanonicalJson.requireJsonSafe`; both must produce bytes identical to the other side's, which
 * is why they are templates and not `JSON.stringify`: an encoder is free to reorder keys or
 * escape differently, and these bytes are sealed and later re-parsed by another implementation.
 *
 * The cost of hand-composing is that an interpolated value can break out of its JSON string, and
 * every value they interpolate except the base64 ones is SERVER-SUPPLIED (`userId` from the
 * session response, `vaultId` from a synced vault row). Without this check a hostile server could
 * return `x","keyType":"canary` and choose the JSON STRUCTURE of the blob the enrolling client
 * seals — no secret leaks (it is sealed to a public key the attacker does not hold), but the
 * member's recovery blob decodes as the wrong keyType or not at all, and nobody finds out until
 * the drill or the real recovery.
 *
 * A conforming id is a lowercase UUID, so `"` and `\` — the only two characters that can escape a
 * JSON string — can never appear in one. Refusing to seal is the honest failure: an availability
 * denial the server could mount anyway (spec 05 T1), surfaced now instead of at the worst possible
 * moment. Fails LOUD and early; a blob whose structure an attacker chose seals and stores fine and
 * only fails years later.
 */
export function requireJsonSafe(value: string, what: string): void {
  if (value.includes('"') || value.includes("\\")) {
    throw new CryptoError(`${what} must not contain a quote or backslash`);
  }
}
