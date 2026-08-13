import { toHexUpper, utf8 } from "./bytes";
import { sha1 } from "./provider";

/** HIBP k-anonymity range check (spec 03 §8); mirrors core Hibp.kt. */
export async function hibpSha1UpperHex(password: string): Promise<string> {
  return toHexUpper(await sha1(utf8(password)));
}

export const hibpPrefix = (sha1UpperHex: string) => sha1UpperHex.slice(0, 5);
export const hibpSuffix = (sha1UpperHex: string) => sha1UpperHex.slice(5);

/**
 * spec 03 §8 k-anonymity breach check for a MASTER password / backup passphrase (audit F31 —
 * until now only item passwords were ever checked, from Vault/Health). Twin of core
 * `Strength.breachCount`, which lives beside the floors because KMP has no ambient crypto
 * provider; on web the primitives are here, so the seam is here.
 *
 * Privacy contract: SHA-1 is computed in this tab and ONLY the 5-hex-character prefix is handed
 * to [fetchRange] — never the password, never the full hash. Nothing is logged or persisted.
 * Callers MUST pass the relay (`ApiClient.hibpRange` → `GET /api/v1/hibp/range/{prefix}`), never
 * a direct upstream call: the relay is what keeps the client's IP out of it.
 *
 * FAILS OPEN and SILENT: any transport or crypto failure resolves to null — "unknown", never
 * "breached", never an error the caller has to render. A password manager must not refuse an
 * enrollment because a breach API was unreachable, and the check is advisory anyway
 * (strength.ts BREACHED_PASSWORD_WARNING warns; nothing blocks).
 *
 * @returns the breach count (0 = not found), or null when the check could not be made.
 */
export async function hibpBreachCount(
  password: string,
  fetchRange: (prefix: string) => Promise<string>,
): Promise<number | null> {
  if (!password) return null;
  try {
    const hash = await hibpSha1UpperHex(password);
    return hibpCountInRange(await fetchRange(hibpPrefix(hash)), hash);
  } catch {
    return null; // fail open — the network, not the password, is what failed
  }
}

export function hibpCountInRange(rangeResponse: string, sha1UpperHex: string): number {
  const want = hibpSuffix(sha1UpperHex).toUpperCase();
  for (const line of rangeResponse.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const colon = trimmed.indexOf(":");
    if (colon <= 0) continue;
    if (trimmed.slice(0, colon).toUpperCase() === want) {
      const count = Number.parseInt(trimmed.slice(colon + 1).trim(), 10);
      return Number.isNaN(count) ? 0 : count;
    }
  }
  return 0;
}
