import { toHexUpper, utf8 } from "./bytes";
import { sha1 } from "./provider";

/**
 * HIBP k-anonymity range check (spec 03 §8); mirrors core Hibp.kt. For ITEM passwords only
 * (Vault's "Check breach exposure", the Health scan): never hash the master password or a backup
 * passphrase with these, because its prefix would reach the server that holds the Argon2id
 * verifier (security review 2026-10, root cause C).
 */
export async function hibpSha1UpperHex(password: string): Promise<string> {
  return toHexUpper(await sha1(utf8(password)));
}

export const hibpPrefix = (sha1UpperHex: string) => sha1UpperHex.slice(0, 5);
export const hibpSuffix = (sha1UpperHex: string) => sha1UpperHex.slice(5);

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
