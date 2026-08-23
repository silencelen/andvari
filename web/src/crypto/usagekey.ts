import { utf8 } from "./bytes";
import { hkdfSha256 } from "./hkdf";

/**
 * The usage-ledger key (spec 02 §8.2) — the TS mirror of core UsageKey.kt.
 *
 * Derived from the PERSONAL VAULT KEY rather than the UVK, and the reason is a client
 * constraint rather than a cryptographic preference. The browser extension's UVK is
 * memory-only and never persisted (spec 01 breaker B1), and an MV3 service worker is evicted
 * routinely — the snapshot that restores its session carries `vaultKeys` but no UVK. A
 * UVK-bound ledger would therefore have been unwritable from the extension for most fills,
 * which is the client that does most of the filling. Every unlocked client holds the personal
 * VK in every session, evicted or not, so this binding lets all four participate.
 *
 * Domain-separated from the VK's own AEAD use exactly as the lifecycle key is
 * (lifecycleproof.ts): same construction, different info string. The AEAD associated data
 * stays `andvari/v1|usage|{userId}` (§2), so the blob is still bound to the user's slot and a
 * hostile endpoint cannot serve one member's ledger into another's.
 */
const USAGE_INFO = "andvari/v1|usage";

/** usageKey = HKDF-SHA-256(ikm = VK(personalVault), salt = "", info = "andvari/v1|usage", 32). */
export function usageKey(vk: Uint8Array): Promise<Uint8Array> {
  return hkdfSha256(vk, new Uint8Array(0), utf8(USAGE_INFO), 32);
}
