import { adVkPersonal, fromB64, open } from "./crypto.ts";

/**
 * The personal vault in the extension (security review 2026-10, root cause A §4; A5 review H-1).
 * Core twin: `Account.applyPersonalWrap` / `applyCachedPersonalWrap`; web: account.ts.
 *
 *  - A served `AccountKeys.personalWrap` decides: `Envelope(UVK, VK, adVkPersonal(vaultId, userId))`, which
 *    only this user's UVK can mint. Its VK is installed FIRST (precedence rule 1). Present but unopenable:
 *    NO personal vault ("unreadable").
 *  - No wrap served, but this device cached one it authenticated before (UVK-sealed, so caching is safe):
 *    the server WITHHELD it, an anomaly; the cached wrap stands ("withheld").
 *  - No wrap anywhere: NO personal vault. The extension never picks by a server label or role and never
 *    mints a wrap; a full client asks the human.
 */

export interface PersonalWrapWire {
  vaultId: string;
  wrappedVk: string;
}

export type PersonalPick = { vaultId: string; source: "wrap" | "withheld" | "none" | "unreadable" };

function openWrap(wrap: PersonalWrapWire, uvk: Uint8Array, userId: string): Uint8Array | null {
  try {
    const vk = open(uvk, fromB64(wrap.wrappedVk), adVkPersonal(wrap.vaultId, userId));
    return vk.length === 32 ? vk : null;
  } catch {
    return null;
  }
}

export function pickPersonal(
  wrap: PersonalWrapWire | null | undefined,
  uvk: Uint8Array,
  userId: string,
  vaultKeys: Map<string, Uint8Array>,
  opts?: { cached?: PersonalWrapWire | null },
): PersonalPick {
  const chosen = wrap ?? opts?.cached ?? null;
  if (!chosen) return { vaultId: "", source: "none" };
  const vk = openWrap(chosen, uvk, userId);
  if (!vk) return { vaultId: "", source: "unreadable" };
  vaultKeys.set(chosen.vaultId, vk);
  return { vaultId: chosen.vaultId, source: wrap ? "wrap" : "withheld" };
}
