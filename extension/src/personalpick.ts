import { adVkPersonal, fromB64, open } from "./crypto.ts";

/**
 * The personal vault in the extension (security review 2026-10, root cause A §4; A5 review H-1; A5b).
 * Core twin: `Account.applyPersonalWrap` / `applyCachedPersonalWrap` / `holdPersonalChange`; web: account.ts.
 *
 *  - A served `AccountKeys.personalWrap` decides: `Envelope(UVK, VK, adVkPersonal(vaultId, userId))`, which
 *    only this user's UVK can mint. Its VK is installed FIRST (precedence rule 1).
 *  - ...unless this device cached a wrap for a DIFFERENT vault (A5b M-2 / L-2: a re-designation elsewhere,
 *    or an older wrap replayed). Then the device does NOT switch: the cached wrap stays in force ("changed",
 *    with the served wrap carried for the human to confirm in the popup).
 *  - Served but unopenable: the cached wrap, if it opens, stays in force ("unreadable-cached", A5b L-1);
 *    otherwise NO personal vault ("unreadable").
 *  - No wrap served, but this device cached one it authenticated before (UVK-sealed, so caching is safe):
 *    the server WITHHELD it, an anomaly; the cached wrap stands ("withheld").
 *  - No wrap anywhere: NO personal vault. The extension never picks by a server label or role and never
 *    mints a wrap; a full client asks the human.
 */

export interface PersonalWrapWire {
  vaultId: string;
  wrappedVk: string;
}

export type PersonalPick =
  | { vaultId: string; source: "wrap" | "withheld" | "none" | "unreadable" | "unreadable-cached" }
  | { vaultId: string; source: "changed"; served: PersonalWrapWire };

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
  const cached = opts?.cached ?? null;
  const cachedVk = () => (cached ? openWrap(cached, uvk, userId) : null);
  if (wrap) {
    const vk = openWrap(wrap, uvk, userId);
    if (vk) {
      vaultKeys.set(wrap.vaultId, vk); // our own key either way (it opened under our UVK)
      if (cached && cached.vaultId !== wrap.vaultId) {
        const cvk = cachedVk();
        if (cvk) {
          vaultKeys.set(cached.vaultId, cvk);
          return { vaultId: cached.vaultId, source: "changed", served: { vaultId: wrap.vaultId, wrappedVk: wrap.wrappedVk } };
        }
      }
      return { vaultId: wrap.vaultId, source: "wrap" };
    }
    const cvk = cachedVk();
    if (cached && cvk) {
      vaultKeys.set(cached.vaultId, cvk);
      return { vaultId: cached.vaultId, source: "unreadable-cached" };
    }
    return { vaultId: "", source: "unreadable" };
  }
  if (!cached) return { vaultId: "", source: "none" };
  const cvk = cachedVk();
  if (!cvk) return { vaultId: "", source: "unreadable" };
  vaultKeys.set(cached.vaultId, cvk);
  return { vaultId: cached.vaultId, source: "withheld" };
}
