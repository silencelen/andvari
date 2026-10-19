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
 *  - A served wrap that opens on a browser with NO cached wrap (A9 review MEDIUM-1): a "proposed" vault, not a
 *    default. Nothing is captured into it until the human confirms it once.
 *  - A11 (q13): a served wrap's key is installed only once that wrap is IN FORCE ("wrap"). In "proposed" and
 *    "changed" it is used for nothing (not decrypt-for-match, not an update target); accept installs it.
 */

export interface PersonalWrapWire {
  vaultId: string;
  wrappedVk: string;
}

export type PersonalPick =
  | { vaultId: string; source: "wrap" | "withheld" | "none" | "unreadable" | "unreadable-cached" }
  | { vaultId: string; source: "changed" | "proposed"; served: PersonalWrapWire };

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
      // A11 (q13): the served key is installed ONLY on the in-force branch below. While proposed or changed it is
      // used for nothing (no decrypt-for-match, no update target): the server picks which of the account's wraps to
      // serve, and a superseded one names a vault the user may have left. The popup's accept re-opens and installs it.
      // A9 review MEDIUM-1: with NOTHING cached (a fresh profile, cleared storage) the served wrap is a PROPOSAL, not a
      // default: the server keeps every wrap the account ever minted and chooses which to serve, so a superseded one
      // for a co-held vault would otherwise become the capture destination silently. No personal vault until the human
      // confirms it once (the popup's describe/accept flow, which re-opens the wrap under the UVK and caches it).
      if (!cached) return { vaultId: "", source: "proposed", served: { vaultId: wrap.vaultId, wrappedVk: wrap.wrappedVk } };
      if (cached.vaultId !== wrap.vaultId) {
        const cvk = cachedVk();
        if (cvk) {
          vaultKeys.set(cached.vaultId, cvk);
          return { vaultId: cached.vaultId, source: "changed", served: { vaultId: wrap.vaultId, wrappedVk: wrap.wrappedVk } };
        }
      }
      vaultKeys.set(wrap.vaultId, vk); // in force: our own key (it opened under our UVK), precedence rule 1
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
