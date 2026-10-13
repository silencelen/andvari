import { adVk, adVkPersonal, fromB64, open } from "./crypto.ts";
import type { PersonalWrapWire } from "./personalpick.ts";

/**
 * Vault keys in the extension (security review 2026-10, root cause A, branch A6; DESIGN-A §1.7, owner decision
 * Q8). LEAF module (no chrome), so `node --test` grades the production code path.
 *
 * The extension takes UVK WRAPS ONLY. It adopts a vault key only when it opens under this user's UVK: the
 * personal wrap (personalpick.ts) and a grant row's `wrappedVk` (an owner wrap, a transfer wrap, or a member
 * self-wrap a full client minted after verifying the grant). It NEVER opens a grant seal:
 *  - a v1 `sealedVk` is `crypto_box_seal` to our PUBLIC key, so anyone (the server included) can mint one;
 *  - a v2 `signedGrant` must be verified against a pinned identity, which needs an Edwards→Montgomery
 *    conversion tweetnacl lacks; adding a curve library would be a new supply-chain item (Q8 declined it).
 * A row that carries a seal or a signed grant but no wrap is WAITING: the popup says "open andvari to review",
 * and a full client verifies it (§1.4) and posts the self-wrap this module can then open. After an MV3 eviction
 * (no UVK in memory) nothing new is adopted at all.
 *
 * Gone with the seal: the A1 "vault key mismatch" compare of a seal against an opened wrap. Comparing requires
 * opening the seal; the wrap wins either way, and the full clients still raise that anomaly.
 */

export interface GrantRow {
  vaultId: string;
  userId: string;
  role: string;
  wrappedVk: string;
  sealedVk?: string | null;
  signedGrant?: string | null;
}

export interface VaultKeysFromWraps {
  vaultKeys: Map<string, Uint8Array>;
  vaultRoles: Map<string, string>;
  /** H64: vaults somebody else can read (any seal or signed grant on the row, or a non-owner role). */
  memberGranted: Set<string>;
  /** Our wrap is on the row and does not open: the vault stays keyless (never a seal fallback). */
  keyUnreadable: Set<string>;
  /** Rows with no wrap but a seal or a signed grant: waiting for a full client to verify and self-wrap. */
  waiting: Set<string>;
}

const carriesGrant = (g: GrantRow) => !!g.sealedVk || !!g.signedGrant;

export function buildVaultKeysFromWraps(grants: readonly GrantRow[], uvk: Uint8Array, userId: string): VaultKeysFromWraps {
  const vaultKeys = new Map<string, Uint8Array>();
  const vaultRoles = new Map<string, string>();
  const memberGranted = new Set<string>();
  const keyUnreadable = new Set<string>();
  const waiting = new Set<string>();
  for (const g of grants) {
    if (!g.wrappedVk) {
      if (carriesGrant(g)) waiting.add(g.vaultId); // never opened here (Q8)
      continue;
    }
    let vk: Uint8Array | null;
    try {
      vk = open(uvk, fromB64(g.wrappedVk), adVk(g.vaultId, userId)); // owner / transfer / member self-wrap
      if (vk.length !== 32) vk = null;
    } catch {
      vk = null;
    }
    if (vk === null) {
      keyUnreadable.add(g.vaultId); // damaged or substituted wrap: NO seal fallback
      continue;
    }
    vaultKeys.set(g.vaultId, vk);
    if (carriesGrant(g) || g.role !== "owner") memberGranted.add(g.vaultId);
    // G21: the role beside the key — "reader" means the server denies every push to this vault.
    vaultRoles.set(g.vaultId, g.role);
  }
  return { vaultKeys, vaultRoles, memberGranted, keyUnreadable, waiting };
}

/** Rows still waiting for a full client, computed WITHOUT the UVK (a resync after an eviction can refresh it). */
export function waitingGrantCount(grants: readonly GrantRow[], held: ReadonlySet<string>): number {
  let n = 0;
  for (const g of grants) if (!g.wrappedVk && carriesGrant(g) && !held.has(g.vaultId)) n++;
  return n;
}

/**
 * A5b review LOW-4 (closed in A6): "Use the new personal vault" re-authenticates the STAGED served wrap before
 * installing anything: it must open under the session UVK with the vk-personal AD for its own vaultId and this
 * user. A session restored from a snapshot after an MV3 eviction holds no UVK (breaker B1: memory-only), so it
 * cannot re-authenticate and the human is sent through a full unlock instead (`need_full_unlock`). The key
 * installed is the one re-opened here, never one merely present in the session's key map.
 */
export function reopenStagedPersonalWrap(
  staged: PersonalWrapWire,
  uvk: Uint8Array | undefined,
  userId: string,
): { ok: true; vk: Uint8Array } | { ok: false; code: "need_full_unlock" | "unverified" } {
  if (!uvk) return { ok: false, code: "need_full_unlock" };
  try {
    const vk = open(uvk, fromB64(staged.wrappedVk), adVkPersonal(staged.vaultId, userId));
    return vk.length === 32 ? { ok: true, vk } : { ok: false, code: "unverified" };
  } catch {
    return { ok: false, code: "unverified" };
  }
}

/** A vault's display name from its meta blob under a HELD key (spec 02 §4: only a JSON string is a name). */
export function vaultNameFromMeta(vk: Uint8Array | undefined, vaultId: string, metaBlob: string | undefined): string | null {
  if (!vk || !metaBlob) return null;
  try {
    const plain = open(vk, fromB64(metaBlob), new TextEncoder().encode(`andvari/v1|vaultmeta|${vaultId}`));
    const obj = JSON.parse(new TextDecoder().decode(plain)) as { name?: unknown };
    return typeof obj?.name === "string" && obj.name.length > 0 ? obj.name : null;
  } catch {
    return null;
  }
}

/** A5b review LOW-3 (closed in A6): the popup's change notice names BOTH vaults, and (fix round, LOW-1 parity)
 *  says how to KEEP the current one first, before anything about the new one. */
export function personalChangeNotice(currentName: string | null, newName: string | null): string {
  const cur = currentName ? `“${currentName}”` : "your current vault";
  const next = newName ? `“${newName}”` : "another vault";
  return `This browser keeps saving to ${cur}. To keep ${cur}, choose it again in the web vault (Settings, Personal vault). ` +
    `The server says your personal vault was changed to ${next} on another device (or it sent an older record).`;
}

/** A9 review MEDIUM-1: the popup line for a served wrap this browser never confirmed (no cached wrap). Confirming is
 *  the describe/accept flow below it, or any full client; until then nothing is captured. */
export function personalProposalNotice(newName: string | null): string {
  const next = newName ? `“${newName}”` : "a vault";
  return `This browser hasn't confirmed your personal vault yet, so it can't save new logins. ` +
    `Open andvari to confirm your personal vault, or confirm ${next} below.`;
}

/** A co-holder as the popup shows it: what the SERVER reports (it informs; it decides nothing). */
export interface CoHolderView {
  displayName: string;
  email: string;
  role: string;
}

/** Everyone the server reports on the vault except this account. */
export function coHoldersOf(members: readonly { userId: string; displayName: string; email: string; role: string }[], myUserId: string): CoHolderView[] {
  return members.filter((m) => m.userId !== myUserId).map((m) => ({ displayName: m.displayName, email: m.email, role: m.role }));
}

/** A5b review LOW-2 parity: the co-holder line, labelled as server-reported. */
export function coHoldersLine(coHolders: readonly CoHolderView[]): string {
  if (coHolders.length === 0) return "Who else holds the new vault, as reported by the server: no one else.";
  return "Who else holds the new vault, as reported by the server: " +
    coHolders.map((c) => `${c.displayName} (${c.email}, ${c.role})`).join(", ") + ".";
}

/**
 * A5b review LOW-1 parity (A6 fix round): the service worker accepts "Use the new personal vault" only after a
 * describe step loaded the co-holders of THAT served vault, for THIS account, in this SW lifetime. Null = may
 * proceed (the wrap is still re-opened under the UVK afterwards, LOW-4).
 */
export function acceptGate(
  described: { vaultId: string; userId: string } | null,
  servedVaultId: string,
  userId: string,
): "coholders_not_loaded" | null {
  if (!described || described.vaultId !== servedVaultId || described.userId !== userId) return "coholders_not_loaded";
  return null;
}
