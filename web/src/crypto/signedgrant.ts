import { ctEquals, toB64 } from "./bytes";
import { type KeyPairBytes, sealOpen, sealTo } from "./provider";
import {
  buildSignedStatement,
  parseFrame,
  parseVaultGrantRouting,
  SignedStatementError,
  type StatementVerdict,
  type VaultGrantStatement,
  verifySignedStatement,
} from "./signedstatement";
import { CryptoError } from "./sodium";

/**
 * Signed vault grants, format v2 (security review 2026-10, root cause A §1.4–§1.5; spec 01 §6) — web twin of core
 * `SignedGrant.kt`, graded off the same spec/test-vectors/sharedgrant-v2.json. The sender builds a `vault-grant`
 * statement with `toKey` taken from ITS PIN for the member, signs it with its joint key and seals the frame to that
 * pinned key; the recipient runs {@link openSignedGrant}, DESIGN §1.4 in order.
 *
 * THE INVARIANT (no laundering): a key is adopted only when the frame verifies under the identity this account
 * PINNED for the sender the statement NAMES (`contacts[from]`), and the pin is current on this device.
 * `verifySignedStatement` binds the signer to a pin but not to `from`, so the pin is chosen here, by `from`, and
 * the VERIFIED statement's `from`, `to`, `toKey` and `vaultId` are re-checked after the signature; the key is the
 * verified statement's, never the unverified parse output's.
 */

export type GrantVerdict =
  | "adopt"
  | "unopenable"
  | "bad_frame"
  | "non_canonical"
  | "bad_statement"
  | "misaddressed"
  | "vault_mismatch"
  | "pending_invitation"
  | "signer_not_pinned_key"
  | "bad_signature"
  | "bad_vk"
  | "vk_mismatch";

const ANOMALY: ReadonlySet<GrantVerdict> = new Set(["misaddressed", "vault_mismatch", "signer_not_pinned_key", "bad_signature", "vk_mismatch"]);

/** True for the verdicts that raise the "the server may be misbehaving — tell your admin" notice. */
export function isGrantAnomaly(v: GrantVerdict): boolean {
  return ANOMALY.has(v);
}

export type GrantOutcome =
  | { readonly verdict: "adopt"; readonly anomaly: false; readonly vk: Uint8Array; readonly from: string; readonly grantIdB64: string; readonly issuedAt: number }
  /** §1.6: `from` is UNVERIFIED routing data naming whom to verify. No key is exposed. */
  | { readonly verdict: "pending_invitation"; readonly anomaly: false; readonly from: string; readonly grantIdB64: string }
  | { readonly verdict: Exclude<GrantVerdict, "adopt" | "pending_invitation">; readonly anomaly: boolean };

/** A pinned contact as the verifier sees it: the human-verified key, and whether the pin is current here (L-3). */
export interface GrantPin {
  identityPub: Uint8Array;
  current: boolean;
}

const refused = (verdict: Exclude<GrantVerdict, "adopt" | "pending_invitation">): GrantOutcome => Object.freeze({ verdict, anomaly: ANOMALY.has(verdict) });

function fromStatement(v: StatementVerdict): Exclude<GrantVerdict, "adopt" | "pending_invitation"> {
  switch (v) {
    case "non_canonical":
    case "bad_statement":
    case "signer_not_pinned_key":
    case "bad_signature":
      return v;
    default:
      return "bad_frame"; // unknown_format, bad_frame, and the escrow-only verdicts
  }
}

/** Build the signed frame (no seal). Callers outside this module sign only through Account.buildSignedGrant. */
export function buildGrantFrame(signer: KeyPairBytes, statement: VaultGrantStatement): Uint8Array {
  return buildSignedStatement(signer, statement);
}

/** Seal a signed frame to the member's PINNED identity key. */
export function sealGrantFrame(pinnedMemberIdentityPub: Uint8Array, frame: Uint8Array): Uint8Array {
  if (pinnedMemberIdentityPub.length !== 32) throw new CryptoError("member identity key must be 32 bytes");
  return sealTo(pinnedMemberIdentityPub, frame);
}

/**
 * Recipient verification, DESIGN §1.4 (normative order; the first failing step decides): 1 open (`unopenable`);
 * 2 v2 frame, purpose vault-grant (`bad_frame`); 3 strict parse (`non_canonical`); 4 `v`/purpose/`from != to`
 * (`bad_statement`); 5 `to == me`, `toKey == my identityPub` (`misaddressed`); 6 `vaultId == row` (`vault_mismatch`);
 * 7 pin = pinFor(from), present and current, else `pending_invitation`; 8 signer → pin (`signer_not_pinned_key`);
 * 9 signature (`bad_signature`); 10 32-byte key (`bad_vk`); 11 `heldVk` (from our OWN wrap) must equal it
 * (`vk_mismatch`; ours wins).
 */
export function openSignedGrant(p: {
  myUserId: string;
  myIdentityPub: Uint8Array;
  myIdentityPriv: Uint8Array;
  rowVaultId: string;
  sealed: Uint8Array;
  pinFor: (userId: string) => GrantPin | null;
  heldVk: Uint8Array | null;
}): GrantOutcome {
  let frame: Uint8Array;
  try {
    frame = sealOpen(p.myIdentityPub, p.myIdentityPriv, p.sealed);
  } catch {
    return refused("unopenable");
  }
  let routing: ReturnType<typeof parseVaultGrantRouting>;
  try {
    const f = parseFrame(frame);
    if (f.purposeCode !== 1) return refused("bad_frame");
    routing = parseVaultGrantRouting(f.statement);
  } catch (e) {
    if (e instanceof SignedStatementError) return refused(fromStatement(e.verdict));
    return refused("bad_frame");
  }
  if (routing.to !== p.myUserId || !ctEquals(routing.toKey, p.myIdentityPub)) return refused("misaddressed");
  if (routing.vaultId !== p.rowVaultId) return refused("vault_mismatch");
  const pinUserId = routing.from;
  const pin = p.pinFor(pinUserId);
  if (!pin || !pin.current) return Object.freeze({ verdict: "pending_invitation", anomaly: false, from: pinUserId, grantIdB64: toB64(routing.grantId) });

  let verified;
  try {
    verified = verifySignedStatement(frame, 1, pin.identityPub);
  } catch (e) {
    if (e instanceof SignedStatementError) return refused(fromStatement(e.verdict));
    return refused("bad_frame");
  }
  const st = verified.statement;
  if (st.purpose !== "vault-grant") return refused("bad_frame");
  // Use the VERIFIED result only, bound to the pin we chose.
  if (st.from !== pinUserId) return refused("signer_not_pinned_key");
  if (st.to !== p.myUserId || !ctEquals(st.toKey, p.myIdentityPub)) return refused("misaddressed");
  if (st.vaultId !== p.rowVaultId) return refused("vault_mismatch");
  if (st.vk.length !== 32) return refused("bad_vk");
  if (p.heldVk && !ctEquals(p.heldVk, st.vk)) return refused("vk_mismatch");
  return Object.freeze({ verdict: "adopt", anomaly: false, vk: st.vk, from: st.from, grantIdB64: toB64(st.grantId), issuedAt: st.issuedAt });
}

/** Release N (branches A6/A7) is inside the compatibility window; branch A8 flips this. */
export const LEGACY_IN_WINDOW = true;

export type LegacyGrantMode = "frozen" | "confirmed" | "read_only" | "refused";

/** What a client does with a key whose ONLY origin is a v1 seal (§8.2 / §8.6; sharedgrant.json `legacyMode`). */
export function decideLegacyGrant(inWindow: boolean, preUpgradeEvidence: boolean, confirmed: boolean): LegacyGrantMode {
  if (preUpgradeEvidence) return "frozen";
  if (!inWindow) return "refused";
  return confirmed ? "confirmed" : "read_only";
}
