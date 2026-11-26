import nacl from "tweetnacl";
import { boxKeypairFromSeed } from "./crypto.ts";
import { b64Strict, parseFrame, PURPOSE_CODES, signatureValid, signerIs, type ParseVerdict } from "./statement.ts";

/**
 * The account genesis in the extension (design 2026-11-15-onboarding-trust §5.1, §5.2, §12.2 rule 2). At
 * every unlock, after the identity seed is opened under the UVK, the extension derives its own Ed25519 key
 * (tweetnacl `sign.keyPair.fromSeed`) and its own X25519 key (the `crypto_box_seed_keypair` construction),
 * and requires, in §2.4's order (VR-13): the parse; `signerPub` byte-equal to its Ed25519 key
 * (`signer_not_pinned_key`); the signature (`bad_signature`); `identityKey` equal to its X25519 key
 * (`identity_mismatch`); `userId` the session's (`user_mismatch`); `instanceId` the pinned card's
 * (`instance_mismatch`); and a served personal wrap naming `personalVaultId` (`personal_vault_mismatch`).
 * Every failure is the identity fault (IDENTITY_MISMATCH copy). Graded by `accountgenesis.json`
 * (`expect.extensionVerdict`).
 */

const GENESIS_CODE = PURPOSE_CODES["account-genesis"]!;

export type GenesisVerdict =
  | ParseVerdict
  | "signer_not_pinned_key"
  | "bad_signature"
  | "identity_mismatch"
  | "user_mismatch"
  | "instance_mismatch"
  | "personal_vault_mismatch";

/** The extension's own keys, from the identity seed. */
export interface OwnKeys {
  readonly signPub: Uint8Array;
  readonly identityPub: Uint8Array;
}

/** Both public keys of the identity seed (§12.2 rule 2). */
export function ownKeysFromSeed(seed: Uint8Array): OwnKeys {
  return { signPub: nacl.sign.keyPair.fromSeed(seed).publicKey, identityPub: boxKeypairFromSeed(seed).publicKey };
}

export interface GenesisContext {
  readonly own: OwnKeys;
  readonly sessionUserId: string;
  readonly pinnedInstanceId: string;
  /** The served `personalWrap.vaultId`, or null when no wrap is served. */
  readonly servedPersonalVaultId: string | null;
}

export interface Genesis {
  readonly userId: string;
  readonly instanceId: string;
  readonly personalVaultId: string;
  readonly createdAt: number;
}

export type GenesisResult = { ok: true; genesis: Genesis } | { ok: false; verdict: GenesisVerdict };

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/** §5.2's checks on a served (or cached) genesis frame, in order. */
export function verifyGenesis(frame: Uint8Array, ctx: GenesisContext): GenesisResult {
  const parsed = parseFrame(frame, "account-genesis");
  if (!parsed.ok) return parsed;
  const p = parsed.value;
  if (!signerIs(p.signerPub, ctx.own.signPub)) return { ok: false, verdict: "signer_not_pinned_key" };
  if (!signatureValid(GENESIS_CODE, p.signerPub, p.signature, p.statement)) return { ok: false, verdict: "bad_signature" };
  const identityKey = b64Strict(p.values.identityKey as string);
  if (identityKey === null || !sameBytes(identityKey, ctx.own.identityPub)) return { ok: false, verdict: "identity_mismatch" };
  if (p.values.userId !== ctx.sessionUserId) return { ok: false, verdict: "user_mismatch" };
  if (p.values.instanceId !== ctx.pinnedInstanceId) return { ok: false, verdict: "instance_mismatch" };
  if (ctx.servedPersonalVaultId !== null && ctx.servedPersonalVaultId !== p.values.personalVaultId) {
    return { ok: false, verdict: "personal_vault_mismatch" };
  }
  return {
    ok: true,
    genesis: {
      userId: p.values.userId as string,
      instanceId: p.values.instanceId as string,
      personalVaultId: p.values.personalVaultId as string,
      createdAt: p.values.createdAt as number,
    },
  };
}
