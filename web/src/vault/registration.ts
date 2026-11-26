import type { EscrowUpload, NewDevice, RegisterRequestV2 } from "../api/wire";
import { adIdkey, adUvk, adVaultMeta, adVk, adVkPersonal } from "../crypto/ad";
import { toB64, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { assertServerKdfParams, authKey as deriveAuthKey, type KdfParams, masterKey, wrapKey as deriveWrapKey } from "../crypto/keys";
import { sealUvkV3 } from "../crypto/escrow";
import { generate as generateMemberRecovery } from "../crypto/member-recovery";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../crypto/provider";
import { signGenesis } from "../crypto/trust/genesis";
import { emailNorm } from "../crypto/trust/grammar";
import type { WebPin } from "./pinstore";

/**
 * The body of `POST /auth/register` for a web sign-up (spec 03 §14.3, design §7.3), and the keys it creates.
 *
 * The browser makes every key itself: the UVK, the identity seed (and from it the X25519 identity key and the
 * joint Ed25519 signing key), the personal vault's key, and a fresh recovery secret for the mandatory kit. It
 * signs exactly one account genesis (§5.2), naming the instance of the card this browser PINNED, never one the
 * server reported. The master key lives only long enough to split into its two purposes.
 *
 * The web registers only with a sign-up ticket (§13). The recovery posture is `private` unless the caller
 * passes an escrow the recovery module sealed under §4.5's conditions; the account-state `recovery` record and
 * this browser's mirror are written by the caller once the session exists (§4.5, §7.7).
 */
export interface Registration {
  readonly request: RegisterRequestV2;
  readonly userId: string;
  readonly personalVaultId: string;
  /** Owned by the caller: the session's UVK. */
  readonly uvk: Uint8Array;
  /** The kit secret, to show and confirm before the vault opens (§10); the caller wipes it after. */
  readonly recoverySecret: Uint8Array;
}

function uuidv4(): string {
  const b = randomBytes(16);
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export async function buildRegistration(params: {
  email: string;
  displayName: string;
  password: string;
  kdfParams: KdfParams;
  signupTicket: string;
  pin: WebPin;
  ageConfirmed: boolean;
  device: NewDevice;
  nowMs: number;
  /**
   * The operator-recovery choice at sign-up (design §7.7): the offered key, already hashed to the pinned card's
   * `recoveryFp` at full length by the offer. The UVK is sealed to it here, with the account's own signing key,
   * since neither exists before this call.
   */
  operatorEscrow?: { readonly recoveryPub: Uint8Array; readonly fp: string };
}): Promise<Registration> {
  if (emailNorm(params.email) === null) throw new Error("invalid_email");
  // H1: the policy's KDF params are server-supplied; nothing derives under params outside the fence.
  assertServerKdfParams(params.kdfParams);
  const userId = uuidv4();
  const personalVaultId = uuidv4();
  const kdfSalt = randomBytes(16);
  const mk = masterKey(params.password, kdfSalt, params.kdfParams);
  let authKey: Uint8Array;
  let wrapKey: Uint8Array;
  try {
    authKey = await deriveAuthKey(mk);
    wrapKey = await deriveWrapKey(mk);
  } finally {
    mk.fill(0);
  }
  const uvk = randomBytes(32);
  const seed = randomBytes(32);
  const vk = randomBytes(32);
  let signingSecret: Uint8Array | null = null;
  try {
    const identity = boxKeypairFromSeed(seed);
    const signing = signKeypairFromSeed(seed);
    signingSecret = signing.privateKey;
    identity.privateKey.fill(0);
    const genesis = signGenesis(signing, {
      userId,
      identityKey: toB64(identity.publicKey),
      instanceId: params.pin.instanceId,
      personalVaultId,
      createdAt: params.nowMs,
    });
    const recovery = await generateMemberRecovery(userId, uvk);
    let escrow: EscrowUpload | null = null;
    if (params.operatorEscrow) {
      try {
        // Spec 04 §3: the copy names the address this registration sends, in its emailNorm (checked above).
        const sealed = await sealUvkV3({
          recoveryPub: params.operatorEscrow.recoveryPub,
          verifiedRecoveryFp: params.operatorEscrow.fp,
          userId,
          emailNorm: emailNorm(params.email) ?? "",
          identityPub: identity.publicKey,
          signer: signing,
          uvk,
          issuedAt: params.nowMs,
        });
        escrow = { sealed: toB64(sealed), fingerprint: params.operatorEscrow.fp };
      } catch (e) {
        // A key that does not hash to the verified fingerprint: nothing is registered, and the new keys are wiped.
        uvk.fill(0);
        recovery.recoverySecret.fill(0);
        throw e;
      }
    }
    const request: RegisterRequestV2 = {
      auth: { signupTicket: params.signupTicket },
      email: params.email,
      displayName: params.displayName,
      userId,
      kdfSalt: toB64(kdfSalt),
      kdfParams: params.kdfParams,
      authKey: toB64(authKey),
      wrappedUvk: toB64(seal(wrapKey, uvk, adUvk(userId))),
      identityPub: toB64(identity.publicKey),
      encryptedIdentitySeed: toB64(seal(uvk, seed, adIdkey(userId))),
      genesis: toB64(genesis),
      personalVault: {
        vaultId: personalVaultId,
        wrappedVk: toB64(seal(uvk, vk, adVk(personalVaultId, userId))),
        metaBlob: toB64(seal(vk, utf8(JSON.stringify({ name: "Personal" })), adVaultMeta(personalVaultId))),
      },
      personalWrap: { vaultId: personalVaultId, wrappedVk: toB64(seal(uvk, vk, adVkPersonal(personalVaultId, userId))) },
      memberRecovery: { recoveryWrappedUvk: recovery.recoveryWrappedUvk, recoveryAuthKey: recovery.recoveryAuthKey },
      recovery: escrow ? { posture: "operator", escrow } : { posture: "private" },
      ageConfirmed: params.ageConfirmed,
      device: params.device,
    };
    return { request, userId, personalVaultId, uvk, recoverySecret: recovery.recoverySecret };
  } finally {
    signingSecret?.fill(0);
    authKey.fill(0);
    wrapKey.fill(0);
    seed.fill(0);
    vk.fill(0);
  }
}

/**
 * The sign-up proof of work (design §7.5, spec 03 §14.1): a nonce such that SHA-256 of the domain string has
 * `powBits` leading zero bits, searched in slices so the page stays responsive and can show progress. The
 * search runs in a Web Worker where one is available (vault/powworker.ts); this is the slice loop both use.
 */
export async function solvePow(
  powBits: number,
  utcDate: string,
  search: (from: number, tries: number) => number | null,
  onProgress: (tried: number) => void = () => {},
  signal?: AbortSignal,
  slice = 20_000,
): Promise<{ date: string; nonce: number }> {
  if (powBits <= 0) return { date: utcDate, nonce: 0 };
  for (let from = 0; from < Number.MAX_SAFE_INTEGER; from += slice) {
    if (signal?.aborted) throw new DOMException("aborted", "AbortError");
    const found = search(from, slice);
    if (found !== null) return { date: utcDate, nonce: found };
    onProgress(from + slice);
    await new Promise((r) => setTimeout(r, 0));
  }
  throw new Error("pow: no nonce found");
}

/** `YYYY-MM-DD` in UTC (§2.3), the date the proof of work hashes. */
export function utcDate(nowMs: number): string {
  return new Date(nowMs).toISOString().slice(0, 10);
}
