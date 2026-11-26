import { fromB64 } from "./bytes";
import { boxKeypairFromSeed, type KeyPairBytes, sealOpen } from "./provider";
import { parseFrame, parseStatement } from "./signedstatement";

/**
 * Tests only: the statement version and the address a sealed recovery copy names, opened with [recovery] (spec 04 §3).
 * The signature is not checked here; the escrow opener's own tests do that.
 */
export function copyOf(sealedB64: string, recovery: KeyPairBytes): { v: number; email: string | null } {
  const frame = sealOpen(recovery.publicKey, recovery.privateKey, fromB64(sealedB64));
  const f = parseFrame(frame);
  const st = parseStatement(f.purposeCode, f.statement) as unknown as { email: string | null };
  const text = new TextDecoder().decode(f.statement);
  return { v: Number(/^\{"v":(\d+)/.exec(text)![1]), email: st.email };
}

/** [copyOf] with whichever of the vector recovery keys (seeds as base64url) opens the copy. */
export function copyOfAny(sealedB64: string, seedsB64: readonly string[]): { v: number; email: string | null } {
  for (const s of seedsB64) {
    try {
      return copyOf(sealedB64, boxKeypairFromSeed(fromB64(s)));
    } catch {
      /* not this key */
    }
  }
  throw new Error("no recovery key opens this copy");
}
