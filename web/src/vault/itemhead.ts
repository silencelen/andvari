import type { ItemDoc } from "../api/types";

/**
 * The vault log head an item carries (spec 02 §3 `logHead`, design §3.9 "Gossip through items"): a writer stamps the
 * verified head of the shared vault it writes to into the encrypted document. A reader treats it as a hint to fetch,
 * never as a verdict (FS-R4): any writer, or a removed member working with the server, can put any value there.
 */
export interface ItemLogHead {
  readonly seq: number;
  readonly hash: string;
}

const HEX64 = /^[0-9a-f]{64}$/;

/** The head [doc] carries, or null when it carries none or one that is not a non-negative integer and 64 hex. */
export function itemLogHead(doc: ItemDoc): ItemLogHead | null {
  const raw = (doc as unknown as Record<string, unknown>).logHead;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const { seq, hash } = raw as Record<string, unknown>;
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 0) return null;
  if (typeof hash !== "string" || !HEX64.test(hash)) return null;
  return { seq, hash };
}

/**
 * [doc] as a writer seals it: carrying [head] (the verified head of the vault it is written to), or no head at all
 * (the personal vault, a vault whose log is not verified, and a copy from another vault, whose old head names a
 * different log). Every other field, known or not, is kept.
 */
export function stampLogHead(doc: ItemDoc, head: ItemLogHead | null): ItemDoc {
  const rest = { ...(doc as unknown as Record<string, unknown>) };
  delete rest.logHead;
  if (head !== null) rest.logHead = { seq: head.seq, hash: head.hash };
  return rest as unknown as ItemDoc;
}
