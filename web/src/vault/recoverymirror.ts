import type { KeyValue } from "../api/devicesecret";
import { isHex64n, isMs } from "../crypto/trust/grammar";
import type { RecoveryRecord } from "./accountdoc";
import { type AccountStateStore, type StateWrite } from "./accountdocstore";
import { withRecovery } from "./accountdoc";

/**
 * This browser's own mirror of the account's recovery record (design §4.5, T2-R-e). It is set on this browser
 * only by a choice the person made here (sign-up, Settings, re-consent) or a verified re-seal made here, never
 * from a served document. A seal or re-seal without asking happens only while the mirror agrees with the
 * account-state record. A record that does not decode reads as no mirror (the safe side: the browser asks).
 */
export interface RecoveryMirror {
  readonly posture: "private" | "operator";
  readonly fp: string;
  readonly at: number;
}

const key = (userId: string): string => `andvari.recmirror.${userId}`;

export function readMirror(storage: KeyValue, userId: string): RecoveryMirror | null {
  const text = storage.get(key(userId));
  if (text === null) return null;
  try {
    const o = JSON.parse(text) as Record<string, unknown>;
    const posture = o.posture;
    const fp = o.fp;
    const at = o.at;
    if ((posture !== "private" && posture !== "operator") || typeof fp !== "string" || !isHex64n(fp) || typeof at !== "number" || !isMs(at)) return null;
    return { posture, fp, at };
  } catch {
    return null;
  }
}

export function writeMirror(storage: KeyValue, userId: string, m: RecoveryMirror): void {
  storage.set(key(userId), JSON.stringify({ posture: m.posture, fp: m.fp, at: m.at }));
}

/** True when this browser may act on [record] without asking: its own mirror says the same thing. */
export function mirrorAgrees(mirror: RecoveryMirror | null, record: RecoveryRecord | null): boolean {
  return mirror !== null && record !== null && mirror.posture === record.posture && mirror.fp === record.fp && mirror.at === record.at;
}

/**
 * The person's recovery choice made on this browser: written to the account state (merged, compare-and-set) and,
 * once it is there, to this browser's mirror. A record that supersedes another is stamped later than it (§5.4):
 * `at` is raised above the record in force when the clock says otherwise.
 */
export async function recordRecoveryChoice(
  store: AccountStateStore,
  storage: KeyValue,
  userId: string,
  choice: { posture: "private" | "operator"; fp: string },
  nowMs: number,
  send?: Parameters<AccountStateStore["updateVia"]>[1],
): Promise<StateWrite> {
  let written: RecoveryMirror | null = null;
  const change = (doc: Parameters<typeof withRecovery>[0]) => {
    const prior = doc.recovery?.at ?? 0;
    const at = Math.max(nowMs, prior + 1);
    written = { posture: choice.posture, fp: choice.fp, at };
    return withRecovery(doc, written);
  };
  const w = send ? await store.updateVia(change, send) : await store.update(change);
  if (w.kind === "written" && written !== null) writeMirror(storage, userId, written);
  if (w.kind === "unchanged" && w.document.recovery) {
    const r = w.document.recovery;
    if (r.posture === choice.posture && r.fp === choice.fp) writeMirror(storage, userId, { posture: r.posture, fp: r.fp, at: r.at });
  }
  return w;
}
