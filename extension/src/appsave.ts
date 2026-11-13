import { blake2b } from "@noble/hashes/blake2.js";
import nacl from "tweetnacl";
import type { BuildTarget } from "./buildtarget.ts";
import { toB64, fromB64 } from "./crypto.ts";
import { canonicalizeServerUrl } from "./serverurl.ts";

/**
 * Safari on iOS: a captured login is saved through the andvari app, not by this extension. The app publishes the
 * account's public key to the App Group; the extension seals the login to it (libsodium's sealed box) and hands the
 * ciphertext to its native handler, which queues it in the group. The app opens it at its next unlock and shows it
 * before anything is written. The extension needs no session for this, and the handler never sees the plaintext.
 *
 * The formats and bounds are the Kotlin core's (`core.app.SaveQueue`): this is their second implementation, and
 * appsave.test.ts pins the bounds. LEAF module: no chrome import.
 */

export const SAVE_QUEUE_VERSION = 1;
export const SAVE_MAGIC = "andvari-queued-save-v1";
export const MAX_ENTRY_BYTES = 8 * 1024;
export const MAX_FIELD_CHARS = 1024;
export const MAX_SITE_CHARS = 2048;

/** The account the app published: its server, its user id and its X25519 identity key. Public material. */
export type SaveKey = { origin: string; userId: string; identityPub: Uint8Array };

/** The handler's `saveKey` reply: `{ok: true, type: "saveKey", key: <the app's key.json text> | null}`. */
export function parseSaveKeyReply(reply: unknown): SaveKey | "none" | "unavailable" {
  if (typeof reply !== "object" || reply === null) return "unavailable";
  const r = reply as { ok?: unknown; type?: unknown; key?: unknown };
  if (r.ok !== true || r.type !== "saveKey") return "unavailable";
  if (r.key === null) return "none";
  if (typeof r.key !== "string") return "unavailable";
  try {
    const k = JSON.parse(r.key) as { v?: unknown; origin?: unknown; userId?: unknown; identityPub?: unknown };
    if (k.v !== SAVE_QUEUE_VERSION || typeof k.origin !== "string" || typeof k.userId !== "string" || typeof k.identityPub !== "string") return "unavailable";
    if (canonicalizeServerUrl(k.origin) !== k.origin || k.userId === "") return "unavailable";
    const pub = fromB64(k.identityPub);
    return pub.length === 32 ? { origin: k.origin, userId: k.userId, identityPub: pub } : "unavailable";
  } catch {
    return "unavailable";
  }
}

/** crypto_box_seal: an ephemeral key, the nonce blake2b(epk ‖ pk), and the box. Opens with crypto.ts sealOpen. */
export function sealTo(recipientPub: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const eph = nacl.box.keyPair();
  try {
    const nonce = blake2b(new Uint8Array([...eph.publicKey, ...recipientPub]), { dkLen: 24 });
    const box = nacl.box(plaintext, nonce, recipientPub, eph.secretKey);
    const out = new Uint8Array(32 + box.length);
    out.set(eph.publicKey, 0);
    out.set(box, 32);
    return out;
  } finally {
    eph.secretKey.fill(0);
  }
}

/**
 * The queue entry for one captured login, as the text the handler writes; null when there is nothing to save or a
 * field is over its bound. The inside names the account again, so an entry moved to another account does not open as
 * theirs.
 */
export function buildQueuedSave(key: SaveKey, site: string, username: string, password: string, nowMs: number): string | null {
  if (password === "" || password.length > MAX_FIELD_CHARS || username.length > MAX_FIELD_CHARS || site.trim() === "" || site.length > MAX_SITE_CHARS) return null;
  const inside = JSON.stringify({ magic: SAVE_MAGIC, origin: key.origin, userId: key.userId, site, username, password, capturedAtMs: nowMs, source: "safari" });
  const sealed = sealTo(key.identityPub, new TextEncoder().encode(inside));
  const entry = JSON.stringify({ v: SAVE_QUEUE_VERSION, origin: key.origin, userId: key.userId, sealed: toB64(sealed) });
  return new TextEncoder().encode(entry).length <= MAX_ENTRY_BYTES ? entry : null;
}

/** How handing a capture to the app ended. */
export type AppSaveResult = "queued" | "no_account" | "refused" | "unavailable";

type NativeSend = (msg: { type: string; id?: string; entry?: string }) => Promise<unknown>;

function bounded(p: Promise<unknown>, ms: number): Promise<unknown> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const silence = new Promise<undefined>((resolve) => {
    timer = setTimeout(() => resolve(undefined), ms);
  });
  return Promise.race([p, silence]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

/** How many ids one capture tries: the handler never replaces an entry, and answers a taken id as such. */
export const ID_ATTEMPTS = 3;

/** A new entry id: 128 bits from the platform's CSPRNG. */
export function newSaveId(): string {
  return `c-${[...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

/**
 * Seal a captured login to the app's account and queue it through the native handler, as an entry of its own: every
 * attempt has a new id from [mintId] (tests pass their own), and the handler never replaces an entry, so no capture
 * can overwrite another. A taken id is tried again under a new one. A retry after a lost answer may queue the same
 * login twice; the app keeps only the newest capture of a login. Never throws.
 */
export async function queueSaveToApp(
  sendNative: NativeSend,
  capture: { site: string; username: string; password: string },
  nowMs: number,
  timeoutMs = 3000,
  mintId: () => string = newSaveId,
): Promise<AppSaveResult> {
  try {
    const key = parseSaveKeyReply(await bounded(sendNative({ type: "saveKey" }), timeoutMs));
    if (key === "none") return "no_account";
    if (key === "unavailable") return "unavailable";
    const entry = buildQueuedSave(key, capture.site, capture.username, capture.password, nowMs);
    if (entry === null) return "refused";
    for (let attempt = 0; attempt < ID_ATTEMPTS; attempt++) {
      const id = mintId();
      if (!/^[A-Za-z0-9-]{1,64}$/.test(id)) return "refused";
      const r = (await bounded(sendNative({ type: "queueSave", id, entry }), timeoutMs)) as { ok?: unknown; type?: unknown; queued?: unknown; taken?: unknown } | undefined;
      if (typeof r !== "object" || r === null || r.type !== "queueSave") return "unavailable";
      if (r.ok === true && r.queued === true) return "queued";
      if (r.ok !== true || r.taken !== true) return "refused";
    }
    return "refused";
  } catch {
    return "unavailable";
  }
}

/** Only the Safari build saves through the app; the others save with their own session. */
export function savesThroughApp(target: BuildTarget): boolean {
  return target === "safari";
}
