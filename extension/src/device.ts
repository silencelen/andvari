import { b64Encode, b64Strict, isDnsHost, isUuid } from "./statement.ts";

/**
 * The device object a sign-in sends (design 2026-11-15-onboarding-trust §8.7; spec 03 §2, §0.3):
 * `{platform: "extension", name, deviceSecret, deviceId?}`. The `deviceSecret` is 32 CSPRNG bytes the extension
 * generates and keeps; the server stores its hash with the device row. A sign-in that sends the `deviceId` of a row
 * whose hash matches is from a KNOWN device (no new-device email, and allowed under "New devices must be linked").
 *
 * One record per origin namespace and account (keyed by the email's `emailNorm`), in the trusted store. It is not a
 * trust decision: a lost or replaced record only makes the next sign-in a new device.
 *
 * LEAF module: no chrome.
 */

export const DEVICE_PLATFORM = "extension";
export const DEVICE_NAME = "Browser extension";

export interface DeviceRecord {
  readonly deviceSecret: string;
  readonly deviceId: string | null;
}

/** The wire object of a password sign-in. */
export interface DeviceObject {
  readonly platform: string;
  readonly name: string;
  readonly deviceSecret: string;
  readonly deviceId?: string;
}

/** The longest local part an `emailNorm` takes (§2.3, spec 01 §5.5). */
export const EMAIL_LOCAL_MAX = 64;
/** A dot-atom over the lowercased local part: letters, digits and the 19 punctuation characters, single dots between
 *  non-empty parts. No quotes, comments, angle brackets or spaces. */
const DOT_ATOM = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;

/**
 * `emailNorm` (§2.3, VR-6), or null when the address is refused: strip space, tab, CR and LF from both
 * ends; refuse anything that is then shorter than 3 or longer than 254 octets, holds a byte outside 0x21..0x7E, or
 * lacks exactly one `@` between two non-empty parts; lowercase ASCII A–Z only; then the local part must be a dot-atom
 * of at most 64 characters and the domain two or more labels under the origin type's host grammar (`isDnsHost`, the
 * one function `isOrigin` uses too).
 *
 * The device record is keyed by this value. A record written under the older, looser rule for an address this rule
 * refuses (`a@b`, `a"b@example.com`, …) is never read or written again: such an address has no record, the sign-in
 * that names it is a new device, and the server (which applies the same rule) refuses it anyway.
 */
export function emailNorm(raw: string): string | null {
  let s = 0;
  let e = raw.length;
  const ws = (c: string) => c === " " || c === "\t" || c === "\r" || c === "\n";
  while (s < e && ws(raw[s]!)) s++;
  while (e > s && ws(raw[e - 1]!)) e--;
  const t = raw.slice(s, e); // a linear strip (a trailing-run regex is quadratic on long inner white space)
  if (!/^[\x21-\x7e]{3,254}$/.test(t)) return null;
  const at = t.indexOf("@");
  if (at <= 0 || at !== t.lastIndexOf("@") || at === t.length - 1) return null;
  const norm = t.replace(/[A-Z]/g, (c) => c.toLowerCase());
  const local = norm.slice(0, at);
  if (local.length > EMAIL_LOCAL_MAX || !DOT_ATOM.test(local)) return null;
  return isDnsHost(norm.slice(at + 1)) ? norm : null;
}

/** The trusted-store key of the email the person last signed in with (non-secret; the popup prefills it). */
export const LAST_EMAIL_KEY = "lastEmail";

/** A remembered email: a short, single-line string (it only prefills the popup's field). */
export function rememberableEmail(v: unknown): string | null {
  if (typeof v !== "string" || v.length === 0 || v.length > 320) return null;
  for (const ch of v) {
    const c = ch.codePointAt(0)!;
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029) return null; // controls and line separators
  }
  return v;
}

/** The trusted-store key of the device record for an account, under the origin's namespace. */
export const deviceKey = (emailNormalized: string): string => `device:${emailNormalized}`;

/** A fresh record: a new secret, no device row yet. */
export function newDeviceRecord(): DeviceRecord {
  return { deviceSecret: b64Encode(crypto.getRandomValues(new Uint8Array(32))), deviceId: null };
}

/** A stored record, or null when it is absent or not exactly one (a fresh one is then made). */
export function decodeDeviceRecord(raw: unknown): DeviceRecord | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.deviceSecret !== "string" || r.deviceSecret.length !== 43 || b64Strict(r.deviceSecret)?.length !== 32) return null;
  if (r.deviceId !== null && !(typeof r.deviceId === "string" && isUuid(r.deviceId))) return null;
  return { deviceSecret: r.deviceSecret, deviceId: r.deviceId };
}

/** The device object for a sign-in from this record. */
export function deviceObject(rec: DeviceRecord): DeviceObject {
  return rec.deviceId === null
    ? { platform: DEVICE_PLATFORM, name: DEVICE_NAME, deviceSecret: rec.deviceSecret }
    : { platform: DEVICE_PLATFORM, name: DEVICE_NAME, deviceSecret: rec.deviceSecret, deviceId: rec.deviceId };
}
