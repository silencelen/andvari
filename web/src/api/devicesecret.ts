import { toB64, toHexLower, utf8 } from "../crypto/bytes";
import { randomBytes, sha256Sync } from "../crypto/provider";
import { emailNorm, isB64_32, isUuid } from "../crypto/trust/grammar";

/**
 * This browser's device identity (design §8.7, spec 03 §0.3): a 32-byte `deviceSecret` it generates once,
 * and per account the `deviceId` the server answered when this browser created its row.
 *
 * Every device-creating request carries the secret (register, password login, the kit recovery commit);
 * a login also carries the `deviceId` it holds for that account, so the server can tell a known device
 * from a new one (S3-Q2). The server stores only the hash of the 32 decoded bytes and never returns it.
 *
 * Where it lives. A browser is a device, and its device state is this origin's localStorage: §8.7 asks only
 * that the device keep the secret, and the web's own server serves the code that reads it, so no browser
 * store would protect it better from that server. It lives under ONE key that is not scoped to an account,
 * so signing out or wiping one account's local data never forgets it (a forgotten secret would make this
 * browser a new device, which `requireLink` refuses).
 *
 * The account a login is for is known only by its email, so the record maps the hex SHA-256 of `emailNorm`
 * to a userId (the address itself is not stored). A record that fails to decode is replaced by a fresh one:
 * the browser is then a new device, the fail-safe outcome (§8.7: a wrong or missing secret never dodges
 * `requireLink`).
 */
export const DEVICE_KEY = "andvari.device.v2";

interface DeviceRecord {
  v: 2;
  secret: string;
  /** userId -> deviceId */
  devices: Record<string, string>;
  /** hex SHA-256(emailNorm) -> userId */
  accounts: Record<string, string>;
}

/** Storage seam: localStorage in the app, a map in tests. */
export interface KeyValue {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}

/** A storage seam over a Map: for tests, and for a browser whose storage is unavailable. */
export function memoryStorage(): KeyValue & { readonly map: Map<string, string> } {
  const map = new Map<string, string>();
  return { map, get: (k) => map.get(k) ?? null, set: (k, v) => void map.set(k, v), remove: (k) => void map.delete(k) };
}

export const browserStorage: KeyValue = {
  get(key) {
    try {
      return typeof localStorage === "undefined" ? null : localStorage.getItem(key);
    } catch {
      return null;
    }
  },
  remove(key) {
    try {
      if (typeof localStorage !== "undefined") localStorage.removeItem(key);
    } catch {
      /* storage unavailable */
    }
  },
  set(key, value) {
    try {
      if (typeof localStorage !== "undefined") localStorage.setItem(key, value);
    } catch {
      /* storage unavailable: the secret lives for this page only, and the next load is a new device */
    }
  },
};

function decode(text: string | null): DeviceRecord | null {
  if (text === null) return null;
  try {
    const o = JSON.parse(text) as Partial<DeviceRecord>;
    if (o.v !== 2 || typeof o.secret !== "string" || !isB64_32(o.secret)) return null;
    const devices: Record<string, string> = {};
    for (const [u, d] of Object.entries(o.devices ?? {})) if (isUuid(u) && typeof d === "string" && isUuid(d)) devices[u] = d;
    const accounts: Record<string, string> = {};
    for (const [h, u] of Object.entries(o.accounts ?? {})) if (/^[0-9a-f]{64}$/.test(h) && typeof u === "string" && isUuid(u)) accounts[h] = u;
    return { v: 2, secret: o.secret, devices, accounts };
  } catch {
    return null;
  }
}

const emailKey = (email: string): string | null => {
  const n = emailNorm(email);
  return n === null ? null : toHexLower(sha256Sync(utf8(n)));
};

export class DeviceIdentity {
  constructor(private readonly store: KeyValue = browserStorage) {}

  private load(): DeviceRecord {
    const held = decode(this.store.get(DEVICE_KEY));
    if (held) return held;
    const fresh: DeviceRecord = { v: 2, secret: toB64(randomBytes(32)), devices: {}, accounts: {} };
    this.store.set(DEVICE_KEY, JSON.stringify(fresh));
    return fresh;
  }

  /** The secret every device-creating request carries; generated on first use. */
  secret(): string {
    return this.load().secret;
  }

  /** The deviceId this browser holds for the account [email] names, if it created a row there. */
  deviceIdFor(email: string): string | null {
    const rec = this.load();
    const k = emailKey(email);
    const userId = k ? rec.accounts[k] : undefined;
    return userId ? (rec.devices[userId] ?? null) : null;
  }

  /** The account this browser last signed in to as [email], if any (the account of [deviceIdFor]'s row). */
  userIdFor(email: string): string | null {
    const k = emailKey(email);
    return k ? (this.load().accounts[k] ?? null) : null;
  }

  /** Remember the row the server answered (register, login, recovery commit) for [userId] signed in as [email]. */
  remember(email: string, userId: string, deviceId: string): void {
    if (!isUuid(userId) || !isUuid(deviceId)) return;
    const rec = this.load();
    const k = emailKey(email);
    if (k) rec.accounts[k] = userId;
    rec.devices[userId] = deviceId;
    this.store.set(DEVICE_KEY, JSON.stringify(rec));
  }

  /**
   * A deleted account (spec 03 §13 client duty): drop its deviceId and every address hash that maps to it, so nothing in
   * the record names the account. The secret stays: it is this browser's, shared by every account on it.
   */
  forget(userId: string): void {
    const held = decode(this.store.get(DEVICE_KEY));
    if (!held) return;
    let changed = userId in held.devices;
    delete held.devices[userId];
    for (const [k, u] of Object.entries(held.accounts)) {
      if (u !== userId) continue;
      delete held.accounts[k];
      changed = true;
    }
    if (changed) this.store.set(DEVICE_KEY, JSON.stringify(held));
  }
}
