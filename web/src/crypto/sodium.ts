import _sodium from "libsodium-wrappers-sumo";

/** Raised whenever a primitive fails — bad MAC, malformed input, bad encoding. */
export class CryptoError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "CryptoError";
  }
}

export type Sodium = typeof _sodium;

let instance: Sodium | null = null;

/** Await once at startup (and at the top of test files); everything after is sync. */
export async function initSodium(): Promise<Sodium> {
  if (!instance) {
    await _sodium.ready;
    instance = _sodium;
  }
  return instance;
}

export function sodium(): Sodium {
  if (!instance) throw new CryptoError("sodium not initialized — call initSodium() first");
  return instance;
}
