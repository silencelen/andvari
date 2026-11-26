import { TrustedStoreUnavailable, type KvArea } from "./trustedkv.ts";

/**
 * The first launch after the cut-over (design 2026-11-15-onboarding-trust §12.4, R9): the extension upgrades in place,
 * so the first start of a new-format build deletes every pre-cut-over local store before anything else runs — the
 * trusted store (the server choice, pins, caches, quick-unlock records), storage.local and storage.session — once,
 * keyed by a format marker in the trusted store. New builds read none of the old stores: there is no migration (clean
 * break), which is also why the A15 one-time migration (trustmigrate.ts) is gone.
 *
 * Returns how the trusted store answered, which worker start needs anyway (serverstate.ts). LEAF module.
 */

export const FORMAT_KEY = "storeFormat";
export const STORE_FORMAT = 2;

async function clearArea(area: KvArea): Promise<void> {
  const keys = Object.keys(await area.get(null));
  if (keys.length > 0) await area.remove(keys);
}

/**
 * [others]: storage.local and storage.session. [keyStores]: the extension's other IndexedDB databases, the quick-unlock
 * co-key database and the session-seal key database (§12.4 "quick-unlock keys", "the extension's IndexedDB records").
 *
 * With no trusted store at all (`unavailable`: no IndexedDB in this browser mode), [others] are cleared at every start:
 * nothing can be kept in them then anyway (since A15 storage.local holds no trust state, and nothing in storage.session
 * can be sealed without the seal's key database), and none of it may outlive the cut-over. A store that only timed out is
 * left alone: it exists, and the next start reads its marker.
 */
export async function wipeOldFormatOnce(trusted: KvArea, others: readonly KvArea[], keyStores: readonly KvArea[] = []): Promise<"ok" | "unavailable" | "timedOut"> {
  let marker: unknown;
  try {
    marker = (await trusted.get(FORMAT_KEY))[FORMAT_KEY];
  } catch (e) {
    if (e instanceof TrustedStoreUnavailable && e.timedOut) return "timedOut";
    for (const a of others) await clearArea(a).catch(() => {});
    return "unavailable";
  }
  if (marker === STORE_FORMAT) return "ok";
  try {
    await clearArea(trusted);
    for (const a of [...others, ...keyStores]) await clearArea(a).catch(() => {});
    await trusted.set({ [FORMAT_KEY]: STORE_FORMAT });
    return "ok";
  } catch (e) {
    // The old stores could not all be deleted: nothing is read from them at this start, and the next start tries again.
    return e instanceof TrustedStoreUnavailable && e.timedOut ? "timedOut" : "unavailable";
  }
}
