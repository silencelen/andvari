import { beforeAll, describe, expect, it, vi } from "vitest";
import { AnswerCutOffError, AnswerLimitError, ApiClient, NoAnswerInTimeError } from "../api/client";
import { WireApi } from "../api/wireclient";
import type { SyncResponse } from "../api/types";
import { toB64 } from "../crypto/bytes";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "../vault/account";
import { type ItemWire, NoPersonalVaultError, OfflineNotSavedError, VaultNotOpenError, VaultStore } from "../vault/store";
import * as C from "./copy";
import { saveErrorText } from "./saveerror";

/**
 * What the save screen says when a save was not made (the 2026-11-16 walk's "Save failed" with the
 * server gone): each refusal the store names carries its own sentence; only an unexpected failure is generic.
 */

function session(upload: () => Promise<never> = async () => { throw new TypeError("Failed to fetch"); }) {
  const seed = randomBytes(32);
  const personalVaultId = crypto.randomUUID();
  const account = Account.fromOpened(
    { userId: crypto.randomUUID(), uvk: randomBytes(32), identity: boxKeypairFromSeed(seed), signing: signKeypairFromSeed(seed), genesis: null as never, personalVaultId, personalVk: randomBytes(32) },
    null,
  );
  const sent: string[] = [];
  const offline = async (): Promise<never> => {
    throw new TypeError("Failed to fetch");
  };
  const wire = {
    async sync(since: number): Promise<SyncResponse> {
      return { rev: 1, full: since === 0, vaults: [], grants: [], items: [], removedGrants: [] };
    },
    pushMutations: async (m: unknown[]) => {
      sent.push(`push ${m.length}`);
      return offline();
    },
    uploadAttachment: async () => {
      sent.push("upload");
      return upload();
    },
  };
  const store = new VaultStore({ onRefusedIds: undefined } as unknown as ApiClient, account, undefined, undefined, wire as unknown as ItemWire);
  return { account, store, sent, personalVaultId };
}

describe("the save screen's sentences", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("with the server gone and no offline copy in this browser, the save is refused as such and nothing stays", async () => {
    const { store } = session();
    const e = await store.save(null, { type: "note", name: "n", notes: "x" }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(OfflineNotSavedError);
    expect((e as OfflineNotSavedError).reason).toBe("no_offline_copy");
    expect(store.list()).toEqual([]);
    expect(saveErrorText(e, true)).toBe(C.SAVE_OFFLINE_NO_COPY);
  });

  it("a file can't go up with the server gone: refused before the item is written", async () => {
    const { store, sent } = session();
    const id = crypto.randomUUID();
    const e = await store
      .save(null, { type: "note", name: "n", notes: "x", attachments: [{ id, name: "a.txt", size: 1, fileKey: toB64(randomBytes(32)) }] }, [{ id, data: new Uint8Array([1]) }])
      .catch((x: unknown) => x);
    expect((e as OfflineNotSavedError).reason).toBe("attachments");
    expect(sent).toEqual(["upload"]);
    expect(saveErrorText(e, true)).toBe(C.SAVE_OFFLINE_ATTACHMENTS);
  });

  it("an upload a limit ended (no answer, or its answer cut off) is said as not saved, never as may-or-may-not", async () => {
    for (const ended of [new NoAnswerInTimeError("stalled", 30_000), new AnswerCutOffError(200, new AnswerLimitError("stalled", 30_000))]) {
      const { store, sent } = session(async () => {
        throw ended;
      });
      const id = crypto.randomUUID();
      const e = await store
        .save(null, { type: "note", name: "n", notes: "x", attachments: [{ id, name: "a.txt", size: 1, fileKey: toB64(randomBytes(32)) }] }, [{ id, data: new Uint8Array([1]) }])
        .catch((x: unknown) => x);
      expect(sent, "nothing is pushed after the file").toEqual(["upload"]);
      expect(store.list()).toEqual([]);
      expect(saveErrorText(e, true)).toBe(C.SAVE_OFFLINE_ATTACHMENTS);
      expect(saveErrorText(e, true)).not.toBe(C.ANSWER_STALLED);
    }
  });

  it("a real upload that never gets an answer is ended by its limit and said as not saved", async () => {
    vi.useFakeTimers();
    try {
      const pushes: string[] = [];
      vi.stubGlobal(
        "fetch",
        vi.fn(
          (url: string, init: RequestInit) =>
            new Promise<Response>((_, reject) => {
              pushes.push(new URL(url).pathname);
              init.signal?.addEventListener("abort", () => reject(init.signal?.reason));
            }),
        ),
      );
      const client = new ApiClient("https://family.example");
      client.setTokens({ accessToken: "a", refreshToken: "r" });
      const wire = new WireApi(client);
      const seed = randomBytes(32);
      const account = Account.fromOpened(
        { userId: crypto.randomUUID(), uvk: randomBytes(32), identity: boxKeypairFromSeed(seed), signing: signKeypairFromSeed(seed), genesis: null as never, personalVaultId: crypto.randomUUID(), personalVk: randomBytes(32) },
        null,
      );
      const store = new VaultStore(client, account, undefined, undefined, wire as unknown as ItemWire);
      const id = crypto.randomUUID();
      const outcome: { e?: unknown } = {};
      const p = store
        .save(null, { type: "note", name: "n", notes: "x", attachments: [{ id, name: "a.txt", size: 1, fileKey: toB64(randomBytes(32)) }] }, [{ id, data: new Uint8Array([1]) }])
        .catch((x: unknown) => (outcome.e = x));
      await vi.advanceTimersByTimeAsync(31_000);
      await p;
      expect(outcome.e).toBeInstanceOf(OfflineNotSavedError);
      expect(saveErrorText(outcome.e, true)).toBe(C.SAVE_OFFLINE_ATTACHMENTS);
      expect(pushes.every((path) => path.startsWith("/api/v1/attachments/")), "no push of the item").toBe(true);
    } finally {
      vi.useRealTimers();
      vi.unstubAllGlobals();
    }
  });

  it("a browser that has not granted lasting storage: its own sentence", () => {
    expect(saveErrorText(new OfflineNotSavedError("not_persistent", new TypeError("x")), true)).toBe(C.SAVE_OFFLINE_NOT_PERSISTENT);
  });

  it("the personal vault named with no key held (after an anomaly) is refused before anything is sealed or sent", async () => {
    const { account, store, sent, personalVaultId } = session();
    (account as unknown as { vaultKeys: Map<string, Uint8Array> }).vaultKeys.delete(personalVaultId);
    expect(account.personalVaultId).toBe(personalVaultId);
    const e = await store.save(null, { type: "note", name: "n", notes: "x" }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(VaultNotOpenError);
    expect(sent).toEqual([]);
    expect(saveErrorText(e, true)).toBe(C.SAVE_VAULT_NOT_OPEN);
  });

  it("the other refusals keep their own words; only an unexpected failure is generic", () => {
    expect(saveErrorText(new NoPersonalVaultError(), true)).toBe("Choose a vault for this item.");
    expect(saveErrorText(new Error("boom"), true)).toBe("Save failed — nothing was changed.");
  });
});
