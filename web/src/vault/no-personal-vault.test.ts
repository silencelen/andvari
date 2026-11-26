import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { SyncResponse } from "../api/types";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { NO_PERSONAL_VAULT } from "../ui/copy";
import { NoPersonalVaultNotice } from "../ui/NoPersonalVault";
import { memoryClientState } from "./accountstatesync";
import { Account } from "./account";
import { NullCache } from "./idbcache";
import { SharedLogSession } from "./sharedlogs";
import { type ItemWire, NoPersonalVaultError, VaultStore } from "./store";

const ME = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const PV = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

/** A session the way enterVault builds it, with or without the personal wrap having opened at unlock. */
function session(personal: boolean) {
  const seed = randomBytes(32);
  const p = { userId: ME, uvk: randomBytes(32), identity: boxKeypairFromSeed(seed), signing: signKeypairFromSeed(seed) };
  const account = Account.fromOpened({ ...p, genesis: null as never, personalVaultId: personal ? PV : null, personalVk: personal ? randomBytes(32) : null }, null);
  const empty: SyncResponse = { rev: 1, full: true, vaults: [], grants: [], items: [], removedGrants: [] } as unknown as SyncResponse;
  const wire = { sync: async () => empty } as unknown as ItemWire;
  const store = new VaultStore({} as ApiClient, account, new NullCache(), memoryClientState(), wire);
  const logWire = {
    accountState: async () => ({ sealedState: null, seq: 0 }),
    putAccountState: async () => { throw new Error("not in this test"); },
    logPage: async () => { throw new Error("not in this test"); },
    appendLog: async () => { throw new Error("not in this test"); },
    putSelfWrap: async () => { throw new Error("not in this test"); },
  };
  store.attachSharedLogs(new SharedLogSession(p, logWire as never, memoryStorage(), account.logKeyRing()));
  return { account, store };
}

describe("design §5.3: a withheld or unopenable personal wrap is 'no personal vault' with the anomaly", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("asks no designation question, has no default destination, and shows the anomaly", async () => {
    const { account, store } = session(false);
    await store.sync();
    // No designation question exists to ask (the store has no designation method at all: web-pins).
    expect(account.personalVaultId).toBe("");
    await expect(store.save(null, { type: "note", name: "n" })).rejects.toBeInstanceOf(NoPersonalVaultError);
    expect(renderToStaticMarkup(createElement(NoPersonalVaultNotice, { account }))).toContain(NO_PERSONAL_VAULT.slice(NO_PERSONAL_VAULT.indexOf("Until")));
  });

  it("a personal wrap that opened at unlock is in force with no question and no notice", async () => {
    const { account, store } = session(true);
    await store.sync();
    expect(account.personalVaultId).toBe(PV);
    expect(renderToStaticMarkup(createElement(NoPersonalVaultNotice, { account }))).toBe("");
  });
});
