import "fake-indexeddb/auto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { enterVault } from "../ui/opensession";
import { openVaultCache } from "../vault/idbcache";
import { changePassword } from "../vault/settingsflow";
import { Browser } from "./browser";
import { journeysUnavailable, type SharePeerProcess, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 14: a new wrap at a cost the server will take. An account is made while the server serves one hashing cost;
 * the operator then raises the server's floor on the memory figure and lowers the work figure below the account's. A
 * password change derives the new wrap at the higher of the account's and the server's cost, figure by figure: the server
 * takes it, and the new password signs in. (Before, the browser kept the account's own cost unless the served one was at
 * least as high on both figures, so the server refused every new password of such an account.)
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const MIB = 1_048_576;

function webStorage(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k: string) => m.get(k) ?? null,
    key: (i: number) => [...m.keys()][i] ?? null,
    removeItem: (k: string) => void m.delete(k),
    setItem: (k: string, v: string) => void m.set(k, v),
  } as Storage;
}

describe.skipIf(skip !== null)("journey 14: a password change after the server raised its floor on one figure", () => {
  let inst: TestInstance;
  let operator: SharePeerProcess;

  beforeAll(async () => {
    await initSodium();
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
    inst = await TestInstance.start({ kind: "private", mode: "open", enrolOperator: false });
    operator = await inst.policyPeer("operator@example.org", "operator horse Battery 9 staple");
  }, HOOK.start);

  afterAll(async () => {
    await operator?.stop();
    vi.unstubAllGlobals();
    await inst?.stop();
  }, HOOK.stop);

  it("the new wrap takes the higher of each figure; the server takes it and the new password signs in", async () => {
    const EMAIL = "rae@example.org";
    const P1 = "rae's first Horse 4 battery";
    const P2 = "rae's second Horse 7 battery";
    // The account is made at four passes over 64 MiB.
    expect(await operator.cmd(`kdf 4 ${64 * MIB}`)).toMatchObject({ ops: 4, memBytes: 64 * MIB });
    const browser = new Browser(inst, "Firefox at Rae's");
    const signed = await browser.signUp(EMAIL, P1, "Rae");
    expect(signed.wrap.kdfParams).toMatchObject({ ops: 4, memBytes: 64 * MIB });
    const tab = await enterVault(browser.ctx, { opened: signed.opened, keys: signed.session.accountKeys, wrap: signed.wrap, email: EMAIL, pin: signed.pin, cardNotice: null, how: null }, (u) => openVaultCache(u));

    // The operator raises the floor to 128 MiB, at three passes: above the account on memory, below it on passes.
    expect(await operator.cmd(`kdf 3 ${128 * MIB}`)).toMatchObject({ ops: 3, memBytes: 128 * MIB });
    const served = (await browser.wire.clientPolicy()).kdfParams;
    expect(served).toMatchObject({ ops: 3, memBytes: 128 * MIB });

    const r = await changePassword(tab.meta.settings, P1, P2, served);
    expect(r.kind, JSON.stringify(r)).toBe("done");
    const keys = await browser.wire.accountKeys();
    expect(keys.kdfParams, "the higher of each figure").toMatchObject({ ops: 4, memBytes: 128 * MIB });

    const other = new Browser(inst, "Safari on a Mac");
    expect((await other.signIn(EMAIL, P2)).kind, "the new password signs in").toBe("opened");
  }, 900_000);
});
