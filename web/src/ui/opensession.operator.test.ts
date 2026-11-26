import { describe, expect, it } from "vitest";
import type { OpenedAccount } from "../vault/accountopen";
import type { WebPin } from "../vault/pinstore";
import { enterVault, OperatorAccountError, type WebContext } from "./opensession";

/**
 * Design §12.2 rule 7 and §13: a verified card naming the account as `operator` (a handover made this member the
 * operator) refuses the session before anything of it is kept, for every way in, the unlock of a held session too.
 */
const U = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const pinNaming = (operator: string) => ({ operator, origin: "https://vault.example.org" }) as unknown as WebPin;

function ctx(stored: WebPin | null): WebContext {
  // Nothing past the check may be reached: any other use of the context throws.
  const trap = new Proxy({}, { get: () => { throw new Error("reached past the operator check"); } });
  return { client: trap, wire: trap, storage: trap, origin: "https://vault.example.org", pins: { pinFor: () => stored } } as unknown as WebContext;
}

const opened = { userId: U } as unknown as OpenedAccount;
const WRAP = { kdfSalt: "c2FsdA", kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67108864 }, wrappedUvk: "" };

describe("enterVault refuses the operator account by card", () => {
  it("the pin the session was opened under names this account", async () => {
    await expect(enterVault(ctx(null), { opened, keys: { kdfSalt: "c2FsdA" }, wrap: WRAP, email: "a@example.org", pin: pinNaming(U), cardNotice: null })).rejects.toBeInstanceOf(OperatorAccountError);
  });

  it("the stored pin advanced to a card naming this account", async () => {
    await expect(enterVault(ctx(pinNaming(U)), { opened, keys: { kdfSalt: "c2FsdA" }, wrap: WRAP, email: "a@example.org", pin: pinNaming(OTHER), cardNotice: null })).rejects.toBeInstanceOf(OperatorAccountError);
  });

  it("another operator lets the session through the check", async () => {
    await expect(enterVault(ctx(pinNaming(OTHER)), { opened, keys: { kdfSalt: "c2FsdA" }, wrap: WRAP, email: "a@example.org", pin: pinNaming(OTHER), cardNotice: null })).rejects.not.toBeInstanceOf(OperatorAccountError);
  });
});
