import { beforeAll, describe, expect, it, vi } from "vitest";
import { fromB64 } from "../bytes";
import { KeysGoneError } from "../keyfloor";
import { signKeypairFromSeed } from "../provider";
import { CryptoError, initSodium } from "../sodium";
import { signFrame } from "./frame";
import { keyMatches, vkCommit } from "./vaultlog";
import { expectSections, gradeEveryAsync, vector } from "./vectors";

/**
 * Spec 01 "Keys in memory and the lock", rule 4, graded off `keyfloor.json` (spec/test-vectors/README.md, "The key floor
 * rows"): each row is an all-zero input and the operation that must refuse it. The web owns `vaultlog.vkCommit`; it handles
 * no links (design §13), so the `links.derive` and `devicelink.derive` rows are other clients' and are NAMED as such here,
 * one by one, never skipped silently: a row of an operation this suite does not know fails it.
 */
const file = vector("keyfloor.json");

/** The operations whose rows belong to another client, and why the web has no function behind them. */
const OTHER_CLIENTS: Record<string, string> = {
  "links.derive": "the web client handles no links (design §13): the shared code and the oracle grade this row",
  "devicelink.derive": "the web client handles no device links (design §13): the shared code and the oracle grade this row",
};

beforeAll(async () => {
  await initSodium();
});

describe("keyfloor.json (spec 01 rule 4)", () => {
  it("has exactly the sections this suite reads", () => {
    expectSections(file, ["_about", "refuse"]);
  });

  it("refuse: every row is refused at its operation, or named as another client's", async () => {
    const named: string[] = [];
    const graded: string[] = [];
    await gradeEveryAsync("keyfloor.refuse", file.refuse, async (row: { name: string; operation: string; input: Record<string, string>; expect: { refused: boolean } }) => {
      expect(row.expect.refused, row.name).toBe(true);
      if (row.operation in OTHER_CLIENTS) {
        named.push(`${row.name}: ${OTHER_CLIENTS[row.operation]}`);
        return;
      }
      if (row.operation !== "vaultlog.vkCommit") throw new Error(`${row.name}: an operation this suite does not know: ${row.operation}`);
      const vk = fromB64(row.input.vkB64!);
      const subtle = vi.spyOn(crypto.subtle, "importKey");
      try {
        // Refused before the HKDF (no key is imported for its HMAC), and as a lock, never as bad input.
        const e = await vkCommit(vk, row.input.vaultId!).then(
          () => null,
          (x: unknown) => x,
        );
        expect(e, row.name).toBeInstanceOf(KeysGoneError);
        expect(e, row.name).not.toBeInstanceOf(CryptoError);
        // The check of a candidate key answers false for it, and does not throw (README: "a zero key matches no
        // vault-key commitment"); the commitment it is checked against is any well-formed one.
        expect(await keyMatches(row.input.vaultId!, "0".repeat(64), vk), row.name).toBe(false);
        expect(subtle).not.toHaveBeenCalled();
      } finally {
        subtle.mockRestore();
      }
      graded.push(row.name);
    });
    expect(graded).toEqual(["vaultlog-vkcommit-zero-key"]);
    expect(named).toEqual([
      `links-derive-zero-secret: ${OTHER_CLIENTS["links.derive"]}`,
      `devicelink-derive-zero-secret: ${OTHER_CLIENTS["devicelink.derive"]}`,
    ]);
  });
});

describe("rule 4 where the trust module signs (no row of the file grades it)", () => {
  it("no frame is signed with a seed of zeros, nor with a wiped secret", async () => {
    const statement = new TextEncoder().encode('{"x":"y"}');
    const zeroSeed = signKeypairFromSeed(new Uint8Array(32));
    expect(() => signFrame(zeroSeed, "vault-log", statement)).toThrow(KeysGoneError);
    const one = new Uint8Array(32);
    one[31] = 1;
    const wiped = signKeypairFromSeed(one);
    wiped.privateKey.fill(0);
    expect(() => signFrame(wiped, "vault-log", statement)).toThrow(KeysGoneError);
    expect(signFrame(signKeypairFromSeed(one), "vault-log", statement).length).toBeGreaterThan(64);
  });
});
