import { describe, expect, it } from "vitest";
import { hibpBreachCount, hibpPrefix, hibpSha1UpperHex, hibpSuffix } from "./hibp";

/**
 * F31: the master password / backup passphrase finally get the k-anonymity check web already
 * ran for item passwords. Twin of core StrengthBreachTest. These pin the two properties the
 * owner decision rests on — ONLY a prefix leaves the tab, and an unreachable breach API never
 * blocks anyone — because neither is visible in a UI screenshot.
 */
describe("hibpBreachCount (spec 03 §8 k-anonymity)", () => {
  const password = "correct horse battery staple";

  it("hands the fetcher the 5-char prefix and nothing else", async () => {
    const hash = await hibpSha1UpperHex(password);
    const seen: string[] = [];
    const count = await hibpBreachCount(password, async (prefix) => {
      seen.push(prefix);
      return `${hibpSuffix(hash)}:42\r\n`;
    });
    expect(count).toBe(42);
    expect(seen).toEqual([hibpPrefix(hash)]);
    const sent = seen[0]!;
    expect(sent).toHaveLength(5);
    expect(hash.startsWith(sent)).toBe(true);
    // The two things that must NEVER cross the seam.
    expect(sent).not.toBe(hash);
    expect(sent).not.toContain(password);
  });

  it("a miss inside a well-formed range is 0, not null", async () => {
    expect(await hibpBreachCount(password, async () => "0000000000000000000000000000000000000:9\r\n")).toBe(0);
  });

  it("fails OPEN and silent when the relay is unreachable", async () => {
    expect(
      await hibpBreachCount(password, () => {
        throw new Error("Failed to fetch");
      }),
    ).toBeNull();
    expect(await hibpBreachCount(password, async () => Promise.reject(new Error("502")))).toBeNull();
    // Garbage that isn't a range response is a miss, never a false "breached".
    expect(await hibpBreachCount(password, async () => "<html>502 Bad Gateway</html>")).toBe(0);
  });

  it("never looks up an empty password", async () => {
    let called = false;
    expect(
      await hibpBreachCount("", async () => {
        called = true;
        return "";
      }),
    ).toBeNull();
    expect(called).toBe(false);
  });
});
