import { beforeAll, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { powAccepts } from "../crypto/trust/signup";
import { runPow } from "./pow";

/** The sign-up proof of work (design §7.5): found over emailNorm and the UTC date, with progress, and cancellable. */
describe("runPow", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("finds a nonce the server's check accepts, over the normal form of the address", async () => {
    const now = Date.UTC(2026, 10, 15, 23, 59);
    let progress = 0;
    const r = await runPow("  Alice@Example.com ", 10, now, (n) => (progress = n));
    expect(r.date).toBe("2026-11-15");
    expect(powAccepts("alice@example.com", r.date, r.nonce, 10)).toBe(true);
    expect(progress).toBeGreaterThanOrEqual(0);
  });

  it("sends no proof when the instance asks for none, and stops when aborted", async () => {
    expect(await runPow("a@b.c", 0, 0)).toEqual({ date: "1970-01-01", nonce: 0 });
    const c = new AbortController();
    c.abort();
    await expect(runPow("a@b.c", 40, 0, () => {}, c.signal)).rejects.toThrow();
  });
});
