import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { composeEnrollLink, parseEnrollLink, type EnrollPayload } from "./enrolllink";

// Consumes the SAME spec/test-vectors/enrolllink.json the Kotlin EnrollLinkVectorTest checks.
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v: any = JSON.parse(readFileSync(vectorsDir + "enrolllink.json", "utf-8"));

describe("enrolllink.json — round trips (link strings byte-frozen)", () => {
  it("compose reproduces the pinned link and parse carries o/t/e back verbatim", () => {
    for (const c of v.roundTrips) {
      expect(composeEnrollLink(c.o, c.t, c.e), `compose ${c.name}`).toBe(c.link);
      const expected: EnrollPayload = { v: 1, o: c.o, t: c.t, e: c.e };
      expect(parseEnrollLink(c.link), `parse ${c.name}`).toEqual(expected);
    }
  });
});

describe("enrolllink.json — parse rows", () => {
  it("returns the pinned payload-or-null for every row", () => {
    for (const c of v.parse) {
      const actual = parseEnrollLink(c.input);
      if (c.expected === null) {
        expect(actual, `parse '${c.name}' must be null`).toBeNull();
      } else {
        expect(actual, `parse '${c.name}'`).toEqual(c.expected);
      }
    }
  });

  it("is TOTAL on truncated links (never throws)", () => {
    const link = composeEnrollLink("https://vault.example", "tok123", "a@example.com");
    for (let len = 0; len <= link.length; len++) parseEnrollLink(link.slice(0, len));
  });
});

describe("captureEnrollFromLocation + peekPendingEnroll (module-singleton semantics)", () => {
  const LINK = composeEnrollLink("https://vault.example", "tok123", "a@example.com");
  const HASH = "#" + LINK.split("#")[1]!;
  const PAYLOAD: EnrollPayload = { v: 1, o: "https://vault.example", t: "tok123", e: "a@example.com" };

  function stubWindow(hash: string) {
    const replaceState = vi.fn();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).window = {
      location: { hash, pathname: "/enroll", search: "?x=1" },
      history: { replaceState },
    };
    return replaceState;
  }

  // Fresh module registry per test — the capture singleton is module state.
  async function freshModule() {
    vi.resetModules();
    return await import("./enrolllink");
  }

  afterEach(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (globalThis as any).window;
    vi.resetModules();
  });

  it("captures a valid enroll hash, strips the fragment, and peek is non-consuming", async () => {
    const replaceState = stubWindow(HASH);
    const mod = await freshModule();
    mod.captureEnrollFromLocation();
    expect(replaceState).toHaveBeenCalledWith(null, "", "/enroll?x=1");
    expect(mod.peekPendingEnroll()).toEqual(PAYLOAD);
    // Non-consuming: a StrictMode double-invoked lazy initializer sees the same payload.
    expect(mod.peekPendingEnroll()).toEqual(PAYLOAD);
  });

  it("a second call after the hash was stripped does not clobber the captured payload", async () => {
    stubWindow(HASH);
    const mod = await freshModule();
    mod.captureEnrollFromLocation();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).window.location.hash = "";
    mod.captureEnrollFromLocation();
    expect(mod.peekPendingEnroll()).toEqual(PAYLOAD);
  });

  it("leaves a non-enroll hash untouched and stores nothing", async () => {
    const replaceState = stubWindow("#/some/route");
    const mod = await freshModule();
    mod.captureEnrollFromLocation();
    expect(mod.peekPendingEnroll()).toBeNull();
    expect(replaceState).not.toHaveBeenCalled();
  });

  it("an invalid first call does not latch — a later valid hash still captures", async () => {
    stubWindow("");
    const mod = await freshModule();
    mod.captureEnrollFromLocation();
    expect(mod.peekPendingEnroll()).toBeNull();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).window.location.hash = HASH;
    mod.captureEnrollFromLocation();
    expect(mod.peekPendingEnroll()).toEqual(PAYLOAD);
  });

  it("a throwing replaceState does not take the capture down", async () => {
    stubWindow(HASH);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).window.history.replaceState = () => {
      throw new Error("denied");
    };
    const mod = await freshModule();
    expect(() => mod.captureEnrollFromLocation()).not.toThrow();
    expect(mod.peekPendingEnroll()).toEqual(PAYLOAD);
  });
});
