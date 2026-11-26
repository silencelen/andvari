import { beforeAll, describe, expect, it } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import type { InstanceResponse } from "../api/wire";
import { initSodium } from "../crypto/sodium";
import { gradeEveryAsync, vector } from "../crypto/trust/vectors";
import { decide } from "./passwordgate";
import { gatePinsOf } from "./passwordgate";
import { cardNamesOperator, PinStore } from "./pinstore";
import { bakedInstance, PUBLIC_INSTANCE_SOURCE } from "./publicinstance";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** The web's pin store (design §4.4): its two roots graded on instancecard.json `roots`, and every pin-store rule. */
const cards = vector("instancecard.json");
const base: string[] = cards.chains.find((c: { name: string }) => c.name === "base").cards.map((c: { frameB64: string }) => c.frameB64);
const pub: string[] = cards.chains.find((c: { name: string }) => c.name === "public").cards.map((c: { frameB64: string }) => c.frameB64);
const ORIGIN_A = "https://vault.example.org";

function storeServing(served: () => string[], baked = null as ReturnType<typeof bakedInstance>) {
  const storage = memoryStorage();
  const fetchInstance = async (): Promise<InstanceResponse> => ({ cards: served(), rotations: [] });
  return { storage, store: new PinStore(storage, fetchInstance, baked) };
}

describe("PinStore", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("grades the baked and typed-address rows of instancecard.json roots", async () => {
    const rows = cards.roots.filter((r: { root: { root: string } }) => r.root.root === "baked" || r.root.root === "typed");
    expect(rows.length).toBe(12);
    await gradeEveryAsync("instancecard.roots (web: baked, typed)", rows, async (row: { name: string; root: Record<string, string>; dialedOrigin: string; frames: string[]; expect: { verdict: string; pinned?: Record<string, unknown> } }) => {
      const baked = row.root.root === "baked" ? { origin: row.root.origin!, instanceId: row.root.instanceId!, card0Hash: row.root.card0Hash!, kind: row.root.kind as "public" } : null;
      const { store } = storeServing(() => row.frames, baked);
      let r = await store.begin(row.dialedOrigin);
      if (r.kind === "needs_trust_gate") r = store.confirmTrustGate(r.ticket);
      if (row.expect.verdict === "ok") {
        expect(r.kind, row.name).toBe("pinned");
        if (r.kind === "pinned") expect({ ...r.pin, root: undefined }, row.name).toEqual({ ...row.expect.pinned, root: undefined });
        if (r.kind === "pinned") expect(r.pin.root, row.name).toBe(baked ? "baked" : "trust_gate");
      } else {
        // An origin_mismatch also carries the address the newest card names (approved entry 8 shows both).
        const { cardOrigin, ...rest } = r as { cardOrigin?: string };
        expect(rest, row.name).toEqual({ kind: "refused", verdict: row.expect.verdict });
        if (row.expect.verdict === "origin_mismatch") {
          expect(cardOrigin, row.name).toMatch(/^https:\/\//);
          expect(cardOrigin, row.name).not.toBe(row.dialedOrigin);
        } else expect(cardOrigin, row.name).toBeUndefined();
      }
    });
  });

  it("a typed address shows the Trust Gate first and pins nothing until it is confirmed", async () => {
    const { store } = storeServing(() => base.slice(0, 2));
    const r = await store.begin(ORIGIN_A);
    expect(r.kind).toBe("needs_trust_gate");
    expect(store.state(ORIGIN_A)).toEqual({ kind: "none" });
    if (r.kind !== "needs_trust_gate") return;
    expect(r.operatorShortFp).toMatch(/^[0-9a-f]{32}$/);
    expect(store.confirmTrustGate(r.ticket).kind).toBe("pinned");
    expect(decide({ purpose: "sign_in", origin: ORIGIN_A, account: "a@b.c", pins: gatePinsOf(ORIGIN_A, store.state(ORIGIN_A)), session: null })).toBe("proceed");
  });

  it("refresh: ok advances, a shorter chain is withheld, a move is reported and the pin stays", async () => {
    let served = base.slice(0, 2);
    const { store } = storeServing(() => served);
    const g = await store.begin(ORIGIN_A);
    if (g.kind !== "needs_trust_gate") throw new Error("gate");
    store.confirmTrustGate(g.ticket);
    served = base.slice(0, 1);
    expect((await store.refresh(ORIGIN_A)).kind).toBe("withheld");
    expect(store.pinFor(ORIGIN_A)!.seq).toBe(1);
    served = base.slice(0, 3);
    const moved = await store.refresh(ORIGIN_A);
    expect(moved.kind).toBe("moved");
    if (moved.kind === "moved") expect(moved.newest.origin).toBe("https://vault2.example.org:8443");
    expect(store.pinFor(ORIGIN_A)!.seq).toBe(1);
  });

  it("a fork is durable, blocks the password rule, and only forgetting the server clears it", async () => {
    let served = base.slice(0, 2);
    const { store } = storeServing(() => served);
    const g = await store.begin(ORIGIN_A);
    if (g.kind !== "needs_trust_gate") throw new Error("gate");
    store.confirmTrustGate(g.ticket);
    served = pub;
    expect((await store.refresh(ORIGIN_A)).kind).toBe("fork");
    // Even the genuine chain served again does not lift it.
    served = base.slice(0, 2);
    expect((await store.refresh(ORIGIN_A)).kind).toBe("fork");
    expect((await store.begin(ORIGIN_A)).kind).toBe("blocked");
    expect(decide({ purpose: "sign_in", origin: ORIGIN_A, account: "a@b.c", pins: gatePinsOf(ORIGIN_A, store.state(ORIGIN_A)), session: null })).toBe("refuse_entry");
    store.forget(ORIGIN_A);
    expect(store.state(ORIGIN_A)).toEqual({ kind: "none" });
  });

  it("every newly verified pin reaches onPinned, never a forked one; a card names its operator account (§12.2 rule 7)", async () => {
    let served = base.slice(0, 2);
    const { store } = storeServing(() => served);
    const seen: number[] = [];
    const stop = store.onPinned((p) => seen.push(p.seq));
    const g = await store.begin(ORIGIN_A);
    if (g.kind !== "needs_trust_gate") throw new Error("gate");
    store.confirmTrustGate(g.ticket);
    expect(seen).toEqual([1]);
    expect((await store.refresh(ORIGIN_A)).kind).toBe("ok");
    expect(seen).toEqual([1, 1]);
    const pin = store.pinFor(ORIGIN_A)!;
    expect(cardNamesOperator(pin, pin.operator)).toBe(true);
    expect(cardNamesOperator(pin, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")).toBe(false);
    expect(cardNamesOperator(null, pin.operator)).toBe(false);
    served = pub;
    expect((await store.refresh(ORIGIN_A)).kind).toBe("fork");
    expect(seen).toEqual([1, 1]);
    stop();
    store.forget(ORIGIN_A);
  });

  it("a root never replaces an existing pin: a ticket for another chain is a conflict", async () => {
    let served = base.slice(0, 2);
    const { store } = storeServing(() => served);
    const first = await store.begin(ORIGIN_A);
    if (first.kind !== "needs_trust_gate") throw new Error("gate");
    // A ticket made earlier, from another chain, confirmed after a pin exists.
    served = base.slice(0, 1);
    const older = await new PinStore(memoryStorage(), async () => ({ cards: served, rotations: [] }), null).begin(ORIGIN_A);
    store.confirmTrustGate(first.ticket);
    if (older.kind !== "needs_trust_gate") throw new Error("gate");
    expect(store.confirmTrustGate(older.ticket)).toEqual({ kind: "pin_conflict", pinned: store.pinFor(ORIGIN_A) });
    expect(store.pinFor(ORIGIN_A)!.seq).toBe(1);
  });

  it("a damaged record blocks and is never read as no pin", async () => {
    const { store, storage } = storeServing(() => base.slice(0, 2));
    storage.set("andvari.pin2." + ORIGIN_A, "{\"instanceId\":1}");
    expect(store.state(ORIGIN_A)).toEqual({ kind: "damaged" });
    expect((await store.begin(ORIGIN_A)).kind).toBe("blocked");
    expect((await store.refresh(ORIGIN_A))).toEqual({ kind: "refused", verdict: "damaged" });
  });

  it("an unreachable instance carries its error and changes nothing", async () => {
    const storage = memoryStorage();
    const store = new PinStore(storage, async () => {
      throw new TypeError("offline");
    }, null);
    const r = await store.begin(ORIGIN_A);
    expect(r.kind).toBe("unreachable");
    expect(storage.map.size).toBe(0);
  });

  it("a kind change is never followed silently, and is accepted only for the chain shown", async () => {
    let served = base.slice(0, 7);
    const ORIGIN_B = "https://vault2.example.org:8443";
    const { store } = storeServing(() => served);
    const g = await store.begin(ORIGIN_B);
    if (g.kind !== "needs_trust_gate") throw new Error("gate");
    store.confirmTrustGate(g.ticket);
    served = base;
    const k = await store.refresh(ORIGIN_B);
    expect(k.kind).toBe("kind_changed");
    expect(store.pinFor(ORIGIN_B)!.kind).toBe("private");
    if (k.kind !== "kind_changed") return;
    expect((await store.acceptKindChange(ORIGIN_B, { newestHash: "0".repeat(64) })).kind).toBe("refused");
    const ok = await store.acceptKindChange(ORIGIN_B, { newestHash: k.newest.hash });
    expect(ok.kind).toBe("ok");
    expect(store.pinFor(ORIGIN_B)!.kind).toBe("public");
  });
});

describe("publicinstance", () => {
  it("is byte-equal to spec/public-instance.json, and has no baked root while a value is a placeholder", () => {
    const spec = JSON.parse(readFileSync(fileURLToPath(new URL("../../../spec/public-instance.json", import.meta.url)), "utf-8"));
    expect(PUBLIC_INSTANCE_SOURCE).toEqual(spec.PUBLIC_INSTANCE);
    const placeholder = Object.values(spec.PUBLIC_INSTANCE).some((v) => typeof v === "string" && v.startsWith("PLACEHOLDER:"));
    expect(bakedInstance() === null).toBe(placeholder);
  });
});
