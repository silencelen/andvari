import { describe, expect, it } from "vitest";
import {
  decodeConfirmedPins,
  decodeConsumedNonces,
  decodeHeldKeys,
  decodeIdSet,
  decodeTokenSet,
  decodeTombstones,
  decodeVouches,
  encodeConfirmedPins,
  encodeConsumedNonces,
  encodeHeldKeys,
  encodeIdSet,
  encodeTokenSet,
  encodeTombstones,
  encodeVouches,
  loadRecord,
} from "./trustrecords";

/**
 * Security review 2026-10 (plugin scan F1/F2; branch A10): the device-local trust records (vouches, held keys,
 * member-granted, declined invitations, issued tombstones, confirmed pins, consumed removal nonces) are JSON records
 * with a strict decode, never delimiter-joined lines. A legacy line record is parsed ONCE on first read: lines whose
 * ids are not UUIDs are ignored, the well-formed lines survive and are re-persisted as JSON. A JSON record of an
 * unknown shape is refused. Twin of core TrustRecordsTest.kt.
 */

const v1 = "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
const v2 = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const u1 = "33333333-3333-4333-8333-333333333333";
const tagA = "a".repeat(64);
const tagB = "b".repeat(64);

describe("trust records (A10)", () => {
  it("legacy vouch lines migrate, and a malformed (forged) line is ignored", () => {
    // The scan's shape: a decoy vault id carrying a line break and a forged line for ANOTHER vault.
    const forged = `${v1}\n${v2}|${tagB}|confirmed`;
    const legacy = [`${forged}|${tagA}|frozen`, `${v2}|${tagA}|confirmed`, `not-a-uuid|${tagA}|confirmed`, `${v1}|short|confirmed`, v1].join("\n");
    const d = decodeVouches(legacy);
    expect(d.rewrite).toBe(true);
    expect(d.rows).toEqual([{ vaultId: v2, tag: tagA, kind: "confirmed" }]);
    const json = encodeVouches(d.rows)!;
    expect(json.startsWith("[")).toBe(true);
    expect(decodeVouches(json)).toEqual({ rows: d.rows, rewrite: false });
  });

  it("a JSON vouch record is decoded strictly", () => {
    expect(decodeVouches(`[{"vaultId":"${v1}","tag":"${tagA}","kind":"frozen"}]`).rows).toEqual([{ vaultId: v1, tag: tagA, kind: "frozen" }]);
    for (const bad of [
      `[{"vaultId":"${v1}","tag":"${tagA}","kind":"frozen","extra":1}]`,
      `[{"vaultId":"${v1}","tag":5,"kind":"frozen"}]`,
      `[{"vaultId":"${v1}","tag":"${tagA}","kind":"maybe"}]`,
      JSON.stringify([{ vaultId: `${v1}\n${v2}`, tag: tagA, kind: "confirmed" }]),
      `[{"vaultId":"${v1}","tag":"${tagA}"}]`,
      `["${v1}"]`,
      `{"vaultId":"${v1}"}`,
    ]) {
      const d = decodeVouches(bad);
      expect(d.rows, bad).toEqual([]);
      expect(d.rewrite, bad).toBe(true);
    }
    expect(decodeVouches(null)).toEqual({ rows: [], rewrite: false });
    expect(encodeVouches([])).toBeNull();
  });

  // A10 review LOW-1: an encoder handed a malformed row by product code THROWS (a silently dropped row is a record
  // that lies — the consumed-nonce case let a verified v1 nonce replay). Only the decoders drop.
  it("an encoder throws on a malformed row instead of dropping it silently", () => {
    const forged = `${v1}\n${v2}|${tagB}|confirmed`;
    expect(() => encodeVouches([{ vaultId: forged, tag: tagA, kind: "confirmed" }])).toThrow(/malformed/);
    expect(() => encodeVouches([{ vaultId: v1, tag: "short", kind: "confirmed" }])).toThrow(/malformed/);
    expect(() => encodeVouches([{ vaultId: v1, tag: tagA, kind: "maybe" as "confirmed" }])).toThrow(/malformed/);
    expect(() => encodeHeldKeys([{ vaultId: forged, tag: tagA }])).toThrow(/malformed/);
    expect(() => encodeIdSet([v1, `${v2}|x`])).toThrow(/malformed/);
    expect(() => encodeTokenSet(["bad token"])).toThrow(/malformed/);
    expect(() => encodeTombstones([{ vaultId: v1, userId: "not-a-uuid", at: 1 }])).toThrow(/malformed/);
    expect(() => encodeTombstones([{ vaultId: v1, userId: u1, at: 1.5 }])).toThrow(/malformed/);
    expect(() => encodeConfirmedPins([{ userId: v1, keyTag: "short" }])).toThrow(/malformed/);
    expect(() => encodeConsumedNonces([{ vaultId: v1, nonce: "a b", issuedAt: 7 }])).toThrow(/malformed/);
    const json = encodeVouches([{ vaultId: v2, tag: tagA, kind: "confirmed" }])!;
    expect(decodeVouches(json).rows).toEqual([{ vaultId: v2, tag: tagA, kind: "confirmed" }]);
    expect(json).not.toContain("\n");
  });

  it("held keys, member-granted and declined migrate the same way", () => {
    const held = decodeHeldKeys(`${v1}|${tagA}\n${v1}\n${v2}|${tagB}|confirmed\nbad|${tagA}\n${v2}|${tagB}`);
    expect(held.rewrite).toBe(true);
    expect(held.rows).toEqual([{ vaultId: v1, tag: tagA }, { vaultId: v2, tag: tagB }]);
    expect(decodeHeldKeys(encodeHeldKeys(held.rows)).rows).toEqual(held.rows);

    const granted = decodeIdSet(`${v1}\nnot-a-uuid\n${v2}|x\n${v2}`);
    expect(granted.rewrite).toBe(true);
    expect(new Set(granted.rows)).toEqual(new Set([v1, v2]));
    expect(new Set(decodeIdSet(encodeIdSet(granted.rows)).rows)).toEqual(new Set([v1, v2]));
    expect(decodeIdSet(`["${v1}","${v2}|x",7]`).rows).toEqual([v1]);

    // Declined invitations are keyed by the grantId's base64url form (not a UUID): the token grammar applies.
    const declined = decodeTokenSet("AAAAAAAAAAAAAAAAAAAAAA\nbad token\n");
    expect(declined.rows).toEqual(["AAAAAAAAAAAAAAAAAAAAAA"]);
    expect(declined.rewrite).toBe(true);
    expect(decodeTokenSet(encodeTokenSet(declined.rows)).rows).toEqual(declined.rows);
  });

  it("tombstones, confirmed pins and consumed nonces migrate the same way", () => {
    const tomb = decodeTombstones(`${v1}|${u1}|1700000000000\n${v1}|${u1}|x\n${v1}\n${v2}|${u1}|5`);
    expect(tomb.rewrite).toBe(true);
    expect(tomb.rows).toEqual([{ vaultId: v1, userId: u1, at: 1700000000000 }, { vaultId: v2, userId: u1, at: 5 }]);
    expect(decodeTombstones(encodeTombstones(tomb.rows)).rows).toEqual(tomb.rows);

    const pins = decodeConfirmedPins(`${u1}|${tagA}\n${u1}|short\n${v1}\n${v2}|${tagB}`);
    expect(pins.rewrite).toBe(true);
    expect(pins.rows).toEqual([{ userId: u1, keyTag: tagA }, { userId: v2, keyTag: tagB }]);
    expect(decodeConfirmedPins(encodeConfirmedPins(pins.rows)).rows).toEqual(pins.rows);

    const nonces = decodeConsumedNonces(`${v1}|AAAAAAAAAAAAAAAAAAAAAA|7\nbad|AAAAAAAAAAAAAAAAAAAAAA|7\n${v1}|a b|7\n${v1}|AAAAAAAAAAAAAAAAAAAAAA|x`);
    expect(nonces.rewrite).toBe(true);
    expect(nonces.rows).toEqual([{ vaultId: v1, nonce: "AAAAAAAAAAAAAAAAAAAAAA", issuedAt: 7 }]);
    expect(decodeConsumedNonces(encodeConsumedNonces(nonces.rows)).rows).toEqual(nonces.rows);
  });

  it("A11 (c11/c16): a legacy record whose first line starts with [ or { keeps its well-formed lines", () => {
    // A server-planted id beginning with "[" that sorted first used to make the whole record look like JSON of an
    // unknown shape, and the migration wiped every vouch, held key, grant tag and confirmed pin. Only a value that
    // PARSES as JSON of the wrong shape is refused; anything that fails to parse is a legacy line record.
    const vouches = decodeVouches([`[planted|${tagA}|confirmed`, `${v1}|${tagA}|frozen`, `${v2}|${tagB}|confirmed`].join("\n"));
    expect(vouches.rewrite).toBe(true);
    expect(vouches.rows).toEqual([{ vaultId: v1, tag: tagA, kind: "frozen" }, { vaultId: v2, tag: tagB, kind: "confirmed" }]);
    expect(decodeHeldKeys(`{x|${tagA}\n${v1}|${tagA}`).rows).toEqual([{ vaultId: v1, tag: tagA }]);
    expect(decodeIdSet(`[planted\n${v1}`).rows).toEqual([v1]);
    expect(decodeTokenSet(`{bad\nAAAAAAAAAAAAAAAAAAAAAA`).rows).toEqual(["AAAAAAAAAAAAAAAAAAAAAA"]);
    expect(decodeTokenSet("1234567890").rows).toEqual(["1234567890"]); // a one-line legacy set that happens to parse as a number
    expect(decodeConfirmedPins(`[x|${tagA}\n${u1}|${tagA}`).rows).toEqual([{ userId: u1, keyTag: tagA }]);
    expect(decodeTombstones(`[x|${u1}|5\n${v1}|${u1}|5`).rows).toEqual([{ vaultId: v1, userId: u1, at: 5 }]);
    expect(decodeConsumedNonces(`[x|AAAAAAAAAAAAAAAAAAAAAA|7\n${v1}|AAAAAAAAAAAAAAAAAAAAAA|7`).rows).toEqual([{ vaultId: v1, nonce: "AAAAAAAAAAAAAAAAAAAAAA", issuedAt: 7 }]);
    // JSON that parses as an object is still refused whole; a bare scalar goes through the line grammar, which refuses it.
    for (const bad of [`{"vaultId":"${v1}"}`, `{"a":1}`, "5", `"${v1}"`, "null"]) {
      expect(decodeVouches(bad).rows, bad).toEqual([]);
      expect(decodeIdSet(bad).rows, bad).toEqual([]);
    }
  });

  it("loadRecord re-persists a legacy record once, as JSON", () => {
    const store = new Map<string, string>([["k", `${v1}|${tagA}|confirmed\nbad`]]);
    const get = (k: string) => store.get(k) ?? null;
    const set = (k: string, v: string | null) => (v === null ? store.delete(k) : store.set(k, v));
    expect(loadRecord("k", get, set, decodeVouches, encodeVouches)).toEqual([{ vaultId: v1, tag: tagA, kind: "confirmed" }]);
    expect(store.get("k")!.startsWith("[")).toBe(true);
    const after = store.get("k");
    loadRecord("k", get, set, decodeVouches, encodeVouches);
    expect(store.get("k")).toBe(after);
    set("k", "bad\nworse");
    expect(loadRecord("k", get, set, decodeVouches, encodeVouches)).toEqual([]);
    expect(store.has("k")).toBe(false);
  });
});
