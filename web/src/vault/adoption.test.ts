import { beforeAll, describe, expect, it } from "vitest";
import { fromB64, toB64, toHexLower } from "../crypto/bytes";
import { adVkShared } from "../crypto/ad";
import { open } from "../crypto/envelope";
import { sha256Sync } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { latestAddOf, NONE_HELD, replayLog, type AddRecord, type VaultState } from "../crypto/trust/vaultlog";
import { gradeEveryAsync, vector } from "../crypto/trust/vectors";
import { type AdoptCondition, checkGrant, checkWrap, readOnlyStanding, recordRefusal, type VaultRecordFields } from "./adoption";
import type { LogStatus } from "./logstore";

/**
 * §3.6 adoption from the account's own wrap, graded on EVERY row of wrapad.json `adopt` (the full client's
 * expect.adopt, expect.failed and expect.vkB64). `extensionOpens` and `extensionHighWater` are the extension's
 * rule (§12.2 rule 1), not the web's, and are not graded here.
 */
const v = vector("wrapad.json");

interface AdoptRow {
  name: string;
  me: string;
  uvkB64: string;
  log: string;
  frames?: string[];
  wrappedVkB64: string | null;
  accountState: { vaults: Record<string, { genesisHash: string; seq: number; hash: string }>; accepted: Record<string, { addSeq: number; decision: "accept" | "decline" }> };
  expect: { adopt: boolean; vkB64?: string; failed?: string[] };
}

describe("wrapad.json adopt (web)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("grades every row", async () => {
    await gradeEveryAsync("wrapad.adopt (web)", v.adopt, async (row: AdoptRow) => {
      const me = v.accounts[row.me].userId as string;
      const frames = (row.frames ?? v.logs[row.log].frames).map((f: string) => fromB64(f));
      const replay = replayLog(v.vaultId, frames, null, NONE_HELD);
      const state = replay.verdict === null ? replay.state : null;
      const hashes = frames.map((f: Uint8Array) => toHexLower(sha256Sync(f)));
      const r = await checkWrap(me, fromB64(row.uvkB64), state, hashes, row.wrappedVkB64, row.accountState.vaults[v.vaultId] ?? null, row.accountState.accepted[v.vaultId] ?? null);
      if (row.expect.adopt) {
        expect(r.adopt, row.name).toBe(true);
        if (r.adopt) expect(toB64(r.vk), row.name).toBe(row.expect.vkB64);
      } else {
        expect(r, row.name).toEqual({ adopt: false, failed: row.expect.failed });
      }
    });
  });
});

/**
 * Design §3.6 (e) as decided on 23 November 2026, the twin of core's `ReadOnlyAdoptionTest`: a record ahead of the
 * served chain (the log withheld) or beside it (the log frozen after the genesis) gives the key read-only when every
 * other condition holds; in every other way (e) fails, and whenever another condition fails, nothing is taken. Graded on
 * every `adopt` row of wrapad.json whose log verifies, with the row's own record replaced by one the case chooses.
 */
describe("read-only adoption (web): a record ahead of or beside the served chain", () => {
  beforeAll(async () => {
    await initSodium();
  });

  interface Row {
    readonly name: string;
    readonly me: string;
    readonly uvk: Uint8Array;
    readonly state: VaultState;
    readonly served: readonly string[];
    readonly wrap: string | null;
    readonly accepted: { addSeq: number; decision: "accept" | "decline" } | null;
    readonly vaultId: string;
  }

  const rows = (): Row[] =>
    (v.adopt as AdoptRow[]).flatMap((row) => {
      const frames = (row.frames ?? v.logs[row.log].frames).map((f: string) => fromB64(f));
      const replay = replayLog(v.vaultId, frames, null, NONE_HELD);
      if (replay.verdict !== null || replay.state === null) return [];
      return [
        {
          name: row.name,
          me: v.accounts[row.me].userId as string,
          uvk: fromB64(row.uvkB64),
          state: replay.state,
          served: frames.map((f: Uint8Array) => toHexLower(sha256Sync(f))),
          wrap: row.wrappedVkB64,
          accepted: row.accountState.accepted[v.vaultId] ?? null,
          vaultId: v.vaultId as string,
        },
      ];
    });

  const withheld = (s: VaultState): LogStatus => ({ kind: "withheld", vaultId: s.vaultId, state: s, servedSeq: s.head.seq });
  const frozen = (s: VaultState, at: number): LogStatus => ({ kind: "frozen", vaultId: s.vaultId, state: s, atSeq: at });
  const verified = (s: VaultState): LogStatus => ({ kind: "verified", vaultId: s.vaultId, state: s, mayBeIncomplete: false });

  const otherHash = "ab".repeat(32);

  /** The record one place above the served head, naming the served chain's genesis. */
  const ahead = (r: Row): VaultRecordFields => ({ genesisHash: r.state.genesisHash, seq: r.state.head.seq + 1, hash: otherHash });

  const check = (r: Row, record: VaultRecordFields | null, log: LogStatus | null, served: readonly string[] = r.served) => checkWrap(r.me, r.uvk, r.state, served, r.wrap, record, r.accepted, log);

  /** The conditions other than (e) that fail for the row, judged with no record. */
  const others = async (r: Row): Promise<AdoptCondition[]> => {
    const c = await check(r, null, null);
    if (c.adopt) {
      c.vk.fill(0);
      return [];
    }
    return [...c.failed];
  };

  const withRecord = (failed: readonly AdoptCondition[]): AdoptCondition[] => [...new Set<AdoptCondition>([...failed, "e"])].sort();

  async function expectRefusedWithRecord(r: Row, got: Awaited<ReturnType<typeof check>>, kase: string): Promise<void> {
    expect(got, `${r.name}: ${kase}`).toEqual({ adopt: false, failed: withRecord(await others(r)) });
  }

  it("a record ahead of a withheld log gives the key read-only only when every other condition holds", async () => {
    const all = rows();
    const kinds = await Promise.all(all.map(async (r) => (await others(r)).length === 0));
    expect(kinds.includes(true) && kinds.includes(false), "the vectors hold rows of both kinds").toBe(true);
    for (const r of all) {
      const got = await check(r, ahead(r), withheld(r.state));
      if ((await others(r)).length === 0) {
        expect(got.adopt, `${r.name}: every other condition holds`).toBe(true);
        if (got.adopt) {
          expect(got.readOnly, r.name).toBe("ahead");
          got.vk.fill(0);
        }
      } else {
        await expectRefusedWithRecord(r, got, "another condition fails although the record is ahead");
      }
    }
  });

  it("a record beside a frozen log gives the key read-only only when every other condition holds", async () => {
    for (const r of rows()) {
      const got = await check(r, ahead(r), frozen(r.state, r.state.head.seq + 1));
      if ((await others(r)).length === 0) {
        expect(got.adopt, r.name).toBe(true);
        if (got.adopt) {
          expect(got.readOnly, r.name).toBe("fork");
          got.vk.fill(0);
        }
      } else {
        await expectRefusedWithRecord(r, got, "another condition fails although the log is frozen");
      }
    }
  });

  it("every other way the record can fail still refuses", async () => {
    for (const r of rows()) {
      const st = r.state;
      // The log is not withheld or frozen (a verified log, or no status given): as before.
      await expectRefusedWithRecord(r, await check(r, ahead(r), verified(st)), "a verified log");
      await expectRefusedWithRecord(r, await check(r, ahead(r), null), "no status");
      // Another beginning: the record names another genesis.
      const otherGenesis: VaultRecordFields = { genesisHash: otherHash, seq: st.head.seq + 1, hash: otherHash };
      await expectRefusedWithRecord(r, await check(r, otherGenesis, withheld(st)), "the record names another genesis");
      await expectRefusedWithRecord(r, await check(r, otherGenesis, frozen(st, st.head.seq + 1)), "another genesis, frozen");
      // A served chain whose first entry is not the verified genesis.
      await expectRefusedWithRecord(r, await check(r, ahead(r), withheld(st), [otherHash, ...r.served.slice(1)]), "another first entry");
      // Frozen at the genesis: another chain under the same id.
      await expectRefusedWithRecord(r, await check(r, ahead(r), frozen(st, 0)), "frozen at the genesis");
      // Frozen at a place the verified state already holds.
      await expectRefusedWithRecord(r, await check(r, ahead(r), frozen(st, st.head.seq)), "frozen at the verified head");
      // The status of another vault.
      const elsewhere: LogStatus = { kind: "withheld", vaultId: "00000000-0000-4000-8000-000000000001", state: st, servedSeq: st.head.seq };
      await expectRefusedWithRecord(r, await check(r, ahead(r), elsewhere), "the status of another vault");
    }
  });

  /**
   * A withheld log alone gives nothing: a record that stands beside the verified chain (another hash at a place at or
   * below the verified head, which the browser's own hashes kept over the record's) is refused, with no key, although the
   * log store calls the vault withheld. Only a record above the served head is "ahead".
   */
  it("a record beside the verified chain is refused although the log is withheld", async () => {
    const all = rows();
    const kinds = await Promise.all(all.map(async (r) => (await others(r)).length === 0));
    expect(kinds.includes(true), "the vectors hold a row whose other conditions all hold").toBe(true);
    for (const r of all) {
      const st = r.state;
      for (let place = 0; place <= st.head.seq; place++) {
        const beside: VaultRecordFields = { genesisHash: st.genesisHash, seq: place, hash: otherHash };
        await expectRefusedWithRecord(r, await check(r, beside, withheld(st)), `beside the chain at ${place} while withheld`);
      }
    }
  });

  /** The rows whose account holds an `add` of its own and whose every other condition holds: the grant road's cases. */
  const grantRows = async (): Promise<[Row, AddRecord][]> => {
    const out: [Row, AddRecord][] = [];
    for (const r of rows()) {
      const add = latestAddOf(r.state, r.me);
      if (add !== null && (await others(r)).length === 0) out.push([r, add]);
    }
    return out;
  };

  /** A grant from [add]'s actor of the row's own key, as the twin's grant check opens one. */
  const grant = (r: Row, add: AddRecord) => ({ vk: open(r.uvk, fromB64(r.wrap!), adVkShared(r.state.vaultId, r.me, r.state.genesisHash)), add });

  async function checkGrantOf(r: Row, add: AddRecord, record: VaultRecordFields, log: LogStatus, current = true, accepted = r.accepted) {
    const g = grant(r, add);
    try {
      return await checkGrant(r.me, r.state, r.served, g, current, record, accepted, log);
    } finally {
      g.vk.fill(0);
    }
  }

  /**
   * The grant road holds the same rule as the wrap road: with the record ahead and the vault withheld, and with the
   * record beside and the vault frozen, a grant gives the key read-only when every other condition holds; when its actor
   * is not a current contact, or the account's answer names an older `add`, it is refused, with no key.
   */
  it("a grant gives the key read-only only when every other condition holds", async () => {
    const all = await grantRows();
    expect(all.length, "the vectors hold a member's row whose other conditions all hold").toBeGreaterThan(0);
    for (const [r, add] of all) {
      const st = r.state;
      for (const [standing, log] of [
        ["ahead", withheld(st)],
        ["fork", frozen(st, st.head.seq + 1)],
      ] as const) {
        const ok = await checkGrantOf(r, add, ahead(r), log);
        expect(ok.adopt, `${r.name}, ${standing}: every other condition holds`).toBe(true);
        if (ok.adopt) {
          expect(ok.readOnly, `${r.name}, ${standing}`).toBe(standing);
          expect(ok.source, `${r.name}, ${standing}`).toBe("grant");
          ok.vk.fill(0);
        }

        const notCurrent = await checkGrantOf(r, add, ahead(r), log, false);
        expect(notCurrent, `${r.name}, ${standing}: the actor is not a current contact`).toEqual({ adopt: false, failed: ["d", "e"] });

        const older = { addSeq: add.seq - 1, decision: "accept" as const };
        const oldAnswer = await checkGrantOf(r, add, ahead(r), log, true, older);
        expect(oldAnswer, `${r.name}, ${standing}: the answer names an older add`).toEqual({ adopt: false, failed: ["d", "e"] });
      }
    }
  });

  it("a record on the served chain is judged as before", async () => {
    for (const r of rows()) {
      const on: VaultRecordFields = { genesisHash: r.state.genesisHash, seq: r.state.head.seq, hash: r.state.head.hash };
      for (const log of [null, verified(r.state), withheld(r.state)]) {
        const got = await check(r, on, log);
        if (got.adopt) {
          expect(await others(r), r.name).toEqual([]);
          expect(got.readOnly, `${r.name}: a record that agrees takes the key as before`).toBeNull();
          got.vk.fill(0);
        } else {
          expect(got.failed, r.name).toEqual(await others(r));
        }
      }
    }
  });

  it("a refusal of the record says how it failed", () => {
    const r = rows()[0]!;
    const st = r.state;
    expect(recordRefusal(st, r.served, ahead(r), verified(st))).toBe("record_ahead");
    expect(recordRefusal(st, r.served, ahead(r), frozen(st, st.head.seq + 1))).toBe("record_fork");
    const beside: VaultRecordFields = { genesisHash: st.genesisHash, seq: st.head.seq, hash: otherHash };
    expect(recordRefusal(st, r.served, beside, verified(st))).toBe("record_fork");
    expect(recordRefusal(st, r.served, ahead(r), frozen(st, 0))).toBe("record_genesis_mismatch");
    const otherGenesis: VaultRecordFields = { genesisHash: otherHash, seq: st.head.seq + 1, hash: otherHash };
    expect(recordRefusal(st, r.served, otherGenesis, withheld(st))).toBe("record_genesis_mismatch");
  });

  it("the standing alone: ahead only while withheld, beside only while frozen after the genesis and beyond the verified head", () => {
    const r = rows()[0]!;
    const st = r.state;
    expect(readOnlyStanding(st, r.served, ahead(r), withheld(st))).toBe("ahead");
    expect(readOnlyStanding(st, r.served, ahead(r), frozen(st, st.head.seq + 1))).toBe("fork");
    expect(readOnlyStanding(st, r.served, null, withheld(st))).toBeNull();
    expect(readOnlyStanding(st, r.served, ahead(r), null)).toBeNull();
    expect(readOnlyStanding(st, r.served, ahead(r), verified(st))).toBeNull();
    expect(readOnlyStanding(st, r.served, ahead(r), frozen(st, 0))).toBeNull();
    expect(readOnlyStanding(st, r.served, ahead(r), frozen(st, st.head.seq))).toBeNull();
    expect(readOnlyStanding(st, r.served, { ...ahead(r), genesisHash: otherHash }, withheld(st))).toBeNull();
    expect(readOnlyStanding(st, [otherHash, ...r.served.slice(1)], ahead(r), withheld(st))).toBeNull();
  });
});
