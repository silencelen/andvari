import { beforeAll, describe, expect, it } from "vitest";
import { utf8, fromB64, toB64 } from "../crypto/bytes";
import { open, sealWithNonce } from "../crypto/envelope";
import { initSodium } from "../crypto/sodium";
import { expectSections, gradeEvery } from "../crypto/trust/vectors";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  acceptance,
  type AccountDocument,
  type AccountLimits,
  decodeDocument,
  DEFAULT_LIMITS,
  EMPTY_DOCUMENT,
  encodeDocument,
  mergeDocuments,
  notWritten,
} from "./accountdoc";
import { isRollback, openAccountBlob } from "./accountdocstore";

/**
 * Grades the account-state document (design §5.4, spec 02 §9) on EVERY row of
 * spec/test-vectors/next/accountstate.json: the sealed sample, every decode row, every merge row and every
 * acceptance row. The harness fails if the file grows a section this suite does not grade, or if a row of a
 * graded section is passed over (gradeEvery counts them against the file).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v: any = JSON.parse(readFileSync(fileURLToPath(new URL("../../../spec/test-vectors/next/accountstate.json", import.meta.url)), "utf-8"));
const USER: string = v.userId;

function docOf(json: unknown): AccountDocument | null {
  if (json === null || json === undefined) return null;
  const d = decodeDocument(USER, JSON.stringify(json));
  if (!d) throw new Error("a vector document did not decode");
  return d.document;
}

/** A document as the JSON value the vectors compare (key order carries no meaning). */
const plain = (doc: AccountDocument): unknown => JSON.parse(encodeDocument(USER, doc));

describe("accountstate.json (next)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("names exactly the sections this suite grades", () => {
    expectSections(v, ["_about", "userId", "uvkB64", "adUtf8", "account", "sample", "samplePlaintext", "sampleNonceB64", "sampleBlobB64", "rejectOpen", "decode", "merge", "acceptance"]);
  });

  it("the sample: the blob opens to the plaintext, seals back byte for byte, and decodes to the sample document", () => {
    const uvk = fromB64(v.uvkB64);
    expect(v.adUtf8).toBe(`andvari/v1|account-state|${USER}`);
    expect(openAccountBlob(uvk, USER, v.sampleBlobB64)).toBe(v.samplePlaintext);
    expect(toB64(sealWithNonce(uvk, fromB64(v.sampleNonceB64), utf8(v.samplePlaintext), utf8(v.adUtf8)))).toBe(v.sampleBlobB64);
    const d = decodeDocument(USER, v.samplePlaintext)!;
    expect(d.dropped).toBe(0);
    expect(plain(d.document)).toEqual(v.sample);
    // The writer: compact, map keys in ascending byte order; the sample was written that way.
    expect(encodeDocument(USER, d.document)).toBe(v.samplePlaintext);
  });

  it("rejectOpen: none opens in this account's slot", () => {
    gradeEvery("accountstate.rejectOpen", v.rejectOpen, (row: { name: string; uvkB64: string; blobB64: string; adUtf8: string }) => {
      expect(() => open(fromB64(row.uvkB64), fromB64(row.blobB64), utf8(row.adUtf8)), row.name).toThrow();
      // And the store's own opener, which binds the AD to the account it reads for, refuses it for the account the AD names.
      const other = row.adUtf8.split("|").pop()!;
      if (other !== USER) expect(openAccountBlob(fromB64(row.uvkB64), other, row.blobB64), row.name).toBeNull();
    });
  });

  it("decode", () => {
    gradeEvery("accountstate.decode", v.decode, (row: { name: string; plaintext: string; expect: { refused: boolean; dropped?: number; doc?: unknown } }) => {
      const d = decodeDocument(USER, row.plaintext);
      if (row.expect.refused) {
        expect(d, row.name).toBeNull();
        return;
      }
      expect(d, row.name).not.toBeNull();
      expect(d!.dropped, row.name).toBe(row.expect.dropped);
      expect(plain(d!.document), row.name).toEqual(row.expect.doc);
    });
  });

  it("merge", () => {
    gradeEvery(
      "accountstate.merge",
      v.merge,
      (row: {
        name: string;
        local: unknown;
        served: unknown;
        highWater: number;
        limits?: Partial<AccountLimits>;
        expect: { rollback: boolean; doc: unknown; keyChange: { userId: string; identityPub: string }[]; genesisAnomalies: string[]; forks: string[]; notWritten?: string };
      }) => {
        const local = docOf(row.local) ?? EMPTY_DOCUMENT;
        const served = docOf(row.served);
        const limits = { ...DEFAULT_LIMITS, ...(row.limits ?? {}) };
        expect(isRollback(served ? served.seq : null, row.highWater), `${row.name}: rollback`).toBe(row.expect.rollback);
        const result = served ? mergeDocuments(local, served, limits) : { document: local, anomalies: [], fits: true };
        expect(plain(result.document), `${row.name}: doc`).toEqual(row.expect.doc);
        const keyChange = result.anomalies.flatMap((a) => (a.kind === "contact_key_change" ? [{ userId: a.served.userId, identityPub: a.served.identityPub }] : []));
        expect(keyChange, `${row.name}: keyChange`).toEqual(row.expect.keyChange);
        const genesis = result.anomalies.flatMap((a) => (a.kind === "vault_genesis_mismatch" ? [a.local.vaultId] : [])).sort();
        expect(genesis, `${row.name}: genesisAnomalies`).toEqual([...row.expect.genesisAnomalies].sort());
        const forks = result.anomalies.flatMap((a) => (a.kind === "vault_record_fork" ? [a.local.vaultId] : [])).sort();
        expect(forks, `${row.name}: forks`).toEqual([...row.expect.forks].sort());
        expect(notWritten(result), `${row.name}: notWritten`).toBe(row.expect.notWritten ?? null);
      },
    );
  });

  it("acceptance", () => {
    gradeEvery("accountstate.acceptance", v.acceptance, (row: { name: string; record: unknown; latestAddSeq: number; expect: { answer: string; extensionOpens: boolean } }) => {
      const vaultId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
      const doc = docOf({ v: 2, userId: USER, seq: 1, accepted: row.record === null ? {} : { [vaultId]: row.record } })!;
      expect(acceptance(doc, vaultId, row.latestAddSeq), row.name).toBe(row.expect.answer);
      // extensionOpens is the extension's row (FN-1); the web's acceptance answer above is the full client's.
    });
  });
});
