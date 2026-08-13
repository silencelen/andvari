import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { ClientPolicy, KdfParams } from "../api/types";
import { concat } from "../crypto/bytes";
import { DEFAULT_KDF_PARAMS } from "../crypto/keys";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { type BackupPayload, buildBackup, openBackup } from "../export/export";
import { backupKdfParams } from "./ExportPanel";

/**
 * spec 07 §2.3: the backup KDF params are the LIVE org policy's ("spec 01 §1 params"),
 * window-checked against the §2.2 open() ceilings and the libsodium minima — the
 * ceiling-or-default guard of AndvariViewModel/DesktopState. A policy-mandated raise
 * of the KDF cost must land in the produced file's header, never be silently replaced
 * by the compiled default.
 */

const policyWith = (kdfParams: KdfParams): Pick<ClientPolicy, "kdfParams"> => ({ kdfParams });

// Non-default but FAST params (vector-gen discipline — never production cost in tests),
// inside the §2.2 window on both ends.
const FAST_POLICY_KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 2, memBytes: 16_384 };

describe("backupKdfParams (spec 07 §2.3 policy window)", () => {
  it("uses the policy's params when inside the §2.2 window", () => {
    expect(backupKdfParams(policyWith(FAST_POLICY_KDF))).toEqual(FAST_POLICY_KDF);
    // The exact window edges are accepted (256 MiB / ops 16; 8 KiB / ops 1).
    const ceiling: KdfParams = { v: 1, alg: "argon2id13", ops: 16, memBytes: 256 * 1024 * 1024 };
    const floor: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8 * 1024 };
    expect(backupKdfParams(policyWith(ceiling))).toEqual(ceiling);
    expect(backupKdfParams(policyWith(floor))).toEqual(floor);
  });

  it("falls back to the compiled default when the policy is absent", () => {
    expect(backupKdfParams(null)).toBe(DEFAULT_KDF_PARAMS);
  });

  it("falls back on params above the open() ceilings (file must stay openable)", () => {
    expect(backupKdfParams(policyWith({ ...FAST_POLICY_KDF, ops: 17 }))).toBe(DEFAULT_KDF_PARAMS);
    expect(backupKdfParams(policyWith({ ...FAST_POLICY_KDF, memBytes: 256 * 1024 * 1024 + 1 }))).toBe(
      DEFAULT_KDF_PARAMS,
    );
  });

  it("falls back on params below the libsodium minima (argon2id cannot run them)", () => {
    expect(backupKdfParams(policyWith({ ...FAST_POLICY_KDF, ops: 0 }))).toBe(DEFAULT_KDF_PARAMS);
    expect(backupKdfParams(policyWith({ ...FAST_POLICY_KDF, memBytes: 4096 }))).toBe(DEFAULT_KDF_PARAMS);
  });

  it("falls back on a foreign alg or params version", () => {
    expect(backupKdfParams(policyWith({ ...FAST_POLICY_KDF, alg: "scrypt" }))).toBe(DEFAULT_KDF_PARAMS);
    expect(backupKdfParams(policyWith({ ...FAST_POLICY_KDF, v: 2 }))).toBe(DEFAULT_KDF_PARAMS);
  });
});

describe("backup container carries the policy KDF params", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a non-default policy lands in the header's kdfParams and the file re-opens", async () => {
    const payload: BackupPayload = {
      v: 1,
      exportedAt: 1_751_850_000_000,
      origin: "https://andvari.test",
      userId: "user-1",
      identityFingerprint: "",
      vaults: [],
      items: [],
      attachments: [],
      skipped: { undecryptable: [], attachmentsOverCap: [], attachmentFetchFailed: [] },
    };
    const kdf = backupKdfParams(policyWith(FAST_POLICY_KDF));
    const parts = await buildBackup("pw pw pw", crypto.randomUUID(), randomBytes(16), kdf, payload, []);
    const opened = await openBackup("pw pw pw", concat(...parts));
    // Header shape uses the §2.2 key `opsLimit` for the wire/crypto `ops`.
    expect(opened.header.kdfParams).toEqual({
      v: FAST_POLICY_KDF.v,
      alg: FAST_POLICY_KDF.alg,
      opsLimit: FAST_POLICY_KDF.ops,
      memBytes: FAST_POLICY_KDF.memBytes,
    });
    expect(opened.header.kdfParams.opsLimit).not.toBe(DEFAULT_KDF_PARAMS.ops); // the old hardcode is gone
  });
});

/**
 * Audit F08 — the CSV formula-injection warning, RENDERED.
 *
 * `writeCsv` deliberately writes a leading `=` `+` `-` `@` verbatim in every column, because
 * mangling would corrupt real secrets, and the whole bargain rests on the UI naming the rows a
 * spreadsheet would evaluate. `csvWarnings.formulaRisk` and `CSV_FORMULA_WARNING` were both
 * computed, exported and vector-pinned — and nothing rendered either, so the compensating control
 * did not exist for a user. It is a sixth bucket beside the five that were already drawn; pinned
 * on the source because this panel reads window/module singletons and cannot render in node.
 */
describe("F08 — the formula-risk bucket reaches the CSV screen", () => {
  const panel = readFileSync(fileURLToPath(new URL("./ExportPanel.tsx", import.meta.url)), "utf8");

  it("the sentence and the names are both rendered, in the CSV branch", () => {
    expect(panel).toContain("{warnings.formulaRisk.length > 0 && (");
    expect(panel).toContain("{CSV_FORMULA_WARNING} {warnings.formulaRisk.join(\", \")}.");
    expect(panel).toContain('CSV_FORMULA_WARNING,'); // …and actually imported, not just referenced
  });

  it("it is drawn like the other five buckets, so it can't be styled out of existence", () => {
    // Every bucket is the same `msg info` block; count them to catch a sixth that was added as a
    // comment, a console.log, or a differently-shaped element nobody notices.
    const csvBranch = panel.slice(panel.indexOf("{/* §1 loss enumeration"), panel.indexOf("The spec 06 plaintext warning"));
    for (const bucket of ["noteItems", "cardItems", "withAttachments", "extraUris", "emptyUsernameAndPassword", "formulaRisk"]) {
      expect(csvBranch, `${bucket} is not enumerated on screen`).toContain(`warnings.${bucket}.join(", ")`);
    }
    expect(csvBranch.match(/warnings\.\w+\.length > 0 && \(/g) ?? []).toHaveLength(6);
  });

  it("the names are enumerated, never counted (spec 07 §1)", () => {
    expect(panel).not.toContain("warnings.formulaRisk.length}");
  });
});
