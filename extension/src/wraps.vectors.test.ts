// Vault keys from UVK wraps (wraps.ts) and the account state the extension reads (accountstate.ts), graded
// by the shared vectors (design 2026-11-15-onboarding-trust §12.2 rule 1, §5.4, §17):
//  - wrapad.json: the shared and personal AD strings (`ad`), which envelopes open (`open`), and EVERY
//    `expect.extensionOpens` of the `adopt` rows, the high-water rows included;
//  - next/accountstate.json: the blob's AD and envelope, the merge rows whose `records` is ["vaults"], and
//    the acceptance rows' `extensionOpens`.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { adVkPersonal, fromB64, open, toB64 } from "./crypto.ts";
import { adAccountState, applyServedState, isRollback, mergeVaults, openAccountState, type ExtAccountState, type VaultRecord } from "./accountstate.ts";
import { adVkShared, openSharedWrap } from "./wraps.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const load = (name: string) => JSON.parse(readFileSync(vectorsDir + name, "utf-8"));
const wa = load("wrapad.json");
const as = load("next/accountstate.json");
const utf8 = (s: string) => new TextEncoder().encode(s);
const text = (u: Uint8Array) => new TextDecoder().decode(u);

test("wrapad.json ad: the genesis-bound shared AD and the unchanged personal AD", () => {
  assert.equal(wa.ad.length, 4);
  for (const r of wa.ad) {
    const got = r.kind === "shared" ? adVkShared(r.vaultId, r.userId, r.genesisHash) : adVkPersonal(r.vaultId, r.userId);
    assert.equal(text(got), r.adUtf8, r.why);
  }
});

test("wrapad.json open: which envelopes open under which AD", () => {
  assert.ok(wa.open.length >= 10);
  for (const r of wa.open) {
    let vk: Uint8Array | null = null;
    try {
      vk = open(fromB64(r.uvkB64), fromB64(r.wrappedVkB64), utf8(r.adUtf8));
    } catch {
      vk = null;
    }
    assert.equal(vk !== null, r.expect.opens, `${r.name}: ${r.why}`);
    if (vk !== null) assert.equal(toB64(vk), r.expect.vkB64, r.name);
  }
});

test("wrapad.json adopt: every expect.extensionOpens, by §12.2 rule 1 and the high-water mark", () => {
  assert.ok(wa.adopt.length >= 25, `adopt rows: ${wa.adopt.length}`);
  let highWaterRows = 0;
  for (const r of wa.adopt) {
    assert.equal(typeof r.expect.extensionOpens, "boolean", `${r.name} carries extensionOpens`);
    const me = wa.accounts[r.me];
    assert.ok(me, `${r.name}: account ${r.me}`);
    const served: ExtAccountState = { seq: r.accountState.seq ?? 0, vaults: r.accountState.vaults, accepted: r.accountState.accepted, dropped: 0 };
    const memory = r.extensionHighWater === undefined ? null : { highWater: r.extensionHighWater, vaults: {} };
    if (memory !== null) highWaterRows++;
    const { usable } = applyServedState(memory, served);
    const got = openSharedWrap(wa.vaultId, r.wrappedVkB64, fromB64(r.uvkB64), me.userId, usable);
    assert.equal(got.opened, r.expect.extensionOpens, `${r.name}: ${r.why}`);
    // A key the extension opens but a full client refuses (it fails the commitment) is not the vault's key.
    if (got.opened && r.expect.vkB64 !== undefined) assert.equal(toB64(got.vk), r.expect.vkB64, r.name);
  }
  assert.ok(highWaterRows >= 5, `the high-water rows are graded: ${highWaterRows}`);
});

test("next/accountstate.json: the blob's AD, and the sample envelope opens to the sample document", () => {
  assert.equal(text(adAccountState(as.userId)), as.adUtf8);
  const got = openAccountState(fromB64(as.sampleBlobB64), fromB64(as.uvkB64), as.userId);
  assert.ok(got.ok);
  assert.equal(got.state.seq, as.sample.seq);
  assert.deepEqual(got.state.vaults, as.sample.vaults);
  assert.deepEqual(got.state.accepted, as.sample.accepted);
  assert.equal(as.rejectOpen.length, 2);
  for (const r of as.rejectOpen) {
    // Each row names the slot it is opened in by its AD; this account's own slot is `as.userId`'s.
    const slot = /^andvari\/v1\|account-state\|(.+)$/.exec(r.adUtf8)?.[1];
    assert.ok(slot, `${r.name}: an account-state AD`);
    const refused = openAccountState(fromB64(r.blobB64), fromB64(r.uvkB64), slot);
    assert.equal(refused.ok, false, `${r.name}: ${r.why}`);
  }
  assert.match(as._about.join(" "), /by the extension for the rows whose `records` is \["vaults"\]/);
});

test("next/accountstate.json merge: every row whose records is [\"vaults\"]", () => {
  const rows = as.merge.filter((r: { records: string[] }) => r.records.length === 1 && r.records[0] === "vaults");
  assert.ok(rows.length >= 6, `vaults rows: ${rows.length}`);
  for (const r of rows) {
    const local: Record<string, VaultRecord> = r.local?.vaults ?? {};
    const served: Record<string, VaultRecord> = r.served?.vaults ?? {};
    const merged = mergeVaults(local, served);
    assert.deepEqual(merged.vaults, r.expect.doc.vaults, `${r.name}: ${r.why}`);
    assert.deepEqual(merged.genesisAnomalies, r.expect.genesisAnomalies, `${r.name}: anomalies`);
    assert.deepEqual(merged.forks, r.expect.forks, `${r.name}: forks`);
    assert.equal(isRollback(r.served?.seq ?? null, r.highWater), r.expect.rollback, `${r.name}: rollback`);
    assert.equal(Math.max(r.local?.seq ?? 0, r.served?.seq ?? 0), r.expect.doc.seq, `${r.name}: seq`);
    // The extension's memory after this read: the mark rises to the larger seq, the records as merged.
    const after = applyServedState({ highWater: r.highWater, vaults: local }, r.served ? { seq: r.served.seq, vaults: served, accepted: {}, dropped: 0 } : null);
    assert.deepEqual(after.memory?.vaults, r.expect.doc.vaults, `${r.name}: memory`);
  }
});

test("next/accountstate.json acceptance: extensionOpens reads decision alone", () => {
  assert.equal(as.acceptance.length, 8);
  for (const r of as.acceptance) {
    const records = { vaults: { v: { genesisHash: "0".repeat(64), seq: 0, hash: "0".repeat(64) } }, accepted: r.record ? { v: r.record } : {} };
    const got = openSharedWrap("v", "AAAA", new Uint8Array(32), "u", records);
    // The decision gate is the only thing graded here: an accepted vault goes on to the (failing) AEAD.
    assert.equal(got.opened === false && got.why === "not_accepted", !r.expect.extensionOpens, `${r.name}: ${r.why}`);
  }
});
