// The instance card in the extension (instancecard.ts), graded by instancecard.json (design
// 2026-11-15-onboarding-trust §4.2, §4.4, §12.2 rule 3, §17): `chains`, `reject`, `pinned`, and the `roots`
// rows of the two roots the extension has (baked and typed). `operatorDevice` is for an operator's own
// devices (VR-11), and the `kit` and `link_offer` roots belong to clients that read kits and links; the
// extension has neither (§12.2), so those rows are counted and named here, never silently skipped.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { b64Strict } from "./statement.ts";
import { comparePinned, firstPin, verifyChain, type Card, type Root } from "./instancecard.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const ic = JSON.parse(readFileSync(vectorsDir + "instancecard.json", "utf-8"));

const frameOf = (s: string): Uint8Array => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const chainNamed = (name: string) => ic.chains.find((c: { name: string }) => c.name === name);

function verified(frames: string[]): readonly Card[] {
  const r = verifyChain(frames.map(frameOf));
  assert.ok(r.ok, `the served chain verifies (${r.ok ? "" : `${r.verdict} at ${r.at}`})`);
  return r.cards;
}

test("instancecard.json chains: every card verifies in order and yields its pin record", () => {
  assert.equal(ic.chains.length, 2);
  for (const chain of ic.chains) {
    const cards = verified(chain.cards.map((c: { frameB64: string }) => c.frameB64));
    assert.equal(cards.length, chain.cards.length, chain.name);
    chain.cards.forEach((c: { hash: string; record: Record<string, unknown> }, i: number) => {
      const got = cards[i]!;
      assert.equal(got.hash, c.hash, `${chain.name} card ${i}`);
      const r = c.record;
      assert.deepEqual(
        { instanceId: got.instanceId, card0Hash: cards[0]!.hash, seq: got.seq, hash: got.hash, origin: got.origin, name: got.name, kind: got.kind, operator: got.operator, operatorSignKey: got.operatorSignKey, recoveryFp: got.recoveryFp },
        { instanceId: r.instanceId, card0Hash: r.card0Hash, seq: r.seq, hash: r.hash, origin: r.origin, name: r.name, kind: r.kind, operator: r.operator, operatorSignKey: r.operatorSignKey, recoveryFp: r.recoveryFp },
        `${chain.name} card ${i}`,
      );
    });
  }
});

test("instancecard.json reject: the verdict is raised at the appended card, in VR-10's order", () => {
  assert.ok(ic.reject.length >= 25, `reject rows: ${ic.reject.length}`);
  for (const r of ic.reject) {
    const base = chainNamed(r.chain);
    assert.ok(base, `${r.name}: chain ${r.chain}`);
    const frames = [...base.cards.slice(0, r.after).map((c: { frameB64: string }) => frameOf(c.frameB64)), frameOf(r.frameB64)];
    const got = verifyChain(frames);
    assert.ok(!got.ok, `${r.name}: refused`);
    assert.equal(got.verdict, r.expect.verdict, `${r.name}: ${r.why}`);
    assert.equal(got.at, r.after, `${r.name}: raised at the appended card`);
  }
});

test("instancecard.json pinned: a served chain against a pinned card", () => {
  assert.ok(ic.pinned.length >= 8, `pinned rows: ${ic.pinned.length}`);
  for (const r of ic.pinned) {
    const got = comparePinned(verified(r.frames), r.pin);
    assert.equal(got.verdict, r.expect.verdict, `${r.name}: ${r.why}`);
    if (got.verdict === "ok") assert.deepEqual({ seq: got.newest.seq, hash: got.newest.hash }, r.expect.newest, r.name);
  }
});

const EXTENSION_ROOTS = new Set(["baked", "typed"]);
const OTHER_ROOTS = new Set(["kit", "link_offer"]);

test("instancecard.json roots: the first pin from the baked and the typed root, origin_mismatch first", () => {
  const rows = ic.roots.filter((r: { root: { root: string } }) => EXTENSION_ROOTS.has(r.root.root));
  assert.ok(rows.length >= 10, `baked and typed rows: ${rows.length}`);
  for (const r of rows) {
    const root: Root = r.root.root === "baked" ? { root: "baked", instanceId: r.root.instanceId, card0Hash: r.root.card0Hash } : { root: "typed" };
    const cards = verified(r.frames);
    const got = firstPin(cards, root, r.dialedOrigin);
    assert.equal(got.verdict, r.expect.verdict, `${r.name}: ${r.why}`);
    if (got.verdict === "ok") assert.deepEqual(got.pin, r.expect.pinned, r.name);
    // Entry 8's second address: the origin the newest verified card names, never the dialed one.
    if (got.verdict === "origin_mismatch") {
      assert.equal(got.cardOrigin, cards[cards.length - 1]!.origin, r.name);
      assert.notEqual(got.cardOrigin, r.dialedOrigin, r.name);
    }
  }
});

test("instancecard.json: every section and every root is graded here or named as another client's", () => {
  const graded = new Set(["chains", "reject", "pinned", "roots"]);
  // VR-11, design §17: `operatorDevice` is graded on an operator's own devices only. The extension is never one: it
  // refuses the operator account (§12.2 rule 7), so the section is another client's, named here, not skipped.
  const notOurs = new Set(["operatorDevice"]);
  for (const k of Object.keys(ic)) {
    if (!Array.isArray(ic[k]) || k === "_about") continue;
    assert.ok(graded.has(k) || notOurs.has(k), `section ${k} is neither graded nor named`);
  }
  for (const r of ic.roots) assert.ok(EXTENSION_ROOTS.has(r.root.root) || OTHER_ROOTS.has(r.root.root), `${r.name}: root ${r.root.root}`);
  // The operator key image the extension cannot check: every operatorDevice row is a full-client row.
  assert.ok(ic.operatorDevice.length > 0);
  // The baked constants of the vectors' public chain are canonical (the shapes the store build bakes).
  const pub = chainNamed("public").cards[0].record;
  assert.equal(b64Strict(pub.operatorSignKey)?.length, 32);
});
